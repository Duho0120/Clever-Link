"""
1-3. SSH 세션 모듈

- 프로파일 기반으로 SSH 접속 (비밀번호/키 파일 자동 분기)
- 처음 보는 서버는 지문(fingerprint)을 사용자에게 보여주고 승인받은 뒤 저장
  (지난 대화에서 지적된 AutoAddPolicy의 "묻지도 따지지도 않고 신뢰" 문제를 여기서 해결)
- keepalive 설정으로 방화벽의 유휴 연결 끊김 방지
"""

import base64
import concurrent.futures
import hashlib
import os
import re
import socket
import threading
import time

import paramiko

import profile_store
from profile_store import get_profile
from host_resolver import resolve_reachable_address
import mac_discovery
import mdns_discovery
import mdns_ambiguity_state
import mac_mismatch_state
import mac_resolved_state
import sheet_diverged_state
import ip_rediscovery_state
import activity_log

KNOWN_HOSTS_FILE = "known_hosts_launcher"  # 우리 앱 전용 known_hosts 파일
# ⚠ 2026-08-11 실사용 중 발견 — 30초는 죽은 연결을 알아채기엔 너무 길었다(터미널
# 재접속 버튼이 뜨는 데 오래 걸리는 원인 중 하나). terminal_server.py의 채널 상태
# 확인 주기(10초)와 맞춰서 더 빨리 감지되도록 단축.
KEEPALIVE_SECONDS = 10
# ⚠ 2026-08-10 실사용 중 발견: IP가 바뀌어 예전 주소가 완전히 죽어있으면(패킷이 조용히
# 버려지는 경우), 타임아웃 없이 client.connect()를 부르면 OS 기본 TCP 연결 타임아웃
# (윈도우 기준 수십 초 이상)까지 그냥 멈춰있는다. 동적 IP 재탐색 로직(아래 connect_profile)은
# socket.timeout을 잡아서 발동하는 구조인데, 타임아웃 자체가 없으면 그 예외가 안 나서
# 재탐색도 안 걸리고 경고 문구도 안 뜨는 채로 무한정 멈춘 것처럼 보인다.
CONNECT_TIMEOUT_SECONDS = 5
# ⚠ 2026-08-11 실사용 중 발견: 현장에서 "연결 끊김"의 대부분은 IP가 실제로 바뀐 게
# 아니라 Wi-Fi 순간 끊김 같은 일시적 문제였다. 곧바로 전체 MAC 스캔으로 넘어가면 이런
# 흔한 케이스에서도 매번 불필요하게 오래 걸려서, 재탐색 전에 짧게 대기했다가 같은
# 주소로 한 번 더 가볍게 시도해본다 (connect_profile 참고).
# ⚠ 2026-08-11 추가 개선(사용자 확인) — 이 재시도는 MAC/mDNS 스캔과 "동시에" 진행된다
# (스캔을 백그라운드로 먼저 시작해두고, 이 재시도가 실패했을 때만 스캔 결과를 기다림).
# 그래서 재시도 자체의 총 소요 시간(대기+접속 시도)을 원래(최대 6.5초)보다 짧은 약
# 4초로 줄여도 안전하다 — 어차피 실패해도 스캔이 이미 진행 중이라 손해가 없다.
QUICK_RETRY_DELAY_SECONDS = 1
QUICK_RETRY_CONNECT_TIMEOUT_SECONDS = 3  # 위 대기(1초) + 이 값(3초) = 약 4초
# ⚠ 2026-08-11 실사용 중 발견: 스캔으로 새 IP를 정확히 찾아도, 방금 재부팅/재연결된
# 장비는 네트워크는 떴지만 sshd는 아직 준비 안 됐을 수 있다. 이 타이밍에 걸려 접속이
# 실패하는 걸 흡수하기 위한 재시도 설정.
NEW_IP_CONNECT_RETRY_COUNT = 3  # 총 시도 횟수 (최초 1회 + 재시도 2회)
NEW_IP_CONNECT_RETRY_BASE_DELAY_SECONDS = 1
NEW_IP_CONNECT_RETRY_MAX_DELAY_SECONDS = 4

# ── 확인창 함수 등록 자리 ──────────────────────────────
# app_ui.py가 시작할 때 set_confirm_callback(ask_confirm)으로 등록해둔다.
# 등록 안 되어 있으면(터미널에서 직접 스크립트 테스트할 때 등) input()으로 대체한다.
_confirm_callback = None
_profile_connect_generations = {}
_profile_connect_generations_guard = threading.Lock()


def set_confirm_callback(func):
    """앱의 확인창 함수를 등록한다. (콘솔 input() 대신 GUI 팝업을 쓰기 위함)"""
    global _confirm_callback
    _confirm_callback = func


def _fingerprint_sha256(key):
    """
    OpenSSH가 보여주는 것과 같은 형식(SHA256:base64...)으로 지문을 계산.
    ssh-keygen -l 이나 실제 ssh 접속 시 봤던 것과 비교 가능하게 하기 위함.
    """
    digest = hashlib.sha256(key.asbytes()).digest()
    encoded = base64.b64encode(digest).decode().rstrip("=")
    return f"SHA256:{encoded}"


class InteractiveHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    처음 보는 서버에 접속할 때, AutoAddPolicy처럼 무조건 믿지 않고
    지문을 보여준 뒤 사용자 승인을 받는다. 승인하면 known_hosts에 저장해서
    다음부터는 같은 서버로 인식하고, 지문이 달라지면(중간자 공격 등)
    paramiko가 자동으로 접속을 거부한다.
    """

    def missing_host_key(self, client, hostname, key):
        # ⚠ 2026-08-11 사용자 요청 — 문구가 너무 길어서 현장에서 바로 읽고 판단하기
        # 어려웠다(특히 앱 창을 안 띄워두고 쓰는 경우, 팝업만 보고 즉시 판단해야 함).
        # known_hosts는 IP(hostname 인자) 기준으로 키를 저장하므로, 이 정책은 "정말
        # 처음 보는 서버"뿐 아니라 "연결 중이던 기기의 IP가 재할당됨"(동적 재탐색으로
        # 새 IP를 찾은 경우)에도 똑같이 걸린다 — 그래서 문구도 두 경우를 함께 아우르게 했다.
        fp = _fingerprint_sha256(key)
        message = (
            f"처음 접속하는 서버이거나, 연결 중이던 기기의 IP가 변경된 것으로 보입니다.\n"
            f"({hostname}) 재접속 시도할까요?\n"
            f"(보안 공격이 의심되어 신뢰하기 어려운 경우라면 취소를 누르세요.)\n\n"
            f"지문: {fp}"
        )

        if _confirm_callback is not None:
            # ⚠ 콘솔 input() 대신 앱의 GUI 팝업(tkinter)으로 물어본다.
            # --windowed로 콘솔을 숨기면 input()은 사용자에게 보이지도 않는 채로
            # 영원히 멈춰버리는 심각한 문제가 있어 반드시 GUI 확인창을 써야 한다.
            approved = _confirm_callback("처음 접속하는 서버", message)
        else:
            # 확인 함수가 등록 안 된 상태 (예: 이 파일을 스크립트로 직접 실행할 때)
            print(f"\n[처음 접속하는 서버] {hostname}")
            print(f"지문(fingerprint): {fp}")
            print("이 지문이 서버 관리자가 알려준 것과 일치하는지 확인하세요.")
            answer = input("신뢰하고 계속 접속하시겠습니까? (yes/no): ").strip().lower()
            approved = (answer == "yes")

        if not approved:
            raise paramiko.SSHException("사용자가 호스트 키 승인을 거부했습니다.")

        client.get_host_keys().add(hostname, key.get_name(), key)
        client.save_host_keys(KNOWN_HOSTS_FILE)
        print("[저장 완료] 다음부터는 이 서버를 자동으로 인식합니다.\n")


def _new_client():
    """known_hosts/정책이 세팅된 새 SSHClient를 만든다 (연결은 아직 안 함)."""
    client = paramiko.SSHClient()
    # 기존에 승인해둔 서버 목록 불러오기 (파일 없으면 그냥 빈 상태로 시작)
    if os.path.exists(KNOWN_HOSTS_FILE):
        client.load_host_keys(KNOWN_HOSTS_FILE)
    client.set_missing_host_key_policy(InteractiveHostKeyPolicy())
    return client


def _handle_changed_host_key(exc):
    """
    ⚠ 저장된 지문과 실제 서버 지문이 다를 때(paramiko.BadHostKeyException) 처리.
    "처음 보는 서버"(missing_host_key)와 달리 이건 policy 훅이 아니라 paramiko가
    client.connect() 안에서 직접 예외로 던지기 때문에 여기서 따로 잡아줘야 한다.

    병동 서버는 IP가 재할당되는 경우가 있어서(예: DHCP로 다른 장비에 같은 IP가
    배정됨), 예전엔 이럴 때 사람이 직접 known_hosts에서 그 서버 항목을 지우고
    다시 접속해서 새 지문을 등록해야 했다(그 과정에서 흔히 쓰는 명령이
    `ssh-keygen -R <호스트>`라, 사용자들이 이 상황을 "keygen 에러"라고 부르곤 함).
    다만 우리 앱은 표준 ~/.ssh/known_hosts가 아니라 자체 KNOWN_HOSTS_FILE을 쓰기
    때문에 그 명령 자체는 우리 파일에 영향이 없었다 — 그래서 여기서 앱이 직접
    같은 일(기존 지문 확인 후 승인받아 교체)을 하도록 만든다.
    지문이 달라지는 건 IP 재할당 같은 정상적인 상황일 수도 있지만, 중간자 공격일
    수도 있어서 자동으로 덮어쓰지 않고 반드시 사용자 승인을 받는다.
    """
    # ⚠ 2026-08-11 사용자 요청 — 문구 단축(missing_host_key와 같은 이유). 이 경우는 같은
    # 주소(hostname)에 예전과 다른 장비가 자리잡았을 가능성이 높은 상황이라, 보안 용어
    # 대신 "다른 기기가 사용 중"이라는 실제 상황 그대로 표현하고, 취소 안내는 Case 1과
    # 동일한 짧은 문구로 통일한다.
    hostname = exc.hostname
    old_fp = _fingerprint_sha256(exc.expected_key)
    new_fp = _fingerprint_sha256(exc.key)
    message = (
        f"'{hostname}' 주소를 지금 다른 기기가 사용 중인 것 같습니다. 재접속 시도할까요?\n"
        f"(보안 공격이 의심되어 신뢰하기 어려운 경우라면 취소를 누르세요.)\n\n"
        f"이전 지문: {old_fp}\n새 지문: {new_fp}"
    )

    if _confirm_callback is not None:
        approved = _confirm_callback("서버 지문이 변경됨", message)
    else:
        print(f"\n[서버 지문 변경됨] {hostname}")
        print(f"이전 지문: {old_fp}\n새 지문: {new_fp}")
        answer = input("신뢰하고 갱신한 뒤 계속 접속하시겠습니까? (yes/no): ").strip().lower()
        approved = (answer == "yes")

    if not approved:
        raise paramiko.SSHException(
            f"'{hostname}' 서버의 지문이 이전과 달라 접속을 거부했습니다. "
            "서버 관리자에게 실제 지문을 확인한 뒤 다시 시도하세요."
        )

    host_keys = paramiko.HostKeys()
    if os.path.exists(KNOWN_HOSTS_FILE):
        host_keys.load(KNOWN_HOSTS_FILE)
    if hostname in host_keys:
        del host_keys[hostname]
    host_keys.add(hostname, exc.key.get_name(), exc.key)
    host_keys.save(KNOWN_HOSTS_FILE)
    print(f"[갱신 완료] '{hostname}'의 새 지문을 저장했습니다.\n")


AUTH_TRANSPORT_RETRY_COUNT = 2  # "진짜 인증 실패"가 아니라 연결이 도중에 끊긴 경우에만 재시도
AUTH_TRANSPORT_RETRY_DELAY_SECONDS = 2


def _is_transient_transport_failure(exc):
    """
    ⚠ 2026-08-11 실사용 중 발견: paramiko는 인증 응답을 기다리는 도중 연결(transport)
    자체가 끊기면(상대 장비의 sshd가 아직 준비되지 않았거나, 순간적인 연결 끊김 등)
    비밀번호가 틀린 것과 똑같은 paramiko.AuthenticationException을 던진다
    ("Authentication failed: transport shut down or saw EOF" — paramiko/auth_handler.py의
    wait_for_response에서, transport.is_active()가 False가 되고 별도 저장된 예외가
    없거나 EOFError 계열일 때 이 메시지로 던져짐). 진짜 자격증명 문제(순수
    "Authentication failed.")와 달리 이건 잠깐 뒤에 재시도하면 성공할 가능성이 높아서
    구분해서 처리한다 — IP가 막 재할당된 직후처럼 원격지가 아직 완전히 준비되지 않은
    상황에서 특히 자주 재현됨(실사용 중 확인).
    """
    message = str(exc).lower()
    return (
        "transport shut down" in message
        or "saw eof" in message
        or "error reading ssh protocol banner" in message
    )


def _is_retryable_connect_failure(exc):
    return isinstance(exc, (socket.timeout, OSError)) or _is_transient_transport_failure(exc)


# ⚠ Windows 전용 소켓 옵션(SIO_KEEPALIVE_VALS)이 없는 환경(리눅스 등)에서도 임포트/실행
# 자체는 안전하게 하기 위해 hasattr로 존재 여부를 매번 확인한다 (아래 함수 참고).
KEEPALIVE_PROBE_IDLE_MS = 3000    # 이만큼 조용하면 첫 프로브 시작
KEEPALIVE_PROBE_INTERVAL_MS = 1000  # 이후 프로브 간격


def _make_keepalive_socket(host, port, timeout):
    """
    ⚠ 진짜 해결책(2026-08-11) — paramiko가 자체적으로 만드는 소켓은 OS 기본 TCP keepalive
    설정을 그대로 쓰는데, 윈도우 기본값은 첫 프로브까지 2시간이라 Wi-Fi처럼 패킷이 조용히
    사라지는 상황(응답 거부(RST)도 없음)을 몇 초 안에 감지하는 데 전혀 도움이 안 된다.
    paramiko의 transport.is_active()는 OS가 스스로 눈치챌 때만 정확해지는 수동적인 값이라,
    우리가 직접 소켓을 만들어서 OS 커널 레벨 TCP keepalive를 짧고 공격적으로(5초 유휴 후
    첫 프로브, 2초 간격 재확인) 설정한 뒤 paramiko에 넘겨준다. 그러면 OS 자체가 약
    10~15초 안에 죽은 연결을 확정해주고, 그 판단이 paramiko의 recv()/is_active()에도
    정확히 반영된다 (터미널 헬스체크가 실제로 의미 있게 동작하려면 이게 전제조건).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)  # 연결 자체가 안 되는 경우를 위한 타임아웃(이 함수 안에서만 적용)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "SIO_KEEPALIVE_VALS"):
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, KEEPALIVE_PROBE_IDLE_MS, KEEPALIVE_PROBE_INTERVAL_MS))
    sock.connect((host, port))
    sock.settimeout(None)  # 연결 후엔 paramiko가 자체 타임아웃(banner/auth_timeout)을 관리하게 둠
    return sock


def _connect(connect_kwargs):
    """BadHostKeyException(지문 변경)이 나면 사용자 승인받아 자동 재시도까지 포함해서 접속."""
    # ⚠ 호출부(connect_profile/open_connection)가 명시적으로 넘긴 값이 있으면 그걸 우선한다 —
    # 기본값은 여기 한 곳에서만 채워서 모든 접속 경로가 빠짐없이 타임아웃을 갖게 한다.
    connect_kwargs = {
        "timeout": CONNECT_TIMEOUT_SECONDS,
        "banner_timeout": CONNECT_TIMEOUT_SECONDS,
        "auth_timeout": CONNECT_TIMEOUT_SECONDS,
        **connect_kwargs,
    }

    def _connect_once():
        # ⚠ 매 시도마다 새 소켓을 직접 만들어서(_make_keepalive_socket) paramiko에 넘긴다 —
        # 소켓 생성 자체가 실패하면(연결 안 됨) socket.timeout/OSError가 그대로 나서
        # 기존 except (socket.timeout, OSError) 처리와 자연스럽게 맞물린다.
        kwargs = dict(connect_kwargs)
        kwargs["sock"] = _make_keepalive_socket(
            kwargs["hostname"], kwargs.get("port", 22), kwargs.get("timeout") or CONNECT_TIMEOUT_SECONDS)
        client = _new_client()
        try:
            client.connect(**kwargs)
        except paramiko.BadHostKeyException as e:
            client.close()
            _handle_changed_host_key(e)  # 승인 안 하면 여기서 예외를 던지고 끝남
            client = _new_client()  # 갱신된 known_hosts로 새로 만들어서 재시도
            kwargs["sock"] = _make_keepalive_socket(
                kwargs["hostname"], kwargs.get("port", 22), CONNECT_TIMEOUT_SECONDS)
            client.connect(**kwargs)
        return client

    for attempt in range(AUTH_TRANSPORT_RETRY_COUNT + 1):
        try:
            return _connect_once()
        except paramiko.AuthenticationException as e:
            if attempt >= AUTH_TRANSPORT_RETRY_COUNT or not _is_transient_transport_failure(e):
                raise  # 진짜 인증 실패(비번 틀림 등)는 재시도하지 말고 그대로 전파
            print(f"[SSH 인증 중 연결 끊김 - 재시도 {attempt + 1}/{AUTH_TRANSPORT_RETRY_COUNT}] {e}")
            time.sleep(AUTH_TRANSPORT_RETRY_DELAY_SECONDS)
        except paramiko.SSHException as e:
            if attempt >= AUTH_TRANSPORT_RETRY_COUNT or not _is_transient_transport_failure(e):
                raise
            print(f"[SSH banner timeout - retry {attempt + 1}/{AUTH_TRANSPORT_RETRY_COUNT}] {e}")
            time.sleep(AUTH_TRANSPORT_RETRY_DELAY_SECONDS)


def open_connection(profile, resolved_host, resolved_port):
    """
    ⚠ 1번 개선사항(마운트 경로 MAC 검증 공백 해소)용 저수준 연결 함수.
    connect_profile()과 달리 동적 IP 재탐색/MAC 검증 로직 없이 지정된 주소로만 순수하게
    SSH 연결을 맺는다. mount_control.py는 SSH 셸이 없어 기존엔 ARP 조회(mac_discovery.
    get_mac_for_ip)만 가능했는데, 이는 터널/라우팅을 거친 원격지에서는 항상 실패하는
    사각지대였다. get_remote_mac()과 같은 방식(원격 장비에 직접 물어보기)을 마운트
    경로에서도 쓸 수 있도록, MAC 확인 전용의 짧은 연결을 열 때 이 함수를 재사용한다.
    실패하면 예외를 그대로 던진다 (호출부에서 ARP 방식으로 대체하도록).
    """
    connect_kwargs = {
        "hostname": resolved_host,
        "port": resolved_port,
        "username": profile["username"],
    }
    if profile["auth_type"] == "password":
        connect_kwargs["password"] = profile["password"]
    else:  # key_file
        connect_kwargs["key_filename"] = profile["key_filename"]
    return _connect(connect_kwargs)


def _rediscover_new_ip(profile_name, profile, resolved_host, resolved_port):
    """
    MAC(1차)/mDNS(2차) 스캔으로 새 IP를 찾는다. 새 IP를 찾으면 반환, 못 찾으면 None.
    mDNS 후보가 여러 개면 RuntimeError를 던진다(그대로 호출부까지 전파돼서 사용자에게
    보여줘야 함).

    ⚠ 2026-08-11 개선 — connect_profile()이 "같은 주소로 짧게 재시도"와 이 스캔을
    순차가 아니라 병렬로 진행하기 위해 별도 함수로 분리했다(백그라운드 스레드에서 먼저
    시작해두고, 재시도가 실패했을 때만 이 결과를 기다리는 구조). 순수하게 "새 IP를
    찾는" 역할만 하고, 찾은 뒤 실제로 재접속하는 것은 호출부의 책임으로 남겨둔다.
    """
    ip_rediscovery_state.mark_in_progress(profile_name)
    try:
        # ⚠ print()에 "—"(em dash) 같은 특수문자를 쓰면 콘솔 인코딩이 UTF-8이 아닐 때
        # (Windows 기본 cp949 등) UnicodeEncodeError로 여기서 그대로 죽어버린다 — 실제로
        # 테스트하다 겪은 버그. 안전하게 일반 하이픈만 사용한다.
        activity_log.log(profile_name, f"[동적 IP 재탐색] '{profile_name}' 접속 실패 - 새 IP 탐색 중...")
        new_ip = None
        if profile.get("mac"):
            new_ip = mac_discovery.find_ip_for_mac(
                profile["mac"], profile["host"], resolved_port, known_ips=profile.get("recent_ips"))
        if (not new_ip or new_ip == resolved_host) and profile.get("hostname"):
            # ⚠ MAC 스캔이 실패하면(ICMP 차단 등) 2차 보험으로 mDNS(호스트 이름)로
            # 한 번 더 시도한다. 호스트 이름을 아직 모르면(SSH 터미널을 한 번도 연
            # 적이 없으면) 애초에 시도할 게 없다.
            activity_log.log(profile_name, f"[동적 IP 재탐색] MAC으로 못 찾음 - mDNS(호스트 이름 '{profile['hostname']}')로 재시도 중...")
            candidates = mdns_discovery.resolve_mdns_hostname_all(profile["hostname"])
            # ⚠ 다른 장비가 같은 호스트 이름을 쓰고 있으면 응답이 여러 개 올 수 있다.
            # 이럴 때 아무거나 하나를 골라 조용히 연결해버리면 엉뚱한 장비에 접속될
            # 위험이 있으므로, 절대 자동으로 고르지 않고 사용자에게 후보를 그대로
            # 보여주고 재탐색을 중단한다 (사용자가 직접 확인 후 수정하도록 유도).
            if len(candidates) >= 2:
                candidate_list = "\n".join(f"  {ip}" for ip in candidates)
                # ⚠ 상태줄(setStatus)은 뒤이은 다른 작업 메시지에 바로 덮어써져서 놓치기
                # 쉽다 — 메인 창에 계속 떠 있는 경고 배너로도 보여주기 위해 별도 기록.
                mdns_ambiguity_state.mark(profile_name, profile["hostname"], candidates)
                raise RuntimeError(
                    f"[동적 IP 재탐색] '{profile_name}'(호스트 이름 '{profile['hostname']}')에 "
                    f"대한 mDNS 응답이 여러 개 발견되었습니다:\n{candidate_list}\n"
                    f"같은 호스트 이름을 쓰는 다른 장비가 있을 수 있어 자동으로 선택하지 "
                    f"않았습니다. 위 후보 IP들을 직접 확인한 뒤, 이 원격지의 정보를 "
                    f"올바른 IP로 수정해주세요."
                )
            new_ip = candidates[0] if candidates else None
        if not new_ip or new_ip == resolved_host:
            activity_log.log(profile_name, f"[동적 IP 재탐색] '{profile_name}' 새 IP를 찾지 못함 (같은 네트워크 대역에 없거나 오프라인)")
            return None
        activity_log.log(profile_name, f"[동적 IP 재탐색] 새 IP 발견: {new_ip} (기존: {resolved_host})")
        return new_ip
    finally:
        ip_rediscovery_state.clear_in_progress(profile_name)


def _connect_profile_inner(profile_name, _mac_retry=False, _connect_generation=None):
    """
    프로파일 이름으로 SSH 연결을 맺고, paramiko.SSHClient를 반환한다.
    비밀번호/키 파일 인증을 자동 분기하고, keepalive를 설정한다.

    _mac_retry: MAC 불일치 자동 복구 재귀 호출인지 표시 (내부용 — 무한 재귀 방지).
    """
    profile = get_profile(profile_name)

    # ⚠ Phase 4-4 확장: 로컬 IP가 안 닿으면(사내망 밖) 보조 주소(터널)로 자동 전환.
    resolved_host, resolved_port = resolve_reachable_address(profile)

    connect_kwargs = {
        "hostname": resolved_host,
        "port": resolved_port,
        "username": profile["username"],
    }

    if profile["auth_type"] == "password":
        connect_kwargs["password"] = profile["password"]
    else:  # key_file
        connect_kwargs["key_filename"] = profile["key_filename"]

    try:
        client = _connect(connect_kwargs)
    except Exception as e:
        if not _is_retryable_connect_failure(e):
            raise
        # ⚠ 2026-08-11 실사용 중 발견: 현장에서 "연결이 끊겼다"의 대부분은 IP가 실제로
        # 바뀐 게 아니라 Wi-Fi 순간 끊김 같은 일시적 문제였다. "같은 주소로 재시도"와
        # "MAC/mDNS 스캔"을 순차로 하면, IP가 진짜 바뀐 경우엔 재시도가 실패할 걸 알면서도
        # 매번 기다려야 했다. 그래서 스캔을 백그라운드로 먼저 시작해두고 재시도를 동시에
        # 진행하다가, 재시도가 실패했을 때만 이미 진행 중이던 스캔 결과를 기다리는 병렬
        # 구조로 바꿨다 (사용자 확인 2026-08-11) — 재시도가 성공하는 흔한 경우는 그대로
        # 빠르고, IP가 진짜 바뀐 드문 경우는 재시도 시간만큼(최대 4초) 덜 기다린다.
        # ⚠ source(수동/시트) 상관없이, MAC이나 호스트 이름을 알고 있으면 무조건 스캔을
        # 시도한다 (시트=고정 IP라는 가정이 항상 맞지는 않을 수 있어서 — 사용자 확인
        # 2026-08-05). 둘 다 모르면(한 번도 성공 접속한 적 없으면) 애초에 찾을 방법이 없다.
        can_rediscover = bool(profile.get("mac") or profile.get("hostname"))
        scan_executor = None
        scan_future = None
        if can_rediscover:
            scan_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            scan_future = scan_executor.submit(
                _rediscover_new_ip, profile_name, profile, resolved_host, resolved_port)

        activity_log.log(profile_name, f"[재접속] '{profile_name}' 같은 주소로 짧게 재시도 중 (순간적인 끊김일 수 있음)...")
        time.sleep(QUICK_RETRY_DELAY_SECONDS)
        quick_retry_kwargs = {
            **connect_kwargs,
            "timeout": QUICK_RETRY_CONNECT_TIMEOUT_SECONDS,
            "banner_timeout": QUICK_RETRY_CONNECT_TIMEOUT_SECONDS,
            "auth_timeout": QUICK_RETRY_CONNECT_TIMEOUT_SECONDS,
        }
        try:
            client = _connect(quick_retry_kwargs)
            activity_log.log(profile_name, f"[재접속] '{profile_name}' 같은 주소로 재시도 성공 - IP 재탐색 불필요")
            if scan_executor:
                # ⚠ 스캔 결과는 이제 안 쓰지만, 이미 시작된 스캔 자체를 강제로 끊을 방법은
                # 없다 — 그냥 백그라운드에서 마저 끝나도록 두고 기다리지 않는다(wait=False).
                scan_executor.shutdown(wait=False)
        except Exception as e:
            if not _is_retryable_connect_failure(e):
                raise
            # ⚠ 진짜 안 닿는 상태 - 기존 동적 IP 재탐색으로 진행
            if not can_rediscover:
                raise
            # ⚠ 스캔이 이미 상당 부분(재시도 대기+접속 시도 시간만큼) 진행돼 있을 것이므로
            # 여기서 기다리는 시간은 순차 방식보다 짧다. mDNS 후보 여러 개 문제였다면
            # RuntimeError가 여기서 그대로 전파된다(_rediscover_new_ip 참고).
            new_ip = scan_future.result()
            scan_executor.shutdown(wait=False)
            if not new_ip:
                raise
            _raise_if_stale_connect_attempt(profile_name, _connect_generation)
            activity_log.log(profile_name, f"[동적 IP 재탐색] 새 IP({new_ip})로 프로파일 갱신 후 재접속")
            profile_store.update_profile_field(profile_name, host=new_ip)
            # ⚠ 초록 배너("재연결 성공") — 실제로 새 IP로 재접속까지 성공해야 의미가
            # 있으므로, 여기선 표시만 준비해두고 아래 재접속(_connect)이 실제로 예외
            # 없이 끝난 뒤에만 mark_resolved를 호출한다.
            old_ip_for_banner = resolved_host
            resolved_host = new_ip
            connect_kwargs["hostname"] = new_ip
            # ⚠ 2026-08-11 실사용 중 발견: 스캔(ping+TCP)은 네트워크 인터페이스가
            # 살아있는지만 확인하는 거라, 젯슨이 막 재부팅/재연결된 직후엔 네트워크는
            # 떴지만 sshd는 아직 완전히 안 떴을 수 있다. 그 타이밍에 걸리면 IP는
            # 정확히 찾았는데도 접속 시도가 타임아웃나서 그대로 실패해버렸다(재시도가
            # 하나도 없었음). 짧게 대기 후 한 번 더 시도해서 이 타이밍 문제를 흡수한다.
            for attempt in range(NEW_IP_CONNECT_RETRY_COUNT):
                _raise_if_stale_connect_attempt(profile_name, _connect_generation)
                try:
                    client = _connect(connect_kwargs)
                    break
                except Exception as e:
                    if not _is_retryable_connect_failure(e):
                        raise
                    if attempt >= NEW_IP_CONNECT_RETRY_COUNT - 1:
                        raise
                    delay = min(
                        NEW_IP_CONNECT_RETRY_BASE_DELAY_SECONDS + attempt,
                        NEW_IP_CONNECT_RETRY_MAX_DELAY_SECONDS,
                    )
                    print(f"[동적 IP 재탐색] 새로 찾은 IP({new_ip}) 접속 실패 - 서비스가 아직 "
                          f"준비 안 됐을 수 있어 {delay}초 후 재시도 중 "
                          f"({attempt + 2}/{NEW_IP_CONNECT_RETRY_COUNT})...")
                    time.sleep(delay)
            try:
                _raise_if_stale_connect_attempt(profile_name, _connect_generation)
            except StaleConnectAttempt:
                client.close()
                raise
            ip_rediscovery_state.mark_resolved(profile_name, old_ip_for_banner, new_ip)
            # ⚠ 여기까지 예외 없이 왔으면 새 IP로 재접속까지 성공한 것. 시트에서 온
            # 프로파일이면(source="sheet") 방금 우리가 로컬에서 바꾼 host가 시트의 마지막
            # 동기화 값(profile["host"], 아직 갱신 전 원래 값)과 달라졌다는 뜻이므로 표시해둔다
            # — 시트는 앱이 자동으로 안 건드리기로 했으니(사용자 확인 2026-08-05), 다음 시트
            # 새로고침 때 이 로컬 교정이 되돌려질 수 있다는 걸 알려주기 위함.
            if profile.get("source") == "sheet":
                sheet_diverged_state.mark(profile_name, profile["host"], new_ip)

    try:
        _raise_if_stale_connect_attempt(profile_name, _connect_generation)
    except StaleConnectAttempt:
        client.close()
        raise

    # ⚠ 여기까지 왔으면 접속에 성공한 것 — 예전에 이 프로파일이 mDNS 후보 여러 개
    # 문제로 배너에 떠 있었더라도 지금은 해소된 것이므로 자동으로 지운다.
    mdns_ambiguity_state.clear(profile_name)

    # ⚠ 5번 개선사항 — 이 IP로 실제 접속에 성공했으니, 다음에 재탐색이 필요할 때
    # 전체 스캔보다 먼저 시도해볼 후보로 기억해둔다.
    profile_store.remember_recent_ip(profile_name, resolved_host)

    # ⚠ keepalive 설정 — 사내망 방화벽이 유휴 연결을 끊는 것 방지
    client.get_transport().set_keepalive(KEEPALIVE_SECONDS)

    # ⚠ 13번 엣지케이스 2차 안전장치: 접속에 성공한 김에 지금 이 IP의 MAC을 캡처해서,
    # 저장되어 있던 "기준 MAC"과 비교한다. 계정명/비밀번호가 우연히 같아서 인증까지
    # 통과해버리면 여기 오기 전까지 아무 에러도 안 나기 때문에, MAC 비교가 사실상
    # "정말 내가 원하던 그 장비가 맞는지" 확인하는 마지막 관문이다.
    # ⚠ 원격 장비에 직접 물어보는 방식(get_remote_mac)을 먼저 시도한다 — 로컬이든
    # 라우팅/터널을 거친 원격이든 상관없이 항상 동작하기 때문. 그게 실패하면(방화벽
    # 등으로 명령이 막히는 등 드문 경우) 기존 ARP 방식으로 대체한다.
    remote_macs = get_remote_macs(client)
    captured_mac = remote_macs[0] if remote_macs else mac_discovery.get_mac_for_ip(resolved_host)
    stored_mac = profile.get("mac")
    if captured_mac:
        if not stored_mac:
            # 최초 캡처 — 앞으로 비교할 기준값으로 저장 (source 상관없이, 사용자 확인 2026-08-05).
            profile_store.update_profile_field(profile_name, mac=captured_mac)
            print(f"[MAC 저장] '{profile_name}' -> {captured_mac}")
            mac_mismatch_state.clear(profile_name)
        elif stored_mac not in remote_macs and stored_mac != captured_mac:
            # ⚠ 저장된 값은 일부러 덮어쓰지 않는다 — 자동으로 새 MAC을 기준값으로
            # 받아들이면, 진짜 엉뚱한 장비에 연결된 상황에서도 다음 접속부턴 조용히
            # "정상"처럼 보이게 되어 안전장치 의미가 없어진다. 사용자가 "수정"으로
            # 직접 확인한 뒤 반영해야만 해소되도록 한다.
            # ⚠ "다르다"에서 그치지 않고, 이 MAC이 혹시 이미 다른 원격지의 기준값으로
            # 등록돼있는지 확인 — 있으면 "사실 이건 그 원격지의 장비"까지 바로 알려줄 수 있다.
            other_owner = profile_store.find_profile_by_mac(captured_mac, exclude_name=profile_name)
            print(f"[MAC 불일치] '{profile_name}' 저장된 MAC({stored_mac}) != 지금 연결된 장비의 MAC({captured_mac})"
                  + (f" (이 MAC은 '{other_owner}'의 기준 MAC과 동일)" if other_owner else ""))
            # ⚠ 자동 복구를 시도하기 전에 일단 먼저 기록한다 — 그래야 화면에 빨간 배너가
            # 보이고, 잠시 후 복구가 성공하면 (아래 else 분기의 "불일치→일치 전환" 로직이
            # 자연스럽게) 초록 확인 배너로 바뀌는 게 사용자 눈에 보인다. 조용히 뒤에서
            # 고쳐버리면 문제가 있었다는 사실 자체를 사용자가 알 길이 없어서 원치 않음
            # (사용자 확인 2026-08-07).
            mac_mismatch_state.mark(profile_name, stored_mac, captured_mac, other_owner)

            # ⚠ 차단하기 전에 한 번, 저장된(신뢰할 수 있는) MAC을 가진 진짜 장비가 혹시
            # 같은 로컬 대역에 있는지 스캔해본다 — 있으면 사용자 개입 없이 자동으로 그
            # 주소로 재접속해서 스스로 복구한다. _mac_retry로 무한 재귀는 막는다.
            recovery_attempted = False
            if not _mac_retry:
                recovery_attempted = True
                # ⚠ 이것도 재탐색 스캔이라 노란/초록 배너 대상이다 — 아까 "동적 IP 재탐색"
                # (완전히 안 닿는 경우) 경로에만 배너를 연결해두고 이 경로(연결은 됐는데
                # MAC이 달라 자동 복구하는 경우)엔 빠뜨려서, 실사용 중 이 경로를 탄
                # 경우에는 배너가 하나도 안 뜨는 문제가 있었다 (2026-08-11 사용자 확인).
                ip_rediscovery_state.mark_in_progress(profile_name)
                try:
                    activity_log.log(profile_name, f"[MAC 불일치 자동 복구 시도] 저장된 MAC({stored_mac})을 가진 진짜 장비를 찾는 중...")
                    correct_ip = mac_discovery.find_ip_for_mac(
                        stored_mac, resolved_host, resolved_port, known_ips=profile.get("recent_ips"))
                    if correct_ip and correct_ip != resolved_host:
                        _raise_if_stale_connect_attempt(profile_name, _connect_generation)
                        activity_log.log(profile_name, f"[MAC 불일치 자동 복구] 올바른 장비를 {correct_ip}에서 찾음 - 재접속 시도")
                        client.close()
                        profile_store.update_profile_field(profile_name, host=correct_ip)
                        # ⚠ 재귀 호출이 실제로 성공해야 의미가 있으므로, 그게 예외 없이
                        # 끝난 뒤에만 초록 배너를 기록한다.
                        result = _connect_profile_inner(
                            profile_name,
                            _mac_retry=True,
                            _connect_generation=_connect_generation,
                        )
                        _raise_if_stale_connect_attempt(profile_name, _connect_generation)
                        ip_rediscovery_state.mark_resolved(profile_name, resolved_host, correct_ip)
                        return result
                    activity_log.log(profile_name, "[MAC 불일치 자동 복구 실패] 로컬 대역에서 진짜 장비를 못 찾음 - 접속 차단")
                finally:
                    ip_rediscovery_state.clear_in_progress(profile_name)

            # ⚠ 경고만 하고 계속 쓰게 두면, 계정/비번이 우연히 같은 엉뚱한 장비의 파일을
            # 만지거나 명령을 실행해버릴 위험이 있다 — 확정된 불일치(조회 실패로 "모름"이
            # 아니라 값이 서로 다름을 확인한 경우)이고 자동 복구도 안 되면, 접속 자체를
            # 차단한다. 배너에 이미 두 MAC 값이 자세히 나오니, 사용자가 확인 후 "수정"으로
            # 반영하면 다음 접속부터 다시 열린다 (사용자 확인 2026-08-06).
            # ⚠ 자동 복구를 실제로 시도했다가 실패한 경우엔, 그냥 "다르다"가 아니라 "찾아봤지만
            # 못 찾았다"는 걸 메시지에 명시한다(사용자 확인 2026-08-07) — 재탐색 자체가
            # 시도됐는지 헷갈리지 않도록.
            recovery_note = (
                "저장된 MAC을 가진 장비를 이 PC의 로컬 네트워크에서 자동으로 재탐색했지만 찾지 못했습니다. "
                if recovery_attempted else ""
            )
            client.close()
            raise RuntimeError(
                f"[MAC 불일치로 접속 차단] '{profile_name}' 접속을 중단했습니다 - 저장된 MAC과 "
                f"실제 연결된 장비의 MAC이 다릅니다. {recovery_note}엉뚱한 장비일 위험이 있어 자동으로 막았습니다. "
                f"아래 경고 배너에서 MAC을 확인한 뒤, 맞는 장비라면 '수정'으로 새 기준값을 입력하고 "
                f"다시 시도해주세요."
            )
        else:
            # ⚠ "불일치였다가 지금 일치로 바뀐" 전환일 때만 초록 확인 배너를 띄운다
            # (매번 일치할 때마다 알리면 스팸이 됨 — 사용자 확인 2026-08-05).
            if profile_name in mac_mismatch_state.get_all():
                mac_resolved_state.mark(profile_name, captured_mac)
            mac_mismatch_state.clear(profile_name)

    # ⚠ mDNS 재탐색(MAC 실패 시 2차 보험)용 호스트 이름도 같은 방식으로 캡처해둔다.
    # 마운트(mount_control.py)는 SSH 셸이 없어서 이 캡처를 못 하므로, 최소 한 번은
    # SSH 터미널로 접속해야 이 값이 채워진다.
    if not profile.get("hostname"):
        try:
            remote_hostname = run_command(client, "hostname").strip()
        except Exception:
            remote_hostname = ""
        if remote_hostname:
            profile_store.update_profile_field(profile_name, hostname=remote_hostname)
            print(f"[호스트 이름 저장] '{profile_name}' -> {remote_hostname}")

    return client


class StaleConnectAttempt(RuntimeError):
    pass


def _next_profile_connect_generation(profile_name):
    with _profile_connect_generations_guard:
        generation = _profile_connect_generations.get(profile_name, 0) + 1
        _profile_connect_generations[profile_name] = generation
        return generation


def cancel_profile_connect(profile_name):
    if not profile_name:
        return
    _next_profile_connect_generation(profile_name)


def _is_current_connect_attempt(profile_name, generation):
    if generation is None:
        return True
    with _profile_connect_generations_guard:
        return _profile_connect_generations.get(profile_name) == generation


def _raise_if_stale_connect_attempt(profile_name, generation):
    if not _is_current_connect_attempt(profile_name, generation):
        raise StaleConnectAttempt(f"[재접속] '{profile_name}' 이전 접속 시도는 새 요청으로 대체되어 중단합니다.")


def connect_profile(profile_name, _mac_retry=False):
    generation = _next_profile_connect_generation(profile_name)
    try:
        return _connect_profile_inner(
            profile_name,
            _mac_retry=_mac_retry,
            _connect_generation=generation,
        )
    except StaleConnectAttempt:
        raise


def run_command(client, command):
    """SFTP 마운트 확인용이 아니라, 명령 한 번 실행하고 결과를 받는 용도."""
    stdin, stdout, stderr = client.exec_command(command)
    return stdout.read().decode()


_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


def _normalize_remote_mac(mac):
    if not mac:
        return None
    mac = mac.strip().lower().replace(":", "-")
    if re.match(r"^[0-9a-f]{2}(-[0-9a-f]{2}){5}$", mac):
        return mac
    return None


def get_remote_macs(client):
    """
    Return MAC addresses reported by the remote Linux host.

    nmap/ARP sees the L2 interface MAC, while the old remote check only read the
    default-route interface. On Jetson setups with Wi-Fi/Ethernet/virtual
    interfaces, those can differ, so identity verification should accept the
    stored MAC if it appears on any real remote interface.
    """
    try:
        default_iface = ""
        route_output = run_command(client, "ip route show default 2>/dev/null")
        match = re.search(r"\bdev\s+(\S+)", route_output)
        if match:
            default_iface = match.group(1)

        output = run_command(client, "for p in /sys/class/net/*/address; do i=$(basename $(dirname $p)); m=$(cat $p 2>/dev/null); echo \"$i $m\"; done")
        primary = []
        secondary = []
        seen = set()
        for line in output.splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            iface, mac = parts
            if iface == "lo" or mac == "00:00:00:00:00:00":
                continue
            normalized = _normalize_remote_mac(mac)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            if iface == default_iface:
                primary.append(normalized)
            elif iface.startswith(("docker", "br-", "veth", "virbr", "tun", "tap")):
                secondary.append(normalized)
            else:
                primary.append(normalized)
        return primary + secondary
    except Exception:
        return []


def get_remote_mac(client):
    """
    ⚠ mac_discovery.get_mac_for_ip()(ARP 조회)의 근본적인 한계 대응 — ARP는 같은
    로컬 네트워크(L2) 안에서만 동작하는 프로토콜이라, 라우터/VPN/터널(loclx.io 등)을
    거쳐 도달하는 원격지는 애초에 ARP로 MAC을 알아낼 방법이 없다(실사용 중 실제로
    발견된 사각지대 — 2026-08-06). "내 PC 기준 밖에서 알아내는" ARP 대신, 이미 SSH로
    연결되어 있으니 "그 장비한테 직접 물어보는" 방식으로 바꾸면 로컬/원격 상관없이 항상
    동작한다.
    도커 veth 등 여러 인터페이스가 섞여있을 수 있어서(이 세션에서 실제 젯슨으로 확인된
    문제 — hostname -I에 도커 브리지 주소도 같이 나옴), 아무 인터페이스나 고르지 않고
    "기본 라우트로 나가는" 인터페이스 하나만 골라서 그 MAC을 쓴다.
    실패하면(명령이 없는 환경 등) None — 이 경우 호출부에서 ARP 방식으로 대체한다.
    """
    try:
        route_output = run_command(client, "ip route show default 2>/dev/null")
        match = re.search(r"\bdev\s+(\S+)", route_output)
        if not match:
            return None
        iface = match.group(1)
        mac_output = run_command(client, f"cat /sys/class/net/{iface}/address 2>/dev/null").strip()
        normalized = _normalize_remote_mac(mac_output)
        if normalized:
            return normalized
    except Exception:
        pass
    return None


EXCLUDE_FS_PREFIXES = (
    "tmpfs", "devtmpfs", "overlay", "proc", "sysfs",
    "cgroup", "udev", "shm", "squashfs", "none",
    "rootfs",  # ⚠ WSL의 /init처럼, 실제로는 폴더가 아니라 파일인 항목이 이 타입으로 잡혀서 마운트 시도 시 실패했음
)
EXCLUDE_MOUNT_PREFIXES = ("/boot", "/dev", "/sys", "/proc", "/run", "/snap")


def get_remote_volumes(profile_name):
    """
    서버에 'df -hP'를 실행해서, 실제로 마운트된 저장소(볼륨) 목록을 돌려준다.
    읽기 전용 명령이라 서버에는 영향 없음.
    tmpfs/proc/sysfs 같은 시스템용 가상 파일시스템, /boot·/dev 등은
    데이터 저장용이 아니라 목록에서 제외한다.
    """
    client = connect_profile(profile_name)
    try:
        output = run_command(client, "df -hP")
    finally:
        client.close()

    volumes = []
    lines = output.strip().splitlines()
    for line in lines[1:]:  # 첫 줄은 헤더(Filesystem Size Used Avail Use% Mounted on)
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        filesystem, size, used, avail, use_pct, mount_point = parts
        if filesystem.lower().startswith(EXCLUDE_FS_PREFIXES):
            continue
        if any(mount_point == p or mount_point.startswith(p + "/") for p in EXCLUDE_MOUNT_PREFIXES):
            continue
        volumes.append({
            "mount_point": mount_point,
            "size": size,
            "used": used,
            "avail": avail,
            "use_percent": use_pct,
        })
    return volumes


def open_terminal_channel(client):
    """
    대화형 터미널(PTY)을 여는 함수. xterm.js(웹 터미널)와 연결된다.
    ⚠ term 기본값(vt100)을 그대로 두면 원격 셸이 방향키 등을 vt100 방식의
    이스케이프 시퀀스로 기대하는데 xterm.js는 xterm 방식으로 보내서 안 맞는다.
    그러면 위/아래 화살표로 명령어 히스토리를 불러오는 대신 "^[[A" 같은 리터럴
    문자가 그대로 화면에 찍힌다. xterm.js와 실제로 맞는 term 타입으로 요청한다.
    """
    # ⚠ 'xterm-256color'로 했다가도 히스토리 화살표가 여전히 안 될 수 있다 —
    # 원격 서버(특히 최소 설치된 임베디드 리눅스)에 그 terminfo 항목 자체가 없으면
    # 오히려 TERM을 못 알아봐서 더 나빠질 수 있음. 'xterm'은 훨씬 널리 깔려있는
    # 기본 terminfo라 더 안전하다.
    channel = client.invoke_shell(term="xterm")
    return channel
