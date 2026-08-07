"""
1-3. SSH 세션 모듈

- 프로파일 기반으로 SSH 접속 (비밀번호/키 파일 자동 분기)
- 처음 보는 서버는 지문(fingerprint)을 사용자에게 보여주고 승인받은 뒤 저장
  (지난 대화에서 지적된 AutoAddPolicy의 "묻지도 따지지도 않고 신뢰" 문제를 여기서 해결)
- keepalive 설정으로 방화벽의 유휴 연결 끊김 방지
"""

import base64
import hashlib
import os
import re
import socket

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

KNOWN_HOSTS_FILE = "known_hosts_launcher"  # 우리 앱 전용 known_hosts 파일
KEEPALIVE_SECONDS = 30

# ── 확인창 함수 등록 자리 ──────────────────────────────
# app_ui.py가 시작할 때 set_confirm_callback(ask_confirm)으로 등록해둔다.
# 등록 안 되어 있으면(터미널에서 직접 스크립트 테스트할 때 등) input()으로 대체한다.
_confirm_callback = None


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
        fp = _fingerprint_sha256(key)
        message = (
            f"처음 접속하는 서버입니다: {hostname}\n\n"
            f"지문(fingerprint): {fp}\n\n"
            f"이 지문이 서버 관리자가 알려준 것과 일치하는지 확인하세요.\n"
            f"신뢰하고 계속 접속하시겠습니까?"
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
    hostname = exc.hostname
    old_fp = _fingerprint_sha256(exc.expected_key)
    new_fp = _fingerprint_sha256(exc.key)
    message = (
        f"'{hostname}' 서버의 지문(fingerprint)이 이전에 저장된 것과 다릅니다.\n\n"
        f"이전 지문: {old_fp}\n"
        f"새 지문: {new_fp}\n\n"
        f"서버 IP가 다른 장비로 재할당됐거나 서버를 새로 설치한 경우 정상적인 변화일 "
        f"수 있지만, 다른 서버로 연결되고 있는(중간자 공격 등) 상황일 수도 있습니다.\n"
        f"서버 관리자에게 확인한 지문과 일치하는 경우에만 신뢰하세요.\n\n"
        f"신뢰하고 새 지문으로 갱신한 뒤 계속 접속하시겠습니까?"
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


def _connect(connect_kwargs):
    """BadHostKeyException(지문 변경)이 나면 사용자 승인받아 자동 재시도까지 포함해서 접속."""
    client = _new_client()
    try:
        client.connect(**connect_kwargs)
    except paramiko.BadHostKeyException as e:
        client.close()
        _handle_changed_host_key(e)  # 승인 안 하면 여기서 예외를 던지고 끝남
        client = _new_client()  # 갱신된 known_hosts로 새로 만들어서 재시도
        client.connect(**connect_kwargs)
    return client


def connect_profile(profile_name, _mac_retry=False):
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
    except (socket.timeout, OSError):
        # ⚠ 동적 IP 재탐색: 접속 자체가 안 되는(호스트 unreachable) 경우에만 시도한다.
        # 비밀번호 오류 등은 paramiko.AuthenticationException이라 여기 안 걸림 — 그런
        # 경우까지 IP를 바꾸려 들면 안 되므로 의도적으로 socket/OSError만 잡는다.
        # ⚠ source(수동/시트) 상관없이, MAC이나 호스트 이름을 알고 있으면 무조건 시도한다
        # (시트=고정 IP라는 가정이 항상 맞지는 않을 수 있어서, 알고 있는 정보가 있으면
        # 그냥 써보자는 방향으로 변경함 — 사용자 확인 2026-08-05). 둘 다 모르면
        # (한 번도 성공 접속한 적 없으면) 애초에 찾을 방법이 없다.
        if not (profile.get("mac") or profile.get("hostname")):
            raise
        # ⚠ print()에 "—"(em dash) 같은 특수문자를 쓰면 콘솔 인코딩이 UTF-8이 아닐 때
        # (Windows 기본 cp949 등) UnicodeEncodeError로 여기서 그대로 죽어버린다 — 실제로
        # 테스트하다 겪은 버그. 안전하게 일반 하이픈만 사용한다.
        print(f"[동적 IP 재탐색] '{profile_name}' 접속 실패 - 새 IP 탐색 중...")
        new_ip = None
        if profile.get("mac"):
            new_ip = mac_discovery.find_ip_for_mac(profile["mac"], profile["host"])
        if (not new_ip or new_ip == resolved_host) and profile.get("hostname"):
            # ⚠ MAC 스캔이 실패하면(ICMP 차단 등) 2차 보험으로 mDNS(호스트 이름)로
            # 한 번 더 시도한다. 호스트 이름을 아직 모르면(SSH 터미널을 한 번도 연
            # 적이 없으면) 애초에 시도할 게 없다.
            print(f"[동적 IP 재탐색] MAC으로 못 찾음 - mDNS(호스트 이름 '{profile['hostname']}')로 재시도 중...")
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
            print(f"[동적 IP 재탐색] '{profile_name}' 새 IP를 찾지 못함 (같은 네트워크 대역에 없거나 오프라인)")
            raise
        print(f"[동적 IP 재탐색] 새 IP 발견: {new_ip} (기존: {resolved_host}) - 프로파일 갱신 후 재접속")
        profile_store.update_profile_field(profile_name, host=new_ip)
        resolved_host = new_ip
        connect_kwargs["hostname"] = new_ip
        client = _connect(connect_kwargs)
        # ⚠ 여기까지 예외 없이 왔으면 새 IP로 재접속까지 성공한 것. 시트에서 온
        # 프로파일이면(source="sheet") 방금 우리가 로컬에서 바꾼 host가 시트의 마지막
        # 동기화 값(profile["host"], 아직 갱신 전 원래 값)과 달라졌다는 뜻이므로 표시해둔다
        # — 시트는 앱이 자동으로 안 건드리기로 했으니(사용자 확인 2026-08-05), 다음 시트
        # 새로고침 때 이 로컬 교정이 되돌려질 수 있다는 걸 알려주기 위함.
        if profile.get("source") == "sheet":
            sheet_diverged_state.mark(profile_name, profile["host"], new_ip)

    # ⚠ 여기까지 왔으면 접속에 성공한 것 — 예전에 이 프로파일이 mDNS 후보 여러 개
    # 문제로 배너에 떠 있었더라도 지금은 해소된 것이므로 자동으로 지운다.
    mdns_ambiguity_state.clear(profile_name)

    # ⚠ keepalive 설정 — 사내망 방화벽이 유휴 연결을 끊는 것 방지
    client.get_transport().set_keepalive(KEEPALIVE_SECONDS)

    # ⚠ 13번 엣지케이스 2차 안전장치: 접속에 성공한 김에 지금 이 IP의 MAC을 캡처해서,
    # 저장되어 있던 "기준 MAC"과 비교한다. 계정명/비밀번호가 우연히 같아서 인증까지
    # 통과해버리면 여기 오기 전까지 아무 에러도 안 나기 때문에, MAC 비교가 사실상
    # "정말 내가 원하던 그 장비가 맞는지" 확인하는 마지막 관문이다.
    # ⚠ 원격 장비에 직접 물어보는 방식(get_remote_mac)을 먼저 시도한다 — 로컬이든
    # 라우팅/터널을 거친 원격이든 상관없이 항상 동작하기 때문. 그게 실패하면(방화벽
    # 등으로 명령이 막히는 등 드문 경우) 기존 ARP 방식으로 대체한다.
    captured_mac = get_remote_mac(client) or mac_discovery.get_mac_for_ip(resolved_host)
    stored_mac = profile.get("mac")
    if captured_mac:
        if not stored_mac:
            # 최초 캡처 — 앞으로 비교할 기준값으로 저장 (source 상관없이, 사용자 확인 2026-08-05).
            profile_store.update_profile_field(profile_name, mac=captured_mac)
            print(f"[MAC 저장] '{profile_name}' -> {captured_mac}")
            mac_mismatch_state.clear(profile_name)
        elif stored_mac != captured_mac:
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
                print(f"[MAC 불일치 자동 복구 시도] 저장된 MAC({stored_mac})을 가진 진짜 장비를 찾는 중...")
                correct_ip = mac_discovery.find_ip_for_mac(stored_mac, resolved_host)
                if correct_ip and correct_ip != resolved_host:
                    print(f"[MAC 불일치 자동 복구] 올바른 장비를 {correct_ip}에서 찾음 - 재접속 시도")
                    client.close()
                    profile_store.update_profile_field(profile_name, host=correct_ip)
                    return connect_profile(profile_name, _mac_retry=True)
                print("[MAC 불일치 자동 복구 실패] 로컬 대역에서 진짜 장비를 못 찾음 - 접속 차단")

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


def run_command(client, command):
    """SFTP 마운트 확인용이 아니라, 명령 한 번 실행하고 결과를 받는 용도."""
    stdin, stdout, stderr = client.exec_command(command)
    return stdout.read().decode()


_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


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
        if _MAC_RE.match(mac_output):
            return mac_output.lower().replace(":", "-")
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


# ── 여기서부터 테스트 ──────────────────────────────────────
if __name__ == "__main__":
    print("=== 1-3 SSH 세션 모듈 테스트 ===\n")

    PROFILE = "WSL테스트_비번"

    print(f"'{PROFILE}' 프로파일로 접속 시도...")
    client = connect_profile(PROFILE)
    print("[접속 성공]\n")

    # 1. exec_command 테스트
    result = run_command(client, "whoami")
    print(f"exec_command 결과: {result.strip()}")

    # 2. invoke_shell (대화형 터미널) 테스트
    print("\n대화형 셸(invoke_shell) 테스트...")
    channel = open_terminal_channel(client)
    channel.send("echo hello_from_shell\n")

    import time
    time.sleep(1)  # 서버 응답 기다리기
    output = channel.recv(4096).decode()
    print(f"셸 출력:\n{output}")

    channel.close()
    client.close()
    print("\n=== 테스트 끝 ===")
    print(f"\n참고: {KNOWN_HOSTS_FILE} 파일이 생성되었는지 확인해보세요.")
    print("다시 이 스크립트를 실행하면, 이번엔 지문 승인 질문 없이 바로 접속됩니다.")