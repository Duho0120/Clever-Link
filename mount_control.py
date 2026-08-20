"""
1-2. 마운트 제어 모듈

- rclone을 rcd(원격 제어 서버) 모드로 백그라운드에 띄우고,
  HTTP API(rc)로 마운트/해제/조회를 수행한다.
- 프로파일의 비밀번호를 rclone.conf에 저장하지 않기 위해,
  매번 "즉석 원격(connection string)"을 만들어서 넘긴다.
  예: :sftp,host=127.0.0.1,user=sky_1214,pass=XXXX,port=22:
- mount/mount 호출 후에는 반드시 mount/listmounts로 재검증한다.
  (rclone이 성공 응답을 주고도 실제로는 마운트 안 되는 사례가 보고되어 있음)
"""

import os
import string
import ctypes
import subprocess
import time
import json
import requests

import profile_store
from profile_store import get_profile
from resource_path import resource_path
from host_resolver import resolve_reachable_address, is_reachable
import mac_discovery
import mdns_discovery
import mdns_ambiguity_state
import mac_mismatch_state
import sheet_diverged_state
import mac_resolved_state
import ssh_session
import ip_rediscovery_state

# ⚠ 2026-08-11 실사용 중 발견(ssh_session.py와 동일한 이유) — "안 닿음"의 대부분은 IP가
# 실제로 바뀐 게 아니라 순간적인 네트워크 끊김이다. 전체 MAC 스캔으로 넘어가기 전에
# 짧게 대기했다가 같은 주소로 한 번 더 확인해서, 흔한 케이스에서 불필요한 스캔을 피한다.
QUICK_RETRY_DELAY_SECONDS = 1.5
# ⚠ 2026-08-11 실사용 중 발견 — 스캔으로 새 IP를 정확히 찾아도, 방금 재부팅/재연결된
# 장비는 네트워크는 떴지만 SFTP 서비스는 아직 준비 안 됐을 수 있다. 이 타이밍 문제를
# 흡수하기 위한 재시도 대기 시간 (ssh_session.py와 동일한 값 사용).
NEW_IP_CONNECT_RETRY_DELAY_SECONDS = 3

RC_ADDR = "127.0.0.1:5572"  # ⚠ "localhost"는 IPv6([::1])로 해석되어 지연/실패를 일으킨 전례가 있어 명시적 IP 사용
RC_USER = "launcher"
RC_PASS = "launcher_local_only"  # localhost 전용이라 단순 고정값으로 충분
RC_BASE_URL = f"http://{RC_ADDR}"

_rcd_process = None  # 우리가 띄운 rcd 프로세스를 기억해두는 곳

MOUNT_STATE_FILE = "mount_state.json"
# ⚠ find_current_drive_for_profile을 rclone의 mount/listmounts "Fs" 문자열 비교로 구현했었으나,
# 실제로는 rclone이 즉석 원격(connection string)을 ":sftp{ZcLhz}:" 같은 내부 해시로만 보여줘서
# host=/user= 문자열이 그 안에 전혀 없었음 -> 항상 None을 반환하는 버그였음 (F-2 검증 중 발견).
# 비밀번호를 rclone.conf에 남기는 대안(named remote 등록) 대신, 민감정보가 없는
# {프로파일명: 드라이브} 매핑만 파일로 따로 관리하고, is_mounted()로 매번 재검증해 자체 교정한다.


def _load_mount_state():
    if not os.path.exists(MOUNT_STATE_FILE):
        return {}
    try:
        with open(MOUNT_STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_mount_state(state):
    with open(MOUNT_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def _remember_mount(profile_name, drive_letter, remote_path="/"):
    state = _load_mount_state()
    state[profile_name] = {"drive": drive_letter, "remote_path": remote_path}
    _save_mount_state(state)


def _entry_drive(entry):
    """옛 형식(문자열)과 새 형식(dict)을 함께 지원."""
    return entry if isinstance(entry, str) else entry.get("drive")


def _forget_drive(drive_letter):
    """이 드라이브 문자를 가리키던 매핑을 전부 지운다 (해제 시 호출)."""
    normalized = drive_letter.rstrip("\\").upper()
    state = _load_mount_state()
    changed = False
    for name in list(state.keys()):
        drive = _entry_drive(state[name])
        if drive and drive.rstrip("\\").upper() == normalized:
            del state[name]
            changed = True
    if changed:
        _save_mount_state(state)


def find_available_drive_letter():
    """
    F-2: 지금 Windows에서 사용 중이지 않은 드라이브 문자를 찾아 하나 돌려준다.
    (사용자가 직접 타이핑하지 않고 자동 배정하기 위함)

    Z부터 거꾸로 찾는 이유: A/B는 옛날 플로피디스크용 관례라 피하고,
    C 근처(로컬 디스크가 몰려있는 낮은 알파벳)와 최대한 안 겹치게 하기 위함.
    """
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    used = set()
    for i, letter in enumerate(string.ascii_uppercase):
        if bitmask & (1 << i):
            used.add(letter)

    for letter in reversed(string.ascii_uppercase):
        if letter in ("A", "B"):
            continue
        if letter not in used:
            return letter

    raise RuntimeError("사용 가능한 드라이브 문자가 없습니다 (모든 알파벳이 사용 중)")


def _find_rclone_exe():
    """
    동봉된 rclone.exe가 있으면 그걸 쓰고, 없으면(개발 중일 때)
    시스템 PATH의 rclone을 그대로 사용한다.
    """
    bundled = resource_path("rclone.exe")
    if os.path.exists(bundled):
        return bundled
    return "rclone"  # 개발 중: winget으로 설치해둔 PATH의 rclone 사용


def _rc_call(endpoint, payload=None):
    """
    rclone rc API를 호출하는 공용 함수.
    ⚠ requests가 던지는 원본 예외 메시지("HTTPConnectionPool(host='127.0.0.1', port=5572): ...")는
    항상 로컬 rcd 주소(127.0.0.1:5572)만 보여줄 뿐 실제로 어떤 원격지에 접속하려 했는지,
    왜 실패했는지는 전혀 알려주지 않아서 매번 똑같이 뜨는 것처럼 보였다 (사용자 확인
    2026-07-21). 여기서 한 번에 알아보기 쉬운 한국어 메시지로 바꿔서 위로 던진다.
    rclone이 진짜 에러를 JSON으로 돌려준 경우(예: 인증 실패)는 그 실제 메시지를 그대로 쓴다.
    """
    url = f"{RC_BASE_URL}/{endpoint}"
    try:
        resp = requests.post(url, json=payload or {}, auth=(RC_USER, RC_PASS), timeout=10)
    except requests.exceptions.Timeout:
        raise RuntimeError("rclone 응답이 10초 안에 오지 않았습니다") from None
    except requests.exceptions.ConnectionError:
        raise RuntimeError("rclone 로컬 서비스(rcd)에 연결할 수 없습니다") from None

    if not resp.ok:
        try:
            detail = resp.json().get("error")
        except (ValueError, AttributeError):
            detail = None
        raise RuntimeError(detail or f"rclone 요청 실패 (HTTP {resp.status_code})")

    return resp.json()


def is_rcd_running():
    """rcd가 이미 떠 있는지 확인 (간단한 API 하나를 찔러봄)."""
    try:
        _rc_call("core/pid")
        return True
    except RuntimeError:
        return False


def ensure_rcd_running():
    """rcd가 없으면 백그라운드로 새로 띄운다."""
    global _rcd_process

    if is_rcd_running():
        print("[rcd] 이미 실행 중입니다.")
        return

    print("[rcd] 새로 시작합니다...")
    rclone_exe = _find_rclone_exe()
    _rcd_process = subprocess.Popen(
        [
            rclone_exe, "rcd",
            "--rc-addr", RC_ADDR,
            "--rc-user", RC_USER,
            "--rc-pass", RC_PASS,
        ],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    # 뜰 때까지 잠깐 기다렸다가 확인 (최대 5초)
    for _ in range(10):
        time.sleep(0.5)
        if is_rcd_running():
            print("[rcd] 정상적으로 시작됨.")
            return

    raise RuntimeError("rcd를 시작하지 못했습니다. rclone 설치 여부를 확인해주세요.")


def _obscure(password):
    """평문 비밀번호를 rclone 전용 난독화 형식으로 변환 (conf 저장용 형식과 동일)."""
    result = _rc_call("core/obscure", {"clear": password})
    return result["obscured"]


def _build_remote_string(profile, resolved_host, resolved_port, remote_path="/"):
    """
    프로파일 정보로 '즉석 원격' 문자열을 만든다.
    이 문자열은 rclone.conf에 전혀 기록되지 않고, 이번 호출에만 쓰인다.

    remote_path: 서버 쪽에서 마운트할 특정 경로(예: "/data"). 기본값 "/"는 홈 디렉터리 루트.
    ⚠ 절대경로("/data")·상대경로(".ssh") 둘 다 콜론 뒤에 그대로 붙이면 rclone이 정확히
    인식한다 (WSL 테스트 서버로 두 경우 다 직접 검증함).
    resolved_host/resolved_port: 어느 주소로 접속할지는 mount_profile()에서 이미
    resolve_reachable_address()로 정해서 넘겨준다 (실패 시 에러 메시지에도 써야 해서
    이 함수 안에서 다시 계산하지 않고 바깥에서 한 번만 계산).
    """
    parts = [
        f"host={resolved_host}",
        f"user={profile['username']}",
        f"port={resolved_port}",
    ]

    if profile["auth_type"] == "password":
        obscured = _obscure(profile["password"])
        parts.append(f"pass={obscured}")
    else:  # key_file
        # ⚠ Windows 절대경로(C:\Users\...)의 콜론을 rclone이 connection string
        # 구분자로 오인해 "C:" 한 글자로 잘라버리는 문제가 있었음 (F-2 검증 중 발견).
        # 작은따옴표로 감싸면 rclone이 콜론을 값의 일부로 인식한다.
        parts.append(f"key_file='{profile['key_filename']}'")

    base = ":sftp," + ",".join(parts) + ":"
    return base if remote_path in ("/", "") else base + remote_path


def _capture_mac(profile, resolved_host, resolved_port):
    """
    ⚠ 1번 개선사항: 기존엔 ARP 조회(mac_discovery.get_mac_for_ip)만 가능해서 터널/라우팅을
    거친 원격지는 마운트 경로에서 MAC 검증 사각지대였다 (ARP는 같은 로컬 네트워크(L2)
    안에서만 동작). ssh_session.get_remote_mac()과 같은 방식(원격 장비에 직접 SSH로
    물어보기)을 쓰기 위해, MAC 확인 전용의 짧은 SSH 연결을 하나 열었다가 바로 닫는다.
    (마운트가 이미 성공한 뒤 호출되므로 SSH 서버 자체는 열려 있음이 보장된 상태.)
    실패하면(방화벽, 명령 제한 등) 기존 ARP 방식으로 대체한다.
    """
    try:
        ssh_client = ssh_session.open_connection(profile, resolved_host, resolved_port)
    except Exception:
        return mac_discovery.get_mac_for_ip(resolved_host)
    try:
        mac = ssh_session.get_remote_mac(ssh_client)
    finally:
        ssh_client.close()
    return mac or mac_discovery.get_mac_for_ip(resolved_host)


def _capture_macs(profile, resolved_host, resolved_port):
    try:
        ssh_client = ssh_session.open_connection(profile, resolved_host, resolved_port)
    except Exception:
        fallback = mac_discovery.get_mac_for_ip(resolved_host)
        return [fallback] if fallback else []
    try:
        macs = ssh_session.get_remote_macs(ssh_client)
    finally:
        ssh_client.close()
    if macs:
        return macs
    fallback = mac_discovery.get_mac_for_ip(resolved_host)
    return [fallback] if fallback else []


def mount_profile(profile_name, drive_letter, remote_path="/", _mac_retry=False):
    """
    프로파일 이름으로 SFTP를 드라이브 문자에 마운트한다.
    remote_path로 서버 쪽 특정 볼륨/폴더(예: "/data")만 골라 마운트할 수 있다 (기본값은 홈 디렉터리 루트).
    성공 응답을 받아도 listmounts로 반드시 재검증한다.

    _mac_retry: MAC 불일치 자동 복구 재귀 호출인지 표시 (내부용 — 무한 재귀 방지).
    """
    ensure_rcd_running()

    profile = get_profile(profile_name)
    # ⚠ Phase 4-4 확장: 로컬 IP가 안 닿으면(사내망 밖) 보조 주소(터널)로 자동 전환.
    resolved_host, resolved_port = resolve_reachable_address(profile)

    # ⚠ 동적 IP 재탐색: rclone 쪽 실패는 "IP가 안 닿아서"인지 "비번이 틀려서"인지
    # 구분 안 되는 뭉뚱그려진 RuntimeError로만 나온다. 그래서 rclone을 부르기 전에
    # 우리가 직접 TCP로 먼저 닿는지 확인해서, 그 결과로만 재탐색을 거는 방식으로
    # 원인을 확실하게 구분한다 (ssh_session.py의 connect_profile()과 같은 이유/패턴).
    # ⚠ source(수동/시트) 상관없이, MAC이나 호스트 이름을 알고 있으면 시도한다
    # (사용자 확인 2026-08-05 — ssh_session.py와 동일하게 범위 확장).
    initially_unreachable = not is_reachable(resolved_host, resolved_port)
    if initially_unreachable:
        # ⚠ 2026-08-11 실사용 중 발견(ssh_session.connect_profile과 동일한 이유) — 대부분의
        # "안 닿음"은 IP가 실제로 바뀐 게 아니라 순간적인 네트워크 끊김이다. 곧바로 전체
        # MAC 스캔으로 넘어가기 전에, 짧게 대기했다가 같은 주소로 한 번 더 확인한다.
        time.sleep(QUICK_RETRY_DELAY_SECONDS)
        initially_unreachable = not is_reachable(resolved_host, resolved_port)

    rediscovered_ip_change = None  # (old_ip, new_ip) - 노란/초록 배너용, 실제 마운트 검증 후에 확정 기록
    if initially_unreachable and (profile.get("mac") or profile.get("hostname")):
        # ⚠ 노란 배너("재탐색 중") — finally로 감싸서 성공/실패 상관없이 반드시 지워지게 한다.
        ip_rediscovery_state.mark_in_progress(profile_name)
        try:
            print(f"[동적 IP 재탐색] '{profile_name}' ({resolved_host}:{resolved_port}) 응답 없음 - 새 IP 탐색 중...")
            new_ip = None
            if profile.get("mac"):
                new_ip = mac_discovery.find_ip_for_mac(
                    profile["mac"], profile["host"], resolved_port, known_ips=profile.get("recent_ips"))
            if (not new_ip or new_ip == resolved_host) and profile.get("hostname"):
                # ⚠ MAC 스캔이 실패하면(ICMP 차단 등) 2차 보험으로 mDNS(호스트 이름)로도
                # 시도해본다. 마운트 경로는 SSH 셸이 없어서 호스트 이름을 직접 캡처는
                # 못 하지만, ssh_session.py 쪽에서 이미 저장해둔 값은 여기서도 쓸 수 있다.
                print(f"[동적 IP 재탐색] MAC으로 못 찾음 - mDNS(호스트 이름 '{profile['hostname']}')로 재시도 중...")
                candidates = mdns_discovery.resolve_mdns_hostname_all(profile["hostname"])
                # ⚠ ssh_session.py의 connect_profile()과 같은 이유로, 후보가 여러 개면
                # 절대 자동으로 고르지 않고 즉시 명확한 안내와 함께 중단한다.
                if len(candidates) >= 2:
                    candidate_list = "\n".join(f"  {ip}" for ip in candidates)
                    mdns_ambiguity_state.mark(profile_name, profile["hostname"], candidates)
                    raise RuntimeError(
                        f"[동적 IP 재탐색] '{profile_name}'(호스트 이름 '{profile['hostname']}')에 "
                        f"대한 mDNS 응답이 여러 개 발견되었습니다:\n{candidate_list}\n"
                        f"같은 호스트 이름을 쓰는 다른 장비가 있을 수 있어 자동으로 선택하지 "
                        f"않았습니다. 위 후보 IP들을 직접 확인한 뒤, 이 원격지의 정보를 "
                        f"올바른 IP로 수정해주세요."
                    )
                new_ip = candidates[0] if candidates else None
            if new_ip and new_ip != resolved_host:
                print(f"[동적 IP 재탐색] 새 IP 발견: {new_ip} (기존: {resolved_host}) - 프로파일 갱신")
                profile_store.update_profile_field(profile_name, host=new_ip)
                # ⚠ 마운트가 실제로 성공해야 의미가 있으므로, 여기선 표시만 준비해두고
                # 마운트 검증(is_mounted)까지 끝난 뒤에 실제로 기록한다 (아래 참고).
                rediscovered_ip_change = (resolved_host, new_ip)
                resolved_host = new_ip
            else:
                print(f"[동적 IP 재탐색] '{profile_name}' 새 IP를 찾지 못함 (같은 네트워크 대역에 없거나 오프라인)")
        finally:
            ip_rediscovery_state.clear_in_progress(profile_name)

    # ⚠ 여기는 원래 profile["host"](시트의 마지막 동기화 값)를 기준으로 비교해야 한다 —
    # rediscovered_ip_change[0]은 "이번에 실제로 접속을 시도했던 주소"라 host_alt(터널)
    # 경로에서는 profile["host"]와 다를 수 있어서 혼동하면 안 된다.
    rediscovered_sheet_host_change = (
        (profile["host"], rediscovered_ip_change[1])
        if rediscovered_ip_change and profile.get("source") == "sheet" else None
    )

    remote_string = _build_remote_string(profile, resolved_host, resolved_port, remote_path)

    print(f"[마운트 시도] '{profile_name}':{remote_path} -> {drive_letter} (대상: {resolved_host}:{resolved_port})")

    def _attempt_mount():
        try:
            _rc_call("mount/mount", {
                "fs": remote_string,
                "mountPoint": drive_letter,
                "vfsOpt": {
                    "CacheMode": "full",
                    "CacheMaxSize": "2G",
                    "CacheMaxAge": "24h",
                    "CachePollInterval": "1m",
                },
                # ⚠ 지정 안 하면 탐색기에 rclone이 즉석 연결 문자열을 해시 처리한
                # "sftp{ZcLhz}" 같은 이름으로 표시되어, 어느 원격지를 마운트한 건지 알아보기
                # 힘들었다 (사용자 확인 2026-07-23). rclone mount의 --volname 옵션에
                # 해당하는 RC 파라미터가 "VolumeName"이라, 원격지 이름을 그대로 넘겨서
                # 탐색기 드라이브 이름이 바로 알아볼 수 있게 뜨도록 한다.
                "mountOpt": {"VolumeName": profile_name},
            })
        except Exception as e:
            # ⚠ 이 예외는 requests가 로컬 rclone 서비스(127.0.0.1:5572)와 통신하다 난 것이라
            # 원래 메시지엔 127.0.0.1:5572만 보이고, 정작 어떤 원격 기기(예: loclx.io:12226)에
            # 접속하려 했는지는 전혀 안 나와서 헷갈렸다 (사용자 확인 2026-07-21). 실제로
            # 접속을 시도했던 목적지 주소를 앞에 붙여서 알려준다.
            raise RuntimeError(f"'{resolved_host}:{resolved_port}' 접속 중 실패했습니다 ({e})") from e

        # ⚠ 성공 응답을 그대로 믿지 않고 재검증
        if not is_mounted(drive_letter):
            raise RuntimeError(
                f"'{drive_letter}' 마운트 응답은 성공이었으나 실제로는 확인되지 않습니다. "
                "네트워크/인증 정보를 다시 확인해주세요."
            )

    # ⚠ 2026-08-11 실사용 중 발견(ssh_session.py와 동일한 이유) — 스캔은 네트워크
    # 인터페이스가 살아있는지만 확인하는 거라, 방금 재탐색으로 찾은 IP는 아직 SFTP
    # 서비스가 완전히 준비 안 됐을 수 있다. 재탐색으로 새 IP를 찾은 경우에 한해 짧게
    # 재시도한다(평소 정상 마운트에는 영향 없음).
    if rediscovered_ip_change:
        try:
            _attempt_mount()
        except RuntimeError:
            print(f"[마운트] 새로 찾은 IP({resolved_host}) 접속 실패 - 서비스가 아직 "
                  f"준비 안 됐을 수 있어 재시도 중...")
            time.sleep(NEW_IP_CONNECT_RETRY_DELAY_SECONDS)
            _attempt_mount()
    else:
        _attempt_mount()

    # ⚠ 여기까지 왔으면 마운트에 성공한 것 — 예전에 mDNS 후보 여러 개 문제로 배너에
    # 떠 있었더라도 지금은 해소된 것이므로 자동으로 지운다.
    mdns_ambiguity_state.clear(profile_name)

    # ⚠ 초록 배너("재연결 성공") — 실제로 새 IP로 마운트까지 검증된 뒤에만 기록한다.
    if rediscovered_ip_change:
        ip_rediscovery_state.mark_resolved(profile_name, *rediscovered_ip_change)

    # ⚠ 5번 개선사항 — 이 IP로 실제 마운트에 성공했으니, 다음에 재탐색이 필요할 때
    # 전체 스캔보다 먼저 시도해볼 후보로 기억해둔다.
    profile_store.remember_recent_ip(profile_name, resolved_host)

    if rediscovered_sheet_host_change:
        sheet_host, new_host = rediscovered_sheet_host_change
        sheet_diverged_state.mark(profile_name, sheet_host, new_host)

    _remember_mount(profile_name, drive_letter, remote_path)
    print(f"[마운트 확인됨] {drive_letter} 정상 동작 중")

    # ⚠ 13번 엣지케이스 2차 안전장치 — ssh_session.py의 connect_profile()과 동일한 목적.
    # 마운트 경로는 별개(paramiko가 아니라 rclone rc API)라 여기서도 똑같이 해줘야
    # "터미널로는 안전한데 마운트로는 안 걸림" 같은 빈틈이 안 생긴다.
    # ⚠ 1번 개선사항(2026-08-07): 예전엔 SSH 셸이 없어서 ARP 조회만 가능했고, 그 결과
    # 라우팅/터널(loclx.io 등)을 거친 원격지는 마운트 경로에서 MAC 검증 사각지대였다.
    # 지금은 _capture_mac()이 MAC 확인 전용의 짧은 SSH 연결을 열어 get_remote_mac()
    # 방식(장비한테 직접 물어보기)을 먼저 시도하고, 그게 실패할 때만 ARP로 대체한다.
    captured_macs = _capture_macs(profile, resolved_host, resolved_port)
    captured_mac = captured_macs[0] if captured_macs else None
    stored_mac = profile.get("mac")
    if captured_mac:
        if not stored_mac:
            profile_store.update_profile_field(profile_name, mac=captured_mac)
            print(f"[MAC 저장] '{profile_name}' -> {captured_mac}")
            mac_mismatch_state.clear(profile_name)
        elif stored_mac not in captured_macs and stored_mac != captured_mac:
            other_owner = profile_store.find_profile_by_mac(captured_mac, exclude_name=profile_name)
            print(f"[MAC 불일치] '{profile_name}' 저장된 MAC({stored_mac}) != 지금 연결된 장비의 MAC({captured_mac})"
                  + (f" (이 MAC은 '{other_owner}'의 기준 MAC과 동일)" if other_owner else ""))
            # ⚠ 자동 복구를 시도하기 전에 일단 먼저 기록한다 — ssh_session.py의
            # connect_profile()과 같은 이유(사용자 확인 2026-08-07). 화면에 빨간 배너가
            # 먼저 보이고, 복구가 성공하면 초록 확인 배너로 바뀌는 게 보여야 함.
            mac_mismatch_state.mark(profile_name, stored_mac, captured_mac, other_owner)

            # ⚠ ssh_session.py의 connect_profile()과 같은 이유/패턴 — 차단하기 전에 저장된
            # MAC을 가진 진짜 장비를 로컬 대역에서 한 번 더 스캔해서, 있으면 사용자 개입
            # 없이 자동으로 그 주소로 재마운트한다. 이미 잘못된 드라이브가 마운트돼있으니
            # 먼저 해제하고, mount_profile()을 처음부터 다시 호출(재귀)한다.
            recovery_attempted = False
            if not _mac_retry:
                recovery_attempted = True
                # ⚠ 이것도 재탐색 스캔이라 노란/초록 배너 대상이다 (ssh_session.py의
                # connect_profile()과 같은 이유 — 2026-08-11 사용자 확인, 이 경로에
                # 배너가 빠져 있어서 실사용 중 못 봤던 문제).
                ip_rediscovery_state.mark_in_progress(profile_name)
                try:
                    print(f"[MAC 불일치 자동 복구 시도] 저장된 MAC({stored_mac})을 가진 진짜 장비를 찾는 중...")
                    correct_ip = mac_discovery.find_ip_for_mac(
                        stored_mac, resolved_host, resolved_port, known_ips=profile.get("recent_ips"))
                    if correct_ip and correct_ip != resolved_host:
                        print(f"[MAC 불일치 자동 복구] 올바른 장비를 {correct_ip}에서 찾음 - 재마운트 시도")
                        unmount(drive_letter)
                        profile_store.update_profile_field(profile_name, host=correct_ip)
                        # ⚠ 재귀 호출이 실제로 성공해야 의미가 있으므로, 그게 예외 없이
                        # 끝난 뒤에만 초록 배너를 기록한다.
                        result = mount_profile(profile_name, drive_letter, remote_path, _mac_retry=True)
                        ip_rediscovery_state.mark_resolved(profile_name, resolved_host, correct_ip)
                        return result
                    print("[MAC 불일치 자동 복구 실패] 로컬 대역에서 진짜 장비를 못 찾음 - 마운트 차단")
                finally:
                    ip_rediscovery_state.clear_in_progress(profile_name)

            # ⚠ 경고만 하고 계속 마운트된 채로 두면 엉뚱한 장비의 파일을 만질 위험이 있다 —
            # 이미 마운트는 성공해버린 뒤라(위에서 _remember_mount까지 끝남) 여기서 바로
            # 해제하고 실패로 처리한다.
            recovery_note = (
                "저장된 MAC을 가진 장비를 이 PC의 로컬 네트워크에서 자동으로 재탐색했지만 찾지 못했습니다. "
                if recovery_attempted else ""
            )
            unmount(drive_letter)
            raise RuntimeError(
                f"[MAC 불일치로 마운트 차단] '{profile_name}' 마운트를 해제했습니다 - 저장된 MAC과 "
                f"실제 연결된 장비의 MAC이 다릅니다. {recovery_note}엉뚱한 장비일 위험이 있어 자동으로 막았습니다. "
                f"아래 경고 배너에서 MAC을 확인한 뒤, 맞는 장비라면 '수정'으로 새 기준값을 입력하고 "
                f"다시 시도해주세요."
            )
        else:
            if profile_name in mac_mismatch_state.get_all():
                mac_resolved_state.mark(profile_name, captured_mac)
            mac_mismatch_state.clear(profile_name)


def is_mounted(drive_letter):
    """
    실제로 마운트되어 있는지 listmounts로 확인.
    ⚠ rcd 자체가 안 떠 있으면(예: 이전 세션이 비정상 종료돼서 mount_state.json엔
    기록이 남아있는데 rcd는 안 켜진 상태) _rc_call이 RuntimeError를 던지는데,
    이걸 그대로 위로 흘려보내면 find_current_drive_for_profile()을 거쳐 JS까지
    처리 안 된 채 전파되어 버튼을 눌러도 조용히 아무 반응이 없는 것처럼 보이는
    문제가 있었다 (2026-07-29 발견). rcd가 안 떠 있다는 건 곧 "마운트 안 되어
    있다"는 뜻이므로 False로 answer하는 게 맞다.
    """
    try:
        result = _rc_call("mount/listmounts")
    except RuntimeError:
        return False
    mounted_points = [m["MountPoint"] for m in result.get("mountPoints", [])]
    # 드라이브 문자는 "S:" 또는 "S:\" 형태로 기록될 수 있어 앞부분만 비교
    return any(mp.rstrip("\\").upper() == drive_letter.rstrip("\\").upper() for mp in mounted_points)


def find_current_drive_for_profile(profile_name):
    """
    이 프로파일이 '지금' 실제로 어느 드라이브에 마운트되어 있는지 알려준다.

    ⚠ 원래는 rclone에게 직접 물어봐서(mount/listmounts의 Fs 문자열과
    host=/user= 비교) 확인하려 했으나, rclone이 즉석 원격(connection string)을
    ":sftp{ZcLhz}:" 같은 내부 해시로만 돌려줘서 절대 매칭되지 않는 버그였음
    (F-2 검증 중 발견). 그래서 {프로파일명: 드라이브} 매핑을 파일(mount_state.json)로
    직접 관리하되, is_mounted()로 매번 재검증해서 죽은 기록은 자동으로 지운다.
    """
    entry = _load_mount_state().get(profile_name)
    if not entry:
        return None

    drive = _entry_drive(entry)
    if not drive or not is_mounted(drive):
        # 기록은 있는데 실제로는 마운트되어 있지 않음 -> 죽은 기록 정리
        if drive:
            _forget_drive(drive)
        return None

    return drive


def find_current_volume_for_profile(profile_name):
    """
    이 프로파일이 '지금' 실제로 마운트된 서버 쪽 볼륨/경로(예: "/data")를 알려준다.
    (find_current_drive_for_profile과 같은 파일에 함께 기록해두고, 마운트 상태가
    아니면 마찬가지로 죽은 기록으로 보고 None을 반환한다)
    """
    entry = _load_mount_state().get(profile_name)
    if not entry or isinstance(entry, str):
        return None  # 옛 형식(문자열)은 remote_path 정보가 없었음

    drive = entry.get("drive")
    if not drive or not is_mounted(drive):
        return None

    return entry.get("remote_path", "/")


def unmount(drive_letter):
    """마운트 해제."""
    _rc_call("mount/unmount", {"mountPoint": drive_letter})
    _forget_drive(drive_letter)
    print(f"[해제 완료] {drive_letter}")


def cleanup_all():
    """앱 시작/종료 시: 남아있는 모든 마운트를 정리."""
    if not is_rcd_running():
        return

    # ⚠ 2026-08-10 실사용 중 발견: rcd가 core/pid 같은 간단한 요청엔 응답하면서도
    # (is_rcd_running()이 True) mount/listmounts 같은 특정 요청에서만 먹통이 되는
    # 사례가 있었다. 이 호출이 예외 없이 그대로 위로 전파되면, 앱 완전 종료(full_quit)의
    # 정리 절차 중간에서 죽어버려서 그 뒤의 os._exit(0)까지 도달을 못 하고, 겉에서
    # 보기엔 "종료 버튼을 눌러도 반응이 없다"는 것처럼 보인다. 정리는 최선을 다해
    # 시도하되, 실패해도 종료 절차 자체는 반드시 계속 진행돼야 하므로 여기서 잡는다.
    try:
        result = _rc_call("mount/listmounts")
    except RuntimeError as e:
        print(f"[정리 실패] rcd가 응답하지 않아 마운트 목록을 가져오지 못했습니다: {e}")
        return

    for m in result.get("mountPoints", []):
        try:
            print(f"[정리] 남아있던 마운트 해제: {m['MountPoint']}")
            unmount(m["MountPoint"])
        except RuntimeError as e:
            print(f"[정리 실패] '{m['MountPoint']}' 해제에 실패했습니다, 다음으로 넘어갑니다: {e}")

    _save_mount_state({})  # 혹시 남아있을 수 있는 매핑까지 확실히 비움


def stop_rcd():
    """
    ⚠ 완전 종료(F-7 [완전히 종료]) 전용. cleanup_all()은 마운트만 해제할 뿐
    rcd(rclone.exe rcd 백그라운드 서버) 프로세스 자체는 계속 살려두는데,
    이 프로세스가 자기 exe 파일(및 그게 들어있는 폴더)을 계속 잠그고 있어서
    앱을 완전히 종료해도 배포 폴더/exe를 못 지우는 문제가 있었다
    (2026-07-28 직원 피드백: "완전히 종료했는데도 이전 버전이 안 지워진다").
    ensure_rcd_running()이 우리가 띄운 게 아니라 이미 떠 있던 rcd를 그대로 쓴
    경우엔 _rcd_process 핸들이 없으므로, 프로세스를 직접 kill하는 대신 rclone
    자체의 종료 API(core/quit)를 호출해 어느 쪽이든 확실히 끈다.
    """
    if not is_rcd_running():
        return
    try:
        _rc_call("core/quit")
    except RuntimeError:
        pass  # quit 호출 도중 연결이 끊기며 에러처럼 보일 수 있음 — 정상 동작
