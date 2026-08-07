"""
Phase 4-4 확장: 로컬 IP + 외부 터널 주소 자동 선택

- 원격지 하나가 사내망 안에서만 닿는 로컬 IP와, 밖에서도 닿는 터널 주소(예: loclx.io)를
  동시에 가질 수 있다. 원격지를 두 개로 나누지 않고 하나로 유지하되, 실제 접속하는
  순간에 지금 어느 쪽이 닿는지 짧게 확인해서 자동으로 그쪽을 쓴다.
- 사용자는 "사내망 안/밖" 구분을 몰라도 원격지 하나만 클릭하면 된다.
"""

import socket

PROBE_TIMEOUT_SECONDS = 1.5


def resolve_reachable_address(profile, timeout=PROBE_TIMEOUT_SECONDS):
    """
    profile(profile_store.get_profile()이 돌려주는 딕셔너리)을 받아서,
    지금 실제로 접속 가능한 (host, port)를 돌려준다.
    - 기본 주소(host/port)를 먼저 짧게 테스트
    - 안 되고 보조 주소(host_alt/port_alt)가 있으면 그쪽으로 자동 전환
    - 둘 다 안 되면(오프라인 등) 그냥 기본 주소를 그대로 돌려준다 —
      실제 연결 시도에서 나는 에러 메시지가 사용자가 원래 기대한 주소 기준으로 나오게 하기 위함
    """
    host, port = profile["host"], profile["port"]
    if is_reachable(host, port, timeout):
        return host, port

    alt_host = profile.get("host_alt")
    if alt_host:
        alt_port = profile.get("port_alt") or port
        if is_reachable(alt_host, alt_port, timeout):
            return alt_host, alt_port

    return host, port


def is_reachable(host, port, timeout=PROBE_TIMEOUT_SECONDS):
    """짧게 TCP 연결을 시도해서 지금 이 (host, port)가 닿는지 확인한다.
    ⚠ mount_control.py도 마운트 실패가 "IP 자체가 안 닿는 것"인지 구분하려고
    이 함수를 그대로 가져다 쓴다(rclone 쪽 에러는 이유 구분이 안 돼서) — 원래
    이 파일 안에서만 쓰던 private 함수였는데 그래서 공개 함수로 바꿈."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
