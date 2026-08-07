"""
동적 IP 프로파일 재탐색

- 사용자가 직접 추가한(source="manual") 원격지 중 동적 IP를 쓰는 장비는, 재부팅 등으로
  IP가 바뀌면 저장해둔 주소로 더 이상 접속이 안 된다.
- IP는 바뀌어도 장비의 MAC 주소는 안 바뀐다는 점을 이용해서, "예전 IP와 같은 네트워크
  대역"을 훑어 그 MAC을 가진 장비의 현재 IP를 찾아낸다.
- ⚠ 같은 네트워크(서브넷) 안에 있을 때만 동작한다 — ARP는 라우터를 못 넘어가므로,
  loclx.io 같은 외부 터널 경유 원격지에는 적용할 수 없다 (호출하는 쪽에서 그런
  프로파일은 애초에 이 모듈을 안 부르도록 걸러야 한다).
"""

import ipaddress
import json
import re
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

PING_TIMEOUT_MS = 300
TCP_PROBE_TIMEOUT_S = 0.3
DEFAULT_PROBE_PORT = 22  # 대상 포트를 모를 때(예: 호출부가 안 넘겨줄 때)의 기본값
SCAN_MAX_WORKERS = 40
SCAN_MAX_HOSTS = 1024  # ⚠ 실제 대역이 너무 넓으면(/22보다 넓으면) 스캔이 너무 느려지므로 상한선
SCAN_RETRY_COUNT = 2  # 한 번 실패해도 순간적인 타이밍/혼잡 문제일 수 있어 재시도

# ⚠ 7번 개선사항 — 백그라운드 점검(2번)이 도는 도중 사용자가 다른 프로파일을 수동
# 접속/마운트하는 것처럼, 서로 다른 스레드에서 전체 서브넷 스캔(최대 1024호스트 ping+TCP)이
# 동시에 걸리면 네트워크 부하가 겹친다. 시간 기반 쿨다운(재시도를 늦추는 방식)은 "빨리
# 찾고 싶다"는 요구와 안 맞아서 대신 락을 쓴다 — 스캔이 하나뿐이면 전혀 안 기다리고 바로
# 돌아가고, 우연히 겹칠 때만 먼저 온 스캔이 끝날 때까지 순서대로 기다렸다가 시작한다.
_scan_lock = threading.Lock()

# Windows `arp -a` 출력에서 "IP  MAC  타입" 줄을 찾는 패턴.
# 예: "  192.168.123.5        11-22-33-44-55-66     dynamic"
_ARP_LINE = re.compile(
    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\w+"
)


def _normalize_mac(mac):
    """"AA:BB:CC:DD:EE:FF"든 "aa-bb-cc-dd-ee-ff"든 비교용으로 소문자+하이픈 형식으로 통일."""
    return mac.strip().lower().replace(":", "-")


def get_mac_for_ip(ip):
    """
    방금 접속에 성공한 IP의 MAC 주소를 ARP 테이블에서 읽어온다.
    (막 통신했으니 캐시에 이미 있을 가능성이 높아 별도 핑 없이 바로 조회)
    실패하거나 못 찾으면 None.
    """
    try:
        result = subprocess.run(
            ["arp", "-a", ip],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (subprocess.SubprocessError, OSError):
        return None

    match = _ARP_LINE.search(result.stdout)
    return _normalize_mac(match.group(2)) if match else None


def _ping_once(ip):
    try:
        subprocess.run(
            ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip],
            capture_output=True, timeout=2,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (subprocess.SubprocessError, OSError):
        pass


def _tcp_probe_once(ip, port):
    """
    ⚠ 3번 개선사항 — ping(ICMP)을 방화벽으로 막아둔 장비는 실제로 켜져 있고 SSH 포트는
    열려 있어도 ping만으로는 스캔에서 놓친다(실사용 확인). 대상 포트로 TCP 연결을 시도하면,
    연결이 성공하든 거부(RST)당하든 상관없이 그 과정에서 운영체제가 ARP로 상대 MAC을 먼저
    알아내 캐시에 남기기 때문에 결과적으로 스캔에 잡힌다. 그래서 포트 자체가 열려있는지는
    신경 쓰지 않고 그냥 시도만 해본다(실패해도 무시).
    """
    try:
        with socket.create_connection((ip, port), timeout=TCP_PROBE_TIMEOUT_S):
            pass
    except OSError:
        pass


def _probe_host(ip, port):
    _ping_once(ip)
    _tcp_probe_once(ip, port)


def _get_local_prefix_length(hint_ip):
    """
    이 PC의 실제 IPv4 인터페이스 중 hint_ip와 같은 /24 대역에 있는 것을 찾아서,
    그 인터페이스가 진짜로 쓰는 서브넷 프리픽스 길이(예: 24, 23...)를 알아온다.
    ⚠ ipconfig 텍스트를 직접 파싱하면 윈도우 언어 설정(한글/영문)에 따라 "서브넷
    마스크"/"Subnet Mask" 같은 라벨이 달라져서 깨지기 쉽다. 대신 PowerShell의
    Get-NetIPAddress를 JSON으로 뽑아서 쓰면 언어와 무관하게 항상 같은 필드명
    (PrefixLength)으로 나와서 더 안정적이다.
    실패하거나 못 찾으면 None (호출부에서 기존처럼 /24로 대체).
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetIPAddress -AddressFamily IPv4 | "
             "Select-Object IPAddress,PrefixLength | ConvertTo-Json"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        entries = json.loads(result.stdout)
        if isinstance(entries, dict):  # 인터페이스가 하나뿐이면 리스트가 아니라 dict 하나로 옴
            entries = [entries]
    except (subprocess.SubprocessError, OSError, ValueError):
        return None

    hint_prefix24 = ".".join(hint_ip.split(".")[:3])
    for entry in entries:
        ip = entry.get("IPAddress", "")
        if ip.startswith(hint_prefix24 + "."):
            return entry.get("PrefixLength")
    return None


def _get_local_networks():
    """
    이 PC의 실제 IPv4 인터페이스들을 (ip, prefix_length) 목록으로 돌려준다.
    링크-로컬(169.254.x, 케이블 빠짐/DHCP 실패 시 자동 할당되는 APIPA)·루프백·WSL
    가상 어댑터 등은 제외 — "이 PC가 물리적으로 실제 붙어있는 네트워크"만 남기기 위함.
    실패하면 빈 리스트.
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetIPAddress -AddressFamily IPv4 | "
             "Select-Object IPAddress,PrefixLength,InterfaceAlias | ConvertTo-Json"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        entries = json.loads(result.stdout)
        if isinstance(entries, dict):
            entries = [entries]
    except (subprocess.SubprocessError, OSError, ValueError):
        return []

    networks = []
    for entry in entries:
        ip = entry.get("IPAddress", "") or ""
        alias = entry.get("InterfaceAlias", "") or ""
        if (ip.startswith("169.254.") or ip.startswith("127.")
                or "Loopback" in alias or "WSL" in alias or "vEthernet" in alias):
            continue
        networks.append((ip, entry.get("PrefixLength")))
    return networks


def _scan_once(target_mac, network, port=DEFAULT_PROBE_PORT):
    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > SCAN_MAX_HOSTS:
        hosts = hosts[:SCAN_MAX_HOSTS]

    with ThreadPoolExecutor(max_workers=SCAN_MAX_WORKERS) as pool:
        list(pool.map(lambda ip: _probe_host(ip, port), hosts))

    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (subprocess.SubprocessError, OSError):
        return None

    for ip_str, mac_str in _ARP_LINE.findall(result.stdout):
        if _normalize_mac(mac_str) == target_mac:
            return ip_str

    return None


def _check_known_ips(target_mac, ips, port):
    """
    ⚠ 5번 개선사항 — 매번 전체 서브넷(최대 1024개 host)을 훑기 전에, 이 장비가 최근에
    있었던 IP 몇 개를 먼저 짧게 찔러본다. DHCP가 같은 대역 안에서만 재할당하는 흔한
    경우엔 대부분 여기서 바로 끝나서 훨씬 빠르다. 못 찾으면 None (호출부가 전체 스캔으로 대체).
    """
    if not ips:
        return None
    with ThreadPoolExecutor(max_workers=min(len(ips), SCAN_MAX_WORKERS)) as pool:
        list(pool.map(lambda ip: _probe_host(ip, port), ips))
    for ip in ips:
        if get_mac_for_ip(ip) == target_mac:
            return ip
    return None


def find_ip_for_mac(mac, subnet_hint_ip, port=DEFAULT_PROBE_PORT, known_ips=None):
    """
    subnet_hint_ip(예전에 쓰던 IP)와 같은 네트워크 대역 전체를 훑어서, mac과
    일치하는 장비의 현재 IP를 찾아 돌려준다. 못 찾으면 None.

    port: 대상 장비의 SSH 포트(프로파일의 port). ping이 막혀 있어도 이 포트로 TCP
    연결을 시도해서 ARP 캐시를 채우기 위해 쓴다 (3번 개선사항 — 아래 _probe_host 참고).
    known_ips: 이 장비가 최근에 실제로 있었던 IP 목록(프로파일의 recent_ips, 최근순).
    있으면 전체 스캔 전에 이것부터 먼저 확인한다 (5번 개선사항).
    ⚠ 전체 서브넷 스캔 구간은 앱 전체에서 한 번에 하나만 돌도록 락으로 감싸져 있다
    (7번 개선사항) — 다른 스캔이 겹치면 그게 끝날 때까지 대기했다가 시작한다.

    ⚠ ARP 테이블은 "최근에 통신한 상대"만 담고 있어서, 먼저 대역 전체에 핑을 돌려
    캐시를 채워야 한다. 병렬로 처리해서 몇 초 안에 끝나게 한다.
    ⚠ 대역은 무조건 /24로 가정하지 않고, 이 PC가 실제로 쓰는 서브넷 설정을 먼저
    확인해서 그 범위로 스캔한다 (실제 대역이 더 넓으면 예전 방식은 못 찾는 장비가
    있었음).
    ⚠ 실사용 중 발견된 버그(2026-08-07): subnet_hint_ip가 이 PC가 실제로 붙어있는
    어떤 네트워크와도 안 맞으면(예: MAC 불일치로 저장된 host가 완전히 다른 대역을
    가리키고 있던 경우 — 13번 엣지케이스 자동 복구 중 실제로 겪음), 예전엔 그 안 맞는
    hint_ip 자체를 기준으로 /24를 만들어서 스캔했다 — 이 PC가 물리적으로 붙어있지도
    않은 네트워크를 스캔하는 셈이라 무조건 못 찾을 수밖에 없었음. 이제는 hint가 안
    맞으면 hint를 버리고, 이 PC가 실제로 붙어있는 네트워크(들)를 대신 스캔한다.
    ⚠ 순간적인 네트워크 혼잡/타이밍 문제로 한 번에 못 찾을 수 있어서, 바로 포기하지
    않고 몇 번 더 시도한다.
    """
    target_mac = _normalize_mac(mac)

    if known_ips:
        found = _check_known_ips(target_mac, [ip for ip in known_ips if ip != subnet_hint_ip], port)
        if found:
            return found

    prefix_len = _get_local_prefix_length(subnet_hint_ip)
    if prefix_len is not None:
        scan_targets = [(subnet_hint_ip, prefix_len)]
    else:
        scan_targets = _get_local_networks()
        if not scan_targets:
            return None

    with _scan_lock:
        for ip, prefix in scan_targets:
            try:
                network = ipaddress.ip_network(f"{ip}/{prefix or 24}", strict=False)
            except ValueError:
                continue
            for _ in range(SCAN_RETRY_COUNT):
                found = _scan_once(target_mac, network, port)
                if found:
                    return found

    return None
