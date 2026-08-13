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
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

# ⚠ 2026-08-11 실측으로 확정한 값 — 예전엔 300ms였는데, 이게 "IP를 막 바꾼 직후에 못 찾는"
# 문제의 진짜 원인이었다. 처음 접촉하는 IP는 ARP 해석부터 해야 해서 첫 응답이 유독 느리다
# (같은 장비가 첫 ping 255ms -> 두 번째부터 4ms). 대역 전체의 응답 시간을 실제로 재봤더니
# 살아있는 47개 중 6개(13%)가 300~1000ms 구간이라 300ms 타임아웃에 통째로 잘려나가고 있었다.
# 사용자가 PowerShell에서 `-w 200`으로 훑었을 때 젯슨이 "빈 IP"로 보였던 것도 같은 이유.
PING_TIMEOUT_MS = 1000
TCP_PROBE_TIMEOUT_S = 1.0
DEFAULT_PROBE_PORT = 22  # 대상 포트를 모를 때(예: 호출부가 안 넘겨줄 때)의 기본값
# ⚠ 타임아웃을 늘린 만큼 스캔이 느려지므로 병렬 수를 함께 올려서 전체 소요 시간을 비슷하게
# 유지한다. 대부분의 시간은 응답 없는 빈 IP에서 소모된다. (ping/TCP를 각각 별도 작업으로
# 큐에 넣으므로 실제 작업 수는 호스트 수의 2배 — _scan_once 참고)
# ⚠ 2026-08-11 실측으로 확정 — 동시 요청을 많이 걸수록 오히려 대상을 놓친다. 같은 대역을
# 반복 측정했더니 96동시=36~48개, 48동시=44~52개, 32동시=51~59개, 24동시=51~52개로,
# 동시 수를 줄일수록 ARP 수집률이 뚜렷하게 올라갔다. 254개 IP에 ping+TCP를 한꺼번에
# 쏟아부으면 그 혼잡에 정작 찾으려는 장비의 응답이 묻히는 것으로 보인다(대상도 Wi-Fi라
# 특히 취약). 실제로 단발 ping은 즉시 성공하는데 스캔만 실패하는 상황을 여러 번 재현함.
# 그래서 1차는 빠르게(96) 훑어 흔한 경우를 즉시 잡고, 놓치면 2차는 촘촘하게(32) 다시 훑는다.
SCAN_WORKERS_BY_ATTEMPT = [96, 32]
SCAN_MAX_WORKERS = SCAN_WORKERS_BY_ATTEMPT[0]  # 기본값(호출부가 따로 안 정할 때)
SCAN_MAX_HOSTS = 1024  # ⚠ 실제 대역이 너무 넓으면(/22보다 넓으면) 스캔이 너무 느려지므로 상한선
SCAN_RETRY_COUNT = len(SCAN_WORKERS_BY_ATTEMPT)  # 시도마다 위 동시 수를 순서대로 적용
# ⚠ 2026-08-10 실사용 중 발견: 장비가 막 재부팅/재연결 중이라 아주 잠깐(1차 스캔 시점에)
# 응답을 못 하다가 몇 초 뒤엔 정상 응답하는 경우가 있었다. 재시도 사이에 간격 없이
# 곧바로 다시 스캔하면 이런 "일시적으로 늦게 붙는" 경우를 놓치기 쉬워서, 짧게 대기했다가
# 재시도한다. 1차 시도에서 찾으면(대부분의 경우) 이 대기는 아예 발생하지 않는다.
SCAN_RETRY_DELAY_SECONDS = 1
# ⚠ 2026-08-11 실측 — 프로브 직후 곧바로 arp -a를 읽으면 늦게 응답한 장비가 누락된다
# (같은 대역에서 46개 -> 3초 뒤 51개, 약 12% 차이). 짧게 기다렸다가 읽어 취합률을 올린다.
ARP_SETTLE_DELAY_SECONDS = 3
# ⚠ 2026-08-12 v4 실험 — nmap이 설치된 환경에서는 먼저 ARP discovery만 짧게 시도한다.
# 핵심은 "단계를 하나 더 늘리는" 게 아니라, nmap이 수 초 안에 MAC을 바로 알려줄 수 있을 때만
# 기존 ping+TCP 전체 스캔을 건너뛰는 빠른 경로로 쓰는 것이다. 권한/Npcap/환경 문제로 느려지거나
# MAC을 못 주면 timeout 후 기존 방식으로 즉시 fallback한다.
NMAP_ARP_DISCOVERY_ENABLED = True
NMAP_MAX_RETRIES = 0
NMAP_HOST_TIMEOUT = "800ms"
NMAP_PROCESS_TIMEOUT_SECONDS = 2
NMAP_NEARBY_RADIUS = 12
NMAP_FULL_SUBNET_ENABLED = False
NMAP_SINGLE_IP_CONCURRENCY = 6
NMAP_SINGLE_IP_LAUNCH_DELAY_SECONDS = 0
NMAP_FULL_SUBNET_PASSES = 4
NMAP_REDISCOVERY_LOOP_DELAY_SECONDS = 1

# ⚠ 7번 개선사항 — 백그라운드 점검(2번)이 도는 도중 사용자가 다른 프로파일을 수동
# 접속/마운트하는 것처럼, 서로 다른 스레드에서 전체 서브넷 스캔(최대 1024호스트 ping+TCP)이
# 동시에 걸리면 네트워크 부하가 겹친다. 시간 기반 쿨다운(재시도를 늦추는 방식)은 "빨리
# 찾고 싶다"는 요구와 안 맞아서 대신 락을 쓴다 — 스캔이 하나뿐이면 전혀 안 기다리고 바로
# 돌아가고, 우연히 겹칠 때만 먼저 온 스캔이 끝날 때까지 순서대로 기다렸다가 시작한다.
_scan_lock = threading.Lock()

# ⚠ 2026-08-11 실사용 중 발견 — 위 락만으로는 부족했다. 백그라운드 점검이 "이 네트워크에
# 없는 장비"를 찾느라 전체 서브넷 스캔을 10초 가까이 돌면서 락을 쥐고 있으면, 정작 사용자가
# 직접 누른 재접속이 그만큼 기다려야 했다(실측: 4.9초 -> 14.35초). 사용자가 기다리는 스캔이
# 있으면 백그라운드 스캔은 재시도를 포기하고 락을 빨리 놓아주도록 우선순위를 둔다.
_priority_lock = threading.Lock()
_user_scans_waiting = 0


def _change_user_waiting(delta):
    global _user_scans_waiting
    with _priority_lock:
        _user_scans_waiting += delta


def _is_user_waiting():
    with _priority_lock:
        return _user_scans_waiting > 0


# ⚠ _get_local_networks()는 PowerShell을 띄우는 무거운 호출이라, 프로파일마다 부르면
# (67개) 그 자체로 수십 초가 든다. 짧게 캐싱해서 재사용한다.
LOCAL_NETWORKS_CACHE_TTL_SECONDS = 60
_local_networks_cache = None
_local_networks_cache_time = 0.0


def get_local_networks_cached():
    global _local_networks_cache, _local_networks_cache_time
    now = time.time()
    if _local_networks_cache is None or now - _local_networks_cache_time > LOCAL_NETWORKS_CACHE_TTL_SECONDS:
        _local_networks_cache = _get_local_networks()
        _local_networks_cache_time = now
    return _local_networks_cache


def is_in_local_network(ip):
    """
    이 PC가 실제로 붙어있는 네트워크 대역 안에 있는 IP인지 판별한다.
    ⚠ 2026-08-11 추가 — 백그라운드 점검이 다른 병원/시설 장비(이 네트워크에 있을 리 없는
    프로파일)까지 전부 훑느라 한 사이클에 6분 넘게 걸리고, 그 과정에서 무의미한 전체 서브넷
    스캔으로 락과 네트워크를 점유하던 문제를 막기 위함. ARP 기반 재탐색/MAC 검증은 애초에
    같은 로컬 네트워크에서만 동작하므로, 대역이 안 맞으면 점검할 실익이 없다.
    IP 형식이 아니면(터널 호스트 이름 등) False — 그런 원격지도 ARP로는 어차피 확인 불가.
    """
    if not ip:
        return False
    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for local_ip, prefix in get_local_networks_cached():
        try:
            network = ipaddress.ip_network(f"{local_ip}/{prefix or 24}", strict=False)
        except ValueError:
            continue
        if target in network:
            return True
    return False


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


def _is_host_alive(ip, port):
    """
    ⚠ 2026-08-11 추가 — ARP 캐시에 남아있는 "낡은 항목"(장비가 떠난 예전 IP)을 걸러내기 위해,
    그 주소가 지금 실제로 응답하는지 확인한다. 포트가 열려있으면 확실히 살아있는 것이고,
    닫혀 있을 수도 있으니 ping으로도 한 번 더 확인한다. 둘 다 실패하면 죽은 주소로 본다.
    """
    try:
        with socket.create_connection((ip, port), timeout=TCP_PROBE_TIMEOUT_S):
            return True
    except OSError:
        pass
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip],
            capture_output=True, timeout=2,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def _select_alive_mac_match(matches, port):
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"[스캔] 같은 MAC이 여러 IP에 보임 {matches} - 실제로 살아있는 주소를 확인합니다")
        for ip_str in matches:
            if _is_host_alive(ip_str, port):
                return ip_str
        return matches[0]
    return None

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
        entries = None

    if entries is None:
        entries = [
            {"IPAddress": ip, "PrefixLength": prefix}
            for ip, prefix in _get_local_networks_from_ipconfig()
        ]

    hint_prefix24 = ".".join(hint_ip.split(".")[:3])
    for entry in entries:
        ip = entry.get("IPAddress", "")
        if ip.startswith(hint_prefix24 + "."):
            return entry.get("PrefixLength")
    return None


def _subnet_mask_to_prefix(mask):
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def _get_local_networks_from_ipconfig():
    """
    Get-NetIPAddress가 권한 문제로 막히는 PC를 위한 fallback.
    ipconfig 출력에서 IPv4 Address/Subnet Mask 쌍을 읽고, 실패하면 해당 IP의 /24로 보수적으로 잡는다.
    """
    try:
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (subprocess.SubprocessError, OSError):
        return []

    networks = []
    current_ip = None
    for line in result.stdout.splitlines():
        match = re.search(r"IPv4[^\:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            current_ip = match.group(1)
            continue
        match = re.search(r"Subnet Mask[^\:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if match and current_ip:
            prefix = _subnet_mask_to_prefix(match.group(1)) or 24
            if not (current_ip.startswith("169.254.") or current_ip.startswith("127.")):
                networks.append((current_ip, prefix))
            current_ip = None

    if not networks:
        try:
            hostname = socket.gethostname()
            for _, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = sockaddr[0]
                if not (ip.startswith("169.254.") or ip.startswith("127.")):
                    networks.append((ip, 24))
        except socket.gaierror:
            pass

    return networks


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
        return _get_local_networks_from_ipconfig()

    networks = []
    for entry in entries:
        ip = entry.get("IPAddress", "") or ""
        alias = entry.get("InterfaceAlias", "") or ""
        if (ip.startswith("169.254.") or ip.startswith("127.")
                or "Loopback" in alias or "WSL" in alias or "vEthernet" in alias):
            continue
        networks.append((ip, entry.get("PrefixLength")))
    return networks


def _find_ip_in_arp_cache(target_mac, network, port=DEFAULT_PROBE_PORT):
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (subprocess.SubprocessError, OSError):
        return None

    entries = _ARP_LINE.findall(result.stdout)
    matches = [
        ip_str
        for ip_str, mac_str in entries
        if _normalize_mac(mac_str) == target_mac and ipaddress.ip_address(ip_str) in network
    ]
    return _select_alive_mac_match(matches, port)


def _nearby_ips(hint_ip, network, radius=NMAP_NEARBY_RADIUS):
    try:
        hint = ipaddress.ip_address(hint_ip)
    except ValueError:
        return []
    if hint not in network:
        return []

    first = int(network.network_address) + 1
    last = int(network.broadcast_address) - 1
    hint_value = int(hint)
    candidates = [hint_value]
    candidates.extend(hint_value + offset for offset in range(1, radius + 1))
    candidates.extend(hint_value - offset for offset in range(1, radius + 1))
    return [
        str(ipaddress.ip_address(value))
        for value in candidates
        if first <= value <= last
    ]


def _find_ip_with_nmap_arp(target_mac, scan_target, port=DEFAULT_PROBE_PORT):
    """
    nmap의 ARP discovery 결과에서 target_mac을 가진 IP를 찾는다.

    `nmap -sn -PR -n`은 포트 스캔 없이 같은 L2 대역의 ARP 응답만 빠르게 수집한다.
    관리자 권한/Npcap 상태에 따라 MAC이 안 나오거나 느려질 수 있으므로 짧은 timeout을 걸고,
    실패하면 호출부가 기존 Python ping+TCP+ARP 방식으로 fallback한다.
    """
    if not NMAP_ARP_DISCOVERY_ENABLED:
        return None
    nmap_path = _find_nmap_exe()
    if not nmap_path:
        return None
    if isinstance(scan_target, (list, tuple)):
        target_args = [str(target) for target in scan_target]
        target_label = ",".join(target_args[:3]) + ("..." if len(target_args) > 3 else "")
        target_size = len(target_args)
    else:
        target_args = [str(scan_target)]
        target_label = str(scan_target)
        target_size = getattr(scan_target, "num_addresses", 1)

    if target_size > SCAN_MAX_HOSTS + 2:
        return None

    started = time.time()
    try:
        result = subprocess.run(
            [
                nmap_path,
                "-sn",
                "-PR",
                "-n",
                "--max-retries", str(NMAP_MAX_RETRIES),
                "--host-timeout", NMAP_HOST_TIMEOUT,
                "-oX", "-",
                *target_args,
            ],
            capture_output=True, text=True, timeout=NMAP_PROCESS_TIMEOUT_SECONDS,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        print(f"[nmap 스캔] {target_label} ARP discovery가 {NMAP_PROCESS_TIMEOUT_SECONDS}초를 넘겨 기존 방식으로 전환")
        return None
    except (subprocess.SubprocessError, OSError):
        return None

    matches = []
    try:
        root = ET.fromstring(result.stdout)
        for host in root.findall("host"):
            ip_addr = None
            mac_addr = None
            for addr in host.findall("address"):
                addr_type = addr.get("addrtype")
                if addr_type == "ipv4":
                    ip_addr = addr.get("addr")
                elif addr_type == "mac":
                    mac_addr = addr.get("addr")
            if ip_addr and mac_addr and _normalize_mac(mac_addr) == target_mac:
                matches.append(ip_addr)
    except ET.ParseError:
        return None

    if matches:
        print(f"[nmap 스캔] 대상 MAC({target_mac}) 발견: {matches} ({time.time() - started:.1f}초)")
        return _select_alive_mac_match(matches, port)

    print(f"[nmap 스캔 진단] 대상={target_label} / {time.time() - started:.1f}초 - 대상 MAC({target_mac}) 없음")
    return None


def _iter_nearby_ips_for_anchors(anchors, network, radius=NMAP_NEARBY_RADIUS):
    seen = set()
    anchor_values = []
    for anchor in anchors:
        try:
            ip = ipaddress.ip_address(anchor)
        except ValueError:
            continue
        if ip in network and ip not in anchor_values:
            anchor_values.append(ip)

    first = int(network.network_address) + 1
    last = int(network.broadcast_address) - 1

    for ip in anchor_values:
        candidate = str(ip)
        seen.add(candidate)
        yield candidate

    for direction in (1, -1):
        for offset in range(1, radius + 1):
            for anchor in anchor_values:
                value = int(anchor) + (direction * offset)
                if not (first <= value <= last):
                    continue
                candidate = str(ipaddress.ip_address(value))
                if candidate in seen:
                    continue
                seen.add(candidate)
                yield candidate


def _find_ip_with_nmap_nearby(target_mac, anchors, network, port=DEFAULT_PROBE_PORT):
    for ip in _iter_nearby_ips_for_anchors(anchors, network):
        found = _find_ip_with_nmap_arp(target_mac, ip, port)
        if found:
            return found
    return None


def _extract_nmap_mac_match(xml_text, target_mac):
    matches = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return matches

    for host in root.findall("host"):
        ip_addr = None
        mac_addr = None
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                ip_addr = addr.get("addr")
            elif addr_type == "mac":
                mac_addr = addr.get("addr")
        if ip_addr and mac_addr and _normalize_mac(mac_addr) == target_mac:
            matches.append(ip_addr)
    return matches


def _find_nmap_exe():
    found = shutil.which("nmap")
    if found:
        return found
    for path in (
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ):
        if os.path.exists(path):
            return path
    return None


def _nmap_single_ip(nmap_path, ip, target_mac):
    try:
        result = subprocess.run(
            [
                nmap_path,
                "-sn",
                "-PR",
                "-n",
                "--max-retries", str(NMAP_MAX_RETRIES),
                "--host-timeout", NMAP_HOST_TIMEOUT,
                "-oX", "-",
                ip,
            ],
            capture_output=True, text=True, timeout=NMAP_PROCESS_TIMEOUT_SECONDS,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return None

    matches = _extract_nmap_mac_match(result.stdout, target_mac)
    return matches[0] if matches else None


def _ordered_hosts_for_nmap_pass(network, pass_index):
    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > SCAN_MAX_HOSTS:
        hosts = hosts[:SCAN_MAX_HOSTS]
    if not hosts:
        return hosts

    lane_count = max(1, NMAP_SINGLE_IP_CONCURRENCY)
    lane_size = (len(hosts) + lane_count - 1) // lane_count
    lanes = [
        hosts[start:start + lane_size]
        for start in range(0, len(hosts), lane_size)
    ]
    if pass_index:
        shift = pass_index % len(lanes)
        lanes = lanes[shift:] + lanes[:shift]

    ordered = []
    max_lane_len = max(len(lane) for lane in lanes)
    for index in range(max_lane_len):
        for lane in lanes:
            if index < len(lane):
                ordered.append(lane[index])
    return ordered


def _find_ip_with_nmap_full_subnet_single_ip(target_mac, network, port=DEFAULT_PROBE_PORT, pass_index=0):
    """
    Scan the whole local subnet using one nmap process per IP, with bounded concurrency.

    Range-style nmap was unreliable in field tests, while exact single-IP nmap was stable.
    This keeps that reliable primitive and feeds it gradually so Wi-Fi/AP ARP handling is
    not hit by a burst of 254 simultaneous probes.
    """
    if not NMAP_ARP_DISCOVERY_ENABLED:
        return None
    nmap_path = _find_nmap_exe()
    if not nmap_path:
        print("[nmap scan] nmap not found; skipping nmap rediscovery")
        return None

    hosts = _ordered_hosts_for_nmap_pass(network, pass_index)
    if not hosts:
        return None

    started = time.time()
    pending = {}
    next_index = 0
    executor = ThreadPoolExecutor(max_workers=NMAP_SINGLE_IP_CONCURRENCY)

    def submit_next():
        nonlocal next_index
        if next_index >= len(hosts):
            return False
        ip = hosts[next_index]
        next_index += 1
        future = executor.submit(_nmap_single_ip, nmap_path, ip, target_mac)
        pending[future] = ip
        return True

    try:
        while len(pending) < NMAP_SINGLE_IP_CONCURRENCY and submit_next():
            time.sleep(NMAP_SINGLE_IP_LAUNCH_DELAY_SECONDS)

        while pending:
            done, _ = wait(set(pending), return_when=FIRST_COMPLETED)
            for future in done:
                scanned_ip = pending.pop(future)
                try:
                    found = future.result()
                except Exception:
                    found = None
                if found:
                    seconds = time.time() - started
                    print(
                        f"[nmap scan] pass={pass_index + 1} found MAC {target_mac} "
                        f"at {found} after {next_index} probes in {seconds:.1f}s"
                    )
                    executor.shutdown(wait=False, cancel_futures=True)
                    return _select_alive_mac_match([found], port) or found

                while len(pending) < NMAP_SINGLE_IP_CONCURRENCY and submit_next():
                    time.sleep(NMAP_SINGLE_IP_LAUNCH_DELAY_SECONDS)

        print(
            f"[nmap scan] pass={pass_index + 1} scanned {len(hosts)} hosts "
            f"in {time.time() - started:.1f}s; MAC {target_mac} not found"
        )
        return None
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _scan_once(target_mac, network, port=DEFAULT_PROBE_PORT, workers=SCAN_MAX_WORKERS):
    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > SCAN_MAX_HOSTS:
        hosts = hosts[:SCAN_MAX_HOSTS]

    # ⚠ 2026-08-11 — 예전엔 호스트마다 ping과 TCP 프로브를 "순서대로" 보냈다. 타임아웃을
    # 1초로 올리면서 응답 없는 빈 IP 하나당 최대 2초(1초+1초)가 들어 스캔이 8초 -> 12초로
    # 느려졌다. 둘은 서로 기다릴 이유가 없으므로 각각 독립된 작업으로 큐에 넣어 동시에
    # 보낸다 (호스트당 최대 2초 -> 1초).
    started = time.time()
    tasks = [(ip, kind) for ip in hosts for kind in ("ping", "tcp")]

    def run_task(task):
        ip, kind = task
        if kind == "ping":
            _ping_once(ip)
        else:
            _tcp_probe_once(ip, port)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(run_task, tasks))
    probe_seconds = time.time() - started

    # ⚠ 2026-08-11 실측으로 발견 — 프로브가 끝나자마자 arp -a를 읽으면 "늦게 응답한" 장비가
    # 아직 ARP 캐시에 반영되기 전이라 통째로 누락된다. 같은 대역을 반복 측정했더니 읽는
    # 시점에 따라 46개 -> 51개로 약 12%나 차이가 났다(프로브 직후 46, 3초 뒤 51). 대상 장비가
    # 하필 이 "늦게 응답하는" 쪽이면 멀쩡히 살아있는데도 계속 못 찾게 된다. 짧게 기다렸다가
    # 읽어서 취합률을 올린다.
    time.sleep(ARP_SETTLE_DELAY_SECONDS)

    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (subprocess.SubprocessError, OSError):
        return None

    entries = _ARP_LINE.findall(result.stdout)
    matches = [ip_str for ip_str, mac_str in entries if _normalize_mac(mac_str) == target_mac]
    found = _select_alive_mac_match(matches, port)
    if found:
        return found

    # ⚠ 진단용 로그(2026-08-11) — 스캔이 실패했을 때 "우리가 실제로 무엇을 봤는지"를 남긴다.
    # 스캔이 대역을 제대로 훑었는데도 대상 MAC이 ARP에 아예 안 잡힌 것인지(=장비가 그 순간
    # 응답을 안 한 것), 아니면 스캔 자체가 비정상적으로 짧게 끝났거나 ARP를 못 읽은 것인지를
    # 구분하기 위함. 실사용 중 "앱에서만 못 찾는" 현상의 원인을 좁히는 용도.
    same_subnet = sum(1 for ip_str, _ in entries if ipaddress.ip_address(ip_str) in network)
    print(f"[스캔 진단] 대역={network} 프로브={len(hosts)}개/{probe_seconds:.1f}초, "
          f"ARP 응답={same_subnet}개(전체 {len(entries)}개) - 대상 MAC({target_mac}) 없음")
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


def find_ip_for_mac(mac, subnet_hint_ip, port=DEFAULT_PROBE_PORT, known_ips=None, background=False):
    """
    subnet_hint_ip(예전에 쓰던 IP)와 같은 네트워크 대역 전체를 훑어서, mac과
    일치하는 장비의 현재 IP를 찾아 돌려준다. 못 찾으면 None.

    port: 대상 장비의 SSH 포트(프로파일의 port). ping이 막혀 있어도 이 포트로 TCP
    연결을 시도해서 ARP 캐시를 채우기 위해 쓴다 (3번 개선사항 — 아래 _probe_host 참고).
    known_ips: 이 장비가 최근에 실제로 있었던 IP 목록(프로파일의 recent_ips, 최근순).
    있으면 전체 스캔 전에 이것부터 먼저 확인한다 (5번 개선사항).
    ⚠ 전체 서브넷 스캔 구간은 앱 전체에서 한 번에 하나만 돌도록 락으로 감싸져 있다
    (7번 개선사항) — 다른 스캔이 겹치면 그게 끝날 때까지 대기했다가 시작한다.
    background: 백그라운드 점검이 부른 스캔인지 (2026-08-11 추가). True면 "사용자가
    직접 눌러서 기다리고 있는 스캔"이 생겼을 때 재시도를 포기하고 락을 빨리 놓아준다 —
    사용자 재접속이 백그라운드 스캔 뒤에서 10초 가까이 밀리던 문제(실측) 대응.

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

    prefix_len = _get_local_prefix_length(subnet_hint_ip)
    if prefix_len is not None:
        scan_targets = [(subnet_hint_ip, prefix_len)]
    else:
        scan_targets = _get_local_networks()
        if not scan_targets:
            return None

    # ⚠ 사용자가 직접 기다리는 스캔이면, 락을 잡기 전에 먼저 "대기 중"으로 표시해둔다 —
    # 그래야 지금 락을 쥐고 있는 백그라운드 스캔이 그걸 보고 빨리 비켜준다.
    if not background:
        _change_user_waiting(1)
    try:
        with _scan_lock:
            for ip, prefix in scan_targets:
                try:
                    network = ipaddress.ip_network(f"{ip}/{prefix or 24}", strict=False)
                except ValueError:
                    continue
                found = _find_ip_in_arp_cache(target_mac, network, port)
                if found:
                    return found
                for attempt in range(NMAP_FULL_SUBNET_PASSES):
                    if background and attempt > 0 and _is_user_waiting():
                        print("[스캔] 사용자 요청 스캔이 대기 중 - 백그라운드 재시도를 건너뛰고 양보합니다")
                        return None
                    if attempt > 0:
                        time.sleep(NMAP_REDISCOVERY_LOOP_DELAY_SECONDS)
                    found = _find_ip_in_arp_cache(target_mac, network, port)
                    if found:
                        return found
                    found = _find_ip_with_nmap_full_subnet_single_ip(
                        target_mac, network, port, pass_index=attempt
                    )
                    if found:
                        return found
                    # ⚠ 시도마다 동시 수를 다르게 — 1차는 빠르게, 놓치면 2차는 촘촘하게
    finally:
        if not background:
            _change_user_waiting(-1)

    return None
