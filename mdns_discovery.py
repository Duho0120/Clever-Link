"""
동적 IP 프로파일 재탐색 - mDNS(avahi 등) 기반 보조 수단

- mac_discovery.py(MAC 주소+ARP 스캔)가 1차 방법이고, 이건 그게 실패했을 때 쓰는
  2차 보험이다. 장비가 mDNS(리눅스는 보통 avahi-daemon)로 자기 호스트 이름을
  네트워크에 광고하고 있으면, IP를 몰라도 이름만으로 지금 IP를 물어볼 수 있다.
- ⚠ 장비의 avahi가 꺼져있으면 당연히 응답이 안 오고 조용히 실패한다(정상 동작).
  이 앱만으로는 원격 장비의 avahi를 켤 수 없다 - 그건 장비 쪽 설정 문제.
"""

import ipaddress

from zeroconf import AddressResolverIPv4, Zeroconf

RESOLVE_TIMEOUT_MS = 3000

# ⚠ 5번 개선사항(도커 대역 필터링, 2026-08-20) — 도커가 설치된 장비(예: 낙상감지가
# 도커로 배포된 젯슨)는 mDNS 응답에 실제 이더넷 IP와 도커 기본 브리지 IP(보통
# 172.17.0.1)가 같이 섞여 나올 수 있다. 넓은 사설 대역(172.16.0.0/12)으로 걸렀다간
# 실제 병동 LAN 대역(172.16.x.x)과 겹쳐서 위험하므로(실측: 68개 프로파일 중 23개가
# 그 대역을 실제로 씀), 도커가 실제로 쓰는 좁은 기본 브리지 대역만 걸러낸다
# (같은 68개 중 이 좁은 대역과 겹치는 실제 원격지는 0개로 확인됨).
DOCKER_DEFAULT_BRIDGE = ipaddress.ip_network("172.17.0.0/16")


def resolve_mdns_hostname_all(hostname, timeout_ms=RESOLVE_TIMEOUT_MS):
    """
    mDNS로 광고되는 호스트 이름을 조회해서, 응답한 IPv4 주소를 전부 리스트로 돌려준다.
    hostname은 "jetson-co6"처럼 짧은 이름이든 "jetson-co6.local."처럼 이미 완전한
    형태든 상관없이 받아서 내부적으로 ".local." 형식으로 맞춰준다.

    ⚠ 같은 이름을 쓰는 장비가 여러 대면(디스크 복제 등으로 호스트 이름이 안 겹치게
    관리가 안 된 경우) 응답이 여러 개 올 수 있다 — 이럴 때 아무거나 하나를 골라
    조용히 연결해버리면 엉뚱한 장비에 연결될 위험이 있어서, 호출하는 쪽에서 "여러 개
    발견됨"을 판단할 수 있도록 전체 목록을 그대로 넘겨준다 (하나만 고르는 건 하지 않음).

    응답이 없으면(장비가 꺼져있음/avahi 비활성) 빈 리스트.
    """
    if not hostname:
        return []

    name = hostname.strip().rstrip(".")
    if not name.endswith(".local"):
        name += ".local"
    name += "."

    zc = Zeroconf()
    try:
        resolver = AddressResolverIPv4(name)
        found = resolver.request(zc, timeout_ms)
        if not found:
            return []
        addresses = resolver.parsed_addresses()
    except Exception:
        return []
    finally:
        zc.close()

    # ⚠ 후보가 2개 이상일 때만 도커 대역을 걸러낸다 — 후보가 원래 1개뿐이면 그게
    # 도커 대역처럼 생겼어도 유일한 응답이니 그대로 신뢰한다(걸러내면 유일한 정답을
    # 잃을 위험). 걸러내다 전부 사라지는 극단적인 경우엔 원래 목록을 그대로 유지한다.
    if len(addresses) >= 2:
        filtered = [ip for ip in addresses if ipaddress.ip_address(ip) not in DOCKER_DEFAULT_BRIDGE]
        if filtered and len(filtered) != len(addresses):
            excluded = [ip for ip in addresses if ip not in filtered]
            print(f"[mDNS] 도커 기본 브리지 주소 제외: {excluded}")
        if filtered:
            addresses = filtered

    return addresses


def resolve_mdns_hostname(hostname, timeout_ms=RESOLVE_TIMEOUT_MS):
    """
    resolve_mdns_hostname_all()의 결과 중 첫 번째 주소만 돌려주는 단순 버전.
    ⚠ 후보가 여러 개인지 신경 써야 하는 호출부(재탐색 로직)는 이 함수 대신
    resolve_mdns_hostname_all()을 직접 써서 개수를 확인해야 한다.
    응답이 없으면 None.
    """
    addresses = resolve_mdns_hostname_all(hostname, timeout_ms)
    return addresses[0] if addresses else None
