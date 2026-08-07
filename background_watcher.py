"""
2번 개선사항 — 백그라운드 사전 점검(Proactive Health Check)

기존에는 IP 변경/MAC 불일치 감지가 전부 "사용자가 접속/마운트를 시도하는 순간"에만
일어났다(리액티브). 즉 젯슨의 IP가 바뀌어도 다음에 누군가 접속을 시도하기 전까지는
아무도 몰랐다. 이 모듈은 앱이 켜져 있는 동안 주기적으로 백그라운드에서 모든 프로파일을
가볍게 재검증해서, 사용자가 접속을 시도하기도 전에 문제를 미리 감지/교정한다.

⚠ 여기서는 SSH 연결(자격 증명 필요, 처음 보는 서버면 호스트 키 확인창이 팝업될 위험)은
절대 열지 않는다 — 순수 TCP 도달성 확인 + ARP 조회(둘 다 자격 증명 불필요, 조용히 실패
가능)만 사용한다. SSH 기반 MAC 검증(get_remote_mac, 터널 경유까지 커버)은 여전히 실제
접속/마운트 시점에만 실행된다 — 그건 mount_control.py/ssh_session.py가 담당.
"""

import threading

import profile_store
import mac_discovery
import mdns_discovery
import mdns_ambiguity_state
import mac_mismatch_state
import mac_resolved_state
from host_resolver import resolve_reachable_address, is_reachable

DEFAULT_INTERVAL_SECONDS = 600  # 10분

_watch_thread = None
_stop_event = threading.Event()


def _check_one_profile(name):
    try:
        profile = profile_store.get_profile(name)
    except (KeyError, ValueError):
        return  # 점검 중 삭제됐거나 keyring 문제 — 조용히 스킵

    resolved_host, resolved_port = resolve_reachable_address(profile)
    reachable = is_reachable(resolved_host, resolved_port)

    if not reachable and (profile.get("mac") or profile.get("hostname")):
        # ⚠ ssh_session.connect_profile()/mount_control.mount_profile()과 같은
        # 1차(MAC+ARP)/2차(mDNS) 폴백 패턴 — 백그라운드에서도 IP 변경을 스스로 교정한다.
        print(f"[백그라운드 점검] '{name}' ({resolved_host}:{resolved_port}) 응답 없음 - 새 IP 탐색 중...")
        new_ip = None
        if profile.get("mac"):
            new_ip = mac_discovery.find_ip_for_mac(profile["mac"], profile["host"], resolved_port)
        if (not new_ip or new_ip == resolved_host) and profile.get("hostname"):
            candidates = mdns_discovery.resolve_mdns_hostname_all(profile["hostname"])
            if len(candidates) >= 2:
                mdns_ambiguity_state.mark(name, profile["hostname"], candidates)
                return
            new_ip = candidates[0] if candidates else None
        if not new_ip or new_ip == resolved_host:
            print(f"[백그라운드 점검] '{name}' 새 IP를 찾지 못함 - 다음 주기에 재시도")
            return
        print(f"[백그라운드 점검] '{name}' 새 IP 발견: {new_ip} (기존: {resolved_host}) - 프로파일 갱신")
        profile_store.update_profile_field(name, host=new_ip)
        resolved_host = new_ip
        reachable = is_reachable(resolved_host, resolved_port)

    if not reachable:
        return  # 여전히 도달 불가 - MAC 확인 불가능, 다음 주기에 재시도

    # ⚠ ARP는 같은 로컬 네트워크(L2)에서만 동작 — 터널 경유 원격지는 None이 돌아오고
    # 조용히 스킵된다 (그런 경우의 MAC 검증은 실제 접속/마운트 시점에 SSH 기반으로 수행됨).
    captured_mac = mac_discovery.get_mac_for_ip(resolved_host)
    stored_mac = profile.get("mac")
    if not captured_mac or not stored_mac:
        return

    if stored_mac == captured_mac:
        if name in mac_mismatch_state.get_all():
            mac_resolved_state.mark(name, captured_mac)
        mac_mismatch_state.clear(name)
        return

    # ⚠ connect_profile()/mount_profile()과 같은 이유 — 차단(여긴 애초에 열린 연결이
    # 없으니 "차단"할 것도 없다)하기 전에, 저장된(신뢰할 수 있는) MAC을 가진 진짜 장비가
    # 로컬 대역에 있는지 한 번 더 스캔해서 있으면 조용히 자동 교정한다.
    other_owner = profile_store.find_profile_by_mac(captured_mac, exclude_name=name)
    correct_ip = mac_discovery.find_ip_for_mac(stored_mac, resolved_host, resolved_port)
    if correct_ip and correct_ip != resolved_host:
        print(f"[백그라운드 점검] '{name}' MAC 불일치 자동 복구 - 올바른 장비를 {correct_ip}에서 찾음")
        profile_store.update_profile_field(name, host=correct_ip)
        mac_mismatch_state.clear(name)
        return

    print(f"[백그라운드 점검] '{name}' MAC 불일치 감지 - 저장됨({stored_mac}) != 실제({captured_mac})"
          + (f" (이 MAC은 '{other_owner}'의 기준 MAC과 동일)" if other_owner else ""))
    mac_mismatch_state.mark(name, stored_mac, captured_mac, other_owner)


def check_all_profiles():
    """등록된 모든 프로파일을 한 바퀴 점검한다. 수동으로도 호출 가능(예: 시트 새로고침 직후)."""
    for name in profile_store.list_profile_names():
        if _stop_event.is_set():
            return
        try:
            _check_one_profile(name)
        except Exception as e:
            print(f"[백그라운드 점검 오류] '{name}': {e}")


def _watch_loop(interval_seconds):
    # ⚠ 앱 시작 직후 바로 한 바퀴 돌리지 않는다 — 시작 시점엔 다른 초기화 작업(rcd 기동,
    # 시트 동기화 등)과 겹치기 쉬워서, 첫 주기는 interval만큼 대기한 뒤 시작한다.
    while not _stop_event.wait(interval_seconds):
        print("[백그라운드 점검] 주기 점검 시작...")
        check_all_profiles()
        print("[백그라운드 점검] 주기 점검 끝")


def start(interval_seconds=DEFAULT_INTERVAL_SECONDS):
    """백그라운드 점검 스레드를 시작한다. 이미 실행 중이면 아무것도 안 한다."""
    global _watch_thread
    if _watch_thread and _watch_thread.is_alive():
        return
    _stop_event.clear()
    _watch_thread = threading.Thread(target=_watch_loop, args=(interval_seconds,), daemon=True)
    _watch_thread.start()
    print(f"[백그라운드 점검] 시작됨 (주기: {interval_seconds}초)")


def stop():
    """앱 종료 시 정리용 (daemon 스레드라 없어도 프로세스 종료 시 자동으로 끝나지만, 명시적으로 멈추고 싶을 때)."""
    _stop_event.set()
