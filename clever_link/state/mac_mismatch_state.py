"""
원격지 이름 + MAC 주소 기반 신원 검증 (13번 엣지케이스에 대한 2차 안전장치)

- profiles.json에 저장된 "기준 MAC"과, 실제로 접속 성공했을 때 그 IP에서 새로 캡처한
  MAC이 다르면, 이 프로파일이 예전과 다른 물리 장비에 연결되고 있다는 강한 신호다.
  (계정명/비밀번호가 우연히 같아서 인증 자체는 성공해버리는 게 13번 엣지케이스의 핵심
  위험 — 접속은 "정상적으로" 성공하니 에러가 하나도 안 나서 사람이 알아채기 어렵다.
  MAC은 hostname/계정명과 달리 물리적 장비에 붙은 값이라 절대 안 겹치므로, 이걸로
  비교하면 확실하게 판단할 수 있다.)
- mdns_ambiguity_state.py와 같은 패턴: 메모리에만 유지, 앱을 껐다 켜면 초기화된다.
- ⚠ 자동으로는 절대 안 지워진다(mdns_ambiguity_state와 차이점) — 재접속해봤자 저장된
  기준 MAC을 우리가 직접 안 바꾸는 한 계속 다른 값이 캡처될 것이므로, "다시 접속해보니
  문제가 저절로 없어짐"은 있을 수 없는 상황이다. 사용자가 "수정"으로 올바른 MAC/호스트를
  직접 확인해서 반영해야만(그러면 새 기준값이 되어 다음 접속부터 일치) 해소된다.
"""

_mismatched = {}  # {profile_name: {"stored_mac", "actual_mac", "actual_mac_owner", "seq"}}
_seq_counter = 0  # ⚠ X로 닫아도 "다음 재시도에서 또 감지되면 다시 뜨게" 하기 위한 일련번호.
                   # (mdns_ambiguity_state.py와 같은 목적/패턴)


def mark(profile_name, stored_mac, actual_mac, actual_mac_owner=None):
    """
    actual_mac_owner: 지금 연결된 장비의 MAC(actual_mac)이 profiles.json에 이미 다른
    원격지의 기준 MAC으로 등록되어 있으면 그 원격지 이름 — "이건 사실 이미 등록된
    다른 원격지의 장비"라는 훨씬 구체적인 단서. 없으면 None(어느 프로파일과도 안 겹침).
    """
    global _seq_counter
    _seq_counter += 1
    _mismatched[profile_name] = {
        "stored_mac": stored_mac,
        "actual_mac": actual_mac,
        "actual_mac_owner": actual_mac_owner,
        "seq": _seq_counter,
    }


def clear(profile_name):
    _mismatched.pop(profile_name, None)


def get_all():
    return dict(_mismatched)
