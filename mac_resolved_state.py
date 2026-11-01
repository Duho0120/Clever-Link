"""
MAC 불일치(mac_mismatch_state)가 해소된 순간을 잠깐 기억해뒀다가, 초록색 확인 배너로
"방금 해소됐습니다"를 알려주기 위한 상태.

- 그냥 매번 "MAC이 일치한다"고 알려주면 스팸이 되므로, "불일치 상태였다가 방금
  일치로 바뀐" 전환 시점에만 기록한다(호출하는 쪽에서 그 판단을 하고 mark()를 부름).
- mac_mismatch_state와 달리 자동으로는 안 지워진다 — 사용자가 실제로 확인했다는
  의미로 X를 눌러야(dismiss) 없어지는 게 자연스럽다고 판단(사용자 확인 2026-08-05).
"""

_resolved = {}  # {profile_name: {"mac": str}}


def mark(profile_name, mac):
    _resolved[profile_name] = {"mac": mac}


def clear(profile_name):
    _resolved.pop(profile_name, None)


def get_all():
    return dict(_resolved)
