"""
mDNS 후보가 여러 개 발견돼서(3번 기능) 재탐색을 중단한 원격지 목록을 기억해두는 곳.

- ssh_session.py/mount_control.py가 재탐색 중 후보를 2개 이상 발견하면 여기에 기록하고,
  app_ui.py가 이 목록을 메인 창 하단에 빨간 경고 배너로 계속 보여준다(사용자가 상태줄
  메시지를 놓쳐도 알 수 있게 — 상태줄은 뒤이은 다른 작업 메시지에 바로 덮어써짐).
- 파일로 저장하지 않고 메모리에만 유지한다 — 앱을 껐다 켜면 초기화되고, 다음에 다시
  연결을 시도할 때 문제가 여전하면 자연스럽게 다시 기록된다.
- "자동으로 사라지게" 요구사항: 같은 원격지로 재탐색 없이 정상 접속(또는 재탐색 성공)이
  될 때마다 clear()를 호출해서, 사용자가 직접 배너를 안 지워도 문제가 실제로 해소되면
  자동으로 사라진다.
"""

_ambiguous = {}  # {profile_name: {"hostname": str, "candidates": [str, ...], "seq": int}}
_seq_counter = 0  # ⚠ X로 닫아도 "다음 재시도에서 또 감지되면 다시 뜨게" 하기 위한 일련번호.
                   # UI 쪽에서 "마지막으로 닫은 seq"를 기억해뒀다가, 지금 seq가 더 크면
                   # (=새로 감지된 것) 닫았던 기록을 무시하고 다시 보여준다.


def mark(profile_name, hostname, candidates):
    global _seq_counter
    _seq_counter += 1
    _ambiguous[profile_name] = {"hostname": hostname, "candidates": list(candidates), "seq": _seq_counter}


def clear(profile_name):
    _ambiguous.pop(profile_name, None)


def get_all():
    """{profile_name: {...}} 형태 그대로 복사본을 돌려준다."""
    return dict(_ambiguous)
