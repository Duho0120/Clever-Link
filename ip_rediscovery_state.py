"""
IP 재탐색(동적 재탐색) 진행 상태 — 노란 배너("재탐색/재접속 시도 중")와 초록 배너
("재연결 성공") 용도.

- 재탐색이 시작되면 mark_in_progress()로 노란 배너 상태를 기록하고, 끝나면(성공/실패
  상관없이) clear_in_progress()로 지운다.
- 재탐색이 실제로 새 IP를 찾아 성공했을 때만 mark_resolved()로 초록 확인 배너를 띄운다.
  mac_resolved_state와 같은 이유로 자동으로는 안 사라짐 — X로 직접 닫아야 한다
  (그냥 스쳐 지나가면 "언제 재연결됐는지" 놓치기 쉬워서, 사용자가 실제로 확인했다는
  의미로 닫게 함).
- 파일로 저장하지 않고 메모리에만 유지한다 — 앱 재시작 시 초기화.
"""

_in_progress = {}  # {profile_name: True}
_resolved = {}  # {profile_name: {"old_ip": str, "new_ip": str, "seq": int}}
_seq_counter = 0  # ⚠ X로 닫아도 "다음에 또 재연결되면 다시 뜨게" 하기 위한 일련번호


def mark_in_progress(profile_name):
    _in_progress[profile_name] = True


def clear_in_progress(profile_name):
    _in_progress.pop(profile_name, None)


def mark_resolved(profile_name, old_ip, new_ip):
    global _seq_counter
    _seq_counter += 1
    _resolved[profile_name] = {"old_ip": old_ip, "new_ip": new_ip, "seq": _seq_counter}


def clear_resolved(profile_name):
    _resolved.pop(profile_name, None)


def get_all_in_progress():
    return dict(_in_progress)


def get_all_resolved():
    return dict(_resolved)
