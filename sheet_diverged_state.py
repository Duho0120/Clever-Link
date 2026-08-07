"""
시트에서 온(source="sheet") 원격지가, 동적 IP 재탐색(MAC/mDNS)으로 자동 교정되면서
profiles.json이 시트의 마지막 동기화 값과 달라진 상태를 기억해두는 곳.

- 시트 반영(구글 시트 자체 수정)은 전체 사용자에게 영향을 주므로 앱이 자동으로 건드리지
  않기로 함(사용자 확인 2026-08-05) — 로컬 profiles.json만 조용히 자동 교정되고, 시트는
  그대로 둔다. 문제는 이 상태로 있다가 "↻ 시트 새로고침"이 일어나면(수동이든 자동이든)
  시트의 예전 값으로 다시 덮어써질 수 있다는 것 — 그래서 "지금 로컬과 시트가 다르다"는
  걸 사용자에게 계속 보이게 알려주는 용도.
- 다음 시트 동기화가 그 프로파일을 실제로 처리하는 순간(값이 같아졌든, 시트 값으로 다시
  덮어써졌든) 자동으로 해소된다 — sheet_sync.py의 sync_from_sheet()가 매 행마다 clear()를
  호출한다.
"""

_diverged = {}  # {profile_name: {"sheet_host": str, "local_host": str}}


def mark(profile_name, sheet_host, local_host):
    _diverged[profile_name] = {"sheet_host": sheet_host, "local_host": local_host}


def clear(profile_name):
    _diverged.pop(profile_name, None)


def get_all():
    return dict(_diverged)
