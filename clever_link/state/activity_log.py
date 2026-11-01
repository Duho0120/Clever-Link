"""
재접속/재탐색 진행 상황을 앱 창의 노란 배너로 잠깐 흘려보내기 위한 최근 메시지 보관소.

- 지금까지 콘솔에만 찍히던 진행 상황("같은 주소로 재시도 중", "새 IP 발견" 등)을
  앱 창에서도 볼 수 있게 한다. 콘솔을 안 띄우고 쓰는 경우가 대부분이라 그동안은
  무슨 일이 벌어지는지 화면에서 전혀 알 수 없었다 (사용자 요청 2026-08-11).
- mac_mismatch_state 같은 "해소될 때까지 남아있는" 상태와 성격이 다르다 — 그냥
  흘러가는 진행 로그라서, X 버튼 없이 MESSAGE_TTL_SECONDS가 지나면 저절로 사라진다.
- 메모리에만 유지한다(파일 기록 없음). 앱을 재시작하면 초기화된다.
"""

import threading
import time
from collections import deque

MESSAGE_TTL_SECONDS = 20  # 이 시간이 지난 메시지는 배너에서 자동으로 빠짐
MAX_MESSAGES = 30

_lock = threading.Lock()
_messages = deque(maxlen=MAX_MESSAGES)  # [(timestamp, profile_name, text)]


def log(profile_name, text):
    """진행 상황을 콘솔에 찍으면서 동시에 배너용으로도 기록한다."""
    print(text)
    with _lock:
        _messages.append((time.time(), profile_name, text))


def get_recent():
    """
    최근 MESSAGE_TTL_SECONDS 이내의 메시지를 오래된 순으로 돌려준다.
    [{"name": 프로파일명, "text": 메시지}, ...]
    """
    now = time.time()
    with _lock:
        items = [(ts, name, text) for ts, name, text in _messages
                 if now - ts <= MESSAGE_TTL_SECONDS]
    return [{"name": name, "text": text} for _, name, text in items]
