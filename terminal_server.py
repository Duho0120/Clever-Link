"""
2-2. WebSocket 서버

- xterm.js(화면)와 ssh_session.py(paramiko 채널) 사이를 중계한다.
- localhost 전용 포트 (rcd가 쓰는 5572와 겹치지 않게 8765 사용)
- 메시지 규칙(JSON):
    클라이언트 -> 서버
        {"type": "init", "profile": "프로파일이름"}   접속 시작
        {"type": "input", "data": "키보드입력"}       터미널에 입력
        {"type": "resize", "cols": N, "rows": M}      창 크기 변경
    서버 -> 클라이언트
        {"type": "output", "data": "..."}             터미널 출력
        {"type": "error", "message": "..."}           오류
        {"type": "closed"}                            연결 종료
"""

import asyncio
import json
import socket
import threading

import websockets

import ssh_session

WS_HOST = "localhost"
WS_PORT = 8765

# ⚠ 2026-08-11 실사용 중 발견 — channel.recv()에 타임아웃이 없어서, 연결이 끊겨도
# OS/paramiko가 알아챌 때까지(수십 초~몇 분, 예측 불가) 무한정 대기했다. 그동안 "재접속"
# 버튼조차 뜨지 않고 터미널이 멈춘 것처럼 보였다. 주기적으로 깨어나 연결 상태를 직접
# 확인하도록 타임아웃을 건다. 이 값은 "사용자가 가만히 있는지"와는 무관하다 — 순수하게
# 네트워크 상태를 확인하는 주기일 뿐이라, 짧게 잡아도 조용히 대기 중인 정상 세션을
# 끊긴 것으로 오판하지 않는다 (아래에서 timeout만으로는 절대 끊긴 것으로 확정하지 않고
# transport.is_active()를 반드시 같이 확인함).
# ⚠ 2026-08-12 v4 — IP 변경 재접속 시간을 더 줄이기 위해 5초 -> 2초로 단축.
# recv 타임아웃만으로 끊김 확정하지 않고 transport.is_active()와 재확인을 거치므로,
# 정상적인 "출력이 없는 터미널"을 끊긴 것으로 오판하지 않는다.
CHANNEL_HEALTH_CHECK_INTERVAL_SECONDS = 2
# ⚠ 한 번 의심스럽다고(타임아웃 + is_active 확인 실패) 바로 "끊김"으로 확정하지 않는다 —
# 아주 짧은(1~2초) 네트워크 흔들림일 수 있어서, 짧게 대기 후 한 번 더 확인한 뒤에만
# 확정한다. 그래야 순간적인 blip마다 "연결 끊김" 배너가 깜빡이는 걸 막을 수 있다.
DEAD_CONFIRM_RETRY_DELAY_SECONDS = 1


async def _relay_channel_to_ws(channel, websocket):
    """SSH 채널의 출력을 계속 읽어서 웹소켓으로 흘려보낸다."""
    loop = asyncio.get_event_loop()
    channel.settimeout(CHANNEL_HEALTH_CHECK_INTERVAL_SECONDS)
    try:
        while True:
            try:
                # channel.recv는 블로킹 함수라 별도 스레드에서 실행
                data = await loop.run_in_executor(None, channel.recv, 4096)
            except socket.timeout:
                # ⚠ 출력이 없었다고 바로 죽었다고 보지 않는다 — 연결(transport) 자체가
                # 살아있으면 그냥 조용한 정상 상태이므로 계속 대기한다.
                transport = channel.get_transport()
                if transport is not None and transport.is_active():
                    continue
                # 짧게 대기 후 한 번 더 확인 — 순간적인 흔들림 봐주기
                await asyncio.sleep(DEAD_CONFIRM_RETRY_DELAY_SECONDS)
                transport = channel.get_transport()
                if transport is not None and transport.is_active():
                    continue
                break  # 진짜 끊긴 것으로 확정
            if not data:
                break
            # ⚠ UTF-8 명시 (한글 깨짐 방지)
            await websocket.send(json.dumps({
                "type": "output",
                "data": data.decode("utf-8", errors="replace"),
            }))
    except Exception:
        pass
    finally:
        try:
            await websocket.send(json.dumps({"type": "closed"}))
        except Exception:
            pass


async def handle_client(websocket):
    client = None
    channel = None
    relay_task = None
    try:
        # 첫 메시지는 반드시 init이어야 한다 (어떤 프로파일에 접속할지)
        init_raw = await websocket.recv()
        init_msg = json.loads(init_raw)

        if init_msg.get("type") != "init":
            await websocket.send(json.dumps({
                "type": "error", "message": "첫 메시지는 init이어야 합니다",
            }))
            return

        profile_name = init_msg["profile"]
        print(f"[터미널 연결] 프로파일: {profile_name}")

        # ⚠ connect_profile()은 블로킹 함수(paramiko 소켓 연결 + 동적 IP 재탐색 스캔까지
        # 포함하면 최대 수십 초)라, asyncio 이벤트 루프 스레드에서 그대로 부르면 이 접속
        # 하나가 오래 걸릴 때 서버 전체(다른 클라이언트의 웹소켓 메시지 처리까지)가 같이
        # 멈춰버린다 (2026-08-10 실사용 중 발견). 별도 스레드에서 돌려서 이벤트 루프는
        # 계속 살아있게 한다.
        loop = asyncio.get_event_loop()
        client = await loop.run_in_executor(None, ssh_session.connect_profile, profile_name)
        channel = ssh_session.open_terminal_channel(client)
        await websocket.send(json.dumps({"type": "connected"}))

        # 출력 중계를 백그라운드 작업으로 시작
        relay_task = asyncio.create_task(_relay_channel_to_ws(channel, websocket))

        # 클라이언트로부터 오는 입력/리사이즈 메시지 처리
        async for message in websocket:
            msg = json.loads(message)

            if msg["type"] == "input":
                # ⚠ channel.send()도 블로킹 함수라, 연결이 끊긴 상태에서는 (settimeout으로
                # 건) 타임아웃까지 멈출 수 있다. 별도 스레드에서 실행해서 asyncio 이벤트
                # 루프(다른 클라이언트 포함) 전체가 같이 멈추지 않게 한다. await로 순서대로
                # 처리해서 — 다음 메시지를 읽기 전에 이번 전송이 끝나길 기다려서 — 빠르게
                # 연타하거나 붙여넣기해도 입력 순서가 꼬이지 않게 한다.
                await loop.run_in_executor(None, channel.send, msg["data"].encode("utf-8"))

            elif msg["type"] == "resize":
                # ⚠ 창 크기 동기화 — 없으면 vim/htop 화면이 깨짐
                channel.resize_pty(width=msg["cols"], height=msg["rows"])

    except Exception as e:
        print(f"[터미널 오류] {e}")
        try:
            await websocket.send(json.dumps({"type": "error", "message": str(e)}))
        except Exception:
            pass
    finally:
        # ⚠ 정상 종료든 예외든 relay_task가 계속 살아서 이미 닫힌 channel/client를 붙잡고
        # 있지 않도록 항상 취소한다 (예전엔 정상 종료 경로에서만 cancel()을 불러서, 예외로
        # 빠지는 경우 relay_task가 정리 안 된 채 남을 수 있었다).
        if relay_task:
            relay_task.cancel()
        if channel:
            channel.close()
        if client:
            client.close()
        print(f"[터미널 종료] {profile_name if 'profile_name' in dir() else '?'}")


def _run_server_forever():
    async def main():
        async with websockets.serve(handle_client, WS_HOST, WS_PORT):
            print(f"[WebSocket 서버] ws://{WS_HOST}:{WS_PORT} 에서 대기 중")
            await asyncio.Future()  # 영원히 대기

    asyncio.run(main())


def start_server_background():
    """앱이 시작할 때 이 함수를 한 번 호출하면, 백그라운드 스레드로 서버가 뜬다."""
    thread = threading.Thread(target=_run_server_forever, daemon=True)
    thread.start()
