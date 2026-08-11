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
import threading

import websockets

import ssh_session

WS_HOST = "localhost"
WS_PORT = 8765


async def _relay_channel_to_ws(channel, websocket):
    """SSH 채널의 출력을 계속 읽어서 웹소켓으로 흘려보낸다."""
    loop = asyncio.get_event_loop()
    try:
        while True:
            # channel.recv는 블로킹 함수라 별도 스레드에서 실행
            data = await loop.run_in_executor(None, channel.recv, 4096)
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

        # 출력 중계를 백그라운드 작업으로 시작
        relay_task = asyncio.create_task(_relay_channel_to_ws(channel, websocket))

        # 클라이언트로부터 오는 입력/리사이즈 메시지 처리
        async for message in websocket:
            msg = json.loads(message)

            if msg["type"] == "input":
                channel.send(msg["data"].encode("utf-8"))

            elif msg["type"] == "resize":
                # ⚠ 창 크기 동기화 — 없으면 vim/htop 화면이 깨짐
                channel.resize_pty(width=msg["cols"], height=msg["rows"])

        relay_task.cancel()

    except Exception as e:
        print(f"[터미널 오류] {e}")
        try:
            await websocket.send(json.dumps({"type": "error", "message": str(e)}))
        except Exception:
            pass
    finally:
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