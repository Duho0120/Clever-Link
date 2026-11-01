"""
F-7. 시스템 트레이 아이콘

- 창의 X 버튼을 눌러도 완전히 종료하지 않고, 창만 숨긴다.
  마운트/터미널 서버는 백그라운드에서 계속 동작한다 (RaiDrive와 동일한 방식).
- 트레이 아이콘에서 [열기](창 다시 보이기) / [완전히 종료]를 선택할 수 있다.
"""

import threading

from PIL import Image
import pystray

from resource_path import resource_path


def _make_icon_image():
    """CLEVER Link 로고(logo.png, 원 바깥 투명 처리된 버전)를 트레이 아이콘으로 그대로 사용."""
    return Image.open(resource_path("logo.png")).convert("RGBA")


def start_tray(window, on_full_quit):
    """
    트레이 아이콘을 백그라운드 스레드로 띄운다.

    window       : pywebview의 Window 객체 (show/hide 제어용)
    on_full_quit : "완전히 종료" 선택 시 호출할 함수 (실제 정리 + 앱 종료 담당)
    """

    def on_open(icon, item):
        window.show()

    def on_quit(icon, item):
        icon.stop()
        on_full_quit()

    menu = pystray.Menu(
        pystray.MenuItem("열기", on_open, default=True),
        pystray.MenuItem("완전히 종료", on_quit),
    )

    icon = pystray.Icon(
        "sftp_ssh_launcher",
        _make_icon_image(),
        "Clever Link",
        menu,
    )

    thread = threading.Thread(target=icon.run, daemon=True)
    thread.start()
    return icon