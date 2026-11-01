"""
PyInstaller로 패키징했을 때와 평소 개발할 때, 둘 다에서
같은 코드로 파일 경로를 찾을 수 있게 해주는 도우미.

- 소스 실행(python run.py): 저장소 루트 기준
- PyInstaller로 묶은 .exe 실행 시: 실행 중 임시로 풀린 폴더(sys._MEIPASS) 기준
"""

import os
import sys


def resource_path(relative_path):
    """상대 경로를 받아서, 지금 실행 환경에 맞는 절대 경로를 돌려준다."""
    if hasattr(sys, "_MEIPASS"):
        # PyInstaller가 실행 중 파일을 풀어놓는 임시 폴더
        base_path = sys._MEIPASS
    else:
        # clever_link/platform에서 저장소 루트까지 올라간다.
        base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    return os.path.join(base_path, relative_path)


def app_dir():
    """
    실행파일(exe)이 실제로 위치한 폴더를 돌려준다.
    resource_path와 달리, --onefile 실행 시 매번 새로 생기는 임시 폴더가 아니라
    exe 파일 자체가 있는 '고정된' 폴더를 가리킨다.
    (WebView2 설정 폴더처럼, 실행할 때마다 위치가 바뀌면 안 되는 데이터를 저장할 때 사용)
    """
    if getattr(sys, "frozen", False):
        default = os.path.dirname(sys.executable)
    else:
        default = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.abspath(os.environ.get("CLEVER_LINK_DATA_DIR", default))
