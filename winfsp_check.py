"""
3-2. WinFsp 설치 확인 및 자동 설치

- WinFsp는 커널 드라이버라서 우리 exe 안에 통째로 넣을 수 없다.
- 대신 이미 검증된 방법(Phase 0에서 성공했던 winget install winfsp)을
  코드에서 그대로 실행하는 방식을 쓴다.
- 이미 설치되어 있으면 아무 것도 하지 않고 조용히 넘어간다.
"""

import os
import subprocess

# ⚠ 사용자 피드백: 파일 존재 확인 자체는 순식간이지만, 어차피 한 번 확인되면
# 다시 물어볼 필요가 없으므로 확인 완료 표시를 로컬에 남겨서 다음 실행부터는
# 아예 건너뛰도록 함 (설치를 거부한 경우엔 표시하지 않아 다음 실행에도 다시 물어봄).
WINFSP_CHECKED_FLAG = "winfsp_checked.flag"


def is_winfsp_installed():
    """
    WinFsp가 이미 설치되어 있는지 확인한다.
    설치되면 항상 만들어지는 대표적인 파일 하나의 존재 여부로 판단한다.
    """
    candidates = [
        r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll",
        r"C:\Program Files\WinFsp\bin\winfsp-x64.dll",
    ]
    return any(os.path.exists(p) for p in candidates)


def install_winfsp():
    """
    winget으로 WinFsp를 설치한다.
    커널 드라이버 설치라 Windows가 자동으로 관리자 권한 승인(UAC)을 요구한다.
    설치가 끝날 때까지 이 함수는 대기한다 (동기 실행).
    """
    print("[WinFsp] winget으로 설치를 시작합니다 (관리자 승인 창이 뜰 수 있습니다)...")
    result = subprocess.run(
        ["winget", "install", "--id", "WinFsp.WinFsp", "-e", "--silent",
         "--accept-package-agreements", "--accept-source-agreements"],
        capture_output=True,
        text=True,
    )
    print("[WinFsp] winget 종료 코드:", result.returncode)
    if result.stdout:
        print(result.stdout[-500:])  # 너무 길면 끝부분만
    if result.stderr:
        print(result.stderr[-500:])
    return result.returncode == 0


def _mark_checked():
    try:
        with open(WINFSP_CHECKED_FLAG, "w", encoding="utf-8") as f:
            f.write("ok")
    except OSError:
        pass  # 표시 파일을 못 남겨도 치명적이지 않음, 다음 실행에 다시 확인할 뿐


def ensure_winfsp(ask_confirm_func):
    """
    앱 시작 시 호출: 설치 안 되어 있으면 사용자에게 물어보고 설치를 진행한다.
    한 번 확인(또는 설치 성공)되면 로컬에 표시를 남겨, 다음 실행부터는
    이 함수 자체를 건너뛴다.

    ask_confirm_func: (title, message) -> bool 형태의 확인창 함수.
                       app_ui.py의 ask_confirm을 그대로 넘겨받아 재사용한다.
    """
    if os.path.exists(WINFSP_CHECKED_FLAG):
        return True

    if is_winfsp_installed():
        print("[WinFsp] 이미 설치되어 있습니다.")
        _mark_checked()
        return True

    answer = ask_confirm_func(
        "필수 구성 요소 설치",
        "드라이브 마운트 기능을 사용하려면 WinFsp가 필요합니다.\n"
        "지금 설치할까요? (관리자 권한 승인 창이 뜰 수 있습니다)",
    )
    if not answer:
        print("[WinFsp] 사용자가 설치를 거부했습니다. 마운트 기능이 동작하지 않을 수 있습니다.")
        return False  # 표시를 남기지 않아 다음 실행에도 다시 확인함

    success = install_winfsp()
    if success:
        _mark_checked()
    else:
        print("[WinFsp] 자동 설치에 실패했습니다. 수동 설치가 필요할 수 있습니다.")
    return success