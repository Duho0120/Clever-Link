"""
Nmap 설치 확인 및 자동 설치

v4 동적 IP 재탐색은 nmap의 ARP discovery를 사용한다.
이미 PATH에서 nmap을 찾을 수 있으면 조용히 넘어가고, 없으면 사용자에게 물어본 뒤
winget으로 설치한다. 한 번 확인되면 flag 파일로 다음 실행부터는 확인을 건너뛴다.
"""

import os
import shutil
import subprocess

NMAP_CHECKED_FLAG = "nmap_checked.flag"


def is_nmap_installed():
    if shutil.which("nmap"):
        return True
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    return any(os.path.exists(p) for p in candidates)


def install_nmap():
    print("[Nmap] winget으로 설치를 시작합니다 (관리자 승인 창이 뜰 수 있습니다)...")
    result = subprocess.run(
        ["winget", "install", "--id", "Insecure.Nmap", "-e", "--silent",
         "--accept-package-agreements", "--accept-source-agreements"],
        capture_output=True,
        text=True,
    )
    print("[Nmap] winget 종료 코드:", result.returncode)
    if result.stdout:
        print(result.stdout[-500:])
    if result.stderr:
        print(result.stderr[-500:])
    return result.returncode == 0


def _mark_checked():
    try:
        with open(NMAP_CHECKED_FLAG, "w", encoding="utf-8") as f:
            f.write("ok")
    except OSError:
        pass


def ensure_nmap(ask_confirm_func):
    if os.path.exists(NMAP_CHECKED_FLAG):
        return True

    if is_nmap_installed():
        print("[Nmap] 이미 설치되어 있습니다.")
        _mark_checked()
        return True

    answer = ask_confirm_func(
        "필수 구성 요소 설치",
        "동적 IP 재탐색 기능을 사용하려면 Nmap이 필요합니다.\n"
        "지금 설치할까요? (관리자 권한 승인 창이 뜰 수 있습니다)",
    )
    if not answer:
        print("[Nmap] 사용자가 설치를 거부했습니다. 동적 IP 재탐색 속도가 느려질 수 있습니다.")
        return False

    success = install_nmap()
    if success:
        _mark_checked()
    else:
        print("[Nmap] 자동 설치에 실패했습니다. 수동 설치가 필요할 수 있습니다.")
    return success
