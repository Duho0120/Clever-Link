"""
Microsoft Edge WebView2 Runtime 설치 확인 및 자동 설치

- pywebview가 Windows에서 화면을 그릴 때 내부적으로 WebView2(Edge 엔진)를 사용한다.
- Windows 11은 기본 내장이지만, 업데이트가 제한된 Windows 10 PC엔 없을 수 있다.
- 없으면 pywebview 창 자체가 못 뜨므로(빈 화면 또는 크래시), 반드시
  webview.create_window()를 호출하기 '전'에 이 모듈로 먼저 확인해야 한다.
  ⚠ 확인/안내창은 pywebview가 아니라 tkinter(ask_confirm_func)로 띄운다.
  WebView2가 진짜 없는 상황에서는 pywebview 자체가 아직 쓸 수 없는 상태이기 때문.
"""

import os
import subprocess
import winreg

# 모든 WebView2 Runtime 채널이 공유하는 고정 GUID (마이크로소프트 공식 문서 기준)
_CLIENT_GUID = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

WEBVIEW2_CHECKED_FLAG = "webview2_checked.flag"


def _pv_from_key(hive, subkey):
    try:
        with winreg.OpenKey(hive, subkey) as key:
            value, _ = winreg.QueryValueEx(key, "pv")
            return value
    except OSError:
        return None


def is_webview2_installed():
    """
    레지스트리에서 WebView2 Runtime의 설치 버전(pv) 값을 확인한다.
    시스템 전체 설치(HKLM, 32/64비트 양쪽)와 사용자별 설치(HKCU) 전부 확인한다.
    """
    candidates = [
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{_CLIENT_GUID}"),
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{_CLIENT_GUID}"),
        (winreg.HKEY_CURRENT_USER, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{_CLIENT_GUID}"),
    ]
    for hive, subkey in candidates:
        pv = _pv_from_key(hive, subkey)
        if pv and pv != "0.0.0.0":
            return True
    return False


def install_webview2():
    """winget으로 설치한다 (WinFsp와 동일한, 이미 검증된 방식 재사용)."""
    print("[WebView2] winget으로 설치를 시작합니다 (인터넷 연결 필요)...")
    result = subprocess.run(
        ["winget", "install", "--id", "Microsoft.EdgeWebView2Runtime", "-e", "--silent",
         "--accept-package-agreements", "--accept-source-agreements"],
        capture_output=True,
        text=True,
    )
    print("[WebView2] winget 종료 코드:", result.returncode)
    if result.stdout:
        print(result.stdout[-500:])
    if result.stderr:
        print(result.stderr[-500:])
    return result.returncode == 0


def ensure_webview2(ask_confirm_func):
    """
    ⚠ 반드시 webview.create_window()보다 먼저 호출해야 한다.
    WinFsp 체크와 마찬가지로, 한 번 확인되면 표시를 남겨 다음 실행부터는 건너뛴다.
    """
    if os.path.exists(WEBVIEW2_CHECKED_FLAG):
        return True

    if is_webview2_installed():
        print("[WebView2] 이미 설치되어 있습니다.")
        _mark_checked()
        return True

    answer = ask_confirm_func(
        "필수 구성 요소 설치",
        "화면 표시에 필요한 Microsoft Edge WebView2 Runtime이 설치되어 있지 않습니다.\n"
        "지금 설치할까요? (인터넷 연결 필요, 설치 후 프로그램 재실행이 필요할 수 있습니다)",
    )
    if not answer:
        print("[WebView2] 사용자가 설치를 거부했습니다. 프로그램이 정상적으로 뜨지 않을 수 있습니다.")
        return False

    success = install_webview2()
    if success:
        _mark_checked()
    else:
        print(
            "[WebView2] 자동 설치에 실패했습니다. 수동 설치가 필요합니다: "
            "https://developer.microsoft.com/microsoft-edge/webview2/"
        )
    return success


def _mark_checked():
    try:
        with open(WEBVIEW2_CHECKED_FLAG, "w", encoding="utf-8") as f:
            f.write("ok")
    except OSError:
        pass
