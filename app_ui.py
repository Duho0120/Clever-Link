"""
2-1. 프로파일 목록 UI

- pywebview로 창을 하나 띄운다 (브라우저가 아니라 독립된 앱 창)
- 프로파일 목록을 보여주고, 각 항목마다 [마운트] [해제] 버튼
- 프로파일 추가 폼
- JS 쪽 버튼 클릭 → js_api를 통해 Python 함수(Api 클래스) 호출
- 지금까지 만든 profile_store.py, mount_control.py를 그대로 재사용한다
"""

import os
import shutil
import threading
import queue
import tkinter as tk
from tkinter import messagebox

import webview
from webview.window import FixPoint

import profile_store
import mount_control
import terminal_server
import winfsp_check
import webview2_check
import ssh_session
import mdns_ambiguity_state
import mac_mismatch_state
import mac_resolved_state
import sheet_diverged_state
import sheet_sync
import tray_icon
from resource_path import resource_path, app_dir

# ⚠ 배포 후 WebView2 캐시 문제 방지용 — 새 버전을 배포할 때마다 이 숫자를 1씩 올려야 한다.
# WebView2는 storage_path(아래 webview_data)를 고정 폴더로 재사용하는데(재시작마다 새로
# 초기화하면 창 뜨는 데 ~10초씩 걸려서 일부러 고정해둔 것 — 그래서 storage_path 자체를
# 매번 지우는 건 안 됨), 그 안의 HTTP 디스크 캐시가 index.html/CSS/JS를 파일 경로 기준으로
# 캐싱해서 내용만 덮어써 배포하면 예전 버전이 계속 캐시에서 나올 수 있다(실제로 개발 중
# 겪은 문제, 2026-08-05). 그래서 "이번에 실행 중인 코드의 버전"과 "마지막으로 실행했을 때
# 버전"을 비교해서, 다르면(=새 버전이 배포된 것) 그때만 캐시를 지운다 — 평소 재실행에는
# 영향 없고, 새 버전 배포 직후 첫 실행 한 번만 느려진다(~10초).
APP_BUILD_VERSION = "15"


# ── 종료 확인 팝업 전용 스레드 ──────────────────────────────
# pywebview의 'closing' 이벤트는 파이썬 메인 스레드가 아닌 내부 스레드에서
# 실행되는데, tkinter 창은 자신을 만든 스레드에서만 조작할 수 있다.
# 그래서 tkinter만 전담하는 스레드를 하나 따로 두고,
# 다른 스레드는 "질문 큐"에 질문을 넣고 "답변 큐"에서 답을 기다리는 방식으로 통신한다.
_question_queue = queue.Queue()
_answer_queue = queue.Queue()
_tk_ready = threading.Event()

# ⚠ 터미널 창 붙여넣기 전용: navigator.clipboard.readText()가 WebView2에서
# 권한 프롬프트 UI가 없어 조용히 막히는 경우가 있어서(Ctrl+V 눌러도 "^V"만 그대로
# 터미널에 찍힘), 대신 이미 떠 있는 tkinter 창의 clipboard_get()으로 우회한다.
# tkinter도 자신을 만든 스레드에서만 조작 가능해서 같은 질문/답변 큐 패턴을 재사용.
_clipboard_request_queue = queue.Queue()
_clipboard_result_queue = queue.Queue()


def _tk_worker():
    root = tk.Tk()
    root.withdraw()
    _tk_ready.set()

    def poll():
        try:
            title, message = _question_queue.get_nowait()
            answer = messagebox.askyesno(title, message, parent=root)
            _answer_queue.put(answer)
        except queue.Empty:
            pass

        try:
            _clipboard_request_queue.get_nowait()
            try:
                text = root.clipboard_get()
            except tk.TclError:
                text = ""  # 클립보드가 비어있거나 텍스트가 아닌 경우
            _clipboard_result_queue.put(text)
        except queue.Empty:
            pass

        root.after(100, poll)

    root.after(100, poll)
    root.mainloop()


def ask_confirm(title, message):
    """다른 스레드에서 안전하게 확인창을 띄우고 답을 받는 함수."""
    _question_queue.put((title, message))
    return _answer_queue.get()  # tkinter 스레드가 답할 때까지 대기


def get_clipboard_text():
    """다른 스레드에서 안전하게 클립보드의 텍스트를 읽어오는 함수."""
    _clipboard_request_queue.put(None)
    return _clipboard_result_queue.get()


class TerminalApi:
    """
    터미널 전용 창(terminal.html)에 연결되는 js_api.
    ⚠ 창을 열 때 url에 file:///...?profile=이름 처럼 쿼리스트링을 직접 붙이는 방식은
    WebView2가 파일을 못 찾는 것으로 처리해버려서(ERR_FILE_NOT_FOUND) 실패했음.
    대신 메인 창과 마찬가지로 순수 파일 경로만 url로 넘기고, 어떤 원격지에 연결할지는
    창마다 별도로 만든 이 js_api 인스턴스가 들고 있다가 JS가 요청하면 알려주는 방식으로 전달한다.
    """

    def __init__(self, profile_name):
        self.profile_name = profile_name

    def get_profile_name(self):
        return self.profile_name

    def get_clipboard_text(self):
        return get_clipboard_text()


class Api:
    """JS에서 window.pywebview.api.함수명() 으로 호출되는 다리 역할."""

    def __init__(self):
        # ⚠ 프레임리스 창 전용: 네이티브 타이틀바가 없어져서 최소화/최대화/닫기/
        # 드래그 이동을 전부 JS 쪽에서 이 Api를 통해 python webview.Window를
        # 직접 조작해야 한다. window는 create_window() 이후에 밖에서 채워준다.
        # ⚠ 반드시 밑줄로 시작하는 이름(_window)이어야 한다 — pywebview가 js_api의
        # JS 브릿지를 만들 때 dir()로 모든 속성을 재귀적으로 훑는데, 밑줄 없는 이름으로
        # 두면 webview.Window(및 그 안의 raw WinForms/WebView2 COM 객체 window.native)까지
        # 통째로 재귀 탐색하다가 .NET 쪽 순환 참조(AccessibilityObject 등)에 걸려
        # "maximum recursion depth exceeded"가 터미널에 쏟아지는 문제가 있었다.
        self._window = None
        self._maximized = False

    def get_window_position(self):
        return {"x": self._window.x, "y": self._window.y}

    def move_window(self, x, y):
        """타이틀바 드래그 중 JS가 계산한 목표 좌표로 창을 옮긴다."""
        self._window.move(int(x), int(y))
        return {"ok": True}

    def minimize_window(self):
        self._window.minimize()
        return {"ok": True}

    def toggle_maximize_window(self):
        """
        ⚠ pywebview에 '지금 최대화 상태인지' 조회하는 API가 없어서 여기서 직접 추적한다.
        Windows 스냅(Win+화살표)처럼 이 버튼을 거치지 않고 상태가 바뀌면 여기 추적값과
        실제 창 상태가 어긋날 수 있지만, 간단한 토글 버튼 용도로는 충분하다.
        """
        if self._maximized:
            self._window.restore()
            self._maximized = False
        else:
            self._window.maximize()
            self._maximized = True
        return {"ok": True, "maximized": self._maximized}

    def close_window(self):
        """⚠ F-7과 동일하게, 닫기 버튼도 완전 종료가 아니라 트레이로 숨기기만 한다."""
        self._window.hide()
        return {"ok": True}

    def get_window_size(self):
        return {"width": self._window.width, "height": self._window.height}

    def resize_window(self, width, height, fix_point):
        """
        ⚠ 프레임리스 창이라 OS 기본 크기조절 테두리가 없다 — index.html의 가장자리
        드래그 핸들이 계산한 목표 크기로 이 함수를 통해 직접 resize()를 호출한다.
        fix_point: JS에서 어느 가장자리를 끌었는지에 따라 계산한 비트값
        (NORTH=1, WEST=2, EAST=4, SOUTH=8 조합) — 반대쪽 가장자리를 고정한 채로 늘어나게 함.
        """
        try:
            self._window.resize(int(width), int(height), FixPoint(int(fix_point)))
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_profiles(self):
        """프로파일 이름 목록을 돌려준다 (민감 정보 없이)."""
        return profile_store.list_profile_names()

    def get_wards(self):
        """
        Phase 4: 지금까지 쓰인 Ward 이름 목록 (Ward 드롭박스 채우는 용도).
        ⚠ 등록된 원격지가 하나도 없는 Ward(예: 시트의 유일한 행이 Room/IP 누락으로
        전부 걸러진 "Atman AI")도, 시트에는 존재하고 "N개 연결 못 함" 경고를 보여줘야
        하므로 profile_store 쪽 목록과 합쳐서 돌려준다.
        """
        wards = set(profile_store.list_wards()) | set(sheet_sync.get_issue_wards())
        return sorted(wards)

    def get_profiles_in_ward(self, ward):
        """Phase 4: 특정 Ward에 속한 원격지(프로파일) 이름 목록만 반환."""
        return profile_store.list_profiles_in_ward(ward)

    def get_sheet_issue_count(self, ward):
        """
        Phase 4-4: 이 Ward에서, 시트에는 있지만 정보 부족(Room/IP 등 누락)으로
        원격지로 등록하지 못한 행이 몇 개인지 돌려준다 (가장 최근 동기화 기준).
        """
        return sheet_sync.get_issue_count(ward)

    def get_ghost_profiles(self, ward):
        """
        Phase 4-5: 이 Ward에서, 예전엔 시트에 있었지만 지금은 사라진 프로파일 목록
        (가장 최근 동기화 기준). 자동으로 삭제하지 않으므로, 화면에서 확인 후
        remove_profile로 직접 지울 수 있게 이름만 돌려준다.
        """
        return [g["name"] for g in sheet_sync.get_ghost_profiles(ward)]

    def sync_from_sheet(self):
        """
        Phase 4-4: 구글 시트를 지금 즉시 한 번 동기화한다 (수동 새로고침용).
        백그라운드 폴링과 별개로, 사용자가 바로 반영되길 원할 때 호출할 수 있다.
        """
        try:
            added, updated = sheet_sync.sync_from_sheet()
            return {"ok": True, "added": added, "updated": updated}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_current_drive(self, name):
        """이 프로파일이 지금 실제로 마운트된 드라이브 문자 (없으면 None)."""
        return mount_control.find_current_drive_for_profile(name)

    def get_current_volume(self, name):
        """이 프로파일이 지금 실제로 마운트된 서버 쪽 볼륨/경로 (없으면 None)."""
        return mount_control.find_current_volume_for_profile(name)

    def add_profile(self, name, host, username, port, auth_type, secret, ward=None):
        try:
            profile_store.save_profile(
                name=name,
                host=host,
                username=username,
                auth_type=auth_type,
                secret=secret,
                port=int(port) if port else 22,
                ward=ward,
                source="manual",
            )
        except Exception as e:
            return {"ok": False, "error": str(e)}

        # F-2: 저장 성공 즉시 자동 마운트. 드라이브 문자는 자동 배정.
        try:
            drive = mount_control.find_available_drive_letter() + ":"
            mount_control.mount_profile(name, drive)
            return {"ok": True, "drive": drive}
        except Exception as e:
            # 프로파일 저장 자체는 성공했으니 ok는 True, 다만 마운트 실패를 별도로 알려줌
            return {"ok": True, "drive": None, "mount_error": str(e)}

    def get_profile_for_edit(self, name):
        """
        "정보 수정" 모달을 열 때 기존 값을 미리 채워 넣기 위한 조회.
        (13번 엣지케이스 대응 — 재탐색으로 여러 IP 후보가 나왔을 때, 사용자가
        직접 확인한 올바른 IP로 여기서 바로 고칠 수 있게 하려는 목적)
        """
        try:
            return {"ok": True, **profile_store.get_profile_for_edit(name)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def update_profile(self, name, host, username, port, auth_type, secret, ward=None,
                        mac=None, hostname=None):
        """
        기존 원격지 정보를 수정한다 (이름은 그대로 유지, 나머지 필드만 덮어씀).
        ⚠ source(sheet/manual)는 원래 값을 그대로 보존한다 — sheet 프로파일을 여기서
        고쳐도, 다음 시트 동기화 때 자동으로 시트 값으로 다시 맞춰지는 기존 동작과
        자연스럽게 이어지도록 하기 위함 (수정은 "다음 새로고침 전까지의 임시 교정"으로
        동작해도 문제없다고 판단 — 사용자 확인 2026-08-05).

        mac/hostname: 동적 IP 재탐색용으로 접속 성공 시 자동 캡처되는 필드지만, 이젠
        모달에서 사용자가 직접 보고 고칠 수도 있다 — 예를 들어 host를 새 IP로 고쳤는데
        그 장비의 MAC을 이미 알고 있다면(라벨 등으로 확인) 굳이 재접속해서 다시 캡처될
        때까지 기다리지 않고 바로 넣어줄 수 있다. 그냥 전달받은 값 그대로 저장한다
        (빈 문자열/None이면 비움 — 다음 접속 성공 시 새로 캡처됨).
        """
        try:
            existing = profile_store.load_profiles().get(name, {})
            profile_store.save_profile(
                name=name,
                host=host,
                username=username,
                auth_type=auth_type,
                secret=secret,
                port=int(port) if port else 22,
                ward=ward,
                host_alt=existing.get("host_alt"),
                port_alt=existing.get("port_alt"),
                source=existing.get("source"),
            )
            # ⚠ save_profile()은 new_entry를 통째로 덮어써서 mac/hostname처럼 save_profile이
            # 모르는 필드를 지워버리므로, 폼에서 넘어온 값(사용자가 직접 고쳤거나, 모달을
            # 열었을 때 미리 채워져 있던 그대로일 수도 있음)으로 다시 채워넣는다.
            new_mac = (mac or "").strip() or None
            profile_store.update_profile_field(
                name,
                mac=new_mac,
                hostname=(hostname or "").strip() or None,
            )
            # ⚠ 재접속 없이 "수정" 저장만으로도 초록 확인 배너가 뜨게 하려면, 지금 막
            # 지우려는 불일치 정보가 "그 장비의 실제 MAC을 사용자가 그대로 받아들여서
            # 새 기준값으로 넣은 것"인지 판단해야 한다 — 불일치 기록에 남아있던
            # actual_mac(실제 연결됐던 장비의 MAC)과 사용자가 지금 입력한 값이 같으면,
            # "확인했고 이걸 맞다고 받아들인다"는 뜻이므로 해소 확인으로 처리한다.
            # (host를 아예 다른 값으로 바꾼 경우처럼 그냥 안 맞는 값을 넣은 거라면 굳이
            # 확인 표시를 안 하고 조용히 지우기만 함 — 다음 접속에서 다시 검증됨.)
            pending_mismatch = mac_mismatch_state.get_all().get(name)
            if pending_mismatch and new_mac and new_mac == pending_mismatch.get("actual_mac"):
                mac_resolved_state.mark(name, new_mac)
            mdns_ambiguity_state.clear(name)
            mac_mismatch_state.clear(name)

            # ⚠ 터미널은 버튼을 누를 때마다 새로 연결/해제되지만, 마운트는 한 번 붙으면
            # 앱을 완전히 껐다 켜지 않는 이상 다시 붙을 계기가 없었다 — 그래서 host를
            # 고쳐도 예전 연결(rclone 캐시)이 그대로 살아있는 것처럼 보이는 문제가 있었음
            # (2026-08-06, 사용자 확인). "수정" 저장을 재연결 계기로 삼아서, 지금 마운트
            # 되어 있으면 방금 고친 정보로 바로 다시 붙인다.
            remount = None
            current_drive = mount_control.find_current_drive_for_profile(name)
            if current_drive:
                current_volume = mount_control.find_current_volume_for_profile(name) or "/"
                try:
                    mount_control.unmount(current_drive)
                    mount_control.mount_profile(name, current_drive, current_volume)
                    remount = {"ok": True, "drive": current_drive}
                except Exception as e:
                    remount = {"ok": False, "error": str(e)}

            result = {"ok": True}
            if remount is not None:
                result["remount"] = remount
            return result
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def remove_profile(self, name):
        try:
            profile_store.delete_profile(name)
            mdns_ambiguity_state.clear(name)  # 삭제된 원격지의 경고 배너도 같이 정리
            mac_mismatch_state.clear(name)
            mac_resolved_state.clear(name)
            sheet_diverged_state.clear(name)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_mdns_ambiguous_profiles(self):
        """
        3번 기능(mDNS 후보 여러 개) 경고 배너용 — 지금 이 문제가 걸려있는 원격지
        목록을 [{name, hostname, candidates}] 형태로 돌려준다. 문제가 해소되면
        (재탐색 없이 정상 접속되거나, 재탐색이 후보 1개로 성공하면) 자동으로 빠진다.
        """
        return [
            {"name": name, **info}
            for name, info in mdns_ambiguity_state.get_all().items()
        ]

    def get_mac_mismatch_profiles(self):
        """
        13번 엣지케이스 2차 안전장치 — 저장된 기준 MAC과 실제 접속된 장비의 MAC이
        다른 원격지 목록을 [{name, stored_mac, actual_mac}] 형태로 돌려준다.
        mdns_ambiguous와 달리 자동으로는 안 사라짐 — "수정"으로 직접 반영해야 해소됨.
        """
        return [
            {"name": name, **info}
            for name, info in mac_mismatch_state.get_all().items()
        ]

    def get_mac_resolved_profiles(self):
        """
        MAC 불일치가 방금 해소된(불일치 -> 일치로 전환된) 원격지 목록을 초록 확인
        배너용으로 [{name, mac}] 형태로 돌려준다. X로 닫아야만 없어진다(자동 소멸 아님).
        """
        return [
            {"name": name, **info}
            for name, info in mac_resolved_state.get_all().items()
        ]

    def get_duplicate_ip_groups(self):
        """
        5번 기능 — profiles.json에 이미 같은 IP를 쓰는 원격지가 2개 이상 있으면
        [{host, names}] 형태로 돌려준다. Ward 상관없이 앱 전체 기준(같은 IP가 서로
        다른 Ward에 걸쳐 겹치는 경우도 실제로 있었음 — 13번 엣지케이스 발견 당시).
        """
        return profile_store.find_duplicate_host_groups()

    def get_sheet_diverged_profiles(self):
        """
        동적 IP 재탐색으로 로컬 profiles.json이 시트의 마지막 동기화 값과 달라진
        원격지 목록을 [{name, sheet_host, local_host}] 형태로 돌려준다. 다음 시트
        새로고침 때 이 로컬 교정이 되돌려질 수 있다는 걸 미리 알려주기 위함 — X로
        안 지워지는 가운데 정렬 안내문 형태로 표시(사용자 확인 2026-08-05).
        """
        return [
            {"name": name, **info}
            for name, info in sheet_diverged_state.get_all().items()
        ]

    def do_mount(self, name, remote_path="/"):
        """
        ⚠ Windows 드라이브 문자는 더 이상 사용자가 고르지 않는다 (F-2 피드백).
        이미 마운트되어 있으면 같은 드라이브 문자를 재사용해 그 자리에 새 볼륨으로 다시 올리고,
        처음 마운트하는 경우에만 새 드라이브 문자를 자동 배정한다.
        """
        try:
            existing = mount_control.find_current_drive_for_profile(name)
            if existing:
                drive_letter = existing
                mount_control.unmount(existing)
            else:
                drive_letter = mount_control.find_available_drive_letter() + ":"

            mount_control.mount_profile(name, drive_letter, remote_path)
            # 자동으로 탐색기를 열지 않음 — [탐색기] 버튼을 눌렀을 때만 열도록 변경
            return {"ok": True, "drive": drive_letter}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_remote_volumes(self, name):
        """
        이 원격지(서버)에 실제로 마운트되어 있는 저장소(볼륨) 목록을 SSH로 조회한다.
        (읽기 전용 'df -hP' 명령만 실행하므로 서버에 영향 없음)
        """
        try:
            volumes = ssh_session.get_remote_volumes(name)
            return {"ok": True, "volumes": volumes}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def open_explorer(self, drive_letter):
        """지정한 드라이브 위치로 Windows 탐색기를 연다."""
        try:
            os.startfile(drive_letter)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def open_terminal_window(self, name):
        """
        ⚠ F-5: 터미널을 메인 창 안의 패널이 아니라 완전히 별도의 pywebview 창으로 띄운다.
        메인 창(index.html)과 똑같이 순수 파일 경로만 url로 넘기고(쿼리스트링 없음),
        어떤 원격지에 연결할지는 이 창 전용 TerminalApi(js_api)를 통해 전달한다.
        """
        try:
            terminal_path = resource_path("terminal.html")
            webview.create_window(
                f"터미널 - {name}",
                url=terminal_path,
                js_api=TerminalApi(name),
                width=900,
                height=600,
            )
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}




if __name__ == "__main__":
    terminal_server.start_server_background()
    mount_control.cleanup_all()  # 시작 시: 이전 실행에서 남은 유령 마운트 정리

    # tkinter 전담 스레드 시작 (준비될 때까지 대기)
    threading.Thread(target=_tk_worker, daemon=True).start()
    _tk_ready.wait()

    # ⚠ ssh_session의 "처음 접속하는 서버" 확인창이 콘솔 input() 대신
    # 이 GUI 팝업(ask_confirm)을 쓰도록 등록. 안 하면 콘솔을 숨겼을 때(--windowed)
    # 화면에 안 보이는 채로 영원히 멈추는 문제가 있었음.
    ssh_session.set_confirm_callback(ask_confirm)

    # ⚠ WebView2 Runtime 확인은 반드시 webview.create_window()보다 먼저 실행해야 한다.
    # 없으면 pywebview 창 자체를 못 띄우므로(빈 화면/크래시), 확인창은 위에서 이미
    # 준비된 tkinter 기반 ask_confirm으로 띄운다.
    webview2_check.ensure_webview2(ask_confirm)

    # WinFsp 설치 확인 (없으면 사용자 동의 후 winget으로 자동 설치)
    winfsp_check.ensure_winfsp(ask_confirm)

    INDEX_PATH = resource_path("index.html")

    api = Api()
    window = webview.create_window(
        "Clever Link",
        url=INDEX_PATH,   # html="..." 대신 실제 파일을 열도록 변경 (CORB 문제 해결)
        js_api=api,
        width=1000,  # ⚠ min_size(960)보다 작으면 안 됨 — 아래 min_size 주석 참고
        height=600,
        min_size=(960, 480),  # ⚠ 원래 760은 헤더 기준으로만 정했던 값이라, 원격지 줄
                              # (아이콘+이름+상태+볼륨 드롭다운+버튼 4개)이 한 줄에 다
                              # 안 들어가서 줄바꿈되는 문제가 있었음(2026-08-06) — 그
                              # 줄 전체가 한 줄로 들어가는 폭 기준으로 올림. index.html의
                              # MIN_WIN_W와 반드시 같은 값이어야 함(리사이즈 드래그 클램프).
        frameless=True,   # ⚠ 남색 헤더가 타이틀바 역할까지 하도록, OS 기본 타이틀바 제거
        easy_drag=False,  # Windows(WinForms) 백엔드는 easy_drag 미구현 — index.html의 JS 드래그로 대체
        text_select=True,  # ⚠ pywebview 기본값은 False라 텍스트 드래그 선택/복사가 아예 안 됨
                            # (CSS 문제가 아니었음) — 경고 배너의 IP 목록 등을 복사할 수 있어야 해서 켬.
    )
    # Api 메서드(minimize_window 등)가 조작할 실제 Window 객체를 사후 연결
    api._window = window

    def on_closing():
        """
        ⚠ F-7: 창의 X 버튼 = '완전히 종료'가 아니라 '창 숨기기'.
        RaiDrive처럼 창을 닫아도 마운트/터미널은 백그라운드에서 계속 살아있어야
        한다는 피드백에 따라 변경. 실제 종료는 트레이 아이콘의 [완전히 종료]에서만.
        """
        window.hide()
        print("[창 숨김] 트레이 아이콘에서 계속 사용하거나 완전히 종료할 수 있습니다.")
        return False  # False를 반환해 실제 창 파괴(종료)를 막는다

    def full_quit():
        """트레이 아이콘의 [완전히 종료]를 선택했을 때만 실행되는 진짜 종료 절차."""
        count = 0
        try:
            if mount_control.is_rcd_running():
                result = mount_control._rc_call("mount/listmounts")
                count = len(result.get("mountPoints", []))
        except Exception as e:
            print(f"[종료 확인 중 오류] {e}")
            count = 0

        if count > 0:
            answer = ask_confirm(
                "종료 확인",
                f"현재 {count}개의 드라이브가 마운트되어 있습니다.\n"
                f"종료하면 모두 자동으로 해제됩니다. 계속 종료할까요?",
            )
            if not answer:
                return  # 취소 -> 트레이 아이콘도 그대로, 종료 안 함

        print("[종료 처리] 남은 마운트/서버 정리 중...")
        mount_control.cleanup_all()
        mount_control.stop_rcd()  # ⚠ 안 하면 rclone.exe가 백그라운드에 남아 exe/폴더를 계속 잠금

        # ⚠ window.destroy()만으로는 파이썬 프로세스(및 콘솔 창)가 안 끝나는 문제가 있었음.
        # 트레이 아이콘 스레드, WebSocket 서버 스레드 등이 데몬이라도 확실히 죽도록
        # 프로세스 자체를 강제 종료한다.
        os._exit(0)

    window.events.closing += on_closing

    # 트레이 아이콘 시작 (창을 숨겨도 이 아이콘으로 계속 제어 가능)
    tray_icon.start_tray(window, full_quit)

    # ⚠ WebView2 설정 폴더를 exe 위치의 고정 폴더로 지정.
    # 지정 안 하면 --onefile 실행 시 매번 새 임시 폴더를 써서 매번 새로 초기화하느라
    # 창이 뜨는 데 10초 가까이 걸리는 문제가 있었음.
    storage_path = os.path.join(app_dir(), "webview_data")

    # ⚠ 배포 버전이 바뀌었으면(APP_BUILD_VERSION 참고) 그때만 캐시 폴더를 지운다.
    # 버전 표시 파일(webview_data 밖에 따로 둠 — 안에 두면 폴더를 지울 때 같이 지워짐)이
    # 없거나 다르면 "새 버전이 배포된 것"으로 보고 기존 캐시를 지운 뒤 새로 기록한다.
    version_marker_path = os.path.join(app_dir(), "webview_data_version.txt")
    last_version = None
    if os.path.exists(version_marker_path):
        try:
            with open(version_marker_path, "r", encoding="utf-8") as f:
                last_version = f.read().strip()
        except OSError:
            last_version = None

    if last_version != APP_BUILD_VERSION:
        if os.path.exists(storage_path):
            try:
                shutil.rmtree(storage_path)
                print(f"[WebView2 캐시 초기화] 버전이 바뀌어({last_version} -> {APP_BUILD_VERSION}) 캐시를 지웠습니다.")
            except OSError as e:
                # ⚠ 지우다 실패해도(파일 잠김 등) 치명적인 오류는 아님 — 이번엔 예전 캐시가
                # 남아있을 수 있지만, 앱 실행 자체를 막을 이유는 없음.
                print(f"[WebView2 캐시 초기화 실패] {e} — 예전 캐시가 남아있을 수 있습니다.")
        try:
            with open(version_marker_path, "w", encoding="utf-8") as f:
                f.write(APP_BUILD_VERSION)
        except OSError:
            pass

    webview.start(storage_path=storage_path, private_mode=False)