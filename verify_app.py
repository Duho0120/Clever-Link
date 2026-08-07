"""
프로그램이 정상 작동하는지 확인하는 검증 스크립트.

- 화면(pywebview) 없이, 앱이 쓰는 모듈들을 직접 호출해서 확인한다.
- 기본적으로 WSL 테스트 서버(WSL테스트_비번)를 대상으로 한다.
  사내 서버로 확인하고 싶으면 PROFILE 값을 바꿔서 실행할 것.

실행: python verify_app.py
"""

import os
import time

import mount_control
import ssh_session

PROFILE = "WSL테스트_비번"  # profiles.json에 등록된 이름으로 바꿔서 사용


def report(label, ok):
    print(f"[{'PASS' if ok else 'FAIL'}] {label}")


def check_mount():
    print("\n=== 1) 마운트 확인 ===")
    mount_control.cleanup_all()
    time.sleep(1)

    result = mount_control.find_available_drive_letter() + ":"
    mount_control.mount_profile(PROFILE, result, "/")
    time.sleep(1)

    report(f"{result} 실제 접근 가능", os.path.exists(result + "\\"))
    report("is_mounted()로 확인됨", mount_control.is_mounted(result))

    current = mount_control.find_current_drive_for_profile(PROFILE)
    report("find_current_drive_for_profile 정확함", current == result)

    return result


def check_volume_switch(drive):
    print("\n=== 2) 볼륨 전환 확인 (같은 드라이브 문자 재사용되는지) ===")
    mount_control.mount_profile(PROFILE, drive, ".ssh")
    time.sleep(1)

    report(f"{drive} 여전히 접근 가능 (전환 후)", os.path.exists(drive + "\\"))
    volume = mount_control.find_current_volume_for_profile(PROFILE)
    report("현재 볼륨이 '.ssh'로 정확히 조회됨", volume == ".ssh")


def check_unmount(drive):
    print("\n=== 3) 해제 확인 ===")
    mount_control.unmount(drive)
    time.sleep(1)
    report(f"{drive} 해제 후 접근 불가", not os.path.exists(drive + "\\"))
    report("해제 후 find_current_drive_for_profile은 None", mount_control.find_current_drive_for_profile(PROFILE) is None)


def check_terminal():
    print("\n=== 4) 터미널(SSH) 연결 확인 ===")

    def auto_confirm(title, message):
        print(f"  (호스트 지문 확인창 자동 승인: {title})")
        return True

    ssh_session.set_confirm_callback(auto_confirm)

    client = ssh_session.connect_profile(PROFILE)
    report("SSH 접속 성공", client is not None)

    whoami = ssh_session.run_command(client, "whoami").strip()
    print(f"  whoami 결과: {whoami}")
    report("exec_command 정상 동작", len(whoami) > 0)

    channel = ssh_session.open_terminal_channel(client)
    time.sleep(1)
    banner = channel.recv(4096).decode(errors="replace")
    report("대화형 셸(invoke_shell) 배너 수신됨", len(banner) > 0)

    channel.send("echo terminal_ok\n")
    time.sleep(1)
    output = channel.recv(4096).decode(errors="replace")
    report("대화형 셸 명령 실행 및 응답 수신", "terminal_ok" in output)

    channel.close()
    client.close()


if __name__ == "__main__":
    print(f"=== '{PROFILE}' 기준 앱 동작 검증 시작 ===")

    drive = check_mount()
    check_volume_switch(drive)
    check_unmount(drive)
    check_terminal()

    print("\n=== 검증 끝 ===")
