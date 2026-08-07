"""
Phase 4-1. Ward/Room 계층 구조 로컬 테스트 환경 준비 스크립트

- 아래 WARD_ROOM_HOST_DATA에 (Ward, Room, Host name) 목록을 채워 넣고 실행하면:
  1. Host name 개수만큼 WSL(Ubuntu)에 로컬 계정을 만들고
  2. Ward/Room/Host 매핑을 담은 테스트용 JSON 파일(ward_test_mapping.json)을 생성한다.
- IP/포트를 여러 개 안 만들고, 같은 WSL 서버 안에 "계정"만 여러 개 만드는 방식이다.
  계정마다 whoami 결과가 다르게 나오므로, 나중에 "Room을 바꾸면 실제로 다른 대상에
  연결되는지"를 구분해서 검증할 수 있다.
- 실행 전 WSL Ubuntu가 켜져 있어야 한다(0-1에서 이미 구축됨). sudo 비밀번호는
  WSL_SUDO_PASSWORD 상수로 자동 전달되므로 별도 입력은 필요 없다.

실행: python setup_ward_test_env.py
"""

import json
import os
import subprocess
import tempfile

# ⚠ 여기에 실제(또는 대표 샘플) Ward/Room/Host name 데이터를 채운다.
# (ward, room, host_name) 튜플 목록. 사용자가 제공하는 표 그대로 옮기면 된다.
WARD_ROOM_HOST_DATA = [
    ("S서울", "3021", "A0"),
    ("S서울", "3022", "A1"),
    ("S서울", "3161", "B0"),
    ("포항세명기독병원(62)", "21", "A0"),
    ("포항세명기독병원(62)", "22", "B0"),
    ("포항세명기독병원(66)", "6601", "C0"),
    ("포항세명기독병원(66)", "6602", "D0"),
    ("포항세명기독병원(66)", "61", "D1"),
]

WSL_DISTRO = "Ubuntu"
WSL_SUDO_PASSWORD = "482659"  # 0-1에서 만든 sky_1214 계정의 (sudo) 비밀번호 — WSL 테스트 전용
TEST_PASSWORD = "wardtest1234"  # 새로 만드는 각 Room 계정의 로그인 비밀번호, 전부 동일하게 사용
MAPPING_OUTPUT_FILE = "ward_test_mapping.json"


def _windows_path_to_wsl(win_path):
    """C:\\foo\\bar -> /mnt/c/foo/bar"""
    drive, rest = win_path[0].lower(), win_path[2:].replace("\\", "/")
    return f"/mnt/{drive}{rest}"


def run_wsl_script(bash_script_content, use_sudo=False, timeout=15):
    """
    bash 스크립트 "내용"을 임시 파일로 저장한 뒤 WSL에서 그 파일을 실행한다.

    ⚠ 중요: wsl.exe에 -c 인자로 '$'가 포함된 명령 문자열을 직접 넘기면, 이 환경에서는
    $6, $abc 같은 부분이 (마치 정의 안 된 변수처럼) 통째로 사라져버리는 문제를 직접
    재현해서 확인했다. Python subprocess.run으로 셸을 안 거치고 직접 호출해도 똑같이
    발생해서, 원인은 Bash 도구나 my own shell이 아니라 wsl.exe 자체(또는 그 인자 전달
    경로) 어딘가로 추정된다. 반면 명령을 파일에 적어두고 그 파일을 실행하는 방식은
    이 문제가 없다(bash가 파일 '내용'을 읽어서 해석하는 거라, 인자 전달 경로를 안 거침).
    그래서 비밀번호 해시처럼 '$'가 들어가는 내용은 절대 -c 인자로 직접 넘기지 않고,
    항상 이 함수를 통해 파일로 만들어서 실행한다.
    """
    fd, win_path = tempfile.mkstemp(suffix=".sh")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(bash_script_content)

        wsl_path = _windows_path_to_wsl(win_path)
        # ⚠ wsl_path를 wsl.exe에 '독립된 인자'로 바로 넘기면(예: bash "/mnt/c/...")
        # Git Bash가 이걸 자기 자신의 경로로 오인해서 앞에 자기 설치 경로를 붙여버리는
        # 문제가 있었다(예: "C:/Program Files/Git/mnt/c/..."). -c "... 'path' ..."처럼
        # 하나의 문자열 안에 인용부호로 감싸 넣으면 이 문제가 없다.
        runner = f"bash '{wsl_path}'"
        if use_sudo:
            outer = f"echo '{WSL_SUDO_PASSWORD}' | sudo -S {runner}"
        else:
            outer = runner

        try:
            return subprocess.run(
                ["wsl", "-d", WSL_DISTRO, "--", "bash", "-c", outer],
                capture_output=True, encoding="utf-8", errors="replace", timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"[시간 초과] 스크립트가 {timeout}초 안에 끝나지 않았습니다.")
            return None
    finally:
        os.remove(win_path)


def run_wsl_simple(bash_command, timeout=15):
    """'$'가 없는 단순한 명령(예: id -u name)은 굳이 파일로 안 만들고 바로 실행한다."""
    try:
        return subprocess.run(
            ["wsl", "-d", WSL_DISTRO, "--", "bash", "-c", bash_command],
            capture_output=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[시간 초과] 명령이 {timeout}초 안에 끝나지 않았습니다: {bash_command}")
        return None


def ensure_wsl_account(host_name):
    """
    host_name과 같은 이름의 WSL 로컬 계정이 없으면 만든다.
    이미 있으면 건드리지 않고 그대로 둔다 (재실행해도 안전).
    """
    check = run_wsl_simple(f"id -u {host_name}")
    if check is not None and check.returncode == 0:
        print(f"[건너뜀] '{host_name}' 계정이 이미 있습니다.")
        return

    print(f"[생성 중] '{host_name}' 계정...")
    # ⚠ chpasswd는 이 WSL의 PAM 설정에서 "Authentication token manipulation error"로 매번
    # 실패했음 -> usermod -p로 해시를 직접 박아넣는 방식으로 우회.
    # useradd와 usermod를 한 스크립트 안에서 처리해야, sudo가 둘 다에 적용된다
    # (따로 실행하면 && 뒤의 두 번째 명령이 sudo 권한을 못 받는 문제가 있었음).
    script = (
        "set -e\n"
        f"useradd -m {host_name}\n"
        f'HASH=$(openssl passwd -6 "{TEST_PASSWORD}")\n'
        f'usermod -p "$HASH" {host_name}\n'
    )
    result = run_wsl_script(script, use_sudo=True)
    if result is None:
        print(f"[실패] '{host_name}' 계정 생성 시간 초과")
    elif result.returncode != 0:
        print(f"[실패] '{host_name}' 계정 생성 실패:\n{result.stderr}")
    else:
        print(f"[완료] '{host_name}' 계정 생성됨 (비밀번호: {TEST_PASSWORD})")


def build_mapping():
    """Ward -> [ {room, host_name} ... ] 형태의 매핑을 만든다."""
    mapping = {}
    for ward, room, host_name in WARD_ROOM_HOST_DATA:
        mapping.setdefault(ward, []).append({"room": room, "host_name": host_name})
    return mapping


if __name__ == "__main__":
    if not WARD_ROOM_HOST_DATA:
        print("WARD_ROOM_HOST_DATA가 비어있습니다. 스크립트 상단에 (Ward, Room, Host name) 데이터를 채운 뒤 다시 실행하세요.")
        raise SystemExit(1)

    print(f"=== Ward 테스트 환경 준비 ({len(WARD_ROOM_HOST_DATA)}개 항목) ===\n")

    unique_hosts = sorted({host_name for _, _, host_name in WARD_ROOM_HOST_DATA})
    print(f"고유 Host name {len(unique_hosts)}개: {unique_hosts}\n")

    for host_name in unique_hosts:
        ensure_wsl_account(host_name)

    mapping = build_mapping()
    with open(MAPPING_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(mapping, f, ensure_ascii=False, indent=2)

    print(f"\n[완료] 매핑 파일 저장됨: {MAPPING_OUTPUT_FILE}")
    print("모든 계정은 host=127.0.0.1, port=22, 비밀번호는 위 TEST_PASSWORD 값을 씁니다.")
