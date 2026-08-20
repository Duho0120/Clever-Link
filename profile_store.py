"""
1-1. 프로파일 저장소
- 민감하지 않은 정보(이름, 주소, 계정, 인증방식)는 profiles.json에
- 민감한 정보(비밀번호 또는 개인키 경로)는 keyring(Windows 자격 증명 관리자)에
- SFTP 마운트와 SSH 터미널이 이 저장소를 공용으로 사용한다
"""

import json
import os
import keyring

PROFILE_FILE = "profiles.json"
KEYRING_SERVICE = "sftp_ssh_launcher"  # keyring에서 우리 앱을 식별하는 이름
MAX_RECENT_IPS = 3  # 5번 개선사항 — 프로파일별로 기억해둘 최근 성공 IP 개수


def load_profiles():
    """저장된 모든 프로파일을 딕셔너리로 반환. 파일이 없으면 빈 딕셔너리."""
    if not os.path.exists(PROFILE_FILE):
        return {}
    with open(PROFILE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_profile(name, host, username, auth_type, secret, port=22, ward=None,
                  host_alt=None, port_alt=None, source=None):
    """
    프로파일 하나를 저장한다.

    name       : 프로파일 이름 (예: "WSL테스트", "사내GPU서버". Phase 4에서는 Room 번호가 이 이름이 됨)
    host       : 서버 주소 (예: "127.0.0.1")
    username   : 접속 계정
    auth_type  : "password" 또는 "key_file"
    secret     : auth_type이 password면 비밀번호, key_file이면 키 파일 경로
    port       : SSH 포트 (기본 22)
    ward       : Phase 4 — 이 원격지가 속한 Ward(병동) 이름. 없으면 None(어느 Ward에도 안 속함)
    host_alt/port_alt : Phase 4 확장 — 사내망 안(로컬 IP)/밖(터널 주소)을 모두 지원하기 위한
                         보조 접속 주소. host가 안 닿을 때 자동으로 이쪽을 시도한다. 없으면 None.
    source     : 이 프로파일이 어디서 왔는지 ("sheet" = 구글 시트 동기화로 생성됨,
                 "manual" = 사용자가 앱에서 직접 추가함). 시트에서 사라진 행을 감지해
                 "유령 프로파일" 목록을 만들 때, 사용자가 직접 추가한 프로파일까지
                 실수로 유령 취급하지 않기 위해 구분해둔다.

    반환값: 실제로 저장했으면 True, 기존과 완전히 같아서 건너뛰었으면 False.
    ⚠ Phase 4-4: 시트 동기화가 시작 시 1번 + 이후 60초마다 이미 등록된 프로파일까지
    포함해 매번 이 함수를 호출한다. 예전엔 내용이 하나도 안 바뀌어도 매번 파일을
    다시 쓰고 keyring에도 다시 저장해서, 실행할 때마다/60초마다 안 바뀐 프로파일까지
    전부 다시 저장하는 것처럼 보였다 (사용자 확인 2026-07-21). 바뀐 게 없으면
    아무 것도 쓰지 않도록 비교 후 건너뛴다.
    """
    if auth_type not in ("password", "key_file"):
        raise ValueError("auth_type은 'password' 또는 'key_file'이어야 합니다")

    profiles = load_profiles()
    new_entry = {
        "host": host,
        "username": username,
        "auth_type": auth_type,
        "port": port,
        "ward": ward or None,  # 빈 문자열이 들어와도 "어느 Ward에도 안 속함"으로 통일
        "host_alt": host_alt or None,
        "port_alt": port_alt or None,
        "source": source or None,
    }

    existing_entry = profiles.get(name)
    if existing_entry == new_entry:
        existing_secret = keyring.get_password(KEYRING_SERVICE, name)
        if existing_secret == secret:
            return False  # 완전히 동일 -> 다시 쓸 필요 없음

    profiles[name] = new_entry
    with open(PROFILE_FILE, "w", encoding="utf-8") as f:
        json.dump(profiles, f, ensure_ascii=False, indent=2)

    # 민감 정보는 파일이 아니라 keyring에만 저장
    keyring.set_password(KEYRING_SERVICE, name, secret)

    print(f"[저장 완료] 프로파일 '{name}'")
    return True


def get_profile(name):
    """
    프로파일 하나를 조회해서, paramiko.connect()에 바로 넣을 수 있는
    딕셔너리 형태로 돌려준다.
    """
    profiles = load_profiles()
    if name not in profiles:
        raise KeyError(f"프로파일 '{name}'을(를) 찾을 수 없습니다")

    p = profiles[name]
    secret = keyring.get_password(KEYRING_SERVICE, name)

    if secret is None:
        raise ValueError(
            f"'{name}'의 비밀 정보가 keyring에 없습니다. "
            "save_profile로 다시 저장해주세요."
        )

    result = {
        "host": p["host"],
        "username": p["username"],
        "port": p["port"],
        "auth_type": p["auth_type"],
        "host_alt": p.get("host_alt"),
        "port_alt": p.get("port_alt"),
        "source": p.get("source"),
        "mac": p.get("mac"),  # 동적 IP 재탐색용 — 접속 성공 시 자동으로 채워짐 (없으면 None)
        "hostname": p.get("hostname"),  # mDNS 재탐색용(MAC 실패 시 2차 보험) — SSH 터미널 접속 성공 시 채워짐
        "recent_ips": p.get("recent_ips", []),  # 5번 개선사항 — 최근 성공 IP 목록(최근순), 재탐색 시 우선 확인용
    }

    if p["auth_type"] == "password":
        result["password"] = secret
    else:  # key_file
        result["key_filename"] = secret

    return result


def get_profile_for_edit(name):
    """
    "정보 수정" 모달에 미리 채워 넣을 용도 — save_profile()에 그대로 다시 넘길 수 있는
    형태로, 편집 가능한 필드(비밀번호/키 경로 포함)를 전부 돌려준다.
    get_profile()과 달리 paramiko용으로 가공하지 않고 raw 필드(ward 등) 그대로 준다.
    """
    profiles = load_profiles()
    if name not in profiles:
        raise KeyError(f"프로파일 '{name}'을(를) 찾을 수 없습니다")

    p = profiles[name]
    secret = keyring.get_password(KEYRING_SERVICE, name)

    return {
        "host": p["host"],
        "username": p["username"],
        "auth_type": p["auth_type"],
        "port": p["port"],
        "ward": p.get("ward"),
        "secret": secret or "",
        "mac": p.get("mac"),
        "hostname": p.get("hostname"),
    }


def update_profile_field(name, **fields):
    """
    프로파일의 특정 필드 일부만 갱신한다 (예: host, mac).
    ⚠ save_profile()과 달리 keyring 비밀정보나 변경 여부 비교 없이 그냥 덮어쓴다 —
    동적 IP 재탐색처럼 앱이 내부적으로 자동 갱신할 때 쓰는 가벼운 전용 함수라,
    시트 동기화(save_profile)의 "내용 같으면 다시 안 씀" 로직에 영향을 주지 않기 위해
    분리했다. 프로파일이 없으면 조용히 무시한다.
    """
    profiles = load_profiles()
    if name not in profiles:
        return
    profiles[name].update(fields)
    with open(PROFILE_FILE, "w", encoding="utf-8") as f:
        json.dump(profiles, f, ensure_ascii=False, indent=2)


def remember_recent_ip(name, ip):
    """
    5번 개선사항 — 접속/마운트가 실제로 성공한 IP를 프로파일별로 최근 것부터 최대
    MAX_RECENT_IPS개까지 기억해둔다. 다음에 재탐색이 필요할 때 mac_discovery.
    find_ip_for_mac()이 전체 서브넷 스캔 전에 이 IP들부터 먼저 짧게 찔러봐서, DHCP가
    같은 대역 안에서만 재할당하는 흔한 경우엔 전체 스캔(최대 1024개 host)을 건너뛸 수
    있게 한다. 이미 목록에 있던 IP면 맨 앞으로 옮기기만 한다(중복 저장 안 함).
    """
    profiles = load_profiles()
    if name not in profiles:
        return
    recent = profiles[name].get("recent_ips", [])
    recent = [ip] + [x for x in recent if x != ip]
    profiles[name]["recent_ips"] = recent[:MAX_RECENT_IPS]
    with open(PROFILE_FILE, "w", encoding="utf-8") as f:
        json.dump(profiles, f, ensure_ascii=False, indent=2)


def find_duplicate_host_groups():
    """
    13번 엣지케이스의 근본 원인인 "같은 IP를 쓰는 서로 다른 원격지"를 찾는다.
    ⚠ 계정명/비밀번호가 우연히 같은 장비들 사이에서, 저장된(오래된) IP가 다른
    원격지가 지금 쓰는 IP와 겹치면 엉뚱한 장비에 조용히 연결될 위험이 있다는 게
    이 세션에서 실제로 확인된 위험 — 그 원인을 사전에(접속 시도 전에) 눈에 보이게
    알려주기 위한 용도.
    ⚠ host만으로 묶으면 안 된다 — us.loclx.io처럼 터널 중계 주소 하나를 여러 원격지가
    포트만 다르게 나눠 쓰는 건 정상적인 구성이라(실제 데이터에서 9개 원격지가 그렇게
    되어 있는 걸 확인함), 그런 경우까지 "중복"으로 잘못 잡아내면 안 된다. host+port
    조합이 같을 때만 진짜 충돌로 본다.
    ⚠ Ward(=보통 물리적으로 다른 병동/시설)까지 다르면 실제로 같은 LAN에 동시에 있을
    일이 거의 없어서(사설 IP는 그 LAN에 물리적으로 붙어있을 때만 의미가 있음) 위험이
    크게 낮아진다는 게 실사용 확인됨 (2026-08-06). 그래서 host+port가 같아도 Ward까지
    같은 경우만 경고 대상으로 좁힌다 — 서로 다른 Ward끼리 우연히 사설 IP가 겹치는 건
    흔한 일이라 그것까지 매번 경고하면 오히려 진짜 위험한 경우(같은 Ward 안에서 겹침)가
    묻혀버릴 수 있음.
    ⚠ username까지 같아야 진짜 위험이다 — SSH는 `username@host`로 접속하므로, host가
    겹쳐도 username이 다르면 그 계정이 상대 장비에 없어서 인증 단계에서 걸러진다(엉뚱한
    장비에 "성공"으로 붙는 일 자체가 안 생김). 그래서 host+port+ward가 같아도 username까지
    같은 경우만 진짜 충돌로 본다 (2026-08-06, 사용자 확인).
    반환값: [{"host": "192.168.1.1", "port": 22, "ward": "S서울", "username": "beclever",
    "names": ["A", "B"]}, ...] (2개 이상 겹치는 것만)
    """
    profiles = load_profiles()
    by_key = {}
    for name, p in profiles.items():
        host = p.get("host")
        if not host:
            continue
        key = (host, p.get("port"), p.get("ward"), p.get("username"))
        by_key.setdefault(key, []).append(name)
    return [
        {"host": host, "port": port, "ward": ward, "username": username, "names": sorted(names)}
        for (host, port, ward, username), names in sorted(
            by_key.items(), key=lambda kv: (kv[0][0], kv[0][1] or 0, kv[0][2] or "", kv[0][3] or "")
        )
        if len(names) >= 2
    ]


def find_profile_by_mac(mac, exclude_name=None):
    """
    이 MAC 주소를 "기준 MAC"으로 이미 갖고 있는 다른 원격지 이름을 찾는다(있으면).
    MAC 불일치 경고를 띄울 때, "예상과 다르다"에서 그치지 않고 "사실 이건 이미 등록된
    다른 원격지 X의 장비다"까지 알려주기 위한 용도 — 훨씬 더 실질적인 단서가 된다
    (예: IP가 겹쳐서 엉뚱한 곳에 연결된 경우, 그게 정확히 어느 원격지인지 바로 알 수 있음).
    없으면 None. exclude_name은 지금 확인 중인 프로파일 자기 자신을 제외하기 위함.
    """
    if not mac:
        return None
    profiles = load_profiles()
    for name, p in profiles.items():
        if name == exclude_name:
            continue
        if p.get("mac") == mac:
            return name
    return None


def delete_profile(name):
    """프로파일과 그에 딸린 keyring 비밀 정보를 함께 삭제한다."""
    profiles = load_profiles()
    if name in profiles:
        del profiles[name]
        with open(PROFILE_FILE, "w", encoding="utf-8") as f:
            json.dump(profiles, f, ensure_ascii=False, indent=2)

    try:
        keyring.delete_password(KEYRING_SERVICE, name)
    except keyring.errors.PasswordDeleteError:
        pass  # 이미 없으면 무시

    print(f"[삭제 완료] 프로파일 '{name}'")


def list_profile_names():
    """등록된 프로파일 이름 목록만 반환 (민감 정보 없이)."""
    return list(load_profiles().keys())


def list_sheet_profile_names():
    """
    Phase 4-5: source가 "sheet"인(구글 시트 동기화로 생성된) 프로파일 이름만 반환.
    사용자가 앱에서 직접 추가한 프로파일(source="manual")은 시트에 없는 게 당연하므로
    "유령 프로파일" 감지 대상에서 제외하기 위해 구분해서 조회한다.
    """
    profiles = load_profiles()
    return [name for name, p in profiles.items() if p.get("source") == "sheet"]


def list_wards():
    """
    지금까지 프로파일들에 실제로 쓰인 Ward 이름 목록을 돌려준다 (중복 제거, 정렬됨).
    ⚠ Ward를 별도로 등록/관리하는 저장소는 없다 — 어떤 프로파일이든 새 Ward 이름으로
    저장되는 순간, 그 이름은 자동으로 "존재하는 Ward"가 된다.
    """
    profiles = load_profiles()
    wards = {p.get("ward") for p in profiles.values() if p.get("ward")}
    return sorted(wards)


def list_profiles_in_ward(ward):
    """특정 Ward에 속한 프로파일 이름 목록만 반환."""
    profiles = load_profiles()
    return [name for name, p in profiles.items() if p.get("ward") == ward]