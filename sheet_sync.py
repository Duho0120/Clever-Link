"""
Phase 4-4. 구글 시트 연동

- 사내 구글 시트를 CSV로 내려받아 읽어서, 새 행이 생기거나 기존 행의
  접속 정보(IP/ID/PW/Ward)가 바뀌면 profiles.json + keyring에 반영한다.
  ⚠ 자동 폴링(주기적 백그라운드 동기화)은 없다 — "↻ 시트 새로고침" 버튼을 눌렀을 때만
  동기화한다(사용자 결정, 2026-07-22). 원래 앱 시작 시 자동 1회 + 60초 주기 자동
  동기화가 있었는데 그 부분만 뺀 것.
- 시트 컬럼: 기기명, Ward, Room, Host name, IP, ID, PW
  (Ward와 Room 둘 다 병합 셀일 수 있어서, CSV로 내보내면 그룹의 첫 행에만 값이 있고
   나머지는 빈칸 — 빈칸이면 바로 위 행의 값을 그대로 이어받는다. 한 기기가 방 하나를
   전담하는 게 아니라 같은 방을 여러 기기가 나눠 쓰는 경우, Room이 그 여러 행에 걸쳐
   병합되어 있는 걸 실제 화면으로 확인함(2026-07-22))
- 원격지 이름은 "Room-Host name" 형식으로 조합해서 쓴다 (예: "3-co52", "3-co39").
  ⚠ Room 번호만으로는 고유하지 않다 — 같은 Ward 안에서도 여러 기기가 같은 Room 번호를
  공유하는 경우가 실제로 있었다(예: 새소망요양원 Room "3"에 co52/co39 두 기기).
  Host name은 지금까지 확인된 데이터에서 항상 고유하므로, Room과 조합해 이름을 지으면
  Ward 안/밖 어떤 충돌도 겹치지 않는다.
- ⚠ 시트에서 행이 사라져도 그에 대응하는 원격지를 자동으로 삭제하지는 않는다.
  실수로 행이 잠깐 지워지거나 옮겨지는 것만으로 이미 등록된 원격지가 사라지면
  위험하기 때문 — 삭제 동기화가 필요하면 별도 설계/확인 후 추가할 것.

실제 시트 데이터를 확인하며 추가로 처리하는 것들:
- IP 칸이 "주소:포트" 형태면 포트를 자동으로 분리해서 쓴다 (없으면 22 기본값).
- Room 칸에 괄호 없이 줄바꿈으로 여러 개("401\n402")가 들어있으면, 별도 원격지로
  쪼개지 않고 쉼표로 합쳐서 원격지 1개("401,402-co33")로 등록한다 — 기기 하나가
  방 여러 개를 같이 담당하는 것이지, 서로 다른 원격지가 아니기 때문(사용자 확인,
  2026-07-22). 처음엔 반대로(원격지 여러 개로 분할) 처리했었는데 뒤집힌 결정.
- IP 칸에 "로컬IP\n(터널주소)"처럼 두 줄이 있으면, 원격지를 나누지 않고 하나로 유지한
  채 보조 주소(host_alt/port_alt)로 저장한다 — 실제 연결 시점에 host_resolver가
  지금 닿는 쪽을 자동으로 고른다.
- PW 칸이 비어있으면 DEFAULT_PASSWORD를 쓴다 (거의 모든 행이 이 비밀번호를 공유하는
  것으로 확인됨).
- Room/IP/Ward/ID 중 필수 정보가 없어서 원격지로 등록할 수 없는 행은 조용히 건너뛰되,
  Ward별로 개수를 세어뒀다가 화면에서 "N개 연결 못 함" 경고로 보여준다.
"""

import csv
import io
import urllib.request

import profile_store
import sheet_diverged_state

# ⚠ "edit?usp=sharing" 같은 일반 공유 링크는 CSV가 아니라 사람이 보는 화면(HTML)이 내려와서
# 안 된다. "링크 있는 사람에게 공개" 상태의 시트라면 "/export?format=csv"를 붙이면 별도
# 게시(웹에 게시) 절차 없이도 바로 CSV로 받을 수 있다 (직접 확인함).
SHEET_CSV_URL = "https://docs.google.com/spreadsheets/d/1oFZ7UmGDFhAFnSJDOH2CGe3TGlAKyvX6eQ-pHq_UGLQ/export?format=csv"

# 시트의 PW 칸이 비어있는 행 대부분이 이 비밀번호를 공유하는 것으로 확인됨 (2026-07-21).
DEFAULT_PASSWORD = "959811!!"

# 최근 sync_from_sheet() 기준, {ward: 정보 부족으로 원격지로 못 만든 행 개수}
_last_issue_counts = {}

# 최근 sync_from_sheet() 기준, 시트에서는 사라졌지만 profiles.json에는 아직 남아있는
# "유령 프로파일" 목록. [{"name": ..., "ward": ...}, ...] 형태. 자동 삭제는 하지 않고
# 화면에 보여줘서 사용자가 확인 후 직접 지우게 한다 (실수로 행이 잠깐 지워진 것뿐일
# 수도 있어서 자동 삭제는 위험하다고 판단함).
_last_ghost_profiles = []


def _parse_host_port(address, default_port=22):
    """'host:port' 또는 'host'만 있는 문자열을 (host, port)로 나눈다."""
    address = address.strip()
    if ":" in address:
        host, _, port_str = address.rpartition(":")
        try:
            return host.strip(), int(port_str.strip())
        except ValueError:
            return address, default_port
    return address, default_port


def _parse_ip_field(ip_field, default_port=22):
    """
    IP 칸을 파싱해서 (host, port, host_alt, port_alt)를 돌려준다.
    - "192.168.123.3"                          -> host만
    - "loclx.io:12233"                         -> host:port
    - "192.168.20.201\\n(us.loclx.io:12224)"    -> 기본 주소 + 괄호 안 보조 주소
    """
    lines = [line.strip() for line in ip_field.split("\n") if line.strip()]
    if not lines:
        return None, None, None, None

    host, port = _parse_host_port(lines[0], default_port)

    host_alt, port_alt = None, None
    if len(lines) > 1:
        alt_line = lines[1]
        if alt_line.startswith("(") and alt_line.endswith(")"):
            alt_line = alt_line[1:-1].strip()
        if alt_line:
            # 보조 주소에 포트가 따로 없으면, 기본 주소와 같은 포트를 쓴다고 가정
            # (같은 기기를 가리키는 대체 경로일 가능성이 높음)
            host_alt, port_alt = _parse_host_port(alt_line, port)

    return host, port, host_alt, port_alt


def _split_rooms(room_field):
    """
    Room 칸에 줄바꿈으로 여러 개가 들어있으면 목록으로 나눈다.
    ⚠ 실제 데이터에는 두 가지가 섞여 있었다:
    - "401\\n402"                    -> 정말 독립된 Room 두 개 (분할해야 함)
    - "silverking_48\\n(lobby, hall)" -> 둘째 줄은 "이 기기가 담당하는 구역" 설명 메모일 뿐,
                                         별도 Room이 아니다 (처음엔 이것도 분할해버려서
                                         "(lobby, hall)"이라는 이상한 이름의 원격지가 생겼었음).
    괄호로 통째로 감싸인 줄은 메모로 보고 제외한다.
    """
    lines = [line.strip() for line in room_field.split("\n") if line.strip()]
    return [line for line in lines if not (line.startswith("(") and line.endswith(")"))]


def _parse_rows(text):
    """
    CSV 전체 텍스트를 파싱한다.
    반환값: (원격지로 등록 가능한 행 목록, {ward: 등록 못 한 행 개수})
    """
    # ⚠ text.splitlines()로 줄 단위로 잘라서 헤더를 찾으면 안 된다 — Ward/Room 병합 셀처럼
    # 따옴표로 감싸인 셀 안에 실제 줄바꿈이 들어있는 경우, splitlines()가 그 셀 하나를
    # 두 줄로 쪼개버려서 CSV 구조 자체가 깨진다 (실제로 겪은 버그). 대신 csv.reader로
    # 먼저 통째로 파싱해서 "행" 단위로 다룬 다음, 그중에서 진짜 헤더 행(제목 줄이 아니라
    # 기기명/Ward/Room이 있는 행)을 찾는다.
    all_rows = list(csv.reader(io.StringIO(text)))
    header_index = next(
        (i for i, r in enumerate(all_rows) if "Ward" in r and "Room" in r), 0
    )
    header = all_rows[header_index]
    data_rows = all_rows[header_index + 1:]

    resolved = []
    issue_counts = {}
    last_ward = None
    last_room_raw = None

    for fields in data_rows:
        row = dict(zip(header, fields))

        # ⚠ 병합 셀은 "S서울"과 "(3)"이 셀 안에서 줄바꿈으로 나뉘어 있어서, 그대로 두면
        # Ward 이름에 줄바꿈이 섞여 들어간다. 줄바꿈을 없애서 "S서울(3)"처럼 한 줄로 합친다.
        ward_raw = "".join((row.get("Ward") or "").split("\n")).strip()
        if ward_raw:
            last_ward = ward_raw
            # ⚠ Ward가 바뀌었다는 건 완전히 새로운 그룹이 시작됐다는 뜻이라, 이전 그룹
            # 마지막 Room 값을 여기로 넘어와서 이어받으면 안 된다. 실제로 겪은 버그:
            # "우리행복요양병원(3) Room 306" 바로 다음 행이 "Atman AI"(Room 빈칸)인데,
            # Ward 초기화 없이 이어받았더니 Atman AI가 엉뚱하게 Room "306"을 이어받아버림
            # (IP가 마침 비어있어서 지금은 등록까지는 안 되지만, Room 값 자체는 틀렸었음).
            last_room_raw = None
        ward = ward_raw or last_ward

        # ⚠ Room도 Ward처럼 병합 셀일 수 있다는 게 실제로 확인됨(2026-07-22, 새소망요양원
        # co52/co39가 시트 화면에서는 Room "3"이 두 행에 걸쳐 병합되어 보이는데, CSV로는
        # 첫 행에만 값이 있고 다음 행은 빈칸으로 나옴). 처음엔 "Room은 이어받지 말자"고
        # 정했었지만, 실제 병합 화면을 보고 나서 뒤집힌 결정 — Ward와 똑같이 위 행 값을
        # 이어받는다. Room-HostName 조합 이름 방식이 이미 있어서 co52/co39처럼 같은 Room을
        # 이어받아도 Host name이 다르면 "3-co52"/"3-co39"로 안 겹친다. 단, 같은 Ward
        # 안에서만 이어받는다(바로 위에서 last_room_raw를 Ward 전환 시 초기화).
        room_raw = row.get("Room") or ""
        if room_raw.strip():
            last_room_raw = room_raw
        else:
            room_raw = last_room_raw or ""

        room_names = _split_rooms(room_raw)
        ip_field = (row.get("IP") or "").strip()
        host, port, host_alt, port_alt = _parse_ip_field(ip_field) if ip_field else (None, None, None, None)
        user_id = (row.get("ID") or "").strip()
        pw = (row.get("PW") or "").strip() or DEFAULT_PASSWORD
        host_name = "".join((row.get("Host name") or "").split("\n")).strip()

        # 필수 정보(Ward/Room/host/ID)가 하나라도 없으면 원격지로 만들 수 없다.
        if not ward or not room_names or not host or not user_id:
            if ward:  # Ward조차 모르면 어느 Ward 밑에 표시할지 알 수 없으니 집계도 안 함
                issue_counts[ward] = issue_counts.get(ward, 0) + 1
            continue

        # ⚠ 한 행(같은 Host name/IP/ID)에 Room이 여러 줄(예: "401\n402")이면, 서로 다른
        # 원격지가 아니라 기기 하나가 방 여러 개를 같이 담당하는 것이었다(사용자 확인,
        # 2026-07-22 — 명은 co33: 401호/402호를 co33 하나가 담당). 예전엔 room_names를
        # 돌면서 원격지를 room 개수만큼 쪼개 만들었는데, 이제는 쉼표로 합쳐 원격지 1개로
        # 만든다 (예: "401,402-co33"). Room이 하나뿐이면 지금까지와 동일하게 그 값 그대로.
        resolved.append({
            "ward": ward,
            "room": ",".join(room_names),
            "host_name": host_name,
            "host": host,
            "port": port,
            "host_alt": host_alt,
            "port_alt": port_alt,
            "id": user_id,
            "pw": pw,
        })

    return resolved, issue_counts


def fetch_sheet_rows():
    """게시된 CSV를 내려받아 파싱한다. (file:// URL도 지원 — 로컬 테스트용)"""
    with urllib.request.urlopen(SHEET_CSV_URL, timeout=10) as resp:
        text = resp.read().decode("utf-8-sig")

    rows, issue_counts = _parse_rows(text)

    global _last_issue_counts
    _last_issue_counts = issue_counts

    return rows


def get_issue_count(ward):
    """이 Ward에서, 시트에는 있지만 정보 부족으로 원격지로 등록 못 한 행 개수."""
    return _last_issue_counts.get(ward, 0)


def get_issue_wards():
    """
    등록된 원격지는 하나도 없지만(Room/IP 등 누락), 시트에는 존재하는 Ward 이름 목록.
    ⚠ 예: "Atman AI"처럼 유일한 행이 Room/IP가 비어 있어서 원격지로 하나도 못 만든
    Ward는 profile_store.list_wards()에는 절대 안 뜬다(등록된 프로파일이 없으므로).
    그러면 Ward 드롭박스에 선택할 수조차 없어서 "N개 연결 못 함" 경고를 볼 방법이
    없어진다 — 그래서 이 목록을 따로 노출해서 Ward 드롭박스에 합쳐 넣는다.
    """
    return sorted(_last_issue_counts.keys())


def get_ghost_profiles(ward=None):
    """
    Phase 4-5: 시트에서는 사라졌지만 profiles.json에는 아직 남아있는 프로파일 목록
    (최근 sync_from_sheet() 기준). ward를 주면 그 Ward 것만 걸러서 반환.
    """
    if ward is None:
        return list(_last_ghost_profiles)
    return [g for g in _last_ghost_profiles if g["ward"] == ward]


def sync_from_sheet():
    """
    시트 내용을 profiles.json에 반영한다 (새 행은 추가, 이미 있는 행은 덮어써서 갱신).
    반환값: (추가된 개수, 갱신된 개수)
    """
    rows = fetch_sheet_rows()
    existing_profiles = profile_store.load_profiles()
    # ⚠ 실제 데이터 확인 중 발견: Room 번호만으로는 고유하지 않다 — 서로 다른 Ward끼리도
    # (예: "306"이 두 병원에 각각 있었음), 같은 Ward 안에서도(예: 새소망요양원 Room "3"에
    # co52/co39 두 기기) 겹칠 수 있다. profiles.json은 이름 하나짜리 평평한 사전이라
    # 이름이 겹치면 나중에 처리되는 쪽이 먼저 것을 조용히 덮어써버린다 — 실제로 겪은
    # 데이터 유실. 그래서 Host name을 항상 조합해 "Room-HostName"으로 이름을 짓는다.
    # (그래도 혹시 그것마저 겹치는 경우를 대비해 Ward까지 붙이는 안전장치는 남겨둔다.)
    name_to_ward = {name: p.get("ward") for name, p in existing_profiles.items()}

    added = 0
    updated = 0
    current_sheet_names = set()

    for r in rows:
        ward = r["ward"]
        name = f"{r['room']}-{r['host_name']}" if r["host_name"] else r["room"]

        conflicting_ward = name_to_ward.get(name)
        if conflicting_ward is not None and conflicting_ward != ward:
            name = f"{name}({ward})"

        current_sheet_names.add(name)
        was_existing = name in name_to_ward
        name_to_ward[name] = ward

        # ⚠ save_profile()이 내용 동일하면 False를 돌려주고 아무 것도 안 쓴다.
        # was_existing만으로 세면 "이미 있던 이름이니 갱신"으로 매번 잡혀서, 아무것도
        # 안 바뀐 60초 폴링마다도 계속 "갱신됨"으로 뜨고 화면도 매번 새로고침됐다.
        # 실제로 값이 바뀐 경우에만 added/updated로 센다.
        changed = profile_store.save_profile(
            name=name,
            host=r["host"],
            username=r["id"],
            auth_type="password",
            secret=r["pw"],
            port=r["port"],
            ward=ward,
            host_alt=r["host_alt"],
            port_alt=r["port_alt"],
            source="sheet",
        )
        # ⚠ 이 프로파일을 방금 시트 기준으로 처리했으므로(값이 바뀌었든 이미 같아서
        # 안 바뀌었든), 로컬이 시트와 달랐던 상태는 이제 해소된 것 — 동적 IP 재탐색으로
        # 로컬만 조용히 앞서갔던 경우(sheet_diverged_state)가 있었다면 여기서 정리한다.
        sheet_diverged_state.clear(name)

        if not changed:
            continue
        if was_existing:
            updated += 1
        else:
            added += 1

    # ⚠ Phase 4-5: 시트 동기화로 생성된(source="sheet") 프로파일 중, 이번 시트 내용에는
    # 더 이상 없는 이름을 "유령 프로파일"로 감지한다. 자동으로 지우진 않고(실수로 행이
    # 잠깐 지워진 것뿐일 수도 있어서), 화면에 보여줘서 사용자가 직접 확인 후 지우게 한다.
    global _last_ghost_profiles
    _last_ghost_profiles = [
        {"name": name, "ward": name_to_ward.get(name)}
        for name in sorted(set(profile_store.list_sheet_profile_names()) - current_sheet_names)
    ]

    return added, updated


# ── 여기서부터 로컬 테스트 (실제 구글 시트 없이 파싱 로직만 검증) ──────────────
if __name__ == "__main__":
    import os

    # ⚠ 병합 셀이 CSV로 내보내질 때 실제 줄바꿈이 들어갈 수 있는데, 이 경우 CSV 표준은
    # 그 셀 전체를 큰따옴표로 감싸서 표현한다 (csv.writer가 알아서 처리해줌). 손으로
    # 문자열을 짜면 이 부분을 놓치기 쉬워서, csv 모듈로 직접 만든다.
    sample_rows = [
        ["기기명", "Ward", "Room", "Host name", "IP", "ID", "PW"],
        ["Jetson Orin Nano", "S서울\n(3)", "3021", "co6", "192.168.123.3", "beclever", "959811!!"],
        ["Jetson Orin Nano", "", "3022", "co32", "192.168.123.5", "beclever", ""],  # PW 빈칸 -> 기본값
        ["Jetson Orin Nano", "", "3161", "co9", "loclx.io:12233", "beclever", ""],  # 포트 분리
        ["Jetson Orin Nano", "", "3162\n3163", "co10", "192.168.123.2", "beclever", ""],  # Room 여러 개 -> 원격지 1개("3162,3163-co10")로 합쳐짐
        ["Jetson Orin Nano", "", "3164", "co11", "192.168.20.201\n(us.loclx.io:12224)", "beclever", ""],  # 로컬+터널
        ["Jetson Orin Nano", "포항세명기독병원\n(62)", "", "co99", "", "", ""],  # Room/IP 없음 -> 집계만 되고 건너뜀
    ]

    tmp_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_sheet_sync_test.csv")
    with open(tmp_path, "w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerows(sample_rows)

    SHEET_CSV_URL = "file:///" + tmp_path.replace("\\", "/")
    rows = fetch_sheet_rows()
    for r in rows:
        print(r)
    print("issue counts:", _last_issue_counts)

    os.remove(tmp_path)
