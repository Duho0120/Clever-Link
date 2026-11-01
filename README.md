# Clever-Link

Windows용 SFTP 파일 접근·SSH 터미널 통합 도구입니다. Google Sheets 기반 장비 목록 관리와 MAC 기반 재탐색·재접속 기능을 제공합니다.

## 공개 범위

운영 환경의 시트 URL, 비밀번호, 장비 목록은 포함하지 않습니다. 문서에 등장하는 시설·계정·장비 식별값은 공개용 예시입니다. 현장에서 경험한 문제와 설계 과정은 유지했습니다.

## 실행

1. Python 환경에 `requirements.txt`의 패키지를 설치합니다.
2. Windows에 WebView2 Runtime, WinFsp, Nmap/Npcap을 설치합니다. ARP 탐색에는 로컬 네트워크 접근과 적절한 실행 권한이 필요합니다.
3. 공식 배포처의 `rclone.exe`를 앱 폴더에 준비합니다. 외부 바이너리는 이 저장소에 포함하지 않습니다.
4. `python app_ui.py`로 실행합니다. 시트 설정 없이도 장비를 수동 등록할 수 있습니다.

## 선택 사항: 시트 연동

`config.example.json`을 참고해 앱 폴더에 비공개 `config.json`을 생성합니다. `sheet_csv_url`에는 CSV 내보내기 URL을 설정합니다. `default_password`는 PW 셀이 빈 행에 적용할 선택적 기본값이며, 필요하지 않으면 비워 둡니다.

환경변수 `CLEVER_LINK_SHEET_CSV_URL`, `CLEVER_LINK_DEFAULT_PASSWORD`가 있으면 로컬 설정보다 우선합니다. 설정 변경 후 앱을 재시작합니다. 미설정 상태에서 시트 새로고침을 누르면 설정 안내를 표시합니다.

컬럼: `기기명`, `Ward`, `Room`, `Host name`, `IP`, `ID`, `PW`. 개인 장비용 비공개 시트만 사용하고, 인증정보가 포함된 시트를 공개 링크로 공유하지 마세요. 현재 구현은 CSV URL을 읽으며 별도의 Google OAuth 흐름은 제공하지 않습니다.

`config.json`, `profiles.json` 및 접속 기록은 Git에서 제외됩니다. 설정 파일의 기본 비밀번호는 평문이므로 로컬 접근 권한을 제한하세요. 등록된 프로파일의 비밀번호는 keyring을 통해 Windows 자격 증명 관리자에 저장합니다.

## 개발·빌드

`requirements.txt`는 코드의 직접 의존성을 정리한 것이며, 특정 버전 조합의 재현 환경은 아닙니다. 빌드에는 별도로 PyInstaller가 필요합니다. 기본 spec은 rclone을 포함하며 OpenSSL DLL을 수동 지정해야 하는 환경에서는 `CLEVER_LINK_OPENSSL_DIR`을 설정할 수 있습니다.

## 제한 사항

- ARP 기반 MAC 탐색은 같은 로컬 네트워크에 적용됩니다. 인터넷 너머의 장비를 MAC만으로 찾지는 못합니다.
- MAC 검증은 오접속 방지를 위한 보조 장치이며 암호학적 신원 보증이 아닙니다.
- 재접속 시간은 환경에 따라 달라지고, 항상 일정한 시간 이내 복구를 보장하지 않습니다.
- 본 공개용 복사본은 기존 사내 배포 앱 및 실제 운영 설정을 변경하지 않습니다.
