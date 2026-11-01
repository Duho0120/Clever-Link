# 패키지 구조 변경 검증

## 변경 범위

- 소스는 `clever_link/`의 기능별 패키지로 이동하고, 실행 진입점을 루트 `run.py`로 분리했습니다.
- UI 파일은 `clever_link/ui/`, 개발·설계·배포 문서는 `docs/`, 빌드 설정은 `packaging/`으로 이동했습니다.
- 내부 import, HTML의 CSS·JS·이미지 참조, 앱·트레이의 리소스 경로 및 PyInstaller 수집 경로를 함께 변경했습니다.
- 설정·프로파일·마운트 상태·known_hosts·설치 확인 플래그는 현재 작업 폴더가 아닌 앱 데이터 폴더를 사용합니다. 기본값은 저장소 루트 또는 exe 옆이며, `CLEVER_LINK_DATA_DIR`로 분리할 수 있습니다.
- 기존 사내 앱 및 운영 파일은 수정하지 않았습니다.

## 자동 테스트

```powershell
python -B -m unittest discover -s tests -v
```

11개 테스트를 통과했습니다. 전체 모듈 import, Python 구문, HTML 리소스 참조, 다른 작업 폴더에서의 API·데이터 경로, 배포판 경로 모사, spec의 스크립트·UI·아이콘 경로, 설정 로딩과 URL 미설정 처리를 확인합니다.

## 실제 GUI 스모크 테스트

실제 pywebview/WebView2 창을 별도의 빈 데이터 폴더로 실행했습니다.

| 대상 | 확인 결과 |
| --- | --- |
| 메인 화면 | DOM 로드 완료, CSS 규칙 94개, 로고 이미지 로드 |
| Python–JavaScript 연결 | `get_profiles` API 노출 확인 |
| 추가 창 | `openAddModal()` 호출 후 모달 표시 확인 |
| 터미널 화면 | xterm 생성자·FitAddon·CSS 규칙 35개 로드 |
| 종료 | 검증용 프로세스 종료 및 잔존 Python 프로세스 없음 확인 |

기존 마운트 정리, 배경 탐색, 설치 프로그램 실행, 운영 WebSocket 포트 사용은 테스트 하네스에서 차단했습니다. 터미널은 접속 API 없이 리소스 로딩만 검사했습니다. 실제 SSH·SFTP 연결, 네트워크 탐색, 설치 확인 흐름, 트레이 동작 및 새 EXE 빌드·실행을 검증한 것은 아닙니다.
