# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['app_ui.py'],
    pathex=[],
    # ⚠ 이 컴퓨터엔 conda 환경마다 서로 다른 버전의 libcrypto/libssl DLL이 깔려 있는데,
    # PyQt5를 제외(excludes)했더니 PyInstaller가 자동으로 엉뚱한(다른 conda 환경) 버전을
    # 주워담아서 cryptography(paramiko가 SSH에 사용)가 로드되자마자 Rust 패닉으로 죽는
    # 문제가 있었다 (2026-07-29). 실제 이 앱을 돌리는 anaconda3 기본 환경의 파일을
    # 명시적으로 지정해서 고정 — 다른 환경의 버전이 대신 들어가지 않게 한다.
    binaries=[
        ('rclone.exe', '.'),
        ('C:/Users/ASUS/anaconda3/Library/bin/libcrypto-3-x64.dll', '.'),
        ('C:/Users/ASUS/anaconda3/Library/bin/libssl-3-x64.dll', '.'),
    ],
    # ⚠ style-v1~v3.css/wordmark.png은 배포판에서 실제로 안 씀 (index.html은 항상
    # style-v4.css만 참조하고, v4는 헤더 텍스트를 이미지가 아니라 Georgia 폰트로 씀).
    # 소스 폴더엔 그대로 남겨서 나중에 dev 중 버전 토글용으로 계속 쓸 수 있게 하되,
    # 배포용 datas에서만 뺀다.
    datas=[('index.html', '.'), ('terminal.html', '.'), ('xterm.min.js', '.'), ('xterm.min.css', '.'), ('addon-fit.min.js', '.'), ('style-v4.css', '.'), ('logo.png', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # ⚠ pywebview는 GTK/QT/WinForms 등 여러 GUI 백엔드를 try/except import로 방어적으로
    # 시도하는 구조라, PyInstaller가 실제로 어떤 백엔드가 쓰일지 몰라서 전부 다 묶어버린다.
    # 이 앱은 Windows에서 항상 WinForms+WebView2 백엔드만 쓰므로 QT 계열은 완전히 죽은 코드
    # (전체 470MB 중 PyQt5/Qt5WebEngine만 200MB+ 차지 — 2026-07-29 확인).
    # numpy는 우리 코드/실제 쓰는 clr_loader 어디서도 import 안 하고, pythonnet 패키지의
    # "optional extra" 의존성으로만 딸려온 것으로 확인(METADATA 확인, 실제 import 없음).
    # _testcapi류는 CPython 자체 테스트용 내부 모듈이라 배포 앱엔 원천적으로 불필요.
    excludes=[
        'PyQt5', 'PySide2', 'PySide6', 'PyQt6',
        'numpy',
        '_testcapi', '_testinternalcapi', '_testlimitedcapi',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

# ⚠ --onefile -> --onedir 전환 (실행 속도 문제).
# onefile은 실행할 때마다 임시 폴더에 압축을 새로 풀어야 해서 매번 느렸음.
# onedir은 EXE()에 실제 바이너리/데이터를 담지 않고(exclude_binaries=True),
# COLLECT()가 옆에 폴더로 그대로 풀어놓기 때문에 압축 해제 과정이 없어져 빨라진다.
# 대신 exe 파일 하나가 아니라 dist/SFTP_SSH_통합앱 폴더 전체를 전달해야 한다.
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Clever Link',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='appicon.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Clever Link',
)
