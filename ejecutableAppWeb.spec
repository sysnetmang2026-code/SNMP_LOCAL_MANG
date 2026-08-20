# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['ejecutableAppWeb.py'],
    pathex=[],
    binaries=[],
    datas=[('view', 'view'), ('data', 'data'), ('env', 'env'), ('img', 'img'), ('src', 'src'), ('test', 'test'), ('tests', 'tests'), ('docs', 'docs'), ('.env.example', '.env.example')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ejecutableAppWeb',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
