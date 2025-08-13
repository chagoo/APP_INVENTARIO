param(
    [int]$Port = 8001,
    [int]$Threads = 4,
    [switch]$Reinstall
)

$ErrorActionPreference = "Stop"
Write-Host "== Iniciando Inventario en puerto $Port (threads=$Threads) ==" -ForegroundColor Cyan

# Raíz del repo (donde está wsgi.py)
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Directorio del código (el paquete "inventario" vive en la raíz)
$codeDir = $root

# Usaremos .venv en la raíz del repo para simplificar
$venvDir = Join-Path $root ".venv"
$activate = Join-Path $venvDir "Scripts/Activate.ps1"
$reqFile = Join-Path $root "requirements.txt"

if (Test-Path $venvDir) {
    if ($Reinstall) {
        Write-Host "Reinstalación solicitada: removiendo venv..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $venvDir
    }
}

if (-not (Test-Path $venvDir)) {
    Write-Host "Creando entorno virtual..." -ForegroundColor Green
    python -m venv $venvDir
}

. $activate

if (Test-Path $reqFile) {
    Write-Host "Instalando dependencias..." -ForegroundColor Green
    try { python -m pip install --upgrade pip | Out-Null } catch { Write-Warning "No se pudo actualizar pip (continuando). $_" }
    python -m pip install -r $reqFile
} else {
    Write-Warning "No se encontró $reqFile (revisa que exista requirements.txt en la raíz)"
}

$env:FLASK_PROJECT = "inventario"
# Aseguramos que la raíz está al frente de PYTHONPATH
if ($env:PYTHONPATH) {
    $env:PYTHONPATH = "$root;$env:PYTHONPATH"
} else {
    $env:PYTHONPATH = "$root"
}

Write-Host "Levantando Waitress..." -ForegroundColor Green
if (-not (Test-Path (Join-Path $root 'wsgi.py'))) { Write-Error "No se encontró wsgi.py en $root"; exit 1 }

# Diagnóstico rápido (solo primera vez)
if (-not $env:SKIP_WSGI_DIAG) {
    Write-Host "(Diagnóstico) import wsgi" -ForegroundColor DarkGray
    $tmp = [System.IO.Path]::GetTempFileName() + '.py'
    $code = @'
import sys, os, importlib, traceback
print('CWD:', os.getcwd(), flush=True)
print('sys.executable:', sys.executable, flush=True)
print('sys.path:', sys.path, flush=True)
print('Dir root:', os.listdir('.'), flush=True)
try:
    mod = importlib.import_module('wsgi')
    print('OK wsgi import. Has application:', hasattr(mod, 'application'), flush=True)
except Exception as e:
    print('Fallo import wsgi (repr):', repr(e), flush=True)
    traceback.print_exc()
    with open('wsgi_import_error.log','w', encoding='utf-8') as f:
        f.write('Exception repr: ' + repr(e) + '\n')
        traceback.print_exc(file=f)
    raise SystemExit(97)
'@
    Set-Content -Encoding UTF8 -Path $tmp -Value $code
    python $tmp 2>&1 | Tee-Object -FilePath wsgi_import_error.log
    $diagCode = $LASTEXITCODE
    Remove-Item $tmp -ErrorAction SilentlyContinue
    if ($diagCode -eq 97) { Write-Error "Fallo import wsgi (ver wsgi_import_error.log)"; exit 1 }
    $env:SKIP_WSGI_DIAG = 1
}

$entry = "wsgi:application"

function Start-WaitressDirect {
    param($Port,$Threads,$Entry)
    $module,$callable = $Entry.Split(':')
    $code = @"
import importlib
mod = importlib.import_module('$module')
app = getattr(mod, '$callable')
from waitress import serve
serve(app, listen='0.0.0.0:$Port', threads=$Threads)
"@
    $tmp2 = [System.IO.Path]::GetTempFileName() + '.py'
    Set-Content -Encoding UTF8 -Path $tmp2 -Value $code
    try { python $tmp2 } finally { Remove-Item $tmp2 -ErrorAction SilentlyContinue }
}

# Lanzar servidor (intenta waitress-serve si existe; si no, fallback a python -m waitress; último recurso ejecución directa)
if (Get-Command waitress-serve -ErrorAction SilentlyContinue) {
    Write-Host "Iniciando waitress-serve (bloqueante Ctrl+C para detener)..." -ForegroundColor Green
    Start-Process -FilePath (Get-Command waitress-serve).Source -ArgumentList @("--listen=0.0.0.0:$Port","--threads=$Threads","$entry") -NoNewWindow -Wait
    exit $LASTEXITCODE
}

python -m waitress --listen=0.0.0.0:$Port --threads=$Threads $entry
if ($LASTEXITCODE -ne 0) {
    Write-Warning "python -m waitress falló (código $LASTEXITCODE). Usando ejecución directa."
    Start-WaitressDirect -Port $Port -Threads $Threads -Entry $entry
}
