param(
    [int]$Port = 8001,
    [int]$Threads = 4,
    [switch]$Reinstall,
    [switch]$Quiet,
    [switch]$NoInstall,
    [string]$LogDir
)

$ErrorActionPreference = "Stop"
Write-Host "== Iniciando InventarioApp en puerto $Port (threads=$Threads) ==" -ForegroundColor Cyan

# Raíz del repo (donde está wsgi.py)
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# (El paquete 'inventario' vive en la raíz del repositorio)

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

if (-not $NoInstall) {
    if (Test-Path $reqFile) {
        Write-Host "Instalando dependencias..." -ForegroundColor Green
        if ($Quiet) {
            # Determinar carpeta logs si aún no está definida
            if (-not $LogDir) { $LogDir = Join-Path $root 'logs' }
            if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
            $pipLog = Join-Path $LogDir 'pip_install.log'
            Write-Host "(Quiet) Instalando dependencias (salida en $pipLog)" -ForegroundColor DarkGray
            try {
                python -m pip install --upgrade pip 2>&1 | Out-File -FilePath $pipLog -Encoding UTF8 -Append
            } catch {
                Write-Warning "No se pudo actualizar pip (continuando). $_"
            }
            python -m pip install -r $reqFile 2>&1 | Out-File -FilePath $pipLog -Encoding UTF8 -Append
        } else {
            try { python -m pip install --upgrade pip | Out-Null } catch { Write-Warning "No se pudo actualizar pip (continuando). $_" }
            python -m pip install -r $reqFile
        }
    } else {
        Write-Warning "No se encontró $reqFile (revisa que exista requirements.txt en la raíz)"
    }
} else {
    Write-Host "(NoInstall) Omitiendo instalación de dependencias" -ForegroundColor DarkYellow
}

$env:FLASK_PROJECT = "inventario"
# Aseguramos que la raíz está al frente de PYTHONPATH
if ($env:PYTHONPATH) {
    $env:PYTHONPATH = "$root;$env:PYTHONPATH"
} else {
    $env:PYTHONPATH = "$root"
}

if (-not $LogDir) { $LogDir = Join-Path $root 'logs' }
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

Write-Host "Levantando Waitress..." -ForegroundColor Green
if (-not (Test-Path (Join-Path $root 'wsgi.py'))) { Write-Error "No se encontró wsgi.py en $root"; exit 1 }

# Comprobación ligera de import wsgi (solo primera vez por sesión)
if (-not $env:SKIP_WSGI_DIAG) {
    Write-Host "(Diag) Verificando que wsgi.application existe..." -ForegroundColor DarkGray
    $tmp = [System.IO.Path]::GetTempFileName() + '.py'
    $code = @'
import importlib, sys
mod = importlib.import_module('wsgi')
assert hasattr(mod,'application'), 'wsgi.application no encontrado'
print('WSGI OK', flush=True)
'@
    Set-Content -Encoding UTF8 -Path $tmp -Value $code
    python $tmp
    if ($LASTEXITCODE -ne 0) { Write-Error "Fallo verificación wsgi (exit $LASTEXITCODE)"; exit 1 }
    Remove-Item $tmp -ErrorAction SilentlyContinue
    $env:SKIP_WSGI_DIAG = 1
}

$entry = "wsgi:application"

# Siempre usar python -m waitress para evitar problemas en PowerShell ISE con wrapper waitress-serve
Write-Host "Iniciando (python -m waitress) puerto=$Port threads=$Threads Quiet=$Quiet" -ForegroundColor Green

$outLog = Join-Path $LogDir 'inventario_out.log'
$errLog = Join-Path $LogDir 'inventario_err.log'
$appLog = Join-Path $LogDir 'inventario_app.log'

if ($Quiet) {
    # Creamos script temporal que configura logging a archivo rotativo simple
    $tmpApp = [System.IO.Path]::GetTempFileName() + '.py'
    $safeAppLog = $appLog.Replace('\\','\\\\')
    $py = @"
import importlib, logging, logging.handlers, sys, traceback
try:
    mod,callable_name='wsgi','application'
    app = getattr(importlib.import_module(mod), callable_name)
    handler = logging.handlers.RotatingFileHandler(r'$safeAppLog', maxBytes=1048576, backupCount=3)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
    handler.setFormatter(fmt)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    logging.info('Arrancando waitress (quiet) puerto=${Port} threads=${Threads}')
    from waitress import serve
    serve(app, listen='0.0.0.0:${Port}', threads=${Threads})
except Exception as e:
    traceback.print_exc(file=sys.stderr)
    sys.stderr.flush()
    raise
"@
    Set-Content -Encoding UTF8 -Path $tmpApp -Value $py
    Write-Host "InventarioApp -> host=0.0.0.0 port=$Port threads=$Threads" -ForegroundColor Cyan
    Write-Host "(Stdout: $outLog  Stderr: $errLog  RotatingLog: $(Split-Path $appLog -Leaf))" -ForegroundColor DarkCyan
    Write-Host "Para seguir logs: Get-Content $outLog -Wait" -ForegroundColor DarkGray
    # Ejecutar redirigiendo stdout/stderr
    & python $tmpApp 1>> $outLog 2>> $errLog
    $ec = $LASTEXITCODE
    Remove-Item $tmpApp -ErrorAction SilentlyContinue
    if ($ec -ne 0) { Write-Error "Servidor terminó con código $ec (ver $errLog)" }
} else {
    # Modo normal pantalla
    $oldPref = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    Write-Host "InventarioApp -> host=0.0.0.0 port=$Port threads=$Threads (modo pantalla)" -ForegroundColor Cyan
    & python -m waitress --listen=0.0.0.0:$Port --threads=$Threads $entry 2>&1 | ForEach-Object { $_ }
    $exit = $LASTEXITCODE; $ErrorActionPreference = $oldPref
    if ($exit -ne 0) {
        Write-Warning "Fallo python -m waitress (código $exit). Intentando fallback directo."
        $tmp2 = [System.IO.Path]::GetTempFileName() + '.py'
        $code2 = @"
import importlib
mod,callable_name = 'wsgi','application'
app = getattr(importlib.import_module(mod), callable_name)
from waitress import serve
serve(app, listen='0.0.0.0:${Port}', threads=${Threads})
"@
        Set-Content -Encoding UTF8 -Path $tmp2 -Value $code2
        & python $tmp2
        Remove-Item $tmp2 -ErrorAction SilentlyContinue
    }
}
