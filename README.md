# App Inventario (Web + PWA)

Aplicación Flask responsive (móvil, tablet y escritorio) para registrar el estado de equipos y generar reportes.

Campos obligatorios: **región**, **local** y **farmacia**.

## Funcionalidades
- CRUD completo (crear, listar, editar, eliminar y cerrar reportes)
- Búsqueda por local
- Exportación CSV
- API REST JSON para integración móvil / apps externas (requiere header `X-API-KEY` para operaciones de escritura)
- PWA: manifest + service worker (cache básico offline)

## Requisitos
Python 3.10+

## Instalación
```bash
pip install -r requirements.txt
export API_TOKEN="mi-token"  # opcional, requerido para API de escritura
python app.py
```
Abrir: http://localhost:5000

Al iniciarse por primera vez se crea automáticamente un usuario admin con credenciales:

Usuario: admin
Password: admin

(Cámbialo cuanto antes creando otro usuario y eliminando/actualizando éste.)

Para crear usuarios adicionales (en Linux/macOS) usa:
```bash
flask --app app create-user
```
En Windows PowerShell:
```powershell
flask --app app create-user
```
Se solicitarán username, rol (admin/user) y password.

## Endpoints API
GET /api/inventario?search=
POST /api/inventario (JSON, requiere `X-API-KEY`)
POST /api/inventario/<id>/cerrar (requiere `X-API-KEY`)

Ejemplo POST JSON:
```json
{
  "region": "Lima",
  "distrito": "Miraflores",
  "local": "LOC001",
  "farmacia": "Farmacia A",
  "puntos_venta": 5,
  "puntos_falla": 1,
  "monitor_cliente": "SÍ",
  "monitor_asesor": "NO",
  "teclado": "NO",
  "escaner": "SÍ",
  "mouse_pcm": "NO",
  "teclado_pcm": "NO",
  "ups": "NO",
  "red_lenta": "SÍ",
  "pinpad": "NO",
  "estado_reporte": "Abierto",
  "fecha_solucion": null,
  "comentarios": "Observación"
}
```

## PWA
Instalable en Android/Chrome. Íconos vacíos de ejemplo: reemplazar en `static/icons/`.

## Próximos pasos sugeridos
- Fortalecer autenticación (expiración de sesión, forzar cambio primera vez)
- Validaciones adicionales (longitud de campos, rangos numéricos)
- Tests automatizados
- Cache más granular y estrategia background sync

## Uso con SQL Server (en lugar de SQLite)
Por defecto la app usa un archivo SQLite (`inventario/data.sqlite`). Para apuntar a SQL Server define la variable de entorno `DATABASE_URL` antes de iniciar.

### Cadena de conexión ejemplo
Formato general con pyodbc:
```
DATABASE_URL="mssql+pyodbc://USUARIO:PASS@SERVIDOR/NombreBD?driver=ODBC+Driver+17+for+SQL+Server&TrustServerCertificate=yes"
```
Ejemplo PowerShell (sesión actual):
```powershell
$env:DATABASE_URL = 'mssql+pyodbc://sa:MiPass123@MIHOST/InventarioDB?driver=ODBC+Driver+17+for+SQL+Server&TrustServerCertificate=yes'
./start_inventario.ps1 -NoInstall
```

### Requisitos en Windows
1. Instalar el driver ODBC de SQL Server (Driver 17) desde Microsoft: 
  https://learn.microsoft.com/sql/connect/odbc/download-odbc-driver-for-sql-server
2. Asegurarse de tener `pyodbc` instalado (ya está en `requirements.txt`).
3. Dar permisos al usuario de la cadena de conexión para CRUD sobre la base.
4. Crear previamente la base de datos en el servidor (el código no ejecutará `create_all()` sobre motores externos por seguridad). Crea las tablas ejecutando el esquema inicial o habilita migraciones (ver nota abajo).

### Crear tablas inicialmente
Opción rápida (dar permisos para DDL temporalmente):
1. Quita momentáneamente la variable `DATABASE_URL` (deja que arranque con SQLite una vez para inspeccionar el esquema) o crea un script de migración.
2. Genera un script SQL a partir de modelos usando una herramienta externa (Alembic recomendado para producción).

### Campos / Tablas clave
- `inventario`
- `user`
- `operation_checklist`
- `operation_checklist_item`
- `checklist_actividad`
- `audit_log`
- `local_ref`

### Migrar datos existentes de SQLite a SQL Server
Se puede usar el script opcional `migrate_to_mssql.py` (si lo agregas) para copiar filas tabla por tabla a tu servidor.

### Seguridad cadena de conexión
Evita commitear tu `DATABASE_URL`. Usa variables de entorno (en Windows: `$env:DATABASE_URL=...` antes de ejecutar el script) o un archivo `.env` gestionado fuera del control de versiones.

### Nota sobre migraciones
### Archivo .env
La aplicación intenta cargar automáticamente un archivo `.env` (si existe y está instalada la librería `python-dotenv`). Crea un archivo `.env` en la raíz del proyecto con contenido similar a:

```
DATABASE_URL=mssql+pyodbc://usuario:Password123@SERVIDOR/InventarioDB?driver=ODBC+Driver+17+for+SQL+Server&TrustServerCertificate=yes
SECRET_KEY=mi-clave-super-secreta
API_TOKEN=token-api-opcional
```

Luego simplemente ejecuta el script de arranque sin tener que exportar variables manualmente.

### Uso de sesión SQL fuera de Flask
Si necesitas ejecutar scripts de mantenimiento (carga masiva, validaciones) sin levantar la app Flask, usa el helper `get_sql_session` definido en `config.py`:

```python
from config import get_sql_session
from sqlalchemy import text

with get_sql_session() as s:
  total = s.execute(text('SELECT COUNT(*) FROM checklist_actividad')).scalar()
  print('Actividades:', total)
```

Esto carga automáticamente `.env` y abre una sesión segura (commit si todo OK, rollback si hay excepción).

### Variables componentes (alternativa a DATABASE_URL)
Si prefieres no escribir la URL completa, puedes definir en `.env`:
```
SQL_SERVER=MIHOST
SQL_USER=sa
SQL_PASSWORD=Password123
SQL_DBNAME=InventarioDB
#SQL_DRIVER=ODBC Driver 17 for SQL Server  # opcional, default 17
```
Si `DATABASE_URL` no está presente, la aplicación construirá internamente:
`mssql+pyodbc://SQL_USER:SQL_PASSWORD@SQL_SERVER/SQL_DBNAME?driver=SQL_DRIVER&TrustServerCertificate=yes`
Esto aplica tanto para Flask como para `config.get_sql_session()`.

Para evolución de esquema a largo plazo instala Alembic:
```
pip install alembic
alembic init migrations
```
Luego genera revisiones cuando cambies modelos (`alembic revision --autogenerate -m "msg"`).

## Ejecución y Script de Arranque (PowerShell)

Además de `python app.py` se incluye un script avanzado `start_inventario.ps1` que:

1. Crea (o reutiliza) un entorno virtual `.venv` en la raíz.
2. Instala dependencias (`requirements.txt`) salvo que se use `-NoInstall`.
3. Ajusta `PYTHONPATH`.
4. Verifica que `wsgi.application` cargue.
5. Levanta la aplicación con Waitress (`python -m waitress`).
6. Soporta modo silencioso con logs a archivos.

### Uso básico
```powershell
./start_inventario.ps1
```

### Parámetros
| Parámetro | Descripción |
|-----------|-------------|
| `-Port <int>` | Puerto (default 8001). |
| `-Threads <int>` | Hilos Waitress (default 4). |
| `-Reinstall` | Borra `.venv` y recrea entorno antes de iniciar. |
| `-NoInstall` | Omite instalación de dependencias (más rápido). |
| `-Quiet` | No muestra salida de servidor ni pip; todo va a logs. |
| `-LogDir <ruta>` | Directorio para logs (default `./logs`). |

### Modo Quiet
Ejemplo:
```powershell
./start_inventario.ps1 -Quiet -NoInstall
```
Salida compacta esperada:
```
InventarioApp -> host=0.0.0.0 port=8001 threads=4
(Stdout: logs/inventario_out.log  Stderr: logs/inventario_err.log  RotatingLog: inventario_app.log)
Para seguir logs: Get-Content .\logs\inventario_out.log -Wait
```

### Archivos de log
| Archivo | Contenido |
|---------|-----------|
| `inventario_out.log` | STDOUT del servidor (Waitress / prints). |
| `inventario_err.log` | STDERR (tracebacks). |
| `inventario_app.log` | Log rotativo (INFO/ERROR) configurado por el script. |
| `pip_install.log` | Salida de instalación de dependencias en modo Quiet. |

### Seguir logs en tiempo real
```powershell
Get-Content .\logs\inventario_out.log -Wait
Get-Content .\logs\inventario_err.log -Wait
```

### Reinicio limpio
```powershell
./start_inventario.ps1 -Reinstall -Quiet
```

### Diferencias PowerShell ISE vs Terminal normal
PowerShell ISE tiende a colorear líneas en rojo cuando algo se escribe en STDERR aunque el proceso no falle. En modo Quiet esto se evita redirigiendo la salida a archivos. Para desarrollo interactivo se recomienda usar la terminal integrada de VS Code o PowerShell estándar.

### Ejemplos combinados
| Objetivo | Comando |
|----------|---------|
| Arranque rápido silencioso | `./start_inventario.ps1 -Quiet -NoInstall` |
| Cambiar puerto | `./start_inventario.ps1 -Port 8050` |
| Logs en carpeta personalizada | `./start_inventario.ps1 -Quiet -LogDir .\runlogs` |
| Reinstalar entorno y arrancar | `./start_inventario.ps1 -Reinstall -Quiet` |

### Troubleshooting
1. Puerto ocupado: cambiar `-Port` o liberar el puerto.
2. Error importando `wsgi`: revisar `wsgi_import_error.log` (se genera sólo si falla la verificación inicial) o revisar `inventario_err.log`.
3. Cambios no reflejados: asegurarse de no tener múltiples procesos Waitress activos (`Get-Process python`).
4. Actualizar dependencias: usar `-Reinstall` si hay inconsistencias.

