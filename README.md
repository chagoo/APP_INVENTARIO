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
