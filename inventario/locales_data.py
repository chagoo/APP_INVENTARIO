"""Datos estáticos auxiliares.

Incluye catálogo de locales de ejemplo y la lista base de servicios para el
Checklist de Operación Diaria.
"""

# Lista de locales con sus datos asociados para autocompletar.
# (Mantenida corta como muestra; se puede ampliar) 
LOCALES = [
    {"region": "REGIÓN 1", "distrito": "MONTERREY 10", "local": "N785", "farmacia": "Suc. La capital"},
    {"region": "REGIÓN 1", "distrito": "Z. APERTURAS REGION 1 - ELIM", "local": "N811", "farmacia": "Suc. Privadas Las Estancias"},
    {"region": "REGIÓN 1", "distrito": "MONTERREY 5", "local": "N787", "farmacia": "Suc. Lucca"},
    {"region": "REGIÓN 1", "distrito": "MONTERREY 7", "local": "N795", "farmacia": "Suc. Héroes de Lincoln"},
    {"region": "REGIÓN 1", "distrito": "Z. APERTURAS REGION 1 - ELIM", "local": "N801", "farmacia": "Suc. Merco Israel Cavazos"},
    {"region": "REGIÓN 1", "distrito": "MONTERREY 1", "local": "N817", "farmacia": "Suc. Vasconcelos 250"},
    {"region": "REGIÓN 1", "distrito": "Z. APERTURAS REGION 1 - ELIM", "local": "N856", "farmacia": "Suc. Lomas Buena Vista"},
]

# Lista base (servicio, responsable, hora)
CHECKLIST_SERVICIOS_BASE = [
    ("Promociones en canales digitales", "Carlos Villa", "6am o día anterior"),
    ("señalización en ecommerce", "Carlos Villa", "6am"),
    ("Orquestador de promociones", "Carlos Villa", "6am"),
    ("Lealtad activo y aplicación de descuentos (ej. lunes y jueves)", "Lucero", "6am"),
    ("- Farmacia, SVT, ecommerce", "Lucero", "6am"),
    ("Venta Telefónica activa", "Carlos Villa", "6am"),
    ("Operación DLI", "Jorge Armando", ""),
    ("Facturas mayoristas", "Reynaldo", "7am y 9am"),
    ("Pedido a mayoristas", "Reynaldo", "10am"),
    ("ABF recetas, empleados y SVT", "Lucero", "6am"),
    ("Planogramas - SMB", "Lucero", "6am"),
    ("Conexión MDY hacia CAF - llamada para asegurar que tengan acceso a SVT", "Lucero", "6am"),
    ("Procesos nocturnos para Farmacias", "Reynaldo", "6am"),
    ("Tarjetas de crédito/débito (revisar que esté activo y existan transacciones)", "Reynaldo", "6am y 9am"),
    ("Pago Servicios y Recargas (revisar que esté activo y existan transacciones)", "Reynaldo", "6am y 9am"),
    ("Escaneo de productos en POS", "Reynaldo", "6am y 9am"),
    ("Cantidad de Farmacias activas", "Supervisor", ""),
]
