"""Script manual para crear (solo si faltan) las tablas de Checklist
OperationChecklist y OperationChecklistItem directamente sobre el
archivo SQLite usado por la aplicación.

Uso:
    # Activar el venv si no está activo
    # .\.venv\Scripts\Activate.ps1

    python create_checklist_tables.py

Este script NO depende de los modelos ya definidos; crea las tablas
con SQL directo si no existen. Si luego ajustas los modelos, tendrás
que reflejar los cambios manualmente (o usar migraciones reales).
"""
from pathlib import Path
import sqlite3
from datetime import datetime

DB_PATH = Path(__file__).parent / 'inventario' / 'data.sqlite'

DDL_OPERATION_CHECKLIST = """
CREATE TABLE IF NOT EXISTS operation_checklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha DATE,
    comentarios TEXT,
    usuario_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(usuario_id) REFERENCES user(id)
);
"""

DDL_OPERATION_CHECKLIST_ITEM = """
CREATE TABLE IF NOT EXISTS operation_checklist_item (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checklist_id INTEGER NOT NULL,
    servicio VARCHAR(200),
    responsable VARCHAR(120),
    hora_objetivo VARCHAR(40),
    estado VARCHAR(20) DEFAULT 'Pendiente',
    observacion TEXT,
    FOREIGN KEY(checklist_id) REFERENCES operation_checklist(id) ON DELETE CASCADE
);
"""

INDEXES = [
    ("idx_operation_checklist_fecha", "CREATE INDEX IF NOT EXISTS idx_operation_checklist_fecha ON operation_checklist(fecha)"),
    ("idx_operation_checklist_created", "CREATE INDEX IF NOT EXISTS idx_operation_checklist_created ON operation_checklist(created_at)"),
    ("idx_operation_checklist_item_checklist", "CREATE INDEX IF NOT EXISTS idx_operation_checklist_item_checklist ON operation_checklist_item(checklist_id)"),
    ("idx_operation_checklist_item_servicio", "CREATE INDEX IF NOT EXISTS idx_operation_checklist_item_servicio ON operation_checklist_item(servicio)")
]


def table_exists(cur, name: str) -> bool:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None


def main():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON")
    cur = conn.cursor()

    created = []

    if not table_exists(cur, 'operation_checklist'):
        print("Creando tabla operation_checklist ...")
        cur.executescript(DDL_OPERATION_CHECKLIST)
        created.append('operation_checklist')
    else:
        print("Tabla operation_checklist ya existe")

    if not table_exists(cur, 'operation_checklist_item'):
        print("Creando tabla operation_checklist_item ...")
        cur.executescript(DDL_OPERATION_CHECKLIST_ITEM)
        created.append('operation_checklist_item')
    else:
        print("Tabla operation_checklist_item ya existe")

    # Indexes
    for idx_name, ddl in INDEXES:
        print(f"Asegurando índice {idx_name} ...")
        cur.execute(ddl)

    conn.commit()

    if created:
        print("Tablas creadas:", ", ".join(created))
    else:
        print("No se crearon tablas nuevas (ya estaban)")

    conn.close()
    print(f"Listo. Base de datos: {DB_PATH}")

if __name__ == '__main__':
    main()
