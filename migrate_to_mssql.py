"""Script básico para migrar datos desde el SQLite local a una base SQL Server.

Uso:
  1. Asegúrate de tener poblado el archivo SQLite (por defecto inventario/data.sqlite).
  2. Define la variable de entorno DEST_DATABASE_URL apuntando a tu SQL Server, por ej:
       set DEST_DATABASE_URL=mssql+pyodbc://user:pass@SERVIDOR/InventarioDB?driver=ODBC+Driver+17+for+SQL+Server&TrustServerCertificate=yes
  3. Ejecuta:  python migrate_to_mssql.py

Notas:
  - No borra datos existentes en destino; sólo inserta si la tabla está vacía.
  - Asume que el esquema (tablas) ya existe en el destino (creado manualmente o por migraciones).
  - No migra relaciones incrementales si ya hay datos discordantes (ids distintos). Usa para una migración inicial.
  - Ajusta la lista TABLES_ORDER si agregas tablas nuevas que dependan de otras.
"""
from __future__ import annotations
import os
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from pathlib import Path

SQLITE_PATH = Path(__file__).parent / 'inventario' / 'data.sqlite'
SRC_URL = f'sqlite:///{SQLITE_PATH}'
DEST_URL = os.environ.get('DEST_DATABASE_URL')

if not DEST_URL:
    raise SystemExit('ERROR: Define la variable de entorno DEST_DATABASE_URL con la cadena de conexión destino.')

TABLES_ORDER = [
    'user',
    'local_ref',
    'inventario',
    'checklist_actividad',
    'operation_checklist',
    'operation_checklist_item',
    'audit_log',
]

SKIP_IDENTITY_RESET = { 'user' }  # tablas donde no queremos manipular IDENTITY (puede requerir permisos)

def rowcount(engine: Engine, table: str) -> int:
    with engine.connect() as conn:
        return conn.execute(text(f'SELECT COUNT(*) FROM {table}')).scalar() or 0


def copy_table(src: Engine, dest: Engine, table: str):
    src_count = rowcount(src, table)
    if src_count == 0:
        print(f'- {table}: origen vacío, nada que copiar')
        return
    dest_count = rowcount(dest, table)
    if dest_count > 0:
        print(f'- {table}: destino ya tiene {dest_count} filas, se omite (no duplicar)')
        return
    print(f'- {table}: copiando {src_count} filas...')
    with src.connect() as sconn, dest.begin() as dtx:
        rows = sconn.execute(text(f'SELECT * FROM {table}')).mappings().all()
        if not rows:
            return
        cols = rows[0].keys()
        col_list = ','.join(cols)
        param_list = ','.join(f':{c}' for c in cols)
        # Para tablas con identidad puede ser necesario SET IDENTITY_INSERT ON
        if table not in SKIP_IDENTITY_RESET:
            try:
                dtx.connection.execute(text(f'SET IDENTITY_INSERT {table} ON'))
            except Exception:
                pass  # si falla, continuamos (SQLite destino u otro motor)
        insert_sql = text(f'INSERT INTO {table} ({col_list}) VALUES ({param_list})')
        for chunk_start in range(0, len(rows), 500):
            chunk = rows[chunk_start:chunk_start+500]
            dtx.connection.execute(insert_sql, chunk)  # bulk parameter list
        if table not in SKIP_IDENTITY_RESET:
            try:
                dtx.connection.execute(text(f'SET IDENTITY_INSERT {table} OFF'))
            except Exception:
                pass
    print(f'- {table}: OK')


def main():
    if not SQLITE_PATH.exists():
        raise SystemExit(f'Archivo SQLite no encontrado: {SQLITE_PATH}')
    print('Origen (SQLite):', SRC_URL)
    print('Destino (MSSQL):', DEST_URL)
    src_engine = create_engine(SRC_URL)
    dest_engine = create_engine(DEST_URL, fast_executemany=True)
    for t in TABLES_ORDER:
        try:
            copy_table(src_engine, dest_engine, t)
        except Exception as e:
            print(f'ERROR copiando {t}: {e}')
    print('Migración finalizada.')

if __name__ == '__main__':
    main()
