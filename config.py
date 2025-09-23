"""Configuración centralizada y helper de sesión SQL fuera del contexto Flask.

Uso:
    from config import get_sql_session
    with get_sql_session() as session:
        session.execute(text('SELECT 1'))

Lee variables desde .env (python-dotenv) si están presentes.
"""
from __future__ import annotations
import os
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

try:  # cargar .env si existe
    from dotenv import load_dotenv  # type: ignore
    load_dotenv(override=False)
except Exception:
    pass

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    srv = os.environ.get('SQL_SERVER')
    usr = os.environ.get('SQL_USER')
    pwd = os.environ.get('SQL_PASSWORD')
    dbn = os.environ.get('SQL_DBNAME')
    drv = os.environ.get('SQL_DRIVER', 'ODBC Driver 17 for SQL Server')
    if srv and usr and pwd and dbn:
        from urllib.parse import quote_plus
        DATABASE_URL = f"mssql+pyodbc://{quote_plus(usr)}:{quote_plus(pwd)}@{srv}/{dbn}?driver={quote_plus(drv)}&TrustServerCertificate=yes"
if not DATABASE_URL:
    from pathlib import Path
    DATABASE_URL = f"sqlite:///{(Path(__file__).parent / 'inventario' / 'data.sqlite')}"

_ENGINE = create_engine(DATABASE_URL, pool_pre_ping=True)
_SessionLocal = sessionmaker(bind=_ENGINE, expire_on_commit=False, autoflush=False, autocommit=False)

@contextmanager
def get_sql_session():
    """Yield de una sesión SQLAlchemy sin depender de Flask.

    Ejemplo:
        from sqlalchemy import text
        with get_sql_session() as s:
            rows = s.execute(text('SELECT COUNT(*) FROM checklist_actividad')).scalar()
            print(rows)
    """
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

__all__ = ["get_sql_session", "DATABASE_URL"]
