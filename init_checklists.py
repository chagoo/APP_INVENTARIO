"""Script para crear las tablas de Checklist de Operación Diaria y (opcional) sembrar un registro inicial.

Uso básico (desde la raíz del proyecto, con el venv activado):

    python init_checklists.py            # Solo crea tablas si faltan
    python init_checklists.py --seed     # Crea tablas y genera un checklist de hoy si no existe

Puedes ejecutar esto tantas veces como quieras; es idempotente.
"""

from datetime import date
from inventario import create_app, db
from inventario.models import OperationChecklist, OperationChecklistItem
from inventario.locales_data import CHECKLIST_SERVICIOS_BASE
from sqlalchemy import inspect
import argparse


def ensure_tables():
    """Crea únicamente las tablas faltantes relacionadas al checklist."""
    inspector = inspect(db.engine)
    existing = set(inspector.get_table_names())
    needed = {OperationChecklist.__tablename__, OperationChecklistItem.__tablename__}
    missing = needed - existing
    if missing:
        # create_all creará solo las que no existen ya que metadata sabe cuáles faltan
        db.create_all()
        return True, missing
    return False, set()


def seed_today_if_absent():
    today = date.today()
    exists = OperationChecklist.query.filter_by(fecha=today).first()
    if exists:
        return False, exists.id
    chk = OperationChecklist(fecha=today, comentarios="Checklist inicial auto-generado", usuario_id=1)
    for servicio, responsable, hora in CHECKLIST_SERVICIOS_BASE:
        chk.items.append(OperationChecklistItem(
            servicio=servicio,
            responsable=responsable,
            hora_objetivo=hora,
            estado='Pendiente'
        ))
    db.session.add(chk)
    db.session.commit()
    return True, chk.id


def main():
    parser = argparse.ArgumentParser(description="Inicializa tablas de checklist")
    parser.add_argument('--seed', action='store_true', help='Crear un checklist para hoy si no existe')
    args = parser.parse_args()

    app = create_app({'TESTING': False})
    with app.app_context():
        created, missing = ensure_tables()
        if created:
            print(f"Tablas creadas: {', '.join(sorted(missing))}")
        else:
            print("Tablas ya existían (sin cambios)")
        if args.seed:
            seeded, chk_id = seed_today_if_absent()
            if seeded:
                print(f"Checklist de hoy creado (id={chk_id})")
            else:
                print(f"Ya existía checklist de hoy (id={chk_id}) — no se creó otro")


if __name__ == '__main__':
    main()
