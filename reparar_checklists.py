"""Script de reparación de checklists antiguos.

Completa los campos servicio, responsable y hora_objetivo de OperationChecklistItem
que quedaron en NULL (o 'None') en registros previos a la corrección del formulario.

Estrategia:
1. Si existe catálogo dinámico (ChecklistActividad) activo -> se usa en orden (orden, id).
2. Si no hay actividades activas -> se usa la lista estática CHECKLIST_SERVICIOS_BASE.
3. Para cada checklist se recorren sus items por id ascendente y se asignan valores
   de la lista base solo a los items que tengan servicio/responsable/hora_objetivo nulos.
4. No sobre-escribe valores ya presentes.

Uso:
    python reparar_checklists.py

Salida:
    Imprime número de items reparados.

Es seguro ejecutar varias veces (idempotente sobre items ya llenos).
"""
from inventario import create_app, db
from inventario.models import OperationChecklist, OperationChecklistItem, ChecklistActividad
from inventario.locales_data import CHECKLIST_SERVICIOS_BASE

app = create_app()


def build_base_list():
    actividades = ChecklistActividad.query.filter_by(activo=True).order_by(ChecklistActividad.orden, ChecklistActividad.id).all()
    if actividades:
        return [(a.servicio, a.responsable, a.hora_objetivo) for a in actividades]
    return CHECKLIST_SERVICIOS_BASE


def needs_repair(item: OperationChecklistItem) -> bool:
    return (not item.servicio) or item.servicio == 'None'


def main():
    with app.app_context():
        base = build_base_list()
        reparados = 0
        for chk in OperationChecklist.query.order_by(OperationChecklist.id).all():
            items = sorted(chk.items, key=lambda x: x.id)
            for idx, it in enumerate(items):
                if idx >= len(base):
                    break  # no más patrones disponibles
                if needs_repair(it):
                    serv, resp, hora = base[idx]
                    it.servicio = serv
                    it.responsable = resp
                    it.hora_objetivo = hora
                    reparados += 1
        if reparados:
            db.session.commit()
        print(f"Items reparados: {reparados}")


if __name__ == '__main__':
    main()
