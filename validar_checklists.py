
from inventario import create_app
from inventario.models import ChecklistActividad
app = create_app()
with app.app_context():
    print("DB URI:", app.config['SQLALCHEMY_DATABASE_URI'])
    print("Actividades count:", ChecklistActividad.query.count())
    for a in ChecklistActividad.query.order_by(ChecklistActividad.id):
        print(a.id, a.servicio, a.activo)


