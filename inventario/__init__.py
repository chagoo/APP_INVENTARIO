from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_cors import CORS
from flask_login import LoginManager
from pathlib import Path
import os
try:
    from dotenv import load_dotenv  # type: ignore
except ImportError:  # librería opcional
    load_dotenv = None

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()


def create_app(test_config=None):
    app = Flask(__name__, static_folder="static", template_folder="templates")

    # Cargar variables desde .env si existe y la librería está disponible
    if load_dotenv:
        load_dotenv(override=False)

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    # Permitir usar una base externa (por ejemplo SQL Server) mediante DATABASE_URL.
    # Ejemplos:
    #   MSSQL con ODBC Driver 17:
    #   mssql+pyodbc://usuario:password@SERVIDOR/NombreBD?driver=ODBC+Driver+17+for+SQL+Server&TrustServerCertificate=yes
    #   PostgreSQL: postgresql://user:pass@host:5432/dbname
    # Si no se define DATABASE_URL, se cae a SQLite local.
    external_url = os.environ.get('DATABASE_URL')
    if not external_url:
        # Construir desde componentes SQL_* si se proporcionan
        srv = os.environ.get('SQL_SERVER')
        usr = os.environ.get('SQL_USER')
        pwd = os.environ.get('SQL_PASSWORD')
        dbn = os.environ.get('SQL_DBNAME')
        drv = os.environ.get('SQL_DRIVER', 'ODBC Driver 17 for SQL Server')
        if srv and usr and pwd and dbn:
            from urllib.parse import quote_plus
            # codificar password y driver
            external_url = f"mssql+pyodbc://{quote_plus(usr)}:{quote_plus(pwd)}@{srv}/{dbn}?driver={quote_plus(drv)}&TrustServerCertificate=yes"
    if external_url:
        app.config['SQLALCHEMY_DATABASE_URI'] = external_url
    else:
        db_path = os.path.join(Path(__file__).parent, 'data.sqlite')
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['API_TOKEN'] = os.environ.get('API_TOKEN')

    if test_config:
        app.config.update(test_config)

    CORS(app)
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'web.login'

    with app.app_context():
        from . import models  # noqa: F401
        # Sólo ejecutar create_all y migración ligera si estamos en SQLite local.
        if not external_url or app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:'):
            db.create_all()
            _ensure_user_new_columns()
        else:
            # En bases externas asumimos que el esquema ya existe (o se maneja con migraciones externas).
            masked = app.config['SQLALCHEMY_DATABASE_URI']
            if '://' in masked:
                # enmascarar password si formato tradicional mssql+pyodbc://user:pass@host
                try:
                    proto, rest = masked.split('://',1)
                    creds_host = rest.split('@',1)
                    if len(creds_host)==2 and ':' in creds_host[0]:
                        user_part, host_part = creds_host[0], creds_host[1]
                        u, p = user_part.split(':',1)
                        masked = f"{proto}://{u}:***@{host_part}"
                except Exception:
                    pass
            app.logger.info('Usando base externa (no create_all): %s', masked)
        from .routes import web_bp, api_bp
        app.register_blueprint(web_bp)
        app.register_blueprint(api_bp, url_prefix="/api")
        # Seed default admin si no hay usuarios
        from .models import User
        if User.query.count() == 0 and not app.config.get('TESTING'):
            # Solo auto-seed en entorno SQLite local para conveniencia de desarrollo.
            if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:'):
                default_user = os.environ.get('ADMIN_USER', 'admin')
                default_pass = os.environ.get('ADMIN_PASS', 'admin')
                u = User(username=default_user, role='admin')
                u.set_password(default_pass)
                db.session.add(u)
                db.session.commit()
                app.logger.info(f"Usuario admin creado: {default_user} (cambia la contraseña ASAP)")
            else:
                app.logger.info('Base externa sin usuarios: usar /bootstrap para crear el primer admin.')

    # Registrar comandos CLI
    register_cli(app)

    return app


@login_manager.user_loader
def load_user(user_id):
    from .models import User
    return User.query.get(int(user_id))

# Flask CLI commands
def register_cli(app):
    @app.cli.command('create-user')
    def create_user_command():
        """Crear un usuario interactivo"""
        from .models import User
        import getpass
        username = input('Username: ').strip()
        role = input('Role [admin/user] (default user): ').strip() or 'user'
        password = getpass.getpass('Password: ')
        if not username or not password:
            print('Username y password requeridos')
            return
        if User.query.filter_by(username=username).first():
            print('Usuario ya existe')
            return
        u = User(username=username, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        print('Usuario creado')

    @app.cli.command('orphan-images')
    def orphan_images_command():
        """Lista (y opcionalmente elimina) imágenes huérfanas en static/actividades.

        Uso:
          flask orphan-images            -> solo listar
          FLASK_ORPHAN_DELETE=1 flask orphan-images  -> eliminar huérfanas
        """
        import os
        from .models import OperationChecklistItem, ChecklistActividad
        base_dir = os.path.join(app.static_folder, 'actividades')
        if not os.path.isdir(base_dir):
            print('No existe carpeta de actividades.')
            return
        referenced = set()
        for r in ChecklistActividad.query.with_entities(ChecklistActividad.imagen_ref).all():
            if r[0]:
                referenced.add(r[0])
        for r in OperationChecklistItem.query.with_entities(OperationChecklistItem.imagen_ref).all():
            if r[0]:
                referenced.add(r[0])
        all_files = {f for f in os.listdir(base_dir) if os.path.isfile(os.path.join(base_dir, f))}
        orphans = sorted(all_files - referenced)
        if not orphans:
            print('Sin huérfanas. Total archivos:', len(all_files))
            return
        delete = os.environ.get('FLASK_ORPHAN_DELETE') == '1'
        print(f"Encontradas {len(orphans)} imágenes huérfanas de {len(all_files)} archivos totales:")
        for f in orphans:
            print(' -', f)
            if delete:
                try:
                    os.remove(os.path.join(base_dir, f))
                except Exception as e:
                    print('   error eliminando', f, e)
        if delete:
            print('Eliminación completada.')
        else:
            print('Para eliminar establecer FLASK_ORPHAN_DELETE=1')

def _ensure_user_new_columns():
    """Light auto-migration for newly added User columns (SQLite only)."""
    from sqlalchemy import text
    from sqlalchemy.exc import OperationalError
    engine = db.engine
    try:
        with engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info('user')"))
            cols = {row[1] for row in result}
            to_add = []
            if 'email' not in cols:
                to_add.append("ALTER TABLE user ADD COLUMN email VARCHAR(120)")
            if 'failed_attempts' not in cols:
                to_add.append("ALTER TABLE user ADD COLUMN failed_attempts INTEGER DEFAULT 0")
            if 'locked_until' not in cols:
                to_add.append("ALTER TABLE user ADD COLUMN locked_until DATETIME")
            if 'last_login' not in cols:
                to_add.append("ALTER TABLE user ADD COLUMN last_login DATETIME")
            if 'last_password_change' not in cols:
                to_add.append("ALTER TABLE user ADD COLUMN last_password_change DATETIME")
            if 'created_at' not in cols:
                to_add.append("ALTER TABLE user ADD COLUMN created_at DATETIME")
            for stmt in to_add:
                try:
                    conn.execute(text(stmt))
                except OperationalError:
                    pass
            if 'email' not in cols:
                try:
                    conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_user_email ON user(email)"))
                except OperationalError:
                    pass
    except Exception:
        return
