from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_cors import CORS
from flask_login import LoginManager
from pathlib import Path
import os

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()


def create_app(test_config=None):
    app = Flask(__name__, static_folder="static", template_folder="templates")

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
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
        # Importar modelos antes de crear tablas para que todos estén registrados (incluye LocalRef)
        from . import models  # noqa: F401
        db.create_all()  # crea tablas faltantes sin tocar las existentes
        _ensure_user_new_columns()  # asegurar columnas nuevas en user
        from .routes import web_bp, api_bp
        app.register_blueprint(web_bp)
        app.register_blueprint(api_bp, url_prefix="/api")
        # Seed default admin si no hay usuarios
        from .models import User
        if User.query.count() == 0 and not app.config.get('TESTING'):
            default_user = os.environ.get('ADMIN_USER', 'admin')
            default_pass = os.environ.get('ADMIN_PASS', 'admin')
            u = User(username=default_user, role='admin')
            u.set_password(default_pass)
            db.session.add(u)
            db.session.commit()
            app.logger.info(f"Usuario admin creado: {default_user} (cambia la contraseña ASAP)")

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
