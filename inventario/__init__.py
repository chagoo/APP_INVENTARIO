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

    from .routes import web_bp, api_bp
    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    with app.app_context():
        db.create_all()
        # Seed default admin if no users exist
        from .models import User
        if User.query.count() == 0:
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
