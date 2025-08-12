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

    return app


@login_manager.user_loader
def load_user(user_id):
    from .models import User
    return User.query.get(int(user_id))
