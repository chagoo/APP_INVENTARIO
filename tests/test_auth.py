import pytest
from inventario import create_app, db
from inventario.models import User


@pytest.fixture
def app():
    app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
    })
    with app.app_context():
        admin = User(username='admin', role='admin')
        admin.set_password('secret')
        user = User(username='user', role='user')
        user.set_password('secret')
        db.session.add_all([admin, user])
        db.session.commit()
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, username, password):
    return client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)


def test_requires_login(client):
    resp = client.get('/inventario/nuevo')
    assert resp.status_code == 302


def test_admin_can_access(client):
    login(client, 'admin', 'secret')
    resp = client.get('/inventario/nuevo')
    assert resp.status_code == 200


def test_user_forbidden(client):
    login(client, 'user', 'secret')
    resp = client.get('/inventario/nuevo')
    assert resp.status_code == 403
