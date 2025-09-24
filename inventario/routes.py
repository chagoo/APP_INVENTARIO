from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file, current_app, make_response
from flask_login import login_user, logout_user, login_required, current_user
from . import db, csrf
from .models import Inventario, User, AuditLog
from .forms import InventarioForm, SearchForm, LoginForm, UserCreateForm, UserEditForm, LocalRefForm, OperationChecklistForm
from .models import LocalRef, OperationChecklist, OperationChecklistItem, ChecklistActividad, NOCIncident, Operador
from .locales_data import CHECKLIST_SERVICIOS_BASE
from io import StringIO, BytesIO
import csv
from datetime import datetime, timedelta
import secrets
import hashlib
from functools import wraps
from PIL import Image
import os

MAX_IMAGE_BYTES = 500 * 1024  # 500 KB
ALLOWED_FORMATS = {'PNG','JPEG','JPG','GIF','WEBP'}

def validate_image(file_storage):
    """Valida tamaño y formato real de la imagen.

    Retorna (ok, error_message, detected_format)
    """
    if not file_storage or not getattr(file_storage, 'filename', None):
        return False, 'Archivo vacío', None
    # Tamaño (si está disponible via stream)
    file_storage.stream.seek(0, 2)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size > MAX_IMAGE_BYTES:
        return False, f'Tamaño excede 500KB ({size//1024}KB)', None
    try:
        img = Image.open(file_storage.stream)
        fmt = (img.format or '').upper()
        if fmt == 'JPG':
            fmt = 'JPEG'
        if fmt not in ALLOWED_FORMATS:
            return False, f'Formato no permitido: {fmt}', fmt
        # Rewind para permitir save()
        file_storage.stream.seek(0)
        return True, None, fmt
    except Exception:
        file_storage.stream.seek(0)
        return False, 'Archivo no es una imagen válida', None

web_bp = Blueprint('web', __name__)
api_bp = Blueprint('api', __name__)
APP_VERSION = '2025.09.22-checklists'


def require_api_token(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = current_app.config.get('API_TOKEN')
        if token and request.headers.get('X-API-KEY') != token:
            return jsonify({'error': 'unauthorized'}), 401
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                return "Forbidden", 403
            return view(*args, **kwargs)
        return wrapped
    return decorator

@web_bp.route('/')
def index():
    return render_template('index.html')

@web_bp.route('/__health')
def health():
    # Dev aide: lista rutas y versión usando el mapa global de la app
    try:
        rules = sorted([r.rule for r in current_app.url_map.iter_rules()])
    except Exception:
        rules = []
    return jsonify({
        'version': APP_VERSION,
        'routes_contains_checklists': any('checklists' in r for r in rules),
        'total_rules': len(rules),
        'sample': rules[:25]
    })


@web_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # Si no hay usuarios aún, redirigir al bootstrap
    if User.query.count() == 0:
        return redirect(url_for('web.bootstrap_admin'))
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            flash('Credenciales inválidas', 'danger')
        else:
            if user.is_locked():
                flash('Cuenta bloqueada temporalmente. Intenta más tarde.', 'warning')
            elif user.check_password(form.password.data):
                user.failed_attempts = 0
                user.locked_until = None
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user)
                log_event('login_success', user.id, ip=request.remote_addr)
                return redirect(url_for('web.index'))
            else:
                user.register_failed_attempt()
                db.session.commit()
                log_event('login_failed', user.id if user else None, ip=request.remote_addr)
                flash('Credenciales inválidas', 'danger')
    return render_template('login.html', form=form, User=User)

@web_bp.route('/bootstrap', methods=['GET','POST'])
def bootstrap_admin():
    """Crear el primer usuario admin si la tabla user está vacía.

    Expuesto sólo mientras no existan usuarios. Una vez creado redirige a login.
    """
    if User.query.count() > 0:
        return redirect(url_for('web.login'))
    form = UserCreateForm(role='admin')
    # Forzar rol admin y ocultar selección en template (se maneja en template condicionalmente).
    if request.method == 'POST':
        # Forzar rol admin aunque el formulario lo traiga distinto
        form.role.data = 'admin'
        if form.validate_on_submit():
            u = User(username=form.username.data, role='admin')
            u.set_password(form.password.data)
            db.session.add(u)
            db.session.commit()
            flash('Usuario admin creado. Ahora puedes iniciar sesión.','success')
            return redirect(url_for('web.login'))
    return render_template('bootstrap_admin.html', form=form)


@web_bp.route('/logout')
@login_required
def logout():
    logout_user()
    log_event('logout', current_user.id if current_user.is_authenticated else None, ip=request.remote_addr)
    return redirect(url_for('web.index'))

# --- Password Reset ---
def generate_reset_token(user, expires_minutes=30):
    raw = f"{user.id}:{user.password_hash}:{datetime.utcnow().isoformat()}:{secrets.token_urlsafe(16)}"
    token = hashlib.sha256(raw.encode()).hexdigest()
    current_app.config.setdefault('RESET_TOKENS', {})
    current_app.config['RESET_TOKENS'][token] = (user.id, datetime.utcnow() + timedelta(minutes=expires_minutes))
    return token

def validate_reset_token(token):
    data = current_app.config.get('RESET_TOKENS', {}).get(token)
    if not data:
        return None
    user_id, expires = data
    if expires < datetime.utcnow():
        current_app.config['RESET_TOKENS'].pop(token, None)
        return None
    return User.query.get(user_id)

@web_bp.route('/password/reset', methods=['GET','POST'])
def password_reset_request():
    if request.method == 'POST':
        username_or_email = request.form.get('identity','').strip()
        user = User.query.filter((User.username==username_or_email) | (User.email==username_or_email)).first()
        if user:
            token = generate_reset_token(user)
            reset_link = url_for('web.password_reset_token', token=token, _external=True)
            # Placeholder de envío: aquí se integraría con un servicio de correo real
            current_app.logger.info(f"Enlace de reseteo para {user.username}: {reset_link}")
            flash('Si el usuario existe, se envió un enlace de restablecimiento (ver logs).','info')
        else:
            flash('Si el usuario existe, se envió un enlace de restablecimiento (ver logs).','info')
        return redirect(url_for('web.login'))
    return render_template('password_reset_request.html')

@web_bp.route('/password/reset/<token>', methods=['GET','POST'])
def password_reset_token(token):
    user = validate_reset_token(token)
    if not user:
        flash('Token inválido o expirado','danger')
        return redirect(url_for('web.login'))
    if request.method == 'POST':
        pw1 = request.form.get('password')
        pw2 = request.form.get('confirm')
        if not pw1 or len(pw1) < 4:
            flash('Contraseña muy corta','danger')
        elif pw1 != pw2:
            flash('No coincide la confirmación','danger')
        else:
            user.set_password(pw1)
            db.session.commit()
            flash('Contraseña actualizada','success')
            log_event('password_reset', user.id, ip=request.remote_addr)
            return redirect(url_for('web.login'))
    return render_template('password_reset_form.html', token=token)

def log_event(action, user_id=None, entity_type=None, entity_id=None, meta=None, ip=None):
    try:
        event = AuditLog(user_id=user_id, action=action, entity_type=entity_type, entity_id=str(entity_id) if entity_id else None, meta=meta, ip=ip)
        db.session.add(event)
        db.session.commit()
    except Exception:
        db.session.rollback()

@web_bp.route('/inventario/nuevo', methods=['GET','POST'])
@roles_required('admin')
def inventario_nuevo():
    form = InventarioForm()
    locales = LocalRef.query.order_by(LocalRef.local).limit(50).all()  # solo algunos por si quieres mostrar algo inicial
    if form.validate_on_submit():
        # Forzar datos canónicos si el local existe en catálogo
        canon = LocalRef.query.filter_by(local=form.local.data.strip()).first()
        if canon:
            orig_region, orig_distrito, orig_farmacia = form.region.data, form.distrito.data, form.farmacia.data
            form.region.data = canon.region
            form.distrito.data = canon.distrito
            form.farmacia.data = canon.farmacia
            if (orig_region, orig_distrito, orig_farmacia) != (canon.region, canon.distrito, canon.farmacia):
                flash('Datos de región/distrito/farmacia ajustados al catálogo','info')
        item = Inventario(
            region=form.region.data,
            distrito=form.distrito.data,
            local=form.local.data,
            farmacia=form.farmacia.data,
            puntos_venta=form.puntos_venta.data,
            puntos_falla=form.puntos_falla.data,
            monitor_cliente=form.monitor_cliente.data,
            monitor_asesor=form.monitor_asesor.data,
            teclado=form.teclado.data,
            escaner=form.escaner.data,
            mouse_pcm=form.mouse_pcm.data,
            teclado_pcm=form.teclado_pcm.data,
            ups=form.ups.data,
            red_lenta=form.red_lenta.data,
            pinpad=form.pinpad.data,
            estado_reporte=form.estado_reporte.data,
            fecha_solucion=form.fecha_solucion.data,
            comentarios=form.comentarios.data,
        )
        db.session.add(item)
        db.session.commit()
        flash('Inventario guardado','success')
        log_event('inventario_create', current_user.id, 'Inventario', item.id, ip=request.remote_addr)
        return redirect(url_for('web.inventario_listar'))
    return render_template('inventario_form.html', form=form, locales=[l.to_dict() for l in locales])


@web_bp.route('/inventario/<int:item_id>/editar', methods=['GET', 'POST'])
@roles_required('admin','user')
def inventario_editar(item_id):
    item = Inventario.query.get_or_404(item_id)
    form = InventarioForm(obj=item)
    locales = LocalRef.query.order_by(LocalRef.local).limit(50).all()
    if form.validate_on_submit():
        canon = LocalRef.query.filter_by(local=form.local.data.strip()).first()
        if canon:
            form.region.data = canon.region
            form.distrito.data = canon.distrito
            form.farmacia.data = canon.farmacia
            flash('Datos de región/distrito/farmacia ajustados al catálogo','info')
        form.populate_obj(item)
        db.session.commit()
        flash('Inventario actualizado', 'success')
        log_event('inventario_update', current_user.id, 'Inventario', item.id, ip=request.remote_addr)
        return redirect(url_for('web.inventario_listar'))
    return render_template('inventario_form.html', form=form, locales=[l.to_dict() for l in locales])


@web_bp.route('/inventario/<int:item_id>/eliminar', methods=['POST'])
@roles_required('admin')
def inventario_eliminar(item_id):
    item = Inventario.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Inventario eliminado', 'success')
    log_event('inventario_delete', current_user.id, 'Inventario', item.id, ip=request.remote_addr)
    return redirect(url_for('web.inventario_listar'))

@web_bp.route('/inventario', methods=['GET','POST'])
@roles_required('admin','user')
def inventario_listar():
    form = SearchForm()
    page = request.args.get('page', 1, type=int)
    query = Inventario.query
    filtro_local = ''
    if form.validate_on_submit():
        filtro_local = form.search.data or ''
    else:
        filtro_local = request.args.get('search','')
    if filtro_local:
        query = query.filter(Inventario.local.ilike(f"%{filtro_local}%"))
    paginated = query.order_by(Inventario.fecha_registro.desc()).paginate(page=page, per_page=20)
    return render_template('inventario_list.html', form=form, inventario=paginated.items,
                           prev_page=paginated.prev_num if paginated.has_prev else None,
                           next_page=paginated.next_num if paginated.has_next else None,
                           filtro_local=filtro_local)

@web_bp.route('/inventario/<int:item_id>/cerrar', methods=['POST'])
@roles_required('admin','user')
def inventario_cerrar(item_id):
    item = Inventario.query.get_or_404(item_id)
    item.estado_reporte = 'Cerrado'
    if not item.fecha_solucion:
        item.fecha_solucion = datetime.utcnow().date()
    db.session.commit()
    flash('Reporte cerrado','success')
    log_event('inventario_close', current_user.id, 'Inventario', item.id, ip=request.remote_addr)
    return redirect(url_for('web.inventario_listar'))

@web_bp.route('/locales/cargar', methods=['POST'])
@roles_required('admin')
def locales_cargar():
    """Carga masiva rápida desde un textarea (REGION\tDISTRITO\tLOCAL\tFARMACIA)."""
    contenido = request.form.get('data','').strip()
    if not contenido:
        flash('Sin datos','warning')
        return redirect(url_for('web.inventario_listar'))
    # Normalizar: algunos pegados muestran 't\' en vez de \t
    contenido_norm = contenido.replace('t\\', '\t').replace('t/', '\t')
    lines = [l for l in contenido_norm.splitlines() if l.strip()]
    creados = 0
    for line in lines:
        raw_parts = line.split('\t')
        parts = [p.strip() for p in raw_parts if p is not None]
        if len(parts) < 4:
            continue
        region, distrito, local_code, farmacia = parts[:4]
        if not local_code:
            continue
        if not LocalRef.query.filter_by(local=local_code).first():
            db.session.add(LocalRef(region=region, distrito=distrito, local=local_code, farmacia=farmacia))
            creados += 1
    db.session.commit()
    flash(f'{creados} locales cargados','success')
    if creados:
        log_event('locales_bulk_load', current_user.id, 'LocalRef', meta=f'{creados} nuevos', ip=request.remote_addr)
    return redirect(url_for('web.locales_form_cargar'))

@web_bp.route('/locales/cargar', methods=['GET'])
@roles_required('admin')
def locales_form_cargar():
    existentes = LocalRef.query.order_by(LocalRef.local).limit(200).all()
    return render_template('locales_cargar.html', existentes=existentes)

@web_bp.route('/locales', methods=['GET'])
@roles_required('admin')
def locales_listar():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    q = request.args.get('q','').strip()
    query = LocalRef.query
    if q:
        like = f"%{q}%"
        query = query.filter((LocalRef.local.ilike(like)) | (LocalRef.farmacia.ilike(like)) | (LocalRef.distrito.ilike(like)))
    total = query.count()
    paginated = query.order_by(LocalRef.local).paginate(page=page, per_page=per_page)
    return render_template('locales_list.html', locales=paginated.items, total=total, page=page,
                           pages=paginated.pages, q=q, has_prev=paginated.has_prev, has_next=paginated.has_next,
                           prev_page=paginated.prev_num if paginated.has_prev else None,
                           next_page=paginated.next_num if paginated.has_next else None)

@web_bp.route('/locales/nuevo', methods=['GET','POST'])
@roles_required('admin')
def locales_nuevo():
    form = LocalRefForm()
    if form.validate_on_submit():
        if LocalRef.query.filter_by(local=form.local.data).first():
            flash('Local ya existe','warning')
        else:
            l = LocalRef(region=form.region.data, distrito=form.distrito.data, local=form.local.data, farmacia=form.farmacia.data)
            db.session.add(l)
            db.session.commit()
            flash('Local creado','success')
            log_event('local_create', current_user.id, 'LocalRef', l.id, ip=request.remote_addr)
            return redirect(url_for('web.locales_listar'))
    return render_template('local_form.html', form=form, modo='nuevo')

@web_bp.route('/locales/<int:local_id>/editar', methods=['GET','POST'])
@roles_required('admin')
def locales_editar(local_id):
    l = LocalRef.query.get_or_404(local_id)
    form = LocalRefForm(obj=l)
    if form.validate_on_submit():
        # Si cambia el código local validar unicidad
        if form.local.data != l.local and LocalRef.query.filter_by(local=form.local.data).first():
            flash('Código local ya existe','warning')
        else:
            form.populate_obj(l)
            db.session.commit()
            flash('Local actualizado','success')
            log_event('local_update', current_user.id, 'LocalRef', l.id, ip=request.remote_addr)
            return redirect(url_for('web.locales_listar'))
    return render_template('local_form.html', form=form, modo='editar', local_ref=l)

@web_bp.route('/locales/<int:local_id>/eliminar', methods=['POST'])
@roles_required('admin')
def locales_eliminar(local_id):
    l = LocalRef.query.get_or_404(local_id)
    db.session.delete(l)
    db.session.commit()
    flash('Local eliminado','success')
    log_event('local_delete', current_user.id, 'LocalRef', l.id, ip=request.remote_addr)
    return redirect(url_for('web.locales_listar'))

@web_bp.route('/locales/eliminar_todos', methods=['POST'])
@roles_required('admin')
def locales_eliminar_todos():
    borrados = LocalRef.query.delete()
    db.session.commit()
    flash(f'{borrados} locales eliminados','success')
    if borrados:
        log_event('local_delete_all', current_user.id, 'LocalRef', meta=f'{borrados} eliminados', ip=request.remote_addr)
    return redirect(url_for('web.locales_listar'))

@web_bp.route('/locales/csv')
@roles_required('admin')
def locales_csv():
    from io import StringIO, BytesIO
    import csv
    output_text = StringIO()
    writer = csv.writer(output_text)
    writer.writerow(['region','distrito','local','farmacia'])
    for l in LocalRef.query.order_by(LocalRef.local).all():
        writer.writerow([l.region, l.distrito, l.local, l.farmacia])
    data = '\ufeff' + output_text.getvalue()
    bio = BytesIO(data.encode('utf-8'))
    bio.seek(0)
    return send_file(bio, mimetype='text/csv; charset=utf-8', as_attachment=True, download_name='locales.csv')

@web_bp.route('/locales/importar', methods=['GET','POST'])
@roles_required('admin')
def locales_importar_csv():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('Archivo no seleccionado','warning')
            return redirect(request.url)
        try:
            content = file.read().decode('utf-8-sig')
        except UnicodeDecodeError:
            content = file.read().decode('latin-1')
        reader = csv.reader(content.splitlines())
        header = next(reader, [])
        # Permitir encabezados variables en minúsculas
        header_norm = [h.strip().lower() for h in header]
        idx_map = {name: header_norm.index(name) for name in ['region','distrito','local','farmacia'] if name in header_norm}
        if len(idx_map) < 4:
            flash('Encabezados requeridos: region,distrito,local,farmacia','danger')
            return redirect(request.url)
        creados = 0
        for row in reader:
            if not row or len(row) < 4:
                continue
            try:
                region = row[idx_map['region']].strip()
                distrito = row[idx_map['distrito']].strip()
                local_code = row[idx_map['local']].strip()
                farmacia = row[idx_map['farmacia']].strip()
            except Exception:
                continue
            if not local_code:
                continue
            if not LocalRef.query.filter_by(local=local_code).first():
                db.session.add(LocalRef(region=region, distrito=distrito, local=local_code, farmacia=farmacia))
                creados += 1
        db.session.commit()
        flash(f'{creados} locales importados','success')
        if creados:
            log_event('locales_import_csv', current_user.id, 'LocalRef', meta=f'{creados} nuevos', ip=request.remote_addr)
        return redirect(url_for('web.locales_listar'))
    return render_template('locales_importar.html')

@web_bp.route('/usuarios')
@roles_required('admin')
def usuarios_listar():
    usuarios = User.query.order_by(User.username).all()
    return render_template('users_list.html', usuarios=usuarios)

@web_bp.route('/usuarios/nuevo', methods=['GET','POST'])
@roles_required('admin')
def usuarios_nuevo():
    form = UserCreateForm()
    if form.validate_on_submit():
        u = User(username=form.username.data, role=form.role.data)
        u.set_password(form.password.data)
        db.session.add(u)
        db.session.commit()
        flash('Usuario creado','success')
        log_event('user_create', current_user.id, 'User', u.id, ip=request.remote_addr)
        return redirect(url_for('web.usuarios_listar'))
    return render_template('user_form.html', form=form, modo='nuevo')

@web_bp.route('/usuarios/<int:user_id>/editar', methods=['GET','POST'])
@roles_required('admin')
def usuarios_editar(user_id):
    u = User.query.get_or_404(user_id)
    form = UserEditForm(role=u.role)
    if form.validate_on_submit():
        u.role = form.role.data
        if form.password.data:
            u.set_password(form.password.data)
        db.session.commit()
        flash('Usuario actualizado','success')
        log_event('user_update', current_user.id, 'User', u.id, ip=request.remote_addr)
        return redirect(url_for('web.usuarios_listar'))
    return render_template('user_form.html', form=form, modo='editar', usuario=u)

@web_bp.route('/usuarios/<int:user_id>/eliminar', methods=['POST'])
@roles_required('admin')
def usuarios_eliminar(user_id):
    u = User.query.get_or_404(user_id)
    if u.username == 'admin' and User.query.filter_by(role='admin').count() == 1:
        flash('No se puede eliminar el último admin','warning')
        return redirect(url_for('web.usuarios_listar'))
    db.session.delete(u)
    db.session.commit()
    flash('Usuario eliminado','success')
    log_event('user_delete', current_user.id, 'User', u.id, ip=request.remote_addr)
    return redirect(url_for('web.usuarios_listar'))

@web_bp.route('/inventario/csv')
@roles_required('admin')
def inventario_csv():
    """Genera y entrega el CSV en binario (compatibilidad Excel)."""
    si = StringIO()
    writer = csv.writer(si)
    header = ['id','region','distrito','local','farmacia','puntos_venta','puntos_falla','monitor_cliente','monitor_asesor','teclado','escaner','mouse_pcm','teclado_pcm','ups','red_lenta','pinpad','estado_reporte','fecha_solucion','comentarios','fecha_registro']
    writer.writerow(header)
    for item in Inventario.query.order_by(Inventario.id).all():
        writer.writerow([
            item.id,item.region,item.distrito,item.local,item.farmacia,item.puntos_venta,item.puntos_falla,item.monitor_cliente,item.monitor_asesor,item.teclado,item.escaner,item.mouse_pcm,item.teclado_pcm,item.ups,item.red_lenta,item.pinpad,item.estado_reporte,item.fecha_solucion,item.comentarios,item.fecha_registro
        ])
    csv_text = si.getvalue()
    # Agregamos BOM UTF-8 para que Excel en Windows reconozca acentos correctamente
    output = BytesIO(('\ufeff' + csv_text).encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv; charset=utf-8', as_attachment=True, download_name='inventario.csv')

# API endpoints (JSON) for mobile / PWA usage
@api_bp.route('/inventario', methods=['GET'])
def api_inventario_list():
    search = request.args.get('search','')
    query = Inventario.query
    if search:
        query = query.filter(Inventario.local.ilike(f"%{search}%"))
    data = [i.to_dict() for i in query.order_by(Inventario.fecha_registro.desc()).limit(200)]
    return jsonify(data)

@api_bp.route('/locales', methods=['GET'])
def api_locales_list():
    q = request.args.get('q','').strip()
    query = LocalRef.query
    if q:
        like = f"%{q}%"
        query = query.filter((LocalRef.local.ilike(like)) | (LocalRef.farmacia.ilike(like)))
    return jsonify([l.to_dict() for l in query.order_by(LocalRef.local).limit(500)])

@api_bp.route('/inventario', methods=['POST'])
@csrf.exempt
@require_api_token
def api_inventario_create():
    payload = request.get_json() or {}
    canon = None
    if payload.get('local'):
        canon = LocalRef.query.filter_by(local=str(payload.get('local')).strip()).first()
    item = Inventario(
        region=canon.region if canon else payload.get('region'),
        distrito=canon.distrito if canon else payload.get('distrito'),
        local=payload.get('local'),
        farmacia=canon.farmacia if canon else payload.get('farmacia'),
        puntos_venta=payload.get('puntos_venta'),
        puntos_falla=payload.get('puntos_falla'),
        monitor_cliente=payload.get('monitor_cliente','NO'),
        monitor_asesor=payload.get('monitor_asesor','NO'),
        teclado=payload.get('teclado','NO'),
        escaner=payload.get('escaner','NO'),
        mouse_pcm=payload.get('mouse_pcm','NO'),
        teclado_pcm=payload.get('teclado_pcm','NO'),
        ups=payload.get('ups','NO'),
        red_lenta=payload.get('red_lenta','NO'),
        pinpad=payload.get('pinpad','NO'),
        estado_reporte=payload.get('estado_reporte','Abierto'),
        fecha_solucion=datetime.strptime(payload['fecha_solucion'],'%Y-%m-%d').date() if payload.get('fecha_solucion') else None,
        comentarios=payload.get('comentarios'),
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201

# ---------------- Checklist Operación Diaria ----------------
@web_bp.route('/checklists')
@roles_required('admin','user')
def checklist_historial():
    page = request.args.get('page', 1, type=int)
    fecha = request.args.get('fecha','').strip()
    query = OperationChecklist.query
    if fecha:
        try:
            f = datetime.strptime(fecha, '%Y-%m-%d').date()
            query = query.filter(OperationChecklist.fecha==f)
        except ValueError:
            flash('Fecha inválida, use formato YYYY-MM-DD','warning')
    paginated = query.order_by(OperationChecklist.fecha.desc(), OperationChecklist.id.desc()).paginate(page=page, per_page=15)
    return render_template('checklist_list.html', registros=paginated.items, page=page,
                           next_page=paginated.next_num if paginated.has_next else None,
                           prev_page=paginated.prev_num if paginated.has_prev else None,
                           filtro_fecha=fecha)

def _build_checklist_form(fecha=None):
    form = OperationChecklistForm()
    # cargar operadores activos como choices (email mostrado y guardado)
    try:
        ops = Operador.query.filter_by(activo=True).order_by(Operador.nombre).all()
        choices = [('', '-')]+[(o.email, f"{o.nombre} — {o.email}") for o in ops]
    except Exception:
        choices = [('', '-')]
    # email del usuario logueado para autoselección
    try:
        default_email = (current_user.email or '').strip()
    except Exception:
        default_email = ''
    if not form.items.entries:  # inicializar (solo estructura básica)
        actividades = ChecklistActividad.query.filter_by(activo=True).order_by(ChecklistActividad.orden, ChecklistActividad.id).all()
        source = [(a.servicio, a.responsable, a.hora_objetivo) for a in actividades] if actividades else CHECKLIST_SERVICIOS_BASE
        for idx, (servicio, responsable, hora) in enumerate(source):
            form.items.append_entry({})
            entry = form.items.entries[-1]
            entry.form.servicio.data = servicio
            entry.form.responsable.data = responsable
            entry.form.hora_objetivo.data = hora
            # set default solo en GET para no sobrescribir POST
            if request.method != 'POST':
                values = {v for v,_ in choices}
                if default_email and default_email in values:
                    entry.form.operador.data = default_email
            entry.form._idx.data = str(idx)
    # Asegurar que todas las entradas tengan choices configurados (POST/GET)
    for entry in form.items.entries:
        try:
            entry.form.operador.choices = choices
        except Exception:
            pass
    if fecha:
        form.fecha.data = fecha
    # También devolver mapping servicio->imagen_ref para mostrar en template
    imagenes = {}
    try:
        for a in actividades:
            if a.imagen_ref:
                imagenes[a.servicio] = a.imagen_ref
    except Exception:
        pass
    return form, imagenes

@web_bp.route('/checklists/nuevo', methods=['GET','POST'])
@roles_required('admin','user')
def checklist_nuevo():
    from datetime import date
    from werkzeug.utils import secure_filename
    import os
    form, imagenes_map = _build_checklist_form(date.today())
    if form.validate_on_submit():
        chk = OperationChecklist(
            fecha=form.fecha.data or date.today(),
            comentarios=form.comentarios.data,
            usuario_id=current_user.id,
        )
        for entry in form.items.entries:
            # Procesar archivo si se subió para este servicio
            upload = entry.form.image_file.data
            img_filename = imagenes_map.get(entry.form.servicio.data)
            if upload and getattr(upload, 'filename', None):
                ok, err, fmt = validate_image(upload)
                if not ok:
                    flash(f"Imagen inválida para {entry.form.servicio.data}: {err}", 'danger')
                else:
                    fname = secure_filename(upload.filename)
                    os.makedirs(os.path.join(current_app.static_folder, 'actividades'), exist_ok=True)
                    img_filename = f"item_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{fname}"
                    upload.save(os.path.join(current_app.static_folder, 'actividades', img_filename))
            item = OperationChecklistItem(
                servicio=entry.form.servicio.data,
                responsable=entry.form.responsable.data,
                hora_objetivo=entry.form.hora_objetivo.data,
                estado=entry.form.estado.data,
                operador=(entry.form.operador.data or None),
                observacion=entry.form.observacion.data,
                imagen_ref=img_filename
            )
            chk.items.append(item)
        db.session.add(chk)
        db.session.commit()
        flash('Checklist guardado','success')
        log_event('checklist_create', current_user.id, 'OperationChecklist', chk.id, ip=request.remote_addr)
        return redirect(url_for('web.checklist_historial'))
    return render_template('checklist_form.html', form=form, imagenes_map=imagenes_map)

@web_bp.route('/checklists/<int:chk_id>')
@roles_required('admin','user')
def checklist_ver(chk_id):
    chk = OperationChecklist.query.get_or_404(chk_id)
    from datetime import date
    return render_template('checklist_ver.html', chk=chk, hoy=date.today())

def _build_checklist_edit_form(chk: OperationChecklist):
    form = OperationChecklistForm()
    try:
        ops = Operador.query.filter_by(activo=True).order_by(Operador.nombre).all()
        choices = [('', '-')]+[(o.email, f"{o.nombre} — {o.email}") for o in ops]
    except Exception:
        choices = [('', '-')]
    try:
        default_email = (current_user.email or '').strip()
    except Exception:
        default_email = ''
    if request.method != 'POST':
        form.fecha.data = chk.fecha
        form.comentarios.data = chk.comentarios
    items_sorted = sorted(chk.items, key=lambda x: x.id)
    existing_services = set()
    if request.method != 'POST':
        # Construir entradas desde los items del modelo (GET)
        for idx, it in enumerate(items_sorted):
            form.items.append_entry({})
            entry = form.items.entries[-1]
            entry.form.servicio.data = it.servicio
            existing_services.add(it.servicio.strip().lower())
            entry.form.responsable.data = it.responsable
            entry.form.hora_objetivo.data = it.hora_objetivo
            entry.form.estado.data = it.estado
            entry.form.operador.choices = choices
            try:
                entry.form.operador.data = it.operador or (default_email if default_email in {v for v,_ in choices} else '')
            except Exception:
                pass
            entry.form.observacion.data = it.observacion
            entry.form._idx.data = str(idx)
    else:
        # En POST, solo asegurar choices en entradas existentes del form
        for entry in form.items.entries:
            try:
                entry.form.operador.choices = choices
            except Exception:
                pass
    # Detectar actividades nuevas activas que no están en el checklist
    nuevas = ChecklistActividad.query.filter_by(activo=True).order_by(ChecklistActividad.orden, ChecklistActividad.id).all()
    added = 0
    base_idx = len(form.items.entries)
    for offset, act in enumerate(nuevas):
        key = act.servicio.strip().lower()
        if key in existing_services:
            continue
        if request.method != 'POST':
            form.items.append_entry({})
            entry = form.items.entries[-1]
            entry.form.servicio.data = act.servicio
            entry.form.responsable.data = act.responsable
            entry.form.hora_objetivo.data = act.hora_objetivo
            entry.form.estado.data = 'Pendiente'
            entry.form.observacion.data = ''
            entry.form.operador.choices = choices
            # autoselect solo en GET
            if default_email and default_email in {v for v,_ in choices}:
                entry.form.operador.data = default_email
            entry.form._idx.data = str(base_idx + added)
            added += 1
            existing_services.add(key)
    return form

@web_bp.route('/checklists/<int:chk_id>/editar', methods=['GET','POST'])
@roles_required('admin','user')
def checklist_editar(chk_id):
    from datetime import date
    from werkzeug.utils import secure_filename
    import os
    chk = OperationChecklist.query.get_or_404(chk_id)
    if chk.fecha != date.today():
        flash('Solo se pueden editar checklists del día actual','warning')
        return redirect(url_for('web.checklist_ver', chk_id=chk.id))
    form = _build_checklist_edit_form(chk)
    # Mapping de imágenes (actividades + items ya guardados)
    imagenes_map = {a.servicio: a.imagen_ref for a in ChecklistActividad.query.filter(ChecklistActividad.imagen_ref != None).all() if a.imagen_ref}
    for it in chk.items:
        if it.imagen_ref and it.servicio not in imagenes_map:
            imagenes_map[it.servicio] = it.imagen_ref
    if form.validate_on_submit():
        # Actualización parcial: iterar por índice mientras existan model items
        form.comentarios.data and setattr(chk, 'comentarios', form.comentarios.data)
        items_sorted = sorted(chk.items, key=lambda x: x.id)
        total_existing = len(items_sorted)
        # Primero actualizar los existentes
        for i in range(min(total_existing, len(form.items.entries))):
            entry = form.items.entries[i]
            if i >= total_existing:
                break
            model_item = items_sorted[i]
            if entry.form.estado.data:
                model_item.estado = entry.form.estado.data
            model_item.operador = (entry.form.operador.data or None)
            model_item.observacion = entry.form.observacion.data
            upload = entry.form.image_file.data
            if upload and getattr(upload, 'filename', None):
                ok, err, fmt = validate_image(upload)
                if not ok:
                    flash(f"Imagen inválida para {entry.form.servicio.data}: {err}", 'danger')
                else:
                    fname = secure_filename(upload.filename)
                    os.makedirs(os.path.join(current_app.static_folder, 'actividades'), exist_ok=True)
                    img_filename = f"item_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{fname}"
                    upload.save(os.path.join(current_app.static_folder, 'actividades', img_filename))
                    model_item.imagen_ref = img_filename
        # Luego crear nuevos items (los que exceden total_existing)
        nuevos_creados = 0
        normalized_existing = {it.servicio.strip().lower(): it for it in items_sorted}
        for j in range(total_existing, len(form.items.entries)):
            entry = form.items.entries[j]
            # Evitar crear si por alguna razón servicio vacío
            servicio = entry.form.servicio.data
            if not servicio:
                continue
            key = servicio.strip().lower()
            if key in normalized_existing:  # ya existe, no crear duplicado
                continue
            item = OperationChecklistItem(
                servicio=servicio,
                responsable=entry.form.responsable.data,
                hora_objetivo=entry.form.hora_objetivo.data,
                estado=entry.form.estado.data or 'Pendiente',
                operador=(entry.form.operador.data or None),
                observacion=entry.form.observacion.data,
            )
            upload = entry.form.image_file.data
            if upload and getattr(upload, 'filename', None):
                ok, err, fmt = validate_image(upload)
                if ok:
                    fname = secure_filename(upload.filename)
                    os.makedirs(os.path.join(current_app.static_folder, 'actividades'), exist_ok=True)
                    img_filename = f"item_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{fname}"
                    upload.save(os.path.join(current_app.static_folder, 'actividades', img_filename))
                    item.imagen_ref = img_filename
                else:
                    flash(f"Imagen inválida para {servicio}: {err}", 'danger')
            chk.items.append(item)
            nuevos_creados += 1
        # Deduplicar por servicio (caso de estados previos) conservando el primer item
        seen = set()
        to_delete = []
        for it in chk.items:
            k = (it.servicio or '').strip().lower()
            if k in seen:
                to_delete.append(it)
            else:
                seen.add(k)
        for it in to_delete:
            db.session.delete(it)
        db.session.commit()
        msg = 'Checklist actualizado'
        if nuevos_creados:
            msg += f' (+{nuevos_creados} actividades nuevas)'
        if to_delete:
            msg += f' (deduplicadas {len(to_delete)})'
        flash(msg,'success')
        log_event('checklist_update', current_user.id, 'OperationChecklist', chk.id, ip=request.remote_addr)
        return redirect(url_for('web.checklist_ver', chk_id=chk.id))
    return render_template('checklist_form.html', form=form, modo='editar', imagenes_map=imagenes_map)

# ---- Administración de actividades del checklist ----
@web_bp.route('/checklists/actividades')
@roles_required('admin','user')
def checklist_actividades_list():
    acts = ChecklistActividad.query.order_by(ChecklistActividad.activo.desc(), ChecklistActividad.orden, ChecklistActividad.id).all()
    return render_template('checklist_actividades_list.html', actividades=acts)

@web_bp.route('/checklists/actividades/nueva', methods=['GET','POST'])
@roles_required('admin','user')
def checklist_actividad_nueva():
    from .forms import ChecklistActividadForm
    from werkzeug.utils import secure_filename
    import os
    form = ChecklistActividadForm()
    if form.validate_on_submit():
        filename = None
        file = request.files.get('imagen_file')
        if file and file.filename:
            ok, err, fmt = validate_image(file)
            if not ok:
                flash(err,'danger')
                return render_template('checklist_actividad_form.html', form=form, modo='nueva')
            fname = secure_filename(file.filename)
            os.makedirs(os.path.join(current_app.static_folder, 'actividades'), exist_ok=True)
            filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{fname}"
            file.save(os.path.join(current_app.static_folder, 'actividades', filename))
        act = ChecklistActividad(
            servicio=form.servicio.data.strip(),
            responsable=form.responsable.data.strip() if form.responsable.data else None,
            hora_objetivo=form.hora_objetivo.data.strip() if form.hora_objetivo.data else None,
            orden=form.orden.data or 0,
            activo=True if form.activo.data=='1' else False,
            imagen_ref=filename
        )
        db.session.add(act)
        db.session.commit()
        flash('Actividad creada','success')
        return redirect(url_for('web.checklist_actividades_list'))
    return render_template('checklist_actividad_form.html', form=form, modo='nueva')

@web_bp.route('/checklists/actividades/<int:act_id>/editar', methods=['GET','POST'])
@roles_required('admin','user')
def checklist_actividad_editar(act_id):
    from .forms import ChecklistActividadForm
    from werkzeug.utils import secure_filename
    import os
    act = ChecklistActividad.query.get_or_404(act_id)
    form = ChecklistActividadForm(servicio=act.servicio, responsable=act.responsable, hora_objetivo=act.hora_objetivo, orden=act.orden, activo='1' if act.activo else '0')
    form.imagen_ref.data = act.imagen_ref
    if form.validate_on_submit():
        act.servicio = form.servicio.data.strip()
        act.responsable = form.responsable.data.strip() if form.responsable.data else None
        act.hora_objetivo = form.hora_objetivo.data.strip() if form.hora_objetivo.data else None
        act.orden = form.orden.data or 0
        act.activo = True if form.activo.data=='1' else False
        file = request.files.get('imagen_file')
        if file and file.filename:
            ok, err, fmt = validate_image(file)
            if not ok:
                flash(err,'danger')
                return render_template('checklist_actividad_form.html', form=form, modo='editar', actividad=act)
            fname = secure_filename(file.filename)
            os.makedirs(os.path.join(current_app.static_folder, 'actividades'), exist_ok=True)
            filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{fname}"
            file.save(os.path.join(current_app.static_folder, 'actividades', filename))
            act.imagen_ref = filename
        db.session.commit()
        flash('Actividad actualizada','success')
        return redirect(url_for('web.checklist_actividades_list'))
    return render_template('checklist_actividad_form.html', form=form, modo='editar', actividad=act)

@web_bp.route('/checklists/actividades/<int:act_id>/eliminar', methods=['POST'])
@roles_required('admin')
def checklist_actividad_eliminar(act_id):
    act = ChecklistActividad.query.get_or_404(act_id)
    db.session.delete(act)
    db.session.commit()
    flash('Actividad eliminada','success')
    return redirect(url_for('web.checklist_actividades_list'))

@web_bp.route('/checklists/actividades/csv')
@roles_required('admin','user')
def checklist_actividades_csv():
    """Exporta el catálogo actual de actividades a CSV."""
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['servicio','responsable','hora_objetivo','orden','activo','imagen_ref'])
    for a in ChecklistActividad.query.order_by(ChecklistActividad.orden, ChecklistActividad.id).all():
        writer.writerow([
            a.servicio,
            a.responsable or '',
            a.hora_objetivo or '',
            a.orden or 0,
            '1' if a.activo else '0',
            a.imagen_ref or ''
        ])
    data = '\ufeff' + output.getvalue()
    bio = BytesIO(data.encode('utf-8'))
    bio.seek(0)
    return send_file(bio, mimetype='text/csv; charset=utf-8', as_attachment=True, download_name='checklist_actividades.csv')

@web_bp.route('/checklists/actividades/importar', methods=['GET','POST'])
@roles_required('admin','user')
def checklist_actividades_importar():
    """Importación masiva de actividades desde un CSV.

    Columnas esperadas (en cualquier orden, encabezado obligatorio):
    servicio,responsable,hora_objetivo,orden,activo,imagen_ref
    - activo admite: 1/0, si/no, true/false (case-insensitive)
    - orden se convierte a entero (default 0)
    """
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('Archivo no seleccionado','warning')
            return redirect(request.url)
        try:
            content = file.read().decode('utf-8-sig')
        except UnicodeDecodeError:
            try:
                file.seek(0)
                content = file.read().decode('latin-1')
            except Exception:
                flash('No se pudo leer el archivo (encoding)','danger')
                return redirect(request.url)
        reader = csv.reader(content.splitlines())
        header = next(reader, [])
        header_norm = [h.strip().lower() for h in header]
        if not header_norm:
            flash('CSV vacío','warning')
            return redirect(request.url)
        required = ['servicio']
        if not all(r in header_norm for r in required):
            flash('Encabezado debe incluir al menos la columna servicio','danger')
            return redirect(request.url)
        # Mapear nombre->índice sólo una vez (evitar repetir index())
        idx = {name: i for i, name in enumerate(header_norm)}
        creados = 0
        actualizados = 0
        for row in reader:
            if not row:
                continue
            try:
                servicio = row[idx['servicio']].strip()
            except Exception:
                continue
            if not servicio:
                continue
            responsable = row[idx['responsable']].strip() if 'responsable' in idx and len(row) > idx['responsable'] else None
            hora = row[idx['hora_objetivo']].strip() if 'hora_objetivo' in idx and len(row) > idx['hora_objetivo'] else None
            orden_val = 0
            if 'orden' in idx and len(row) > idx['orden']:
                try:
                    orden_val = int((row[idx['orden']] or '0').strip() or '0')
                except Exception:
                    orden_val = 0
            activo_val = True
            if 'activo' in idx and len(row) > idx['activo']:
                raw_act = (row[idx['activo']] or '').strip().lower()
                if raw_act in ('0','no','false','f','n'):
                    activo_val = False
            imagen_ref = row[idx['imagen_ref']].strip() if 'imagen_ref' in idx and len(row) > idx['imagen_ref'] and row[idx['imagen_ref']] else None
            existente = ChecklistActividad.query.filter_by(servicio=servicio).first()
            if existente:
                existente.responsable = responsable or None
                existente.hora_objetivo = hora or None
                existente.orden = orden_val
                existente.activo = activo_val
                if imagen_ref:
                    existente.imagen_ref = imagen_ref
                actualizados += 1
            else:
                db.session.add(ChecklistActividad(
                    servicio=servicio,
                    responsable=responsable or None,
                    hora_objetivo=hora or None,
                    orden=orden_val,
                    activo=activo_val,
                    imagen_ref=imagen_ref or None
                ))
                creados += 1
        db.session.commit()
        flash(f'Importación completada. {creados} creados, {actualizados} actualizados','success')
        total = creados + actualizados
        if total:
            log_event('checklist_actividades_import_csv', current_user.id, 'ChecklistActividad', meta=f'{creados} nuevos, {actualizados} actualizados', ip=request.remote_addr)
        return redirect(url_for('web.checklist_actividades_list'))
    return render_template('checklist_actividades_importar.html')

@web_bp.route('/checklists/<int:chk_id>/eliminar', methods=['POST'])
@roles_required('admin')
def checklist_eliminar(chk_id):
    chk = OperationChecklist.query.get_or_404(chk_id)
    db.session.delete(chk)
    db.session.commit()
    flash('Checklist eliminado','success')
    log_event('checklist_delete', current_user.id, 'OperationChecklist', chk.id, ip=request.remote_addr)
    return redirect(url_for('web.checklist_historial'))

@web_bp.route('/checklists/csv')
@roles_required('admin')
def checklist_csv():
    # Export incluye imagen_ref y operador: fecha, usuario, servicio, responsable, hora_objetivo, estado, operador, observacion, imagen_ref
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['fecha','usuario','servicio','responsable','hora_objetivo','estado','operador','observacion','imagen_ref'])
    for chk in OperationChecklist.query.order_by(OperationChecklist.fecha.desc(), OperationChecklist.id.desc()).limit(1000):
        user = chk.usuario.username if getattr(chk, 'usuario', None) else ''
        for item in chk.items:
            writer.writerow([chk.fecha, user, item.servicio, item.responsable, item.hora_objetivo, item.estado, (item.operador or ''), (item.observacion or '').replace('\n',' '), item.imagen_ref or ''])
    data = '\ufeff' + output.getvalue()
    bio = BytesIO(data.encode('utf-8'))
    bio.seek(0)
    return send_file(bio, mimetype='text/csv; charset=utf-8', as_attachment=True, download_name='checklists.csv')


# ---------------- Bitácora NOC ----------------
@web_bp.route('/noc', methods=['GET'])
@roles_required('admin','user')
def noc_list():
    q = request.args.get('q','').strip()
    fecha = request.args.get('fecha','').strip()
    page = request.args.get('page', 1, type=int)
    per = 20
    query = NOCIncident.query
    if fecha:
        try:
            f = datetime.strptime(fecha, '%Y-%m-%d').date()
            query = query.filter(NOCIncident.fecha==f)
        except Exception:
            flash('Fecha inválida','warning')
    if q:
        like = f"%{q}%"
        query = query.filter((NOCIncident.sucursal.ilike(like)) | (NOCIncident.ticket.ilike(like)) | (NOCIncident.problema.ilike(like)))
    pag = query.order_by(NOCIncident.fecha.desc(), NOCIncident.id.desc()).paginate(page=page, per_page=per)
    return render_template('noc_list.html', registros=pag.items, page=page,
                           next_page=pag.next_num if pag.has_next else None,
                           prev_page=pag.prev_num if pag.has_prev else None,
                           q=q, filtro_fecha=fecha)

@web_bp.route('/noc/nuevo', methods=['GET','POST'])
@roles_required('admin','user')
def noc_nuevo():
    from .forms import NOCIncidentForm
    form = NOCIncidentForm()
    if form.validate_on_submit():
        inc = NOCIncident(
            fecha=form.fecha.data,
            sucursal=form.sucursal.data,
            ticket=form.ticket.data,
            reporta=form.reporta.data,
            problema=form.problema.data,
            proveedor=form.proveedor.data,
            solucion=form.solucion.data,
            tiempo_solucion=form.tiempo_solucion.data,
            caida=form.caida.data or None,
        )
        db.session.add(inc)
        db.session.commit()
        flash('Incidente creado','success')
        return redirect(url_for('web.noc_list'))
    return render_template('noc_form.html', form=form, modo='nuevo')

@web_bp.route('/noc/<int:inc_id>/editar', methods=['GET','POST'])
@roles_required('admin','user')
def noc_editar(inc_id):
    from .forms import NOCIncidentForm
    inc = NOCIncident.query.get_or_404(inc_id)
    form = NOCIncidentForm(obj=inc)
    if form.validate_on_submit():
        form.populate_obj(inc)
        db.session.commit()
        flash('Incidente actualizado','success')
        return redirect(url_for('web.noc_list'))
    return render_template('noc_form.html', form=form, modo='editar', incidente=inc)

@web_bp.route('/noc/<int:inc_id>/eliminar', methods=['POST'])
@roles_required('admin')
def noc_eliminar(inc_id):
    inc = NOCIncident.query.get_or_404(inc_id)
    db.session.delete(inc)
    db.session.commit()
    flash('Incidente eliminado','success')
    return redirect(url_for('web.noc_list'))

@web_bp.route('/noc/csv')
@roles_required('admin','user')
def noc_csv():
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['fecha','sucursal','ticket','reporta','problema','proveedor','solucion','tiempo_solucion','caida'])
    for r in NOCIncident.query.order_by(NOCIncident.fecha.desc(), NOCIncident.id.desc()).limit(2000):
        writer.writerow([
            r.fecha.isoformat() if r.fecha else '', r.sucursal or '', r.ticket or '', r.reporta or '',
            (r.problema or '').replace('\n',' '), r.proveedor or '', (r.solucion or '').replace('\n',' '), r.tiempo_solucion or '', r.caida or ''
        ])
    data = '\ufeff' + output.getvalue()
    bio = BytesIO(data.encode('utf-8'))
    bio.seek(0)
    return send_file(bio, mimetype='text/csv; charset=utf-8', as_attachment=True, download_name='noc_incidentes.csv')

@web_bp.route('/noc/plantilla')
@roles_required('admin','user')
def noc_plantilla():
    """Descarga plantilla CSV con encabezados sugeridos y una fila de ejemplo vacía."""
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['fecha','sucursal','ticket','reporta','problema','proveedor','solucion','tiempo_solucion','caida'])
    writer.writerow(['2025-09-24','M721 tesistan','INC0000012345','Nombre','SIN RED','Telmex','Descripción solución','1 hora','Sí'])
    data = '\ufeff' + output.getvalue()
    bio = BytesIO(data.encode('utf-8'))
    bio.seek(0)
    return send_file(bio, mimetype='text/csv; charset=utf-8', as_attachment=True, download_name='noc_plantilla.csv')

# ---------------- Operadores (catálogo) ----------------
@web_bp.route('/operadores')
@roles_required('admin','user')
def operadores_list():
    ops = Operador.query.order_by(Operador.activo.desc(), Operador.nombre).all()
    return render_template('operadores_list.html', operadores=ops)

@web_bp.route('/operadores/csv')
@roles_required('admin','user')
def operadores_csv():
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['nombre','email','activo'])
    for o in Operador.query.order_by(Operador.nombre):
        writer.writerow([o.nombre, o.email, 'Sí' if o.activo else 'No'])
    data = '\ufeff' + output.getvalue()
    bio = BytesIO(data.encode('utf-8'))
    bio.seek(0)
    return send_file(bio, mimetype='text/csv; charset=utf-8', as_attachment=True, download_name='operadores.csv')

@web_bp.route('/operadores/importar', methods=['GET','POST'])
@roles_required('admin')
def operadores_importar():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not file.filename:
            flash('Archivo no seleccionado','warning')
            return redirect(request.url)
        raw = file.read()
        try:
            text = raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            text = raw.decode('latin-1')
        # Delimitador
        try:
            sample = "\n".join(text.splitlines()[:5])
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            delimiter = dialect.delimiter or ','
        except Exception:
            delimiter = ';' if ';' in (text.splitlines()[0] if text.splitlines() else '') else ','
        reader = csv.DictReader(StringIO(text), delimiter=delimiter)
        # normalizar headers
        def norm(s):
            import re, unicodedata
            s = s or ''
            s = ''.join(c for c in unicodedata.normalize('NFKD', s) if not unicodedata.combining(c))
            s = re.sub(r"\s+", "_", s.strip().lower())
            s = re.sub(r"[^a-z0-9_]", "_", s)
            return s.strip('_')
        field_map = {}
        for h in reader.fieldnames or []:
            nh = norm(h)
            if nh in ('nombre','name'):
                field_map['nombre'] = h
            elif nh in ('email','correo','mail'):
                field_map['email'] = h
            elif nh in ('activo','habilitado','enabled'):
                field_map['activo'] = h
        if 'nombre' not in field_map or 'email' not in field_map:
            flash('Se requieren columnas: nombre, email','danger')
            return redirect(request.url)
        creados, actualizados = 0, 0
        for row in reader:
            nombre = (row.get(field_map['nombre']) or '').strip()
            email = (row.get(field_map['email']) or '').strip()
            if not email:
                continue
            activo = True
            if 'activo' in field_map:
                val = (row.get(field_map['activo']) or '').strip().lower()
                activo = val in ('1','si','sí','true','activo','yes','y')
            op = Operador.query.filter_by(email=email).first()
            if op:
                op.nombre = nombre or op.nombre
                op.activo = activo
                actualizados += 1
            else:
                db.session.add(Operador(nombre=nombre or email.split('@')[0], email=email, activo=activo))
                creados += 1
        db.session.commit()
        flash(f'Importación de operadores: {creados} creados, {actualizados} actualizados','success')
        return redirect(url_for('web.operadores_list'))
    return render_template('operadores_importar.html')

@web_bp.route('/operadores/nuevo', methods=['GET','POST'])
@roles_required('admin')
def operadores_nuevo():
    from .forms import OperadorForm
    form = OperadorForm()
    if form.validate_on_submit():
        op = Operador(nombre=form.nombre.data.strip(), email=form.email.data.strip(), activo=True if form.activo.data=='1' else False)
        db.session.add(op)
        db.session.commit()
        flash('Operador creado','success')
        return redirect(url_for('web.operadores_list'))
    form.activo.data = '1'
    return render_template('operador_form.html', form=form, modo='nuevo')

@web_bp.route('/operadores/<int:op_id>/editar', methods=['GET','POST'])
@roles_required('admin')
def operadores_editar(op_id):
    from .forms import OperadorForm
    op = Operador.query.get_or_404(op_id)
    form = OperadorForm(nombre=op.nombre, email=op.email, activo='1' if op.activo else '0')
    if form.validate_on_submit():
        op.nombre = form.nombre.data.strip()
        op.email = form.email.data.strip()
        op.activo = True if form.activo.data=='1' else False
        db.session.commit()
        flash('Operador actualizado','success')
        return redirect(url_for('web.operadores_list'))
    return render_template('operador_form.html', form=form, modo='editar', operador=op)

@web_bp.route('/operadores/<int:op_id>/eliminar', methods=['POST'])
@roles_required('admin')
def operadores_eliminar(op_id):
    op = Operador.query.get_or_404(op_id)
    db.session.delete(op)
    db.session.commit()
    flash('Operador eliminado','success')
    return redirect(url_for('web.operadores_list'))

@web_bp.route('/noc/importar', methods=['GET','POST'])
@roles_required('admin','user')
def noc_importar():
    """Importa incidentes NOC desde CSV (con vista previa).

    Encabezados aceptados (insensibles a mayúsculas; se permiten acentos y variantes):
    - fecha, sucursal, ticket, reporta, problema, proveedor, solucion, tiempo_solucion|tiempo de solucion, caida|caída
    Fechas aceptadas: YYYY-MM-DD o DD/MM/YYYY.
    Upsert por 'ticket' si viene; si no, crea siempre registro nuevo.
    """
    # Confirmación final (token sin archivo)
    if request.method == 'POST' and 'token' in request.form and not request.files.get('file'):
        token = request.form.get('token')
        cache = current_app.config.setdefault('NOC_IMPORT_CACHE', {})
        payload = cache.pop(token, None)
        if not payload:
            flash('Sesión de importación expirada. Vuelve a cargar el archivo.','warning')
            return redirect(url_for('web.noc_importar'))
        rows = payload.get('rows', [])
        creados, actualizados = 0, 0
        for r in rows:
            ticket = (r.get('ticket') or '').strip()
            if ticket:
                inc = NOCIncident.query.filter_by(ticket=ticket).first()
                if inc:
                    inc.fecha = r.get('fecha') or inc.fecha
                    inc.sucursal = r.get('sucursal') or inc.sucursal
                    inc.reporta = r.get('reporta') or inc.reporta
                    inc.problema = r.get('problema') or inc.problema
                    inc.proveedor = r.get('proveedor') or inc.proveedor
                    inc.solucion = r.get('solucion') or inc.solucion
                    inc.tiempo_solucion = r.get('tiempo_solucion') or inc.tiempo_solucion
                    inc.caida = r.get('caida') or inc.caida
                    actualizados += 1
                else:
                    db.session.add(NOCIncident(**r))
                    creados += 1
            else:
                db.session.add(NOCIncident(**r))
                creados += 1
        db.session.commit()
        flash(f'Importación NOC confirmada: {creados} creados, {actualizados} actualizados','success')
        return redirect(url_for('web.noc_list'))

    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not file.filename:
            flash('Archivo no seleccionado','warning')
            return redirect(request.url)
        raw = file.read()
        # Intentar UTF-8 con BOM y luego latin-1
        try:
            text = raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            text = raw.decode('latin-1')
        # Detectar delimitador automáticamente (Excel en es-MX suele usar ';')
        import re, unicodedata
        try:
            sample = "\n".join(text.splitlines()[:5])
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            delimiter = dialect.delimiter or ','
        except Exception:
            delimiter = ';' if ';' in text.splitlines()[0] else ','
        reader = csv.reader(StringIO(text), delimiter=delimiter)
        header = next(reader, [])
        if not header:
            flash('CSV vacío','warning')
            return redirect(request.url)
        # Normalizar encabezados: quitar BOM/acentos, pasar a minúsculas y colapsar cualquier whitespace/puntuación a '_'
        def norm(s: str) -> str:
            if not isinstance(s, str):
                s = str(s)
            s = s.lstrip('\ufeff')
            s = ''.join(c for c in unicodedata.normalize('NFKD', s) if not unicodedata.combining(c))
            s = s.strip()
            s = re.sub(r"\s+", "_", s)
            s = s.lower()
            s = re.sub(r"[^a-z0-9_]+", "_", s)
            s = s.strip('_')
            return s
        hmap = {norm(h): i for i, h in enumerate(header)}
        # Posibles alias
        def idx_of(*names):
            for n in names:
                if n in hmap:
                    return hmap[n]
            return None
        idx = {
            'fecha': idx_of('fecha','date','fecha_incidente'),
            'sucursal': idx_of('sucursal','suc','tienda','local'),
            'ticket': idx_of('ticket','numero_de_ticket','numero_ticket','nro_ticket'),
            'reporta': idx_of('persona_que_reporta','reporta','persona_reporta'),
            'problema': idx_of('problema_reportado','problema'),
            'proveedor': idx_of('proveedor_reportado','proveedor'),
            'solucion': idx_of('solucion'),
            'tiempo_solucion': idx_of('tiempo_solucion','tiempo_de_solucion'),
            'caida': idx_of('caida','caida_si_no','farmacia_caida_si_no','caida_si_no')
        }
        if not idx['fecha'] or not idx['sucursal']:
            flash('Se requieren columnas al menos: fecha, sucursal','danger')
            return redirect(request.url)
        def parse_fecha(s):
            s = (s or '').strip()
            if not s:
                return None
            for fmt in ('%Y-%m-%d','%d/%m/%Y','%m/%d/%Y'):
                try:
                    return datetime.strptime(s, fmt).date()
                except Exception:
                    continue
            return None
        # Parsear a filas normalizadas
        rows = []
        for row in reader:
            if not row:
                continue
            get = lambda key: (row[idx[key]].strip() if idx.get(key) is not None and len(row) > idx[key] and row[idx[key]] is not None else '')
            r = {
                'fecha': parse_fecha(get('fecha')),
                'sucursal': get('sucursal') or None,
                'ticket': get('ticket') or None,
                'reporta': get('reporta') or None,
                'problema': get('problema') or None,
                'proveedor': get('proveedor') or None,
                'solucion': get('solucion') or None,
                'tiempo_solucion': get('tiempo_solucion') or None,
                'caida': get('caida') or None,
            }
            # Al menos sucursal o ticket para considerar la fila
            if any([r['fecha'], r['sucursal'], r['ticket'], r['problema'], r['solucion']]):
                rows.append(r)
        if not rows:
            flash('No se encontraron filas válidas','warning')
            return redirect(request.url)
        # Guardar en caché para confirmación y mostrar vista previa
        cache = current_app.config.setdefault('NOC_IMPORT_CACHE', {})
        # Limpieza simple de entradas viejas (>30 min)
        try:
            now = datetime.utcnow()
            for k, v in list(cache.items()):
                if (now - v.get('ts', now)).total_seconds() > 1800:
                    cache.pop(k, None)
        except Exception:
            pass
        token = secrets.token_urlsafe(16)
        cache[token] = {'rows': rows, 'ts': datetime.utcnow()}
        # Estadísticas para preview
        with_ticket = sum(1 for r in rows if r.get('ticket'))
        preview = rows[:20]
        return render_template('noc_importar_preview.html', token=token, total=len(rows), con_ticket=with_ticket, preview=preview)
    return render_template('noc_importar.html')


@api_bp.route('/inventario/<int:item_id>/cerrar', methods=['POST'])
@csrf.exempt
@require_api_token
def api_inventario_close(item_id):
    item = Inventario.query.get_or_404(item_id)
    item.estado_reporte = 'Cerrado'
    if not item.fecha_solucion:
        item.fecha_solucion = datetime.utcnow().date()
    db.session.commit()
    return jsonify(item.to_dict())

@web_bp.route('/manifest.json')
def manifest():
    return jsonify({
        "name": "Inventario Equipos",
        "short_name": "Inventario",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#0d6efd",
        "icons": [
            {"src": url_for('static', filename='icons/icon-192.png'), "sizes": "192x192", "type": "image/png"},
            {"src": url_for('static', filename='icons/icon-512.png'), "sizes": "512x512", "type": "image/png"}
        ]
    })

@web_bp.route('/sw.js')
def sw():
    response = make_response(current_app.send_static_file('sw.js'))
    response.headers['Content-Type'] = 'application/javascript'
    return response

@web_bp.app_errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404
