from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file, current_app, make_response
from flask_login import login_user, logout_user, login_required, current_user
from . import db, csrf
from .models import Inventario, User, AuditLog
from .forms import InventarioForm, SearchForm, LoginForm, UserCreateForm, UserEditForm, LocalRefForm, OperationChecklistForm
from .models import LocalRef, OperationChecklist, OperationChecklistItem
from .locales_data import CHECKLIST_SERVICIOS_BASE
from io import StringIO, BytesIO
import csv
from datetime import datetime, timedelta
import secrets
import hashlib
from functools import wraps

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
    # Dev aide: lista rutas y versión
    rules = sorted([r.rule for r in web_bp.url_map.iter_rules()]) if web_bp.url_map else []
    return jsonify({
        'version': APP_VERSION,
        'routes_contains_checklists': any('checklists' in r for r in rules),
        'total_rules': len(rules)
    })


@web_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
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
    return render_template('login.html', form=form)


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
    paginated = OperationChecklist.query.order_by(OperationChecklist.fecha.desc(), OperationChecklist.id.desc()).paginate(page=page, per_page=15)
    return render_template('checklist_list.html', registros=paginated.items, page=page,
                           next_page=paginated.next_num if paginated.has_next else None,
                           prev_page=paginated.prev_num if paginated.has_prev else None)

def _build_checklist_form(fecha=None):
    form = OperationChecklistForm()
    if not form.items.entries:  # inicializar
        for idx, (servicio, responsable, hora) in enumerate(CHECKLIST_SERVICIOS_BASE):
            subf = {}
            form.items.append_entry(subf)
            entry = form.items.entries[-1]
            entry.form.servicio.data = servicio
            entry.form.responsable.data = responsable
            entry.form.hora_objetivo.data = hora
            entry.form._idx.data = str(idx)
    if fecha:
        form.fecha.data = fecha
    return form

@web_bp.route('/checklists/nuevo', methods=['GET','POST'])
@roles_required('admin','user')
def checklist_nuevo():
    from datetime import date
    form = _build_checklist_form(date.today())
    if form.validate_on_submit():
        chk = OperationChecklist(
            fecha=form.fecha.data or date.today(),
            comentarios=form.comentarios.data,
            usuario_id=current_user.id,
        )
        for entry in form.items.entries:
            item = OperationChecklistItem(
                servicio=entry.form.servicio.data,
                responsable=entry.form.responsable.data,
                hora_objetivo=entry.form.hora_objetivo.data,
                estado=entry.form.estado.data,
                observacion=entry.form.observacion.data,
            )
            chk.items.append(item)
        db.session.add(chk)
        db.session.commit()
        flash('Checklist guardado','success')
        log_event('checklist_create', current_user.id, 'OperationChecklist', chk.id, ip=request.remote_addr)
        return redirect(url_for('web.checklist_historial'))
    return render_template('checklist_form.html', form=form)

@web_bp.route('/checklists/<int:chk_id>')
@roles_required('admin','user')
def checklist_ver(chk_id):
    chk = OperationChecklist.query.get_or_404(chk_id)
    return render_template('checklist_ver.html', chk=chk)


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
