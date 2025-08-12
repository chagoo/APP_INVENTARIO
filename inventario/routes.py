from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file, current_app, make_response
from . import db, csrf
from .models import Inventario
from .forms import InventarioForm, SearchForm
from io import StringIO
import csv
from datetime import datetime
from functools import wraps

web_bp = Blueprint('web', __name__)
api_bp = Blueprint('api', __name__)


def require_api_token(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = current_app.config.get('API_TOKEN')
        if token and request.headers.get('X-API-KEY') != token:
            return jsonify({'error': 'unauthorized'}), 401
        return view(*args, **kwargs)
    return wrapped

@web_bp.route('/')
def index():
    return render_template('index.html')

@web_bp.route('/inventario/nuevo', methods=['GET','POST'])
def inventario_nuevo():
    form = InventarioForm()
    if form.validate_on_submit():
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
        return redirect(url_for('web.inventario_listar'))
    return render_template('inventario_form.html', form=form)


@web_bp.route('/inventario/<int:item_id>/editar', methods=['GET', 'POST'])
def inventario_editar(item_id):
    item = Inventario.query.get_or_404(item_id)
    form = InventarioForm(obj=item)
    if form.validate_on_submit():
        form.populate_obj(item)
        db.session.commit()
        flash('Inventario actualizado', 'success')
        return redirect(url_for('web.inventario_listar'))
    return render_template('inventario_form.html', form=form)


@web_bp.route('/inventario/<int:item_id>/eliminar', methods=['POST'])
def inventario_eliminar(item_id):
    item = Inventario.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Inventario eliminado', 'success')
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
def inventario_cerrar(item_id):
    item = Inventario.query.get_or_404(item_id)
    item.estado_reporte = 'Cerrado'
    if not item.fecha_solucion:
        item.fecha_solucion = datetime.utcnow().date()
    db.session.commit()
    flash('Reporte cerrado','success')
    return redirect(url_for('web.inventario_listar'))

@web_bp.route('/inventario/csv')
def inventario_csv():
    si = StringIO()
    writer = csv.writer(si)
    header = ['id','region','distrito','local','farmacia','puntos_venta','puntos_falla','monitor_cliente','monitor_asesor','teclado','escaner','mouse_pcm','teclado_pcm','ups','red_lenta','pinpad','estado_reporte','fecha_solucion','comentarios','fecha_registro']
    writer.writerow(header)
    for item in Inventario.query.order_by(Inventario.id).all():
        writer.writerow([
            item.id,item.region,item.distrito,item.local,item.farmacia,item.puntos_venta,item.puntos_falla,item.monitor_cliente,item.monitor_asesor,item.teclado,item.escaner,item.mouse_pcm,item.teclado_pcm,item.ups,item.red_lenta,item.pinpad,item.estado_reporte,item.fecha_solucion,item.comentarios,item.fecha_registro
        ])
    output = StringIO(si.getvalue())
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='inventario.csv')

# API endpoints (JSON) for mobile / PWA usage
@api_bp.route('/inventario', methods=['GET'])
def api_inventario_list():
    search = request.args.get('search','')
    query = Inventario.query
    if search:
        query = query.filter(Inventario.local.ilike(f"%{search}%"))
    data = [i.to_dict() for i in query.order_by(Inventario.fecha_registro.desc()).limit(200)]
    return jsonify(data)

@api_bp.route('/inventario', methods=['POST'])
@csrf.exempt
@require_api_token
def api_inventario_create():
    payload = request.get_json() or {}
    item = Inventario(
        region=payload.get('region'),
        distrito=payload.get('distrito'),
        local=payload.get('local'),
        farmacia=payload.get('farmacia'),
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
