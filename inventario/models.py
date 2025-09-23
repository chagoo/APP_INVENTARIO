from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import db

class Inventario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    region = db.Column(db.String(80))
    distrito = db.Column(db.String(120))
    local = db.Column(db.String(120), index=True)
    farmacia = db.Column(db.String(120))
    puntos_venta = db.Column(db.Integer)
    puntos_falla = db.Column(db.Integer)
    monitor_cliente = db.Column(db.String(5))
    monitor_asesor = db.Column(db.String(5))
    teclado = db.Column(db.String(5))
    escaner = db.Column(db.String(5))
    mouse_pcm = db.Column(db.String(5))
    teclado_pcm = db.Column(db.String(5))
    ups = db.Column(db.String(5))
    red_lenta = db.Column(db.String(5))
    pinpad = db.Column(db.String(5))
    estado_reporte = db.Column(db.String(30))
    fecha_solucion = db.Column(db.Date)
    comentarios = db.Column(db.Text)
    fecha_registro = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'region': self.region,
            'distrito': self.distrito,
            'local': self.local,
            'farmacia': self.farmacia,
            'puntos_venta': self.puntos_venta,
            'puntos_falla': self.puntos_falla,
            'monitor_cliente': self.monitor_cliente,
            'monitor_asesor': self.monitor_asesor,
            'teclado': self.teclado,
            'escaner': self.escaner,
            'mouse_pcm': self.mouse_pcm,
            'teclado_pcm': self.teclado_pcm,
            'ups': self.ups,
            'red_lenta': self.red_lenta,
            'pinpad': self.pinpad,
            'estado_reporte': self.estado_reporte,
            'fecha_solucion': self.fecha_solucion.isoformat() if self.fecha_solucion else None,
            'comentarios': self.comentarios,
            'fecha_registro': self.fecha_registro.isoformat() if self.fecha_registro else None,
        }


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    last_password_change = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        self.last_password_change = datetime.utcnow()

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_locked(self):
        return self.locked_until and self.locked_until > datetime.utcnow()

    def register_failed_attempt(self, max_attempts=5, lock_minutes=15):
        self.failed_attempts += 1
        if self.failed_attempts >= max_attempts:
            self.locked_until = datetime.utcnow() + timedelta(minutes=lock_minutes)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), index=True)
    entity_type = db.Column(db.String(50))
    entity_id = db.Column(db.String(50))
    ip = db.Column(db.String(45))
    meta = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user = db.relationship('User', backref='audit_events')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'entity_type': self.entity_type,
            'entity_id': self.entity_id,
            'ip': self.ip,
            'meta': self.meta,
            'created_at': self.created_at.isoformat(),
        }


class LocalRef(db.Model):
    """Catálogo de locales para autocompletar campos de Inventario."""
    id = db.Column(db.Integer, primary_key=True)
    region = db.Column(db.String(120), index=True)
    distrito = db.Column(db.String(180), index=True)
    local = db.Column(db.String(50), unique=True, index=True, nullable=False)
    farmacia = db.Column(db.String(200))

    def to_dict(self):
        return {
            'region': self.region,
            'distrito': self.distrito,
            'local': self.local,
            'farmacia': self.farmacia,
        }


# --- Checklist Operación Diaria ---

class OperationChecklist(db.Model):
    """Registro diario de checklist de operación.

    Un registro por día (o múltiples si se desea) con colección de items.
    """
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.Date, index=True, default=datetime.utcnow().date)
    comentarios = db.Column(db.Text)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    usuario = db.relationship('User', backref='operation_checklists')
    items = db.relationship('OperationChecklistItem', backref='checklist', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'fecha': self.fecha.isoformat() if self.fecha else None,
            'comentarios': self.comentarios,
            'usuario_id': self.usuario_id,
            'items': [i.to_dict() for i in self.items],
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class OperationChecklistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    checklist_id = db.Column(db.Integer, db.ForeignKey('operation_checklist.id'), index=True, nullable=False)
    servicio = db.Column(db.String(200), index=True)
    responsable = db.Column(db.String(120))
    hora_objetivo = db.Column(db.String(40))  # texto libre "6am", "7am y 9am" etc
    estado = db.Column(db.String(20), default='Pendiente')  # Pendiente / OK / Alerta
    observacion = db.Column(db.Text)

    def to_dict(self):
        return {
            'servicio': self.servicio,
            'responsable': self.responsable,
            'hora_objetivo': self.hora_objetivo,
            'estado': self.estado,
            'observacion': self.observacion,
        }


# --- Catálogo dinámico de actividades del checklist ---
class ChecklistActividad(db.Model):
    __tablename__ = 'checklist_actividad'
    id = db.Column(db.Integer, primary_key=True)
    servicio = db.Column(db.String(200), nullable=False, index=True)
    responsable = db.Column(db.String(120))
    hora_objetivo = db.Column(db.String(40))
    orden = db.Column(db.Integer, default=0, index=True)
    activo = db.Column(db.Boolean, default=True, index=True)
    creado_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'servicio': self.servicio,
            'responsable': self.responsable,
            'hora_objetivo': self.hora_objetivo,
            'orden': self.orden,
            'activo': self.activo,
        }
