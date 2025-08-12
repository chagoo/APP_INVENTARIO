from datetime import datetime
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
