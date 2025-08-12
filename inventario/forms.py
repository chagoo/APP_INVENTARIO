from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, TextAreaField, SelectField, DateField, SubmitField
from wtforms.validators import DataRequired, Optional

COMMON_CHOICES = [('NO','NO'),('SÍ','SÍ')]
STATE_CHOICES = [('Abierto','Abierto'),('En proceso','En proceso'),('Cerrado','Cerrado')]

class SearchForm(FlaskForm):
    search = StringField('Buscar')
    submit = SubmitField('Buscar')

class InventarioForm(FlaskForm):
    region = StringField('Región', validators=[DataRequired()])
    distrito = StringField('Distrito')
    local = StringField('Local', validators=[DataRequired()])
    farmacia = StringField('Farmacia', validators=[DataRequired()])
    puntos_venta = IntegerField('Pts Venta', validators=[Optional()])
    puntos_falla = IntegerField('Pts Falla', validators=[Optional()])
    monitor_cliente = SelectField('Monitor Cliente', choices=COMMON_CHOICES)
    monitor_asesor = SelectField('Monitor Asesor', choices=COMMON_CHOICES)
    teclado = SelectField('Teclado', choices=COMMON_CHOICES)
    escaner = SelectField('Escáner', choices=COMMON_CHOICES)
    mouse_pcm = SelectField('Mouse PCM', choices=COMMON_CHOICES)
    teclado_pcm = SelectField('Teclado PCM', choices=COMMON_CHOICES)
    ups = SelectField('UPS', choices=COMMON_CHOICES)
    red_lenta = SelectField('Red Lenta', choices=COMMON_CHOICES)
    pinpad = SelectField('Pin Pad', choices=COMMON_CHOICES)
    comentarios = TextAreaField('Comentarios', validators=[Optional()])
    estado_reporte = SelectField('Estado', choices=STATE_CHOICES)
    fecha_solucion = DateField('Fecha Solución', validators=[Optional()])
    submit = SubmitField('Guardar')
