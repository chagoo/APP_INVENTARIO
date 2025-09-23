from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, TextAreaField, SelectField, DateField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Optional, Length, EqualTo, ValidationError, NumberRange
from .models import User
from wtforms import FieldList, FormField, HiddenField


CHECKLIST_ESTADO_CHOICES = [('Pendiente','Pendiente'),('OK','OK'),('Alerta','Alerta')]

COMMON_CHOICES = [('NO','NO'),('SÍ','SÍ')]
STATE_CHOICES = [('Abierto','Abierto'),('En proceso','En proceso'),('Cerrado','Cerrado')]

class SearchForm(FlaskForm):
    search = StringField('Buscar')
    submit = SubmitField('Buscar')

class InventarioForm(FlaskForm):
    region = StringField('Región', validators=[DataRequired()])
    distrito = StringField('Distrito')
    # Regresamos a StringField para permitir autocompletar dinámico (no cargamos miles de opciones en el HTML).
    local = StringField('Local', validators=[DataRequired()])
    farmacia = StringField('Farmacia', validators=[DataRequired()])
    puntos_venta = IntegerField('Pts Venta', validators=[Optional(), NumberRange(min=0)])
    puntos_falla = IntegerField('Pts Falla', validators=[Optional(), NumberRange(min=0)])
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


class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Ingresar')


class UserCreateForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=80)])
    role = SelectField('Rol', choices=[('admin','Admin'),('user','User')], validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=4)], description='Mínimo 4 caracteres')
    confirm = PasswordField('Repetir Contraseña', validators=[DataRequired(), EqualTo('password', message='No coincide')])
    submit = SubmitField('Guardar')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Usuario ya existe')


class UserEditForm(FlaskForm):
    role = SelectField('Rol', choices=[('admin','Admin'),('user','User')], validators=[DataRequired()])
    password = PasswordField('Nueva Contraseña', validators=[Optional(), Length(min=4)])
    confirm = PasswordField('Repetir Contraseña', validators=[Optional(), EqualTo('password', message='No coincide')])
    submit = SubmitField('Actualizar')


class LocalRefForm(FlaskForm):
    region = StringField('Región', validators=[DataRequired()])
    distrito = StringField('Distrito', validators=[DataRequired()])
    local = StringField('Local', validators=[DataRequired(), Length(max=50)])
    farmacia = StringField('Farmacia', validators=[DataRequired(), Length(max=200)])
    submit = SubmitField('Guardar')


class OperationChecklistItemForm(FlaskForm):
    servicio = StringField('Servicio')  # solo lectura en template
    responsable = StringField('Responsable')  # solo lectura
    hora_objetivo = StringField('Hora')  # solo lectura
    estado = SelectField('Estado', choices=CHECKLIST_ESTADO_CHOICES)
    observacion = TextAreaField('Observación', validators=[Optional(), Length(max=500)])
    # hidden para mantener orden
    _idx = HiddenField()


class OperationChecklistForm(FlaskForm):
    fecha = DateField('Fecha', validators=[Optional()])  # default se setea en vista
    comentarios = TextAreaField('Comentarios', validators=[Optional(), Length(max=1000)])
    items = FieldList(FormField(OperationChecklistItemForm))
    submit = SubmitField('Guardar Checklist')


class ChecklistActividadForm(FlaskForm):
    servicio = StringField('Servicio', validators=[DataRequired(), Length(max=200)])
    responsable = StringField('Responsable', validators=[Optional(), Length(max=120)])
    hora_objetivo = StringField('Hora Objetivo', validators=[Optional(), Length(max=40)])
    orden = IntegerField('Orden', validators=[Optional()])
    activo = SelectField('Activo', choices=[('1','Sí'),('0','No')])
    submit = SubmitField('Guardar')
