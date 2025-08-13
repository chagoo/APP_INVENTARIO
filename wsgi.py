"""Punto de entrada WSGI para Waitress/uwsgi/gunicorn.

Expone la variable ``application`` que el servidor WSGI espera.
Usa la factoría ``create_app`` definida en el paquete ``inventario``.
"""

from inventario import create_app  # import de la factoría real

application = create_app()

