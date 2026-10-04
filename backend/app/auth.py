# -*- coding: utf-8 -*-
import os
import time
from fastapi import Request
from fastapi.responses import RedirectResponse


def crear_sesion(request: Request, user: dict):
    """Guarda los datos del usuario en la sesión firmada."""
    request.session['usuario_valido']    = True
    request.session['id_usuario']        = str(user.get('id', ''))
    request.session['nombre_usuario']    = user.get('nombre') or user.get('username') or 'Usuario'
    request.session['documento']         = user.get('documento', '')
    request.session['rol']               = user.get('rol', 'admin_entidad')
    request.session['id_entidad']        = user.get('id_entidad')   # None para super_admin
    request.session['ultimo_movimiento'] = time.time()


def es_sesion_valida(request: Request) -> bool:
    """Verifica que haya sesión activa y no haya expirado por inactividad."""
    if not request.session.get('usuario_valido'):
        return False
    ultimo   = request.session.get('ultimo_movimiento', 0)
    lifetime = int(os.getenv('SESSION_LIFETIME', 3600))
    if (time.time() - ultimo) > lifetime:
        request.session.clear()
        return False
    request.session['ultimo_movimiento'] = time.time()
    return True


def es_super_admin(request: Request) -> bool:
    return request.session.get('rol') == 'super_admin'


def cerrar_sesion(request: Request):
    request.session.clear()


# ── Helpers para usar en rutas ──────────────────────────────────────────────

def redirigir_si_no_autenticado(request: Request):
    """Retorna RedirectResponse si no hay sesión válida, sino None."""
    if not es_sesion_valida(request):
        return RedirectResponse(url='/login', status_code=302)
    return None

def redirigir_si_no_super_admin(request: Request):
    """Retorna RedirectResponse si no es super_admin, sino None."""
    r = redirigir_si_no_autenticado(request)
    if r:
        return r
    if not es_super_admin(request):
        return RedirectResponse(url='/index', status_code=302)
    return None
