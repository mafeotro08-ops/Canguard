# -*- coding: utf-8 -*-
import os
import time
from fastapi import Request
from fastapi.responses import RedirectResponse


def crear_sesion(request: Request, user: dict, nombre_entidad: str | None = None):
    """Guarda los datos del usuario en la sesión firmada."""
    request.session['usuario_valido']    = True
    request.session['id_usuario']        = str(user.get('id', ''))
    request.session['nombre_usuario']    = user.get('nombre') or user.get('username') or 'Usuario'
    request.session['documento']         = user.get('documento', '')
    request.session['rol']               = user.get('rol', 'admin_entidad')
    request.session['id_entidad']        = user.get('id_entidad')   # None para super_admin
    request.session['nombre_entidad']    = nombre_entidad            # se muestra en el menú
    # 2FA obligatoria: mientras sea False solo puede estar en /seguridad (middleware en main.py)
    request.session['totp_activo']       = bool(user.get('totp_activo'))
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


def es_guia(request: Request) -> bool:
    """El guía canino solo trabaja con sus propios caninos y sus propias sesiones."""
    return request.session.get('rol') == 'guia_canino'


def id_usuario_sesion(request: Request) -> int | None:
    """Id del usuario que inició sesión (en la sesión se guarda como texto)."""
    valor = request.session.get('id_usuario')
    return int(valor) if valor and str(valor).isdigit() else None


# Nombre que se muestra en el menú para cada rol
NOMBRE_ROL = {
    'super_admin':   'SUPER ADMIN',
    'admin_entidad': 'ADMIN ENTIDAD',
    'instructor':    'INSTRUCTOR',
    'guia_canino':   'GUÍA CANINO',
    'veterinario':   'VETERINARIO',
}

# Ícono de cada rol en la barra lateral (junto a NOMBRE_ROL)
ICONO_ROL = {
    'super_admin':   'bi-star-fill',
    'admin_entidad': 'bi-person-gear',
    'instructor':    'bi-mortarboard-fill',
    'guia_canino':   'bi-shield-fill',
    'veterinario':   'bi-heart-pulse-fill',
}

# Roles que un administrador de entidad puede asignar a los usuarios de su entidad
ROLES_ENTIDAD = ('admin_entidad', 'instructor', 'guia_canino')


# Rutas a las que puede entrar un usuario logueado que AÚN no configuró su 2FA.
RUTAS_SIN_2FA = ('/seguridad', '/logout', '/static')


# ── Módulos por rol ─────────────────────────────────────────────────────────
# UNA sola lista decide qué módulos ve cada rol en el menú (layout.html) y a
# qué rutas puede entrar (middleware en main.py). Si un rol no tiene el módulo,
# aunque escriba la URL a mano se le devuelve al dashboard.
#
#   super_admin    -> todo, incluidas las entidades
#   admin_entidad, instructor, veterinario -> todo lo de SU entidad, menos entidades
#   guia_canino    -> solo sus caninos, salud, geolocalización, academia y avisos

_ADMINS = ('super_admin', 'admin_entidad', 'instructor', 'veterinario')
_TODOS  = _ADMINS + ('guia_canino',)

MODULOS = (
    # ruta              etiqueta           ícono                   roles que lo ven
    ('/index',           'DASHBOARD',       'bi-speedometer2',      _TODOS),
    ('/entidades',       'ENTIDADES',       'bi-buildings-fill',    ('super_admin',)),
    ('/usuarios',        'USUARIOS',        'bi-people-fill',       _ADMINS),
    ('/gestion-guias',   'GUÍAS K9',        'bi-person-badge-fill', _ADMINS),
    ('/caninos',         'CANINOS K9',      'bi-shield-fill',       _TODOS),
    ('/salud-canina',    'SALUD CANINA',    'bi-heart-pulse-fill',  _TODOS),
    ('/geolocalizacion', 'GEOLOCALIZACIÓN', 'bi-geo-alt-fill',      _TODOS),
    ('/cursos',          'ACADEMIA K9',     'bi-mortarboard-fill',  _TODOS),
    ('/notificaciones',  'NOTIFICACIONES',  'bi-bell-fill',         _TODOS),
)

# Etiqueta distinta para algunos roles (el admin de entidad ve "MIS USUARIOS"...)
_ETIQUETA_POR_ROL = {
    ('admin_entidad', '/usuarios'): 'MIS USUARIOS',
    ('instructor',    '/usuarios'): 'MIS USUARIOS',
    ('veterinario',   '/usuarios'): 'MIS USUARIOS',
    ('guia_canino',   '/caninos'):  'MIS CANINOS',
}

# Rutas que dependen de un módulo y heredan su permiso
_RUTAS_DEL_MODULO = {
    '/entidades':      ('/subentidades', '/RegistroEntidad'),
    '/cursos':         ('/vision', '/vision-artificial'),
    '/notificaciones': ('/api/notificaciones',),
}


def modulos_de(rol: str):
    """Módulos (ruta, etiqueta, ícono) que ve un rol, en el orden del menú."""
    return [(ruta, _ETIQUETA_POR_ROL.get((rol, ruta), etiqueta), icono)
            for ruta, etiqueta, icono, roles in MODULOS if rol in roles]


def ruta_permitida(rol: str, path: str) -> bool:
    """False si la ruta pertenece a un módulo que el rol no tiene. Las rutas que
    no son de ningún módulo (login, seguridad, static...) no se restringen aquí."""
    for ruta, _, _, roles in MODULOS:
        prefijos = (ruta,) + _RUTAS_DEL_MODULO.get(ruta, ())
        if any(path == p or path.startswith(p + '/') for p in prefijos):
            return rol in roles
    return True


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

def redirigir_si_guia(request: Request):
    """Para pantallas de administración: el guía canino no tiene acceso y se le
    envía al inicio. Retorna RedirectResponse o None."""
    r = redirigir_si_no_autenticado(request)
    if r:
        return r
    if es_guia(request):
        return RedirectResponse(url='/index', status_code=302)
    return None
