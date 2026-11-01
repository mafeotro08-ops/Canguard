# -*- coding: utf-8 -*-
#
# Reglas de seguridad compartidas por toda la app:
#   - política de contraseñas (la misma en activar, restablecer y editar)
#   - generación de contraseñas temporales para usuarios nuevos
#   - límite de intentos por IP para las pantallas públicas (login, recuperar)
#
import re
import secrets
import string
import threading
import time
from collections import defaultdict, deque

# ── Política de contraseñas ────────────────────────────────────────────────
# Se aplica en el servidor (validar_password) y también en los formularios
# (atributo pattern + lista de requisitos en pantalla). Si cambias algo aquí,
# cambia también el texto de REGLAS_PASSWORD para que coincida.

LONGITUD_MIN_PASSWORD = 10
LONGITUD_MAX_PASSWORD = 64
CARACTERES_ESPECIALES = '!@#$%^&*()_-+=[]{};:,.<>?/|~'

REGLAS_PASSWORD = (f'Mínimo {LONGITUD_MIN_PASSWORD} caracteres, con al menos una letra mayúscula, '
                   f'una minúscula, un número y un carácter especial (por ejemplo ! @ # $ % & *).')

# Misma regla para el atributo pattern="" de los <input type="password">.
# Los navegadores la aplican completa (anclada) y con el modificador "u".
PASSWORD_PATTERN_HTML = (r'(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).{'
                         + f'{LONGITUD_MIN_PASSWORD},{LONGITUD_MAX_PASSWORD}' + '}')


def validar_password(password: str) -> str | None:
    """Devuelve el mensaje de error si la contraseña no cumple la política,
    o None si está bien."""
    p = password or ''
    if len(p) < LONGITUD_MIN_PASSWORD:
        return f'La contraseña debe tener al menos {LONGITUD_MIN_PASSWORD} caracteres.'
    if len(p) > LONGITUD_MAX_PASSWORD:
        return f'La contraseña no puede tener más de {LONGITUD_MAX_PASSWORD} caracteres.'
    if not re.search(r'[A-Z]', p):
        return 'La contraseña debe incluir al menos una letra mayúscula.'
    if not re.search(r'[a-z]', p):
        return 'La contraseña debe incluir al menos una letra minúscula.'
    if not re.search(r'[0-9]', p):
        return 'La contraseña debe incluir al menos un número.'
    if not re.search(r'[^A-Za-z0-9]', p):
        return 'La contraseña debe incluir al menos un carácter especial (por ejemplo ! @ # $ % & *).'
    if ' ' in p:
        return 'La contraseña no puede contener espacios.'
    return None


def generar_password_temporal(longitud: int = 12) -> str:
    """Contraseña aleatoria que cumple la política. Se usa al crear un usuario:
    va en el correo de activación y el usuario debe cambiarla para activar la cuenta.
    Se evitan caracteres que se confunden al leerlos (0/O, 1/l/I)."""
    mayus = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    minus = 'abcdefghijkmnpqrstuvwxyz'
    digitos = '23456789'
    especiales = '!@#$%&*?'
    todos = mayus + minus + digitos + especiales
    while True:
        # Un carácter de cada grupo garantizado y el resto al azar.
        chars = [secrets.choice(mayus), secrets.choice(minus),
                 secrets.choice(digitos), secrets.choice(especiales)]
        chars += [secrets.choice(todos) for _ in range(longitud - len(chars))]
        secrets.SystemRandom().shuffle(chars)
        password = ''.join(chars)
        if validar_password(password) is None:
            return password


# ── Límite de intentos por IP (anti fuerza bruta / bots) ──────────────────
# Guarda en memoria las marcas de tiempo de los últimos intentos por clave
# (normalmente la IP). Es suficiente para una app con un solo proceso de
# uvicorn; si algún día se corre con varios workers, se cambiaría por Redis.

class LimitadorIntentos:
    def __init__(self):
        self._intentos: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def permitir(self, clave: str, maximo: int, ventana_segundos: int) -> bool:
        """True si la clave aún puede intentar; False si ya agotó `maximo`
        intentos dentro de los últimos `ventana_segundos`."""
        ahora = time.time()
        with self._lock:
            cola = self._intentos[clave]
            while cola and cola[0] < ahora - ventana_segundos:
                cola.popleft()
            if len(cola) >= maximo:
                return False
            cola.append(ahora)
            # Limpieza para que el diccionario no crezca sin control.
            if len(self._intentos) > 10000:
                for k in [k for k, v in self._intentos.items() if not v]:
                    del self._intentos[k]
            return True


limitador_login     = LimitadorIntentos()   # intentos de inicio de sesión por IP
limitador_recuperar = LimitadorIntentos()   # solicitudes de recuperación/activación por IP

# Bloqueo de cuenta tras varios intentos fallidos seguidos (columna
# Usuario.IntentosFallidos / BloqueadoHasta).
MAX_INTENTOS_FALLIDOS = 5
MINUTOS_BLOQUEO       = 15
