# -*- coding: utf-8 -*-
#
# Verificación en dos pasos (2FA) con Google Authenticator o cualquier app
# compatible con TOTP (RFC 6238): la app y el servidor comparten un secreto y
# ambos calculan el mismo código de 6 dígitos cada 30 segundos.
#
#   - El secreto se guarda CIFRADO en Usuario.TotpSecret (no hasheado: hay que
#     leerlo para validar). La clave de cifrado es TOTP_KEY en el .env.
#   - Los códigos de respaldo (para cuando se pierde el celular) se guardan con
#     SHA-256 en la tabla CodigoRespaldo: son aleatorios, no se adivinan por
#     diccionario, y así se verifican rápido. Cada uno sirve una sola vez.
#
# Las rutas están en main.py (sección "Verificación en dos pasos").
import hashlib
import hmac
import os
import secrets
import time

import pyotp
import segno
from cryptography.fernet import Fernet

EMISOR           = 'CanGuard K9'   # nombre que muestra Google Authenticator
PERIODO          = 30              # segundos que dura cada código
CODIGOS_RESPALDO = 10


# ── Secreto TOTP ───────────────────────────────────────────────────────────

def _fernet() -> Fernet:
    clave = os.getenv('TOTP_KEY', '').strip()
    if not clave:
        raise RuntimeError('Falta TOTP_KEY en el .env (ver .env.example para generarla).')
    return Fernet(clave.encode('ascii'))


def generar_secreto() -> str:
    """Secreto aleatorio en Base32 (así lo esperan las apps de autenticación)."""
    return pyotp.random_base32()


def cifrar_secreto(secreto: str) -> str:
    return _fernet().encrypt(secreto.encode('ascii')).decode('ascii')


def descifrar_secreto(valor_cifrado: str) -> str:
    return _fernet().decrypt(valor_cifrado.encode('ascii')).decode('ascii')


def secreto_legible(secreto: str) -> str:
    """En grupos de 4 para copiarlo a mano si no se puede escanear el QR."""
    return ' '.join(secreto[i:i + 4] for i in range(0, len(secreto), 4))


def url_otpauth(secreto: str, nombre_usuario: str) -> str:
    return pyotp.TOTP(secreto).provisioning_uri(name=nombre_usuario, issuer_name=EMISOR)


def qr_data_uri(url: str) -> str:
    """QR como imagen SVG embebida (data:), para ponerla directo en un <img>."""
    return segno.make(url, error='m').svg_data_uri(scale=5, border=2)


def verificar_codigo(secreto: str, codigo: str, ultimo_intervalo: int | None = None) -> int | None:
    """Comprueba un código de 6 dígitos. Devuelve el intervalo (bloque de 30 s)
    al que corresponde si es válido, o None.
    - Tolerancia: se acepta el código actual y el anterior/siguiente (±30 s),
      porque el reloj del celular y el del servidor nunca van exactos.
    - Anti-repetición: no se acepta un intervalo igual o anterior al último
      usado (`ultimo_intervalo`), así un código interceptado no sirve dos veces.
    """
    codigo = (codigo or '').strip().replace(' ', '')
    if len(codigo) != 6 or not codigo.isdigit():
        return None
    totp = pyotp.TOTP(secreto)
    actual = int(time.time()) // PERIODO
    for desplazamiento in (0, -1, 1):
        intervalo = actual + desplazamiento
        if ultimo_intervalo is not None and intervalo <= ultimo_intervalo:
            continue
        if hmac.compare_digest(totp.at(intervalo * PERIODO), codigo):
            return intervalo
    return None


# ── Códigos de respaldo ────────────────────────────────────────────────────
# Sin 0/O ni 1/I/L para que no se confundan al escribirlos.
_ALFABETO = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'


def generar_codigos_respaldo(cantidad: int = CODIGOS_RESPALDO) -> list[str]:
    """Códigos tipo 'ABCD-EFGH'. Se muestran UNA sola vez; en la base va su hash."""
    codigos = []
    for _ in range(cantidad):
        bruto = ''.join(secrets.choice(_ALFABETO) for _ in range(8))
        codigos.append(f'{bruto[:4]}-{bruto[4:]}')
    return codigos


def normalizar_codigo_respaldo(codigo: str) -> str:
    return (codigo or '').upper().replace('-', '').replace(' ', '').strip()


def es_codigo_respaldo(codigo: str) -> bool:
    n = normalizar_codigo_respaldo(codigo)
    return len(n) == 8 and all(c in _ALFABETO for c in n)


def hash_codigo_respaldo(codigo: str) -> str:
    return hashlib.sha256(normalizar_codigo_respaldo(codigo).encode('ascii')).hexdigest()
