# -*- coding: utf-8 -*-
"""Elimina las cuentas que un administrador creó pero nunca se activaron.

Un usuario nuevo nace en estado 'pendiente' y recibe un correo con una
contraseña temporal; la cuenta se activa cuando la cambia desde el enlace.
Si pasan muchos días sin activarla, la cuenta se borra para liberar el
correo, el documento y el nombre de usuario (puede volver a crearse).

Días de espera: variable PENDIENTES_RETENCION_DIAS del .env (por defecto 15).

Uso (desde la carpeta backend):
    python limpiar_pendientes.py             # borra de verdad
    python limpiar_pendientes.py --simular   # solo muestra qué borraría

En el servidor se ejecuta todos los días con cron, igual que limpiar_videos.py.
"""
import os
import sys
from dotenv import load_dotenv

CARPETA_BACKEND = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(CARPETA_BACKEND, '.env'))

from app.models import get_usuarios_pendientes_vencidos, delete_usuario  # noqa: E402


def main():
    simular = '--simular' in sys.argv
    dias = int(os.getenv('PENDIENTES_RETENCION_DIAS', '15'))
    vencidos = get_usuarios_pendientes_vencidos(dias)
    print(f"Espera: {dias} días. Cuentas pendientes sin activar: {len(vencidos)}"
          + (' (MODO SIMULACIÓN: no se borra nada)' if simular else ''))

    for u in vencidos:
        fecha = u['fecha_registro'].strftime('%d/%m/%Y') if u.get('fecha_registro') else '?'
        print(f"  - {u['nombre_usuario']} <{u['email']}> creado el {fecha}")
        if not simular:
            delete_usuario(u['id'])

    if not simular and vencidos:
        print(f"Eliminadas: {len(vencidos)}")


if __name__ == '__main__':
    main()
