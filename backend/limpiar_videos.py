# -*- coding: utf-8 -*-
"""Borra del disco los videos/audios con más de N días para ahorrar espacio.

- Solo borra los que YA tienen transcripción (si no, se perdería su contenido).
- No toca las imágenes.
- La fila en RegistroDocumental y la transcripción se conservan, así que el
  documento Word se puede seguir descargando. Se anota la fecha del borrado
  en ArchivoEliminadoEn.

Días de retención: variable VIDEO_RETENCION_DIAS del .env (por defecto 30).

Uso (desde la carpeta backend):
    python limpiar_videos.py             # borra de verdad
    python limpiar_videos.py --simular   # solo muestra qué borraría, sin tocar nada

En el servidor se ejecuta todos los días con cron (ver la guía de despliegue).
"""
import os
import sys
from dotenv import load_dotenv

CARPETA_BACKEND = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(CARPETA_BACKEND, '.env'))

from app.models import get_videos_vencidos, marcar_archivo_eliminado  # noqa: E402

CARPETA_STATIC = os.path.join(CARPETA_BACKEND, 'app', 'static')


def main():
    simular = '--simular' in sys.argv
    dias = int(os.getenv('VIDEO_RETENCION_DIAS', '30'))
    vencidos = get_videos_vencidos(dias)
    print(f"Retención: {dias} días. Videos vencidos con transcripción: {len(vencidos)}"
          + (' (MODO SIMULACIÓN: no se borra nada)' if simular else ''))

    liberado = 0
    for v in vencidos:
        ruta = os.path.join(CARPETA_STATIC, v['archivo_path'].replace('/', os.sep))
        tamano = os.path.getsize(ruta) if os.path.exists(ruta) else 0
        print(f"  #{v['id']}  {v['archivo_path']}  ({tamano / 1_048_576:.1f} MB, subido {v['created_at']:%d/%m/%Y})")
        if simular:
            continue
        if os.path.exists(ruta):
            os.remove(ruta)
            liberado += tamano
        # Se marca como eliminado aunque el archivo ya no estuviera (borrado a mano, etc.)
        marcar_archivo_eliminado(v['id'])

    if not simular:
        print(f"Espacio liberado: {liberado / 1_048_576:.1f} MB")


if __name__ == '__main__':
    main()
