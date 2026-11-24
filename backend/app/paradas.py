# -*- coding: utf-8 -*-
"""Detección de paradas (permanencia) a partir del recorrido de un dispositivo.

Una parada es un grupo de reportes consecutivos que se mantienen dentro de un
radio alrededor del primer punto del grupo, durante al menos un tiempo mínimo.
Se usa solo la posición y la hora: no depende de la velocidad, porque un GPS de
celular puede reportar velocidad errónea cuando la unidad está quieta.
"""
import math

RADIO_PARADA_M = 30       # radio de tolerancia alrededor del punto de inicio
MINIMO_PARADA_SEG = 180   # permanencia mínima para contar como parada (3 minutos)
MAXIMO_HUECO_SEG = 300    # si pasan más de 5 minutos sin reportes, la parada se corta


def distancia_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Distancia en metros entre dos coordenadas (fórmula de Haversine)."""
    radio_tierra = 6371000.0
    f1, f2 = math.radians(lat1), math.radians(lat2)
    df = math.radians(lat2 - lat1)
    dl = math.radians(lng2 - lng1)
    a = math.sin(df / 2) ** 2 + math.cos(f1) * math.cos(f2) * math.sin(dl / 2) ** 2
    return 2 * radio_tierra * math.asin(math.sqrt(a))


def detectar_paradas(puntos: list, radio_m: float = RADIO_PARADA_M,
                     minimo_seg: float = MINIMO_PARADA_SEG,
                     maximo_hueco_seg: float = MAXIMO_HUECO_SEG) -> list:
    """Devuelve las paradas del recorrido, en orden de tiempo.

    `puntos` debe venir ordenado por hora y cada punto trae lat, lng y epoch.
    Cada parada incluye hora de llegada, hora de salida, duración y el centro
    (promedio de las coordenadas del grupo).
    """
    paradas = []
    n = len(puntos)
    i = 0
    while i < n:
        ancla = puntos[i]
        j = i + 1
        while (j < n
               and puntos[j]['epoch'] - puntos[j - 1]['epoch'] <= maximo_hueco_seg
               and distancia_m(ancla['lat'], ancla['lng'], puntos[j]['lat'], puntos[j]['lng']) <= radio_m):
            j += 1
        grupo = puntos[i:j]
        duracion = grupo[-1]['epoch'] - grupo[0]['epoch'] if len(grupo) > 1 else 0
        if len(grupo) > 1 and duracion >= minimo_seg:
            paradas.append({
                'llegada': grupo[0]['epoch'],
                'salida': grupo[-1]['epoch'],
                'duracion_seg': duracion,
                'lat': sum(p['lat'] for p in grupo) / len(grupo),
                'lng': sum(p['lng'] for p in grupo) / len(grupo),
                'reportes': len(grupo),
            })
            i = j           # los puntos de la parada no se cuentan dos veces
        else:
            i += 1
    return paradas
