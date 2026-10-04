# -*- coding: utf-8 -*-
#
# Envío de correos de la app (por ahora: recuperación de contraseña).
#
# Se configura con variables del .env:
#   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM
#
# Si SMTP_HOST está vacío (modo desarrollo), el correo NO se envía: se imprime
# en la consola de uvicorn, para poder probar el flujo sin un servidor de correo.
import os
import smtplib
from email.message import EmailMessage


def enviar_correo(destinatario: str, asunto: str, texto: str, html: str = None) -> bool:
    host = os.getenv('SMTP_HOST', '').strip()

    if not host:
        print('\n' + '=' * 70)
        print('  [CORREO - MODO DESARROLLO] No hay SMTP configurado en el .env')
        print(f'  Para:   {destinatario}')
        print(f'  Asunto: {asunto}')
        print('-' * 70)
        print(texto)
        print('=' * 70 + '\n')
        return True

    msg = EmailMessage()
    msg['Subject'] = asunto
    msg['From'] = os.getenv('SMTP_FROM') or os.getenv('SMTP_USER')
    msg['To'] = destinatario
    msg.set_content(texto)
    if html:
        msg.add_alternative(html, subtype='html')

    try:
        port = int(os.getenv('SMTP_PORT', 587))
        # 465 usa SSL directo; 587 (Gmail, Outlook) usa STARTTLS.
        if port == 465:
            servidor = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            servidor = smtplib.SMTP(host, port, timeout=15)
            servidor.starttls()
        with servidor:
            usuario = os.getenv('SMTP_USER')
            if usuario:
                servidor.login(usuario, os.getenv('SMTP_PASSWORD', ''))
            servidor.send_message(msg)
        return True
    except Exception as e:
        print(f'[CORREO] Error enviando a {destinatario}: {e}')
        return False
