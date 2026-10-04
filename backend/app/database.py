# -*- coding: utf-8 -*-
import psycopg
from psycopg.rows import dict_row
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def get_db_connection():
    """Crea y devuelve una conexión a PostgreSQL.

    row_factory=dict_row hace que cada fila llegue como diccionario
    ({'id': 1, 'nombre': 'Max'}), igual que hacía MySQL con dictionary=True,
    así el resto de la aplicación no tiene que cambiar.
    """
    try:
        connection = psycopg.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            port=os.getenv('DB_PORT', '5432'),
            user=os.getenv('DB_USER', 'postgres'),
            password=os.getenv('DB_PASSWORD', ''),
            dbname=os.getenv('DB_NAME', 'K9'),
            row_factory=dict_row,
        )
        return connection
    except Exception as e:
        print(f"CRITICAL: Could not connect to PostgreSQL. Check DB_HOST and credentials. Error: {e}")
        return None

def test_connection():
    """Prueba si la conexión funciona"""
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            conn.close()
            return True
        return False
    except Exception as e:
        print(f"Error de conexión: {e}")
        return False
