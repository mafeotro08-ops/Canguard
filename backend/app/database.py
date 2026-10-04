# -*- coding: utf-8 -*-
import mysql.connector
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def get_db_connection():
    """Crea y devuelve una conexión a MySQL"""
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', ''),
            database=os.getenv('DB_NAME', 'k9_simple')
        )
        return connection
    except Exception as e:
        print(f"CRITICAL: Could not connect to MySQL. Check DB_HOST and credentials. Error: {e}")
        return None

def test_connection():
    """Prueba si la conexión funciona"""
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()  # Hay que leer el resultado, si no, mysql-connector lanza "Unread result found" al cerrar el cursor
            cursor.close()
            conn.close()
            return True
        return False
    except Exception as e:
        print(f"Error de conexión: {e}")
        return False
