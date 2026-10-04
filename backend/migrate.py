# -*- coding: utf-8 -*-
"""Ejecuta las migraciones de base de datos para el sistema de roles."""
import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

conn = mysql.connector.connect(
    host=os.getenv('DB_HOST'),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD', ''),
    database=os.getenv('DB_NAME')
)
cur = conn.cursor()

pasos = [
    ("tabla entidades", """
        CREATE TABLE IF NOT EXISTS entidades (
            id             INT AUTO_INCREMENT PRIMARY KEY,
            razon_social   VARCHAR(255) NOT NULL,
            nit_cif        VARCHAR(50)  NOT NULL UNIQUE,
            telefono       VARCHAR(30),
            pais           VARCHAR(10)  DEFAULT 'CO',
            ciudad         VARCHAR(150),
            direccion      VARCHAR(255),
            activo         TINYINT(1)   DEFAULT 1,
            fecha_registro TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
        )
    """),
    ("col rol en usuarios",
        "ALTER TABLE usuarios ADD COLUMN rol VARCHAR(20) NOT NULL DEFAULT 'admin_entidad' AFTER documento"),
    ("col id_entidad en usuarios",
        "ALTER TABLE usuarios ADD COLUMN id_entidad INT NULL AFTER rol"),
    ("col id_entidad en caninos",
        "ALTER TABLE caninos ADD COLUMN id_entidad INT NULL AFTER estado"),
    ("usuario 12345678 a super_admin",
        "UPDATE usuarios SET rol='super_admin', id_entidad=NULL WHERE documento='12345678'"),
    ("col logo_path en entidades",
        "ALTER TABLE entidades ADD COLUMN logo_path VARCHAR(255) NULL AFTER direccion"),
    ("col tipo_documento en usuarios",
        "ALTER TABLE usuarios ADD COLUMN tipo_documento VARCHAR(20) NULL AFTER id_entidad"),
    ("col doc_identidad_path en usuarios",
        "ALTER TABLE usuarios ADD COLUMN doc_identidad_path VARCHAR(255) NULL AFTER tipo_documento"),
    ("col nacionalidad en usuarios",
        "ALTER TABLE usuarios ADD COLUMN nacionalidad VARCHAR(10) NULL DEFAULT 'CO' AFTER doc_identidad_path"),
    ("col nombre_usuario en usuarios",
        "ALTER TABLE usuarios ADD COLUMN nombre_usuario VARCHAR(50) NULL UNIQUE AFTER nombre"),
    ("col foto_perfil_path en usuarios",
        "ALTER TABLE usuarios ADD COLUMN foto_perfil_path VARCHAR(255) NULL AFTER doc_identidad_path"),
    ("nombre_usuario heredado de documento para usuarios existentes",
        "UPDATE usuarios SET nombre_usuario = documento WHERE nombre_usuario IS NULL OR nombre_usuario = ''"),

    # ── Ampliación tabla caninos ──────────────────────────────────────────────
    ("col genero en caninos",
        "ALTER TABLE caninos ADD COLUMN genero VARCHAR(10) NULL AFTER raza"),
    ("col fecha_nacimiento en caninos",
        "ALTER TABLE caninos ADD COLUMN fecha_nacimiento DATE NULL AFTER genero"),
    ("col chip_numero en caninos",
        "ALTER TABLE caninos ADD COLUMN chip_numero VARCHAR(50) NULL AFTER fecha_nacimiento"),
    ("col num_registro en caninos",
        "ALTER TABLE caninos ADD COLUMN num_registro VARCHAR(50) NULL AFTER chip_numero"),
    ("col color_pelaje en caninos",
        "ALTER TABLE caninos ADD COLUMN color_pelaje VARCHAR(100) NULL AFTER num_registro"),
    ("col peso_kg en caninos",
        "ALTER TABLE caninos ADD COLUMN peso_kg DECIMAL(5,2) NULL AFTER color_pelaje"),
    ("col talla_cm en caninos",
        "ALTER TABLE caninos ADD COLUMN talla_cm INT NULL AFTER peso_kg"),
    ("col id_guia en caninos",
        "ALTER TABLE caninos ADD COLUMN id_guia INT NULL AFTER id_entidad"),
    ("col foto_path en caninos",
        "ALTER TABLE caninos ADD COLUMN foto_path VARCHAR(255) NULL AFTER id_guia"),
    ("col fecha_ingreso en caninos",
        "ALTER TABLE caninos ADD COLUMN fecha_ingreso DATE NULL AFTER foto_path"),
    ("col procedencia en caninos",
        "ALTER TABLE caninos ADD COLUMN procedencia VARCHAR(100) NULL AFTER fecha_ingreso"),
    ("col ultima_vacunacion en caninos",
        "ALTER TABLE caninos ADD COLUMN ultima_vacunacion DATE NULL AFTER procedencia"),
    ("col proxima_vacunacion en caninos",
        "ALTER TABLE caninos ADD COLUMN proxima_vacunacion DATE NULL AFTER ultima_vacunacion"),
    ("col observaciones en caninos",
        "ALTER TABLE caninos ADD COLUMN observaciones TEXT NULL AFTER proxima_vacunacion"),
    ("col nombre_vacuna en caninos",
        "ALTER TABLE caninos ADD COLUMN nombre_vacuna VARCHAR(100) NULL AFTER proxima_vacunacion"),
    ("col historial_clinico_path en caninos",
        "ALTER TABLE caninos ADD COLUMN historial_clinico_path VARCHAR(255) NULL AFTER observaciones"),
    ("col motivo_baja en caninos",
        "ALTER TABLE caninos ADD COLUMN motivo_baja VARCHAR(60) NULL AFTER historial_clinico_path"),
    ("col justificacion_baja en caninos",
        "ALTER TABLE caninos ADD COLUMN justificacion_baja TEXT NULL AFTER motivo_baja"),
    ("col fecha_baja en caninos",
        "ALTER TABLE caninos ADD COLUMN fecha_baja DATE NULL AFTER justificacion_baja"),
    ("col carta_baja_path en caninos",
        "ALTER TABLE caninos ADD COLUMN carta_baja_path VARCHAR(255) NULL AFTER fecha_baja"),
    ("tabla caninos_vacunas", """
        CREATE TABLE IF NOT EXISTS caninos_vacunas (
            id                INT AUTO_INCREMENT PRIMARY KEY,
            id_canino         INT NOT NULL,
            nombre_vacuna     VARCHAR(100) NOT NULL,
            fecha_aplicacion  DATE NOT NULL,
            fecha_vencimiento DATE NULL,
            veterinario       VARCHAR(150) NULL,
            notas             TEXT NULL,
            comprobante_path  VARCHAR(255) NULL,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (id_canino) REFERENCES caninos(id) ON DELETE CASCADE
        )
    """),
    ("col comprobante_path en caninos_vacunas",
        "ALTER TABLE caninos_vacunas ADD COLUMN comprobante_path VARCHAR(255) NULL AFTER notas"),

    # ── Módulo Cursos / Academia K9 ──────────────────────────────────────────
    ("tabla cursos_sesiones", """
        CREATE TABLE IF NOT EXISTS cursos_sesiones (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            especialidad  VARCHAR(50) NOT NULL,
            id_canino     INT NOT NULL,
            id_entidad    INT NULL,
            fecha         DATE NOT NULL,
            resultado     VARCHAR(30) NULL,
            observaciones TEXT NULL,
            instructor    VARCHAR(150) NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (id_canino) REFERENCES caninos(id) ON DELETE CASCADE
        )
    """),
    ("tabla programas_k9", """
        CREATE TABLE IF NOT EXISTS programas_k9 (
            id                INT AUTO_INCREMENT PRIMARY KEY,
            clave             VARCHAR(50) NOT NULL UNIQUE,
            nombre            VARCHAR(150) NOT NULL,
            descripcion       TEXT,
            icono             VARCHAR(60) DEFAULT 'bi-mortarboard-fill',
            color             VARCHAR(20) DEFAULT '#b8860b',
            imagen_fondo_path VARCHAR(255) NULL,
            es_fijo           TINYINT(1) DEFAULT 0,
            activo            TINYINT(1) DEFAULT 1,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """),
    ("seed drogas",     "INSERT IGNORE INTO programas_k9 (clave,nombre,descripcion,icono,color,es_fijo) VALUES ('drogas','Detección de Drogas','Especialización olfativa para identificación de sustancias ilícitas en operativos urbanos y de frontera.','bi-eyedropper-fill','#ef4444',1)"),
    ("seed explosivos", "INSERT IGNORE INTO programas_k9 (clave,nombre,descripcion,icono,color,es_fijo) VALUES ('explosivos','Detección de Explosivos','Detección de artefactos explosivos improvisados, munición y materiales peligrosos en zonas de riesgo.','bi-lightning-charge-fill','#f97316',1)"),
    ("seed rescate",    "INSERT IGNORE INTO programas_k9 (clave,nombre,descripcion,icono,color,es_fijo) VALUES ('rescate','Búsqueda y Rescate','Búsqueda de personas en escombros, zonas de avalancha, terrenos selváticos y operaciones de emergencia.','bi-life-preserver','#22c55e',1)"),
    ("seed seguridad",  "INSERT IGNORE INTO programas_k9 (clave,nombre,descripcion,icono,color,es_fijo) VALUES ('seguridad','Seguridad y Protección','Patrullaje, protección de instalaciones, escolta y control de perímetros en entornos operativos.','bi-shield-fill','#3b82f6',1)"),
    ("seed rastreo",    "INSERT IGNORE INTO programas_k9 (clave,nombre,descripcion,icono,color,es_fijo) VALUES ('rastreo','Rastreo y Seguimiento','Seguimiento de rastros humanos y animales, apoyo en investigaciones criminales y operativos de campo.','bi-compass-fill','#8b5cf6',1)"),
    ("seed personas",   "INSERT IGNORE INTO programas_k9 (clave,nombre,descripcion,icono,color,es_fijo) VALUES ('personas','Detección de Personas','Localización de personas vivas o fallecidas en grandes áreas, apoyo humanitario y judicial.','bi-people-fill','#06b6d4',1)"),
    ("seed multiple",   "INSERT IGNORE INTO programas_k9 (clave,nombre,descripcion,icono,color,es_fijo) VALUES ('multiple','Múltiple / Integral','Programa integral que combina más de una especialidad operativa en un mismo binomio canino.','bi-collection-fill','#b8860b',1)"),

    # ── Registro IA / Resultado Final ────────────────────────────────────────
    ("tabla sesion_vision", """
        CREATE TABLE IF NOT EXISTS sesion_vision (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            id_sesion    INT NOT NULL,
            archivo_path VARCHAR(255) NOT NULL,
            tipo         VARCHAR(20) NULL,
            notas        TEXT NULL,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (id_sesion) REFERENCES cursos_sesiones(id) ON DELETE CASCADE
        )
    """),
    ("tabla registros_ia", """
        CREATE TABLE IF NOT EXISTS registros_ia (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            especialidad  VARCHAR(50) NOT NULL,
            id_canino     INT NOT NULL,
            id_entidad    INT NULL,
            fecha         DATE NOT NULL,
            resultado     VARCHAR(50) NULL,
            confianza     INT NULL,
            observaciones TEXT NULL,
            archivo_path  VARCHAR(255) NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (id_canino) REFERENCES caninos(id) ON DELETE CASCADE
        )
    """),
]

for nombre, sql in pasos:
    try:
        cur.execute(sql)
        print(f"  OK {nombre}")
    except Exception as e:
        print(f"  -- {nombre}: {e}")

conn.commit()
cur.close()
conn.close()
print("Migraciones completadas.")
