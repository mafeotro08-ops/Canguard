# -*- coding: utf-8 -*-
#
# Capa de acceso a datos, actualizada al esquema PascalCase de CANGUARD K9
# (ver backend/db/CanGuardK9.sql). Las tablas y columnas ahora son
# Entidad, Usuario, Canino, CaninoVacuna, Sesion, RegistroDocumental,
# ProgramaK9 y RegistroIa (antes: entidades, usuarios, caninos,
# caninos_vacunas, cursos_sesiones, sesion_vision, programas_k9,
# registros_ia).
#
# Para no tener que reescribir main.py ni las plantillas Jinja2 (que leen
# claves en snake_case como canino['nombre'] o usuario['id_entidad']),
# cada SELECT usa "AS alias_snake_case" para devolver los mismos nombres
# de siempre. Los INSERT/UPDATE sí usan directamente los nombres nuevos
# de columna, que es lo que realmente exige la base de datos.
import hashlib
import bcrypt
from datetime import date
from .database import get_db_connection


# ─────────────────────────────────────────────
#  HELPERS INTERNOS
# ─────────────────────────────────────────────

def _hash_password(plain: str) -> str:
    """bcrypt: hash con sal y lento a propósito, para que una copia de la base
    no sirva para adivinar contraseñas. bcrypt solo mira los primeros 72 bytes."""
    return bcrypt.hashpw(plain.encode('utf-8')[:72], bcrypt.gensalt()).decode('ascii')

def _es_hash_legado(password_hash: str) -> bool:
    """Las contraseñas guardadas antes de bcrypt eran SHA-256 en hexadecimal (64 chars)."""
    return bool(password_hash) and len(password_hash) == 64 and all(c in '0123456789abcdef' for c in password_hash)

def verificar_password(plain: str, password_hash: str) -> bool:
    """Compara la contraseña en claro con el hash guardado (bcrypt o SHA-256 legado)."""
    if not plain or not password_hash:
        return False
    if _es_hash_legado(password_hash):
        return hashlib.sha256(plain.encode('utf-8')).hexdigest() == password_hash
    try:
        return bcrypt.checkpw(plain.encode('utf-8')[:72], password_hash.encode('ascii'))
    except ValueError:
        return False

def _query(sql: str, params=(), one=False, write=False):
    """Ejecuta una query y devuelve dict(s) o el id insertado/rowcount."""
    conn = get_db_connection()
    if not conn:
        return None
    # Las filas llegan como dict gracias a row_factory=dict_row (ver database.py).
    cur = conn.cursor()
    # PostgreSQL no tiene lastrowid como MySQL: el id del registro nuevo se pide
    # con RETURNING. En todas las tablas la llave primaria es la primera columna,
    # así que se toma el primer valor de la fila devuelta.
    es_insert = write and sql.lstrip().upper().startswith('INSERT')
    if es_insert:
        sql = f"{sql} RETURNING *"
    cur.execute(sql, params)
    if write:
        fila = cur.fetchone() if es_insert else None
        conn.commit()
        result = next(iter(fila.values())) if fila else cur.rowcount
    elif one:
        result = cur.fetchone()
    else:
        result = cur.fetchall()
    cur.close()
    conn.close()
    return result


# ─────────────────────────────────────────────
#  ENTIDADES  (tabla Entidad)
# ─────────────────────────────────────────────

_CAMPOS_ENTIDAD = """IdEntidad AS id, IdEntidadPadre AS id_entidad_padre,
    RazonSocial AS razon_social, NitCif AS nit_cif, Email AS email,
    Telefono AS telefono, Pais AS pais, Ciudad AS ciudad, Direccion AS direccion,
    LogoPath AS logo_path, Activo AS activo, FechaRegistro AS fecha_registro"""

def get_all_entidades():
    """Entidades activas en orden de árbol: cada entidad seguida de sus sub-entidades.

    WITH RECURSIVE recorre el árbol desde las entidades principales (sin padre)
    hacia abajo. 'nivel' es la profundidad (0 = principal, 1 = sub-entidad, ...),
    'ruta' guarda los nombres desde la raíz, para ordenar padre -> hijos, y
    'ruta_ids' los ids de esa misma cadena (sirve para filtrar por entidad principal).
    """
    return _query(f"""
        WITH RECURSIVE arbol AS (
            SELECT IdEntidad, 0 AS nivel, ARRAY[RazonSocial::TEXT] AS ruta,
                   ARRAY[IdEntidad] AS ruta_ids
            FROM Entidad
            WHERE Activo = 1 AND IdEntidadPadre IS NULL
          UNION ALL
            SELECT h.IdEntidad, a.nivel + 1, a.ruta || h.RazonSocial::TEXT,
                   a.ruta_ids || h.IdEntidad
            FROM Entidad h
            JOIN arbol a ON h.IdEntidadPadre = a.IdEntidad
            WHERE h.Activo = 1
        )
        SELECT e.*, a.nivel, a.ruta_ids, p.RazonSocial AS nombre_padre
        FROM arbol a
        JOIN (SELECT {_CAMPOS_ENTIDAD} FROM Entidad) e ON e.id = a.IdEntidad
        LEFT JOIN Entidad p ON p.IdEntidad = e.id_entidad_padre
        ORDER BY a.ruta
    """)

def get_entidad_by_id(id_entidad: int):
    return _query(f"SELECT {_CAMPOS_ENTIDAD} FROM Entidad WHERE IdEntidad = %s", (id_entidad,), one=True)

def create_entidad(razon_social, nit_cif, telefono, pais, ciudad, direccion, logo_path=None,
                   email=None, id_entidad_padre=None):
    return _query(
        """INSERT INTO Entidad (RazonSocial, NitCif, Telefono, Pais, Ciudad, Direccion, LogoPath,
                                Email, IdEntidadPadre)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (razon_social, nit_cif, telefono, pais, ciudad, direccion, logo_path,
         email or None, id_entidad_padre or None),
        write=True
    )

def update_entidad(id_entidad, razon_social, nit_cif, telefono, pais, ciudad, direccion, logo_path=None,
                   email=None, id_entidad_padre=None):
    sets = ["RazonSocial=%s", "NitCif=%s", "Telefono=%s", "Pais=%s", "Ciudad=%s",
            "Direccion=%s", "Email=%s", "IdEntidadPadre=%s"]
    params = [razon_social, nit_cif, telefono, pais, ciudad, direccion,
              email or None, id_entidad_padre or None]
    if logo_path:
        sets.append("LogoPath=%s")
        params.append(logo_path)
    params.append(id_entidad)
    return _query(
        f"UPDATE Entidad SET {', '.join(sets)} WHERE IdEntidad=%s",
        tuple(params), write=True
    )

def contar_subentidades_activas(id_entidad: int) -> int:
    row = _query("SELECT COUNT(*) AS total FROM Entidad WHERE IdEntidadPadre = %s AND Activo = 1",
                 (id_entidad,), one=True)
    return row['total'] if row else 0

def delete_entidad(id_entidad: int):
    return _query("UPDATE Entidad SET Activo=0 WHERE IdEntidad=%s", (id_entidad,), write=True)


# ─────────────────────────────────────────────
#  USUARIOS  (tabla Usuario + Rol)
# ─────────────────────────────────────────────

_CAMPOS_USUARIO = """IdUsuario AS id, IdEntidad AS id_entidad, Rol AS rol,
    Nombre AS nombre, NombreUsuario AS nombre_usuario, TipoDocumento AS tipo_documento,
    Documento AS documento, Nacionalidad AS nacionalidad, Email AS email, Telefono AS telefono,
    PasswordHash AS password_hash, FotoPerfilPath AS foto_perfil_path,
    DocIdentidadPath AS doc_identidad_path, Estado AS estado, FechaRegistro AS fecha_registro,
    (BloqueadoHasta IS NOT NULL AND BloqueadoHasta > NOW()) AS bloqueado_temporal,
    CEIL(GREATEST(EXTRACT(EPOCH FROM (BloqueadoHasta - NOW())), 0) / 60) AS minutos_bloqueo,
    TotpSecret AS totp_secret, TotpActivo AS totp_activo, TotpUltimoIntervalo AS totp_ultimo_intervalo"""

_CAMPOS_USUARIO_JOIN = """u.IdUsuario AS id, u.IdEntidad AS id_entidad, u.Rol AS rol,
    u.Nombre AS nombre, u.NombreUsuario AS nombre_usuario, u.TipoDocumento AS tipo_documento,
    u.Documento AS documento, u.Nacionalidad AS nacionalidad, u.Email AS email, u.Telefono AS telefono,
    u.PasswordHash AS password_hash, u.FotoPerfilPath AS foto_perfil_path,
    u.DocIdentidadPath AS doc_identidad_path, u.Estado AS estado, u.FechaRegistro AS fecha_registro,
    (u.BloqueadoHasta IS NOT NULL AND u.BloqueadoHasta > NOW()) AS bloqueado_temporal,
    CEIL(GREATEST(EXTRACT(EPOCH FROM (u.BloqueadoHasta - NOW())), 0) / 60) AS minutos_bloqueo,
    u.TotpSecret AS totp_secret, u.TotpActivo AS totp_activo, u.TotpUltimoIntervalo AS totp_ultimo_intervalo"""

def _id_rol_por_clave(clave: str):
    """Busca el IdRol correspondiente a una Clave de Rol (super_admin, admin_entidad, ...).
    El nuevo esquema exige Usuario.IdRol como llave foránea obligatoria hacia Rol,
    además de la columna Usuario.Rol (texto, copia de Rol.Clave) que ya usaba el resto
    de la aplicación para no tener que hacer join en cada consulta."""
    # Alias en minúscula: PostgreSQL devuelve los nombres sin comillas en minúscula (idrol).
    row = _query("SELECT IdRol AS id_rol FROM Rol WHERE Clave = %s", (clave,), one=True)
    return row['id_rol'] if row else None

def get_all_usuarios(id_entidad=None):
    """Trae todos los usuarios. Si se filtra por id_entidad solo retorna los de esa entidad."""
    if id_entidad:
        sql = f"""
            SELECT {_CAMPOS_USUARIO_JOIN}, e.RazonSocial AS nombre_entidad
            FROM Usuario u
            LEFT JOIN Entidad e ON u.IdEntidad = e.IdEntidad
            WHERE u.IdEntidad = %s
            ORDER BY u.Nombre
        """
        return _query(sql, (id_entidad,))
    sql = f"""
        SELECT {_CAMPOS_USUARIO_JOIN}, e.RazonSocial AS nombre_entidad
        FROM Usuario u
        LEFT JOIN Entidad e ON u.IdEntidad = e.IdEntidad
        ORDER BY u.Rol, u.Nombre
    """
    return _query(sql)

def get_user_by_documento(documento: str):
    return _query(f"SELECT {_CAMPOS_USUARIO} FROM Usuario WHERE Documento = %s", (documento,), one=True)

def get_user_by_username(nombre_usuario: str):
    return _query(f"SELECT {_CAMPOS_USUARIO} FROM Usuario WHERE NombreUsuario = %s", (nombre_usuario,), one=True)

def verify_user(nombre_usuario: str, password: str):
    """Devuelve el usuario si la contraseña es correcta; si no, None.
    Si el hash guardado todavía es SHA-256, se vuelve a guardar en bcrypt
    aprovechando que en este momento tenemos la contraseña en claro."""
    user = get_user_by_username(nombre_usuario)
    if user and verificar_password(password, user.get('password_hash')):
        if _es_hash_legado(user['password_hash']):
            _query("UPDATE Usuario SET PasswordHash = %s WHERE IdUsuario = %s",
                   (_hash_password(password), user['id']), write=True)
        return user
    return None

# ─── Bloqueo por intentos fallidos (columnas IntentosFallidos / BloqueadoHasta) ──

def registrar_login_fallido(id_usuario: int, max_intentos: int, minutos_bloqueo: int) -> bool:
    """Suma un intento fallido. Al llegar al máximo bloquea la cuenta por
    `minutos_bloqueo` y reinicia el contador. Devuelve True si quedó bloqueada."""
    _query("UPDATE Usuario SET IntentosFallidos = IntentosFallidos + 1 WHERE IdUsuario = %s",
           (id_usuario,), write=True)
    fila = _query("SELECT IntentosFallidos AS intentos FROM Usuario WHERE IdUsuario = %s",
                  (id_usuario,), one=True)
    if fila and fila['intentos'] >= max_intentos:
        _query("""UPDATE Usuario SET BloqueadoHasta = NOW() + %s * INTERVAL '1 minute',
                                     IntentosFallidos = 0
                   WHERE IdUsuario = %s""", (minutos_bloqueo, id_usuario), write=True)
        return True
    return False

def registrar_login_ok(id_usuario: int):
    _query("""UPDATE Usuario SET IntentosFallidos = 0, BloqueadoHasta = NULL, UltimoAcceso = NOW()
               WHERE IdUsuario = %s""", (id_usuario,), write=True)

# ─── Recuperación de contraseña (tabla TokenRecuperacion) ───────────────────
# En la base solo se guarda el SHA-256 del token, nunca el token en claro:
# si alguien lee la tabla, no puede usar los tokens para cambiar contraseñas.

def get_user_by_username_o_email(identificador: str):
    return _query(
        f"SELECT {_CAMPOS_USUARIO} FROM Usuario WHERE NombreUsuario = %s OR Email = %s",
        (identificador, identificador), one=True
    )

def crear_token_recuperacion(id_usuario: int, token_hash: str, minutos: int, ip: str = None,
                             tipo: str = 'recuperacion'):
    """tipo: 'recuperacion' (olvidé mi contraseña) o 'activacion' (usuario nuevo)."""
    # Se invalidan los tokens anteriores del mismo tipo sin usar: solo vale el último enlace enviado.
    _query("""UPDATE TokenRecuperacion SET UsadoEn = NOW()
               WHERE IdUsuario = %s AND Tipo = %s AND UsadoEn IS NULL""",
           (id_usuario, tipo), write=True)
    return _query(
        """INSERT INTO TokenRecuperacion (IdUsuario, TokenHash, ExpiraEn, IpSolicitud, Tipo)
           VALUES (%s, %s, NOW() + %s * INTERVAL '1 minute', %s, %s)""",
        (id_usuario, token_hash, minutos, ip, tipo), write=True
    )

def get_token_recuperacion_valido(token_hash: str, tipo: str = 'recuperacion'):
    """Devuelve el token si existe, es del tipo pedido, no se ha usado y no ha vencido; si no, None."""
    return _query(
        """SELECT IdTokenRecuperacion AS id, IdUsuario AS id_usuario
             FROM TokenRecuperacion
            WHERE TokenHash = %s AND Tipo = %s AND UsadoEn IS NULL AND ExpiraEn > NOW()""",
        (token_hash, tipo), one=True
    )

def contar_tokens_recientes(id_usuario: int, tipo: str, minutos: int) -> int:
    """Cuántos correos de este tipo se le enviaron al usuario en los últimos
    `minutos`. Sirve para limitar los reenvíos (uno por minuto, pocos por hora)."""
    fila = _query(
        """SELECT COUNT(*) AS n FROM TokenRecuperacion
            WHERE IdUsuario = %s AND Tipo = %s
              AND FechaRegistro > NOW() - %s * INTERVAL '1 minute'""",
        (id_usuario, tipo, minutos), one=True
    )
    return int(fila['n']) if fila else 0

def usar_token_recuperacion(id_token: int, id_usuario: int, nueva_password: str):
    """Cambia la contraseña, marca el token como usado y desbloquea la cuenta."""
    _query("""UPDATE Usuario SET PasswordHash = %s, IntentosFallidos = 0, BloqueadoHasta = NULL
               WHERE IdUsuario = %s""",
           (_hash_password(nueva_password), id_usuario), write=True)
    _query("UPDATE TokenRecuperacion SET UsadoEn = NOW() WHERE IdTokenRecuperacion = %s",
           (id_token,), write=True)

# ─── Activación de cuenta (usuario creado por un administrador) ─────────────

def set_password_temporal(id_usuario: int, password_temporal: str):
    """Guarda una nueva contraseña temporal y deja la cuenta en 'pendiente'
    (se usa al reenviar la activación)."""
    _query("""UPDATE Usuario SET PasswordHash = %s, Estado = 'pendiente',
                                 IntentosFallidos = 0, BloqueadoHasta = NULL
               WHERE IdUsuario = %s""",
           (_hash_password(password_temporal), id_usuario), write=True)

def activar_usuario(id_token: int, id_usuario: int, nueva_password: str):
    """El usuario cambió la contraseña temporal por la suya: la cuenta pasa a
    'activo' (con esto el correo queda verificado) y el token se quema."""
    _query("""UPDATE Usuario SET PasswordHash = %s, Estado = 'activo',
                                 IntentosFallidos = 0, BloqueadoHasta = NULL
               WHERE IdUsuario = %s""",
           (_hash_password(nueva_password), id_usuario), write=True)
    _query("UPDATE TokenRecuperacion SET UsadoEn = NOW() WHERE IdTokenRecuperacion = %s",
           (id_token,), write=True)

# ─── Verificación en dos pasos (Usuario.Totp* + tabla CodigoRespaldo) ──────
# La lógica TOTP (secreto, QR, validación) está en app/dosfactores.py.

def guardar_totp_pendiente(id_usuario: int, secreto_cifrado: str):
    """Secreto recién generado, todavía sin confirmar: TotpActivo sigue en falso."""
    _query("""UPDATE Usuario SET TotpSecret = %s, TotpActivo = FALSE, TotpUltimoIntervalo = NULL
               WHERE IdUsuario = %s""", (secreto_cifrado, id_usuario), write=True)

def activar_totp(id_usuario: int, intervalo: int):
    _query("""UPDATE Usuario SET TotpActivo = TRUE, TotpActivadoEn = NOW(), TotpUltimoIntervalo = %s
               WHERE IdUsuario = %s""", (intervalo, id_usuario), write=True)

def registrar_totp_usado(id_usuario: int, intervalo: int):
    """Guarda el último intervalo aceptado para que el mismo código no sirva dos veces."""
    _query("UPDATE Usuario SET TotpUltimoIntervalo = %s WHERE IdUsuario = %s",
           (intervalo, id_usuario), write=True)

def desactivar_totp(id_usuario: int):
    """Borra el secreto y los códigos de respaldo: la cuenta vuelve a solo contraseña."""
    _query("""UPDATE Usuario SET TotpSecret = NULL, TotpActivo = FALSE,
                                 TotpUltimoIntervalo = NULL, TotpActivadoEn = NULL
               WHERE IdUsuario = %s""", (id_usuario,), write=True)
    _query("DELETE FROM CodigoRespaldo WHERE IdUsuario = %s", (id_usuario,), write=True)

def reemplazar_codigos_respaldo(id_usuario: int, hashes: list[str]):
    _query("DELETE FROM CodigoRespaldo WHERE IdUsuario = %s", (id_usuario,), write=True)
    for h in hashes:
        _query("INSERT INTO CodigoRespaldo (IdUsuario, CodigoHash) VALUES (%s, %s)",
               (id_usuario, h), write=True)

def usar_codigo_respaldo(id_usuario: int, codigo_hash: str) -> bool:
    """Marca el código como gastado. Devuelve False si no existe o ya se usó."""
    afectados = _query("""UPDATE CodigoRespaldo SET UsadoEn = NOW()
                          WHERE IdUsuario = %s AND CodigoHash = %s AND UsadoEn IS NULL""",
                       (id_usuario, codigo_hash), write=True)
    return bool(afectados)

def contar_codigos_respaldo(id_usuario: int) -> int:
    fila = _query("SELECT COUNT(*) AS n FROM CodigoRespaldo WHERE IdUsuario = %s AND UsadoEn IS NULL",
                  (id_usuario,), one=True)
    return int(fila['n']) if fila else 0

def get_usuarios_pendientes_vencidos(dias: int):
    """Usuarios que nunca activaron su cuenta y fueron creados hace más de `dias`."""
    return _query(
        """SELECT IdUsuario AS id, Nombre AS nombre, NombreUsuario AS nombre_usuario,
                  Email AS email, FechaRegistro AS fecha_registro
             FROM Usuario
            WHERE Estado = 'pendiente' AND FechaRegistro < NOW() - %s * INTERVAL '1 day'
            ORDER BY FechaRegistro""",
        (dias,)
    ) or []

def create_usuario(nombre, nombre_usuario, documento, email, telefono, password, rol,
                   id_entidad=None, tipo_documento=None, doc_identidad_path=None,
                   nacionalidad=None, foto_perfil_path=None, estado='pendiente'):
    # IdRol es NOT NULL en el nuevo esquema: se resuelve a partir de la clave de rol.
    id_rol = _id_rol_por_clave(rol)
    # TipoDocumento pasó a ser ENUM NOT NULL DEFAULT 'CC'; si el formulario no
    # manda nada, se conserva ese valor por defecto en vez de insertar NULL.
    return _query(
        """INSERT INTO Usuario
               (Nombre, NombreUsuario, Documento, Email, Telefono, PasswordHash, Rol, IdRol,
                IdEntidad, TipoDocumento, DocIdentidadPath, Nacionalidad, FotoPerfilPath, Estado)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (nombre, nombre_usuario, documento, email, telefono, _hash_password(password), rol, id_rol,
         id_entidad, tipo_documento or 'CC', doc_identidad_path, nacionalidad or 'CO', foto_perfil_path,
         estado),
        write=True
    )

def documento_existe(documento: str) -> bool:
    row = _query("SELECT IdUsuario FROM Usuario WHERE Documento = %s", (documento,), one=True)
    return row is not None

def email_existe(email: str) -> bool:
    row = _query("SELECT IdUsuario FROM Usuario WHERE Email = %s", (email,), one=True)
    return row is not None

def username_existe(nombre_usuario: str) -> bool:
    row = _query("SELECT IdUsuario FROM Usuario WHERE NombreUsuario = %s", (nombre_usuario,), one=True)
    return row is not None

def username_existe_otro(nombre_usuario: str, id_excluir: int) -> bool:
    row = _query(
        "SELECT IdUsuario FROM Usuario WHERE NombreUsuario = %s AND IdUsuario != %s",
        (nombre_usuario, id_excluir), one=True
    )
    return row is not None

def email_existe_otro(email: str, id_excluir: int) -> bool:
    row = _query(
        "SELECT IdUsuario FROM Usuario WHERE Email = %s AND IdUsuario != %s",
        (email, id_excluir), one=True
    )
    return row is not None

def get_usuario_by_id(id_usuario: int):
    return _query(f"SELECT {_CAMPOS_USUARIO} FROM Usuario WHERE IdUsuario = %s", (id_usuario,), one=True)

def update_usuario(id_usuario, nombre, nombre_usuario, email, telefono,
                   password=None, rol=None, id_entidad=False, foto_perfil_path=None):
    sets   = ["Nombre=%s", "NombreUsuario=%s", "Email=%s", "Telefono=%s"]
    params = [nombre, nombre_usuario, email, telefono]
    if password:
        sets.append("PasswordHash=%s")
        params.append(_hash_password(password))
    if foto_perfil_path:
        sets.append("FotoPerfilPath=%s")
        params.append(foto_perfil_path)
    if rol is not None:
        sets.append("Rol=%s")
        params.append(rol)
        # IdRol debe quedar sincronizado con Rol, ya que ahora es una FK obligatoria.
        id_rol = _id_rol_por_clave(rol)
        if id_rol:
            sets.append("IdRol=%s")
            params.append(id_rol)
    if id_entidad is not False:
        sets.append("IdEntidad=%s")
        params.append(id_entidad)
    params.append(id_usuario)
    return _query(
        f"UPDATE Usuario SET {', '.join(sets)} WHERE IdUsuario=%s",
        tuple(params), write=True
    )

def delete_usuario(id_usuario: int):
    return _query("DELETE FROM Usuario WHERE IdUsuario=%s", (id_usuario,), write=True)

def get_guias_caninos(id_entidad=None):
    """Retorna usuarios con rol guia_canino, opcionalmente filtrados por entidad."""
    if id_entidad:
        sql = f"""
            SELECT {_CAMPOS_USUARIO_JOIN}, e.RazonSocial AS nombre_entidad
            FROM Usuario u
            LEFT JOIN Entidad e ON u.IdEntidad = e.IdEntidad
            WHERE u.Rol = 'guia_canino' AND u.IdEntidad = %s
            ORDER BY u.Nombre
        """
        return _query(sql, (id_entidad,))
    sql = f"""
        SELECT {_CAMPOS_USUARIO_JOIN}, e.RazonSocial AS nombre_entidad
        FROM Usuario u
        LEFT JOIN Entidad e ON u.IdEntidad = e.IdEntidad
        WHERE u.Rol = 'guia_canino'
        ORDER BY e.RazonSocial, u.Nombre
    """
    return _query(sql)


# ─────────────────────────────────────────────
#  CANINOS  (tabla Canino)
# ─────────────────────────────────────────────

# El nuevo esquema ya NO guarda nombre_vacuna / ultima_vacunacion / proxima_vacunacion
# en Canino (viven normalizados en CaninoVacuna). Estas 3 subconsultas reconstruyen
# esos mismos campos a partir del último registro de CaninoVacuna, para que el
# formulario de caninos (que todavía los muestra) siga funcionando sin cambios.
_CAMPOS_CANINO = """
    c.IdCanino AS id, c.IdEntidad AS id_entidad, c.IdGuiaActual AS id_guia,
    c.Nombre AS nombre, c.Raza AS raza, c.Genero AS genero,
    c.FechaNacimiento AS fecha_nacimiento, c.ChipNumero AS chip_numero,
    c.NumRegistro AS num_registro, c.ColorPelaje AS color_pelaje, c.PesoKg AS peso_kg,
    c.TallaCm AS talla_cm, c.Especialidad AS especialidad, c.Estado AS estado,
    c.FotoPath AS foto_path, c.Procedencia AS procedencia, c.FechaIngreso AS fecha_ingreso,
    c.Observaciones AS observaciones, c.HistorialClinicoPath AS historial_clinico_path,
    c.MotivoBaja AS motivo_baja, c.JustificacionBaja AS justificacion_baja,
    c.FechaBaja AS fecha_baja, c.CartaBajaPath AS carta_baja_path,
    (SELECT NombreVacuna FROM CaninoVacuna cv WHERE cv.IdCanino = c.IdCanino
        ORDER BY FechaAplicacion DESC LIMIT 1) AS nombre_vacuna,
    (SELECT FechaAplicacion FROM CaninoVacuna cv WHERE cv.IdCanino = c.IdCanino
        ORDER BY FechaAplicacion DESC LIMIT 1) AS ultima_vacunacion,
    (SELECT FechaVencimiento FROM CaninoVacuna cv WHERE cv.IdCanino = c.IdCanino
        AND FechaVencimiento >= CURRENT_DATE ORDER BY FechaVencimiento ASC LIMIT 1) AS proxima_vacunacion
"""

def get_all_caninos(id_entidad=None, id_guia=None, incluir_baja=False):
    """Retorna caninos con join a entidad y guía asignado."""
    conditions = [] if incluir_baja else ["c.Estado != 'baja'"]
    params = []
    if id_entidad:
        conditions.append("c.IdEntidad = %s")
        params.append(id_entidad)
    if id_guia:
        conditions.append("c.IdGuiaActual = %s")
        params.append(id_guia)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"""
        SELECT {_CAMPOS_CANINO},
               e.RazonSocial AS nombre_entidad,
               u.Nombre AS nombre_guia,
               u.FotoPerfilPath AS foto_guia
        FROM Canino c
        LEFT JOIN Entidad e ON c.IdEntidad = e.IdEntidad
        LEFT JOIN Usuario u ON c.IdGuiaActual = u.IdUsuario
        {where}
        ORDER BY e.RazonSocial, c.Nombre
    """
    return _query(sql, tuple(params))

def get_canino_by_id(id_canino: int):
    return _query(f"""
        SELECT {_CAMPOS_CANINO}, e.RazonSocial AS nombre_entidad, u.Nombre AS nombre_guia
        FROM Canino c
        LEFT JOIN Entidad e ON c.IdEntidad = e.IdEntidad
        LEFT JOIN Usuario u ON c.IdGuiaActual = u.IdUsuario
        WHERE c.IdCanino = %s
    """, (id_canino,), one=True)

def create_canino(nombre, raza, genero, especialidad, estado,
                  id_entidad=None, id_guia=None,
                  fecha_nacimiento=None, chip_numero=None, num_registro=None,
                  color_pelaje=None, peso_kg=None, talla_cm=None, foto_path=None,
                  fecha_ingreso=None, procedencia=None,
                  nombre_vacuna=None, ultima_vacunacion=None, proxima_vacunacion=None,
                  observaciones=None):
    # CodigoUnico es NOT NULL/UNIQUE (por entidad) en el nuevo esquema; el
    # formulario actual no lo pide, así que se genera uno interno con marca de tiempo.
    import time as _time
    codigo_unico = f"K9-{int(_time.time() * 1000)}"
    id_canino = _query(
        """INSERT INTO Canino
               (IdEntidad, IdGuiaActual, CodigoUnico, Nombre, Raza, Genero, Especialidad, Estado,
                FechaNacimiento, ChipNumero, NumRegistro, ColorPelaje, PesoKg, TallaCm,
                FotoPath, FechaIngreso, Procedencia, Observaciones)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (id_entidad or None, id_guia or None, codigo_unico, nombre, raza, genero,
         especialidad, estado,
         fecha_nacimiento or None, chip_numero or None, num_registro or None,
         color_pelaje or None, peso_kg or None, talla_cm or None,
         foto_path, fecha_ingreso or None, procedencia or None,
         observaciones or None),
        write=True
    )
    # Las vacunas ya no viven en Canino: si el formulario trajo una, se registra
    # como el primer renglón de CaninoVacuna para este canino.
    if nombre_vacuna and id_canino:
        create_vacuna_canino(
            id_canino, nombre_vacuna,
            ultima_vacunacion or fecha_ingreso or date.today().isoformat(),
            proxima_vacunacion or None,
        )
    return id_canino

def update_canino(id_canino, nombre, raza, genero, especialidad, estado,
                  id_entidad=None, id_guia=None,
                  fecha_nacimiento=None, chip_numero=None, num_registro=None,
                  color_pelaje=None, peso_kg=None, talla_cm=None, foto_path=None,
                  fecha_ingreso=None, procedencia=None,
                  nombre_vacuna=None, ultima_vacunacion=None, proxima_vacunacion=None,
                  observaciones=None):
    sets = [
        "Nombre=%s","Raza=%s","Genero=%s","Especialidad=%s","Estado=%s",
        "IdEntidad=%s","IdGuiaActual=%s","FechaNacimiento=%s","ChipNumero=%s",
        "NumRegistro=%s","ColorPelaje=%s","PesoKg=%s","TallaCm=%s",
        "FechaIngreso=%s","Procedencia=%s","Observaciones=%s",
    ]
    params = [
        nombre, raza, genero, especialidad, estado,
        id_entidad or None, id_guia or None,
        fecha_nacimiento or None, chip_numero or None, num_registro or None,
        color_pelaje or None, peso_kg or None, talla_cm or None,
        fecha_ingreso or None, procedencia or None,
        observaciones or None,
    ]
    if foto_path:
        sets.append("FotoPath=%s")
        params.append(foto_path)
    params.append(id_canino)
    resultado = _query(
        f"UPDATE Canino SET {', '.join(sets)} WHERE IdCanino=%s",
        tuple(params), write=True
    )
    # Solo se crea un nuevo renglón en CaninoVacuna si el dato de vacuna cambió
    # respecto al último registrado; evita duplicar una fila en cada edición del canino.
    if nombre_vacuna:
        ultimo = _query(
            """SELECT NombreVacuna AS nombre_vacuna, FechaVencimiento AS fecha_vencimiento
               FROM CaninoVacuna
               WHERE IdCanino=%s ORDER BY FechaAplicacion DESC LIMIT 1""",
            (id_canino,), one=True
        )
        cambio = (not ultimo
                  or ultimo['nombre_vacuna'] != nombre_vacuna
                  or str(ultimo['fecha_vencimiento'] or '') != str(proxima_vacunacion or ''))
        if cambio:
            create_vacuna_canino(
                id_canino, nombre_vacuna,
                ultima_vacunacion or date.today().isoformat(),
                proxima_vacunacion or None,
            )
    return resultado

def dar_baja_canino(id_canino: int, motivo_baja: str, justificacion_baja: str,
                    fecha_baja: str, carta_baja_path: str = None):
    return _query(
        """UPDATE Canino
           SET Estado='baja', MotivoBaja=%s, JustificacionBaja=%s,
               FechaBaja=%s, CartaBajaPath=%s
           WHERE IdCanino=%s""",
        (motivo_baja, justificacion_baja, fecha_baja, carta_baja_path, id_canino),
        write=True
    )


# ─────────────────────────────────────────────
#  SALUD CANINA — vacunas e historial  (tabla CaninoVacuna)
# ─────────────────────────────────────────────

def get_all_vacunas_agrupadas(ids_caninos: list) -> dict:
    """Devuelve un dict {id_canino: [vacunas]} en una sola query."""
    if not ids_caninos:
        return {}
    ph  = ','.join(['%s'] * len(ids_caninos))
    rows = _query(
        f"""SELECT IdCaninoVacuna AS id, IdCanino AS id_canino, NombreVacuna AS nombre_vacuna,
                   FechaAplicacion AS fecha_aplicacion, FechaVencimiento AS fecha_vencimiento,
                   Veterinario AS veterinario, Notas AS notas, ComprobantePath AS comprobante_path
            FROM CaninoVacuna WHERE IdCanino IN ({ph}) ORDER BY IdCanino, FechaAplicacion DESC""",
        tuple(ids_caninos)
    )
    result: dict = {}
    for r in (rows or []):
        cid = r['id_canino']
        result.setdefault(cid, []).append(r)
    return result

def create_vacuna_canino(id_canino, nombre_vacuna, fecha_aplicacion,
                         fecha_vencimiento=None, veterinario=None, notas=None,
                         comprobante_path=None):
    return _query(
        """INSERT INTO CaninoVacuna
               (IdCanino, NombreVacuna, FechaAplicacion, FechaVencimiento,
                Veterinario, Notas, ComprobantePath)
           VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (id_canino, nombre_vacuna, fecha_aplicacion,
         fecha_vencimiento or None, veterinario or None, notas or None,
         comprobante_path),
        write=True
    )

def delete_vacuna_canino(id_vacuna: int):
    return _query("DELETE FROM CaninoVacuna WHERE IdCaninoVacuna=%s", (id_vacuna,), write=True)

def update_historial_canino(id_canino: int, historial_path: str):
    return _query(
        "UPDATE Canino SET HistorialClinicoPath=%s WHERE IdCanino=%s",
        (historial_path, id_canino), write=True
    )


# ─────────────────────────────────────────────
#  CURSOS / ACADEMIA K9  (tabla Sesion)
# ─────────────────────────────────────────────
# cursos_sesiones se renombró a Sesion en el nuevo esquema (cada fila sigue
# siendo una sesión de entrenamiento, no un curso completo).

_CAMPOS_SESION = """s.IdSesion AS id, s.Especialidad AS especialidad, s.IdCanino AS id_canino,
    s.IdEntidad AS id_entidad, s.Fecha AS fecha, s.Resultado AS resultado,
    s.Observaciones AS observaciones, s.Instructor AS instructor,
    s.IdUsuarioRegistra AS id_usuario_registra"""

def get_sesiones_by_especialidad(especialidad: str, id_entidad=None, id_usuario=None):
    """Sesiones de un programa. id_entidad filtra por entidad; id_usuario deja
    solo las que registró ese usuario (lo que ve un guía canino)."""
    condiciones, params = ["s.Especialidad = %s"], [especialidad]
    if id_entidad:
        condiciones.append("s.IdEntidad = %s"); params.append(id_entidad)
    if id_usuario:
        condiciones.append("s.IdUsuarioRegistra = %s"); params.append(id_usuario)
    sql = f"""
        SELECT {_CAMPOS_SESION}, c.Nombre AS nombre_canino, c.Raza AS raza,
               c.FotoPath AS foto_path, e.RazonSocial AS nombre_entidad
        FROM Sesion s
        JOIN Canino c ON s.IdCanino = c.IdCanino
        LEFT JOIN Entidad e ON s.IdEntidad = e.IdEntidad
        WHERE {' AND '.join(condiciones)}
        ORDER BY s.Fecha DESC
    """
    return _query(sql, tuple(params))

def count_sesiones_por_especialidad(id_entidad=None, id_usuario=None):
    condiciones, params = [], []
    if id_entidad:
        condiciones.append("IdEntidad = %s"); params.append(id_entidad)
    if id_usuario:
        condiciones.append("IdUsuarioRegistra = %s"); params.append(id_usuario)
    where = ("WHERE " + " AND ".join(condiciones)) if condiciones else ""
    rows = _query(
        f"SELECT Especialidad AS especialidad, COUNT(*) AS total FROM Sesion {where} GROUP BY Especialidad",
        tuple(params)
    )
    return {r['especialidad']: r['total'] for r in (rows or [])}

def create_sesion_curso(especialidad, id_canino, id_entidad, fecha,
                        resultado=None, observaciones=None, instructor=None,
                        id_usuario_registra=None):
    # IdUsuarioRegistra = quién registró la sesión; así el guía ve solo lo que él hizo.
    return _query(
        """INSERT INTO Sesion
               (Especialidad, IdCanino, IdEntidad, Fecha, Resultado, Observaciones, Instructor,
                IdUsuarioRegistra)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
        (especialidad, id_canino, id_entidad or None, fecha,
         resultado or None, observaciones or None, instructor or None,
         id_usuario_registra or None),
        write=True
    )

# ─── Comprobaciones de pertenencia (para el rol guía canino) ─────────────────

def canino_es_del_guia(id_canino, id_guia) -> bool:
    """True si el canino está asignado actualmente a ese guía."""
    row = _query("SELECT 1 AS ok FROM Canino WHERE IdCanino=%s AND IdGuiaActual=%s",
                 (id_canino, id_guia), one=True)
    return row is not None

def sesion_es_del_usuario(id_sesion, id_usuario) -> bool:
    """True si la sesión la registró ese usuario."""
    row = _query("SELECT 1 AS ok FROM Sesion WHERE IdSesion=%s AND IdUsuarioRegistra=%s",
                 (id_sesion, id_usuario), one=True)
    return row is not None

def get_id_sesion_de_archivo(id_arch):
    row = _query("SELECT IdSesion AS id_sesion FROM RegistroDocumental WHERE IdRegistroDocumental=%s",
                 (id_arch,), one=True)
    return row['id_sesion'] if row else None

def get_id_canino_de_vacuna(id_vacuna):
    row = _query("SELECT IdCanino AS id_canino FROM CaninoVacuna WHERE IdCaninoVacuna=%s",
                 (id_vacuna,), one=True)
    return row['id_canino'] if row else None

def delete_sesion_curso(id_sesion: int):
    return _query("DELETE FROM Sesion WHERE IdSesion=%s", (id_sesion,), write=True)

def update_sesion_curso(id_sesion, fecha, resultado, observaciones, instructor):
    return _query(
        "UPDATE Sesion SET Fecha=%s, Resultado=%s, Observaciones=%s, Instructor=%s WHERE IdSesion=%s",
        (fecha, resultado or None, observaciones or None, instructor or None, id_sesion),
        write=True
    )

def marcar_sesion_en_proceso(id_sesion: int):
    """Pasa la sesión a 'en_proceso' solo si todavía estaba 'Sin definir' (NULL o vacío).
    Si ya tiene un resultado (aprobado / reprobado / en_proceso) no se modifica."""
    return _query(
        "UPDATE Sesion SET Resultado='en_proceso' WHERE IdSesion=%s AND COALESCE(Resultado, '') = ''",
        (id_sesion,), write=True
    )

def get_sesion_by_id(id_sesion: int):
    rows = _query(f"""
        SELECT {_CAMPOS_SESION}, c.Nombre AS nombre_canino, c.Raza AS raza,
               c.FotoPath AS foto_path, e.RazonSocial AS nombre_entidad
        FROM Sesion s
        JOIN Canino c ON s.IdCanino = c.IdCanino
        LEFT JOIN Entidad e ON s.IdEntidad = e.IdEntidad
        WHERE s.IdSesion = %s
    """, (id_sesion,))
    return rows[0] if rows else None

def get_vision_archivos(id_sesion: int):
    return _query("""
        SELECT IdRegistroDocumental AS id, IdSesion AS id_sesion, ArchivoPath AS archivo_path,
               TipoArchivo AS tipo, Transcripcion AS notas, FechaRegistro AS created_at,
               ArchivoEliminadoEn AS archivo_eliminado_en
        FROM RegistroDocumental WHERE IdSesion=%s ORDER BY FechaRegistro DESC
    """, (id_sesion,)) or []

def create_vision_archivo(id_sesion: int, archivo_path: str, tipo: str, notas: str = None):
    # RegistroDocumental (antes sesion_vision) exige IdEntidad, IdCanino, Titulo
    # y FechaHora (NOT NULL); se obtienen de la sesión/canino padres para no
    # cambiar la firma de esta función en main.py.
    padre = _query(
        """SELECT s.IdEntidad AS id_entidad_sesion, c.IdEntidad AS id_entidad_canino,
                  s.IdCanino AS id_canino
           FROM Sesion s JOIN Canino c ON s.IdCanino = c.IdCanino
           WHERE s.IdSesion = %s""",
        (id_sesion,), one=True
    )
    id_entidad = (padre['id_entidad_sesion'] or padre['id_entidad_canino']) if padre else None
    id_canino  = padre['id_canino'] if padre else None
    titulo = f"Archivo de sesión #{id_sesion}"
    _query(
        """INSERT INTO RegistroDocumental
               (IdEntidad, IdCanino, IdSesion, Titulo, FechaHora, ArchivoPath, TipoArchivo, Transcripcion)
           VALUES (%s,%s,%s,%s,NOW(),%s,%s,%s)""",
        (id_entidad, id_canino, id_sesion, titulo, archivo_path, tipo, notas), write=True
    )

def delete_vision_archivo(id_arch: int):
    _query("DELETE FROM RegistroDocumental WHERE IdRegistroDocumental=%s", (id_arch,), write=True)

# ─── Retención de videos (ver limpiar_videos.py) ─────────────────────────────

def get_videos_vencidos(dias: int):
    """Videos y audios con más de 'dias' días que todavía tienen su archivo y
    YA tienen transcripción. Los que no se pudieron transcribir no se incluyen,
    para no perder su contenido."""
    return _query("""
        SELECT IdRegistroDocumental AS id, ArchivoPath AS archivo_path, FechaRegistro AS created_at
        FROM RegistroDocumental
        WHERE TipoArchivo IN ('video', 'audio')
          AND ArchivoEliminadoEn IS NULL
          AND FechaRegistro < NOW() - %s * INTERVAL '1 day'
          AND COALESCE(TRIM(Transcripcion), '') <> ''
        ORDER BY FechaRegistro
    """, (dias,)) or []

def marcar_archivo_eliminado(id_arch: int):
    """Registra que el archivo se borró del disco; la fila y su transcripción se conservan."""
    _query("UPDATE RegistroDocumental SET ArchivoEliminadoEn = NOW() WHERE IdRegistroDocumental=%s",
           (id_arch,), write=True)

def get_all_vision_archivos(id_entidad=None, id_usuario=None):
    """Todos los archivos de visión con contexto de sesión, canino y programa.
    id_entidad filtra por entidad; id_usuario deja solo los de las sesiones que
    registró ese usuario (lo que ve un guía canino)."""
    campos = """rd.IdRegistroDocumental AS id, rd.ArchivoPath AS archivo_path,
                rd.TipoArchivo AS tipo, rd.Transcripcion AS notas, rd.FechaRegistro AS created_at,
                rd.ArchivoEliminadoEn AS archivo_eliminado_en"""
    condiciones, params = [], []
    if id_entidad:
        condiciones.append("s.IdEntidad = %s"); params.append(id_entidad)
    if id_usuario:
        condiciones.append("s.IdUsuarioRegistra = %s"); params.append(id_usuario)
    where = ("WHERE " + " AND ".join(condiciones)) if condiciones else ""
    sql = f"""
        SELECT {campos},
               s.Fecha AS fecha, s.Especialidad AS especialidad, s.Resultado AS resultado,
               s.IdSesion AS id_sesion,
               c.Nombre AS nombre_canino, c.Raza AS raza, c.FotoPath AS foto_canino,
               e.RazonSocial AS nombre_entidad,
               pk.Nombre AS nombre_programa
        FROM RegistroDocumental rd
        JOIN Sesion s ON rd.IdSesion = s.IdSesion
        JOIN Canino c ON s.IdCanino = c.IdCanino
        LEFT JOIN Entidad e ON s.IdEntidad = e.IdEntidad
        LEFT JOIN ProgramaK9 pk ON s.Especialidad = pk.Clave
        {where}
        ORDER BY rd.FechaRegistro DESC
    """
    return _query(sql, tuple(params)) or []


# ─────────────────────────────────────────────
#  PROGRAMAS K9  (tabla ProgramaK9)
# ─────────────────────────────────────────────

_CAMPOS_PROGRAMA = """IdPrograma AS id, Clave AS clave, Nombre AS nombre,
    Descripcion AS descripcion, Icono AS icono, Color AS color,
    ImagenFondoPath AS imagen_fondo_path, EsFijo AS es_fijo, Activo AS activo"""

def get_all_programas():
    rows = _query(
        f"SELECT {_CAMPOS_PROGRAMA} FROM ProgramaK9 WHERE Activo=1 ORDER BY EsFijo DESC, IdPrograma ASC"
    ) or []
    for r in rows:
        r['key'] = r['clave']
    return rows

def get_programa_by_clave(clave: str):
    rows = _query(f"SELECT {_CAMPOS_PROGRAMA} FROM ProgramaK9 WHERE Clave=%s AND Activo=1", (clave,))
    if rows:
        rows[0]['key'] = rows[0]['clave']
        return rows[0]
    return None

def create_programa(clave, nombre, descripcion, icono, color, imagen_fondo_path=None):
    _query(
        "INSERT INTO ProgramaK9 (Clave,Nombre,Descripcion,Icono,Color,ImagenFondoPath) VALUES (%s,%s,%s,%s,%s,%s)",
        (clave, nombre, descripcion or None, icono, color, imagen_fondo_path),
        write=True
    )

def update_programa(id_prog, nombre, descripcion, icono, color, imagen_fondo_path=None):
    if imagen_fondo_path is not None:
        _query(
            "UPDATE ProgramaK9 SET Nombre=%s,Descripcion=%s,Icono=%s,Color=%s,ImagenFondoPath=%s WHERE IdPrograma=%s",
            (nombre, descripcion or None, icono, color, imagen_fondo_path, id_prog), write=True
        )
    else:
        _query(
            "UPDATE ProgramaK9 SET Nombre=%s,Descripcion=%s,Icono=%s,Color=%s WHERE IdPrograma=%s",
            (nombre, descripcion or None, icono, color, id_prog), write=True
        )

def delete_programa(id_prog: int):
    _query("UPDATE ProgramaK9 SET Activo=0 WHERE IdPrograma=%s", (id_prog,), write=True)


# ─────────────────────────────────────────────
#  REGISTROS IA  (tabla RegistroIa)
# ─────────────────────────────────────────────

def get_registros_ia(especialidad: str, id_entidad=None):
    campos = """r.IdRegistroIa AS id, r.Especialidad AS especialidad, r.IdCanino AS id_canino,
                r.IdEntidad AS id_entidad, r.Fecha AS fecha, r.Resultado AS resultado,
                r.Confianza AS confianza, r.Observaciones AS observaciones, r.ArchivoPath AS archivo_path"""
    if id_entidad:
        sql = f"""
            SELECT {campos}, c.Nombre AS nombre_canino, c.Raza AS raza, c.FotoPath AS foto_path,
                   e.RazonSocial AS nombre_entidad
            FROM RegistroIa r
            JOIN Canino c ON r.IdCanino = c.IdCanino
            LEFT JOIN Entidad e ON r.IdEntidad = e.IdEntidad
            WHERE r.Especialidad = %s AND r.IdEntidad = %s
            ORDER BY r.Fecha DESC
        """
        return _query(sql, (especialidad, id_entidad))
    sql = f"""
        SELECT {campos}, c.Nombre AS nombre_canino, c.Raza AS raza, c.FotoPath AS foto_path,
               e.RazonSocial AS nombre_entidad
        FROM RegistroIa r
        JOIN Canino c ON r.IdCanino = c.IdCanino
        LEFT JOIN Entidad e ON r.IdEntidad = e.IdEntidad
        WHERE r.Especialidad = %s
        ORDER BY r.Fecha DESC
    """
    return _query(sql, (especialidad,))

def create_registro_ia(especialidad, id_canino, id_entidad, fecha,
                       resultado=None, confianza=None, observaciones=None, archivo_path=None):
    _query(
        """INSERT INTO RegistroIa
               (Especialidad, IdCanino, IdEntidad, Fecha, Resultado, Confianza, Observaciones, ArchivoPath)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
        (especialidad, id_canino, id_entidad or None, fecha,
         resultado or None, confianza or None, observaciones or None, archivo_path),
        write=True
    )

def delete_registro_ia(id_reg: int):
    _query("DELETE FROM RegistroIa WHERE IdRegistroIa=%s", (id_reg,), write=True)
