-- ============================================================================
-- Migración: activación de cuentas por correo, bloqueo por intentos fallidos
-- y contraseñas con bcrypt.
--
-- Ejecutar UNA vez sobre la base existente:
--     psql -U <usuario> -d K9 -f migracion_activacion_cuentas.sql
-- CanGuardK9.sql ya incluye estos cambios para instalaciones nuevas.
-- Se puede ejecutar más de una vez sin dañar nada (todo es IF NOT EXISTS).
--
-- Las contraseñas guardadas con SHA-256 NO necesitan migración: la app las
-- reconoce al iniciar sesión y las vuelve a guardar en bcrypt automáticamente.
-- ============================================================================

-- 1. Estado 'pendiente': el usuario fue creado por un administrador pero aún
--    no ha activado su cuenta cambiando la contraseña temporal del correo.
--    El CHECK de Estado puede llamarse distinto según cómo se creó la base
--    (CkUsuarioEstado o usuario_estado_check), por eso se busca por su definición.
DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN SELECT conname FROM pg_constraint
              WHERE conrelid = 'usuario'::regclass AND contype = 'c'
                AND pg_get_constraintdef(oid) ILIKE '%estado%'
    LOOP
        EXECUTE format('ALTER TABLE Usuario DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;
ALTER TABLE Usuario ADD CONSTRAINT CkUsuarioEstado
    CHECK (Estado IN ('pendiente', 'activo', 'inactivo', 'bloqueado'));

-- 2. Bloqueo temporal tras varios intentos fallidos de inicio de sesión.
ALTER TABLE Usuario ADD COLUMN IF NOT EXISTS BloqueadoHasta TIMESTAMP NULL;

-- 3. La tabla de tokens ahora sirve para dos cosas: recuperar contraseña y
--    activar la cuenta. Tipo distingue cada uso.
ALTER TABLE TokenRecuperacion ADD COLUMN IF NOT EXISTS Tipo VARCHAR(12) NOT NULL DEFAULT 'recuperacion';
ALTER TABLE TokenRecuperacion DROP CONSTRAINT IF EXISTS CkTokenTipo;
ALTER TABLE TokenRecuperacion ADD CONSTRAINT CkTokenTipo
    CHECK (Tipo IN ('recuperacion', 'activacion'));
