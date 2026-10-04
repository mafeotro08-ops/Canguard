-- =====================================================================
--  CANGUARD K9 — MODELO DE DATOS
--  MariaDB 10.4+ / InnoDB / utf8mb4_general_ci
--  Nomenclatura PascalCase
--
--  Autora: María Fernanda Otero Rodríguez
--  Universidad Piloto de Colombia — Ingeniería de Sistemas
--
--  CONVENCIONES DE NOMENCLATURA
--    Tablas .......... PascalCase singular          Canino, CaninoVacuna
--    Columnas ........ PascalCase                   FechaNacimiento
--    Llave primaria .. Id + nombre de la entidad    IdCanino
--    Llave foránea ... idéntica a la PK que apunta  IdCanino
--    Vistas .......... Vw + nombre                  VwBinomioVigente
--    Restricciones ... Fk/Uq/Ix/Ck + Tabla + Campo  FkBinomioCanino
--
--  Este script crea la base desde cero. Para migrar una base existente
--  sin perder datos, usar MigracionPascalCase.sql
-- =====================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- =====================================================================
--  S1. ACCESO Y SEGURIDAD              (RF-01, RF-02, RF-03)
-- =====================================================================

CREATE TABLE IF NOT EXISTS Entidad (
    IdEntidad        INT AUTO_INCREMENT PRIMARY KEY,
    RazonSocial      VARCHAR(255) NOT NULL,
    NitCif           VARCHAR(50)  NOT NULL,
    TipoInstitucion  ENUM('policia','militar','vigilancia_privada',
                          'bomberos','defensa_civil','otra')
                     NOT NULL DEFAULT 'vigilancia_privada',
    Email            VARCHAR(150) NULL,
    Telefono         VARCHAR(30)  NULL,
    Pais             VARCHAR(10)  NOT NULL DEFAULT 'CO',
    Departamento     VARCHAR(100) NULL,
    Ciudad           VARCHAR(150) NULL,
    Direccion        VARCHAR(255) NULL,
    LogoPath         VARCHAR(255) NULL,
    Activo           TINYINT(1)   NOT NULL DEFAULT 1,
    FechaRegistro    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FechaModificacion TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT UqEntidadNit UNIQUE (NitCif),
    INDEX IxEntidadActivo (Activo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS Rol (
    IdRol       INT AUTO_INCREMENT PRIMARY KEY,
    Clave       VARCHAR(30)  NOT NULL,
    Nombre      VARCHAR(80)  NOT NULL,
    Descripcion VARCHAR(255) NULL,
    Ambito      ENUM('global','entidad') NOT NULL DEFAULT 'entidad',
    EsFijo      TINYINT(1)   NOT NULL DEFAULT 0,
    Activo      TINYINT(1)   NOT NULL DEFAULT 1,
    CONSTRAINT UqRolClave UNIQUE (Clave)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS Permiso (
    IdPermiso   INT AUTO_INCREMENT PRIMARY KEY,
    Clave       VARCHAR(60) NOT NULL,   -- Canino.Crear, Geo.Ver, ...
    Modulo      VARCHAR(40) NOT NULL,
    Descripcion VARCHAR(255) NULL,
    CONSTRAINT UqPermisoClave UNIQUE (Clave),
    INDEX IxPermisoModulo (Modulo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS RolPermiso (
    IdRol     INT NOT NULL,
    IdPermiso INT NOT NULL,
    PRIMARY KEY (IdRol, IdPermiso),
    CONSTRAINT FkRolPermisoRol     FOREIGN KEY (IdRol)     REFERENCES Rol(IdRol)         ON DELETE CASCADE,
    CONSTRAINT FkRolPermisoPermiso FOREIGN KEY (IdPermiso) REFERENCES Permiso(IdPermiso) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS Usuario (
    IdUsuario        INT AUTO_INCREMENT PRIMARY KEY,
    IdEntidad        INT          NULL,       -- NULL = super administrador
    IdRol            INT          NOT NULL,
    Rol              VARCHAR(30)  NOT NULL,   -- copia de Rol.Clave para lectura rápida
    Nombre           VARCHAR(150) NOT NULL,
    NombreUsuario    VARCHAR(50)  NOT NULL,
    TipoDocumento    ENUM('CC','CE','TI','PA','NIT') NOT NULL DEFAULT 'CC',
    Documento        VARCHAR(30)  NOT NULL,
    Nacionalidad     VARCHAR(10)  NULL DEFAULT 'CO',
    Email            VARCHAR(150) NOT NULL,
    Telefono         VARCHAR(30)  NULL,
    Direccion        VARCHAR(150) NULL,
    PasswordHash     VARCHAR(255) NOT NULL,   -- bcrypt / argon2
    FotoPerfilPath   VARCHAR(255) NULL,
    DocIdentidadPath VARCHAR(255) NULL,
    Estado           ENUM('activo','inactivo','bloqueado') NOT NULL DEFAULT 'activo',
    IntentosFallidos TINYINT      NOT NULL DEFAULT 0,
    UltimoAcceso     DATETIME     NULL,
    FechaRegistro    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FechaModificacion TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT UqUsuarioNombreUsuario UNIQUE (NombreUsuario),
    CONSTRAINT UqUsuarioEmail         UNIQUE (Email),
    CONSTRAINT UqUsuarioDocumento     UNIQUE (TipoDocumento, Documento),
    INDEX IxUsuarioEntidadRol (IdEntidad, Rol),
    CONSTRAINT FkUsuarioEntidad FOREIGN KEY (IdEntidad) REFERENCES Entidad(IdEntidad) ON DELETE RESTRICT,
    CONSTRAINT FkUsuarioRol     FOREIGN KEY (IdRol)     REFERENCES Rol(IdRol)         ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Reemplaza las columnas TokenRecuperacion / ExpiracionToken que estaban
-- dentro de Usuario: un usuario puede solicitar varios restablecimientos
-- y conviene guardar el rastro de cada solicitud.
CREATE TABLE IF NOT EXISTS TokenRecuperacion (
    IdTokenRecuperacion INT AUTO_INCREMENT PRIMARY KEY,
    IdUsuario    INT         NOT NULL,
    TokenHash    CHAR(64)    NOT NULL,
    ExpiraEn     DATETIME    NOT NULL,
    UsadoEn      DATETIME    NULL,
    IpSolicitud  VARCHAR(45) NULL,
    FechaRegistro TIMESTAMP  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT UqTokenHash UNIQUE (TokenHash),
    INDEX IxTokenUsuario (IdUsuario, ExpiraEn),
    CONSTRAINT FkTokenUsuario FOREIGN KEY (IdUsuario) REFERENCES Usuario(IdUsuario) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS Auditoria (
    IdAuditoria    BIGINT AUTO_INCREMENT PRIMARY KEY,
    IdUsuario      INT          NULL,
    IdEntidad      INT          NULL,
    Accion         ENUM('CREATE','UPDATE','DELETE','LOGIN','LOGOUT',
                        'LOGIN_FALLIDO','EXPORT','ASIGNAR','BAJA') NOT NULL,
    TablaAfectada  VARCHAR(60)  NOT NULL,
    IdRegistro     INT          NULL,
    DatosAntes     LONGTEXT     NULL CHECK (DatosAntes   IS NULL OR JSON_VALID(DatosAntes)),
    DatosDespues   LONGTEXT     NULL CHECK (DatosDespues IS NULL OR JSON_VALID(DatosDespues)),
    Ip             VARCHAR(45)  NULL,
    UserAgent      VARCHAR(255) NULL,
    FechaHora      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    INDEX IxAuditoriaUsuario (IdUsuario, FechaHora),
    INDEX IxAuditoriaTabla   (TablaAfectada, IdRegistro),
    INDEX IxAuditoriaEntidad (IdEntidad, FechaHora),
    CONSTRAINT FkAuditoriaUsuario FOREIGN KEY (IdUsuario) REFERENCES Usuario(IdUsuario) ON DELETE SET NULL,
    CONSTRAINT FkAuditoriaEntidad FOREIGN KEY (IdEntidad) REFERENCES Entidad(IdEntidad) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- =====================================================================
--  S2. INVENTARIO K9                   (RF-04 a RF-12)
-- =====================================================================

CREATE TABLE IF NOT EXISTS ProgramaK9 (
    IdPrograma       INT AUTO_INCREMENT PRIMARY KEY,
    IdEntidad        INT          NULL,       -- NULL = programa global
    Clave            VARCHAR(50)  NOT NULL,
    Nombre           VARCHAR(150) NOT NULL,
    Descripcion      TEXT         NULL,
    DuracionHoras    SMALLINT     NULL,
    Nivel            ENUM('basico','intermedio','avanzado') NULL,
    VigenciaMeses    SMALLINT     NULL,       -- validez de la certificación
    Icono            VARCHAR(60)  NOT NULL DEFAULT 'bi-mortarboard-fill',
    Color            VARCHAR(20)  NOT NULL DEFAULT '#b8860b',
    ImagenFondoPath  VARCHAR(255) NULL,
    EsFijo           TINYINT(1)   NOT NULL DEFAULT 0,
    Activo           TINYINT(1)   NOT NULL DEFAULT 1,
    FechaRegistro    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT UqProgramaClave UNIQUE (Clave),
    CONSTRAINT FkProgramaEntidad FOREIGN KEY (IdEntidad) REFERENCES Entidad(IdEntidad) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- La edad NO se almacena: es un dato derivado que se desactualiza solo.
-- Se calcula con TIMESTAMPDIFF(YEAR, FechaNacimiento, CURDATE()).
-- Tampoco se almacenan UltimaVacunacion / ProximaVacunacion / NombreVacuna:
-- viven en CaninoVacuna y se consultan por VwCaninoVacunacion.
CREATE TABLE IF NOT EXISTS Canino (
    IdCanino             INT AUTO_INCREMENT PRIMARY KEY,
    IdEntidad            INT          NOT NULL,
    IdPrograma           INT          NULL,
    IdGuiaActual         INT          NULL,   -- copia del binomio vigente
    CodigoUnico          VARCHAR(30)  NOT NULL,
    Nombre               VARCHAR(100) NOT NULL,
    Raza                 VARCHAR(100) NULL,
    Genero               ENUM('macho','hembra') NULL,
    FechaNacimiento      DATE         NULL,
    ChipNumero           VARCHAR(50)  NULL,
    NumRegistro          VARCHAR(50)  NULL,
    ColorPelaje          VARCHAR(100) NULL,
    PesoKg               DECIMAL(5,2) NULL,
    TallaCm              SMALLINT     NULL,
    Especialidad         VARCHAR(100) NULL,   -- espejo de ProgramaK9.Clave
    Estado               ENUM('activo','entrenamiento','descanso',
                              'incapacitado','retirado','baja')
                         NOT NULL DEFAULT 'entrenamiento',
    FotoPath             VARCHAR(255) NULL,
    Procedencia          VARCHAR(150) NULL,
    FechaIngreso         DATE         NULL,
    Observaciones        TEXT         NULL,
    HistorialClinicoPath VARCHAR(255) NULL,
    MotivoBaja           VARCHAR(60)  NULL,
    JustificacionBaja    TEXT         NULL,
    FechaBaja            DATE         NULL,
    CartaBajaPath        VARCHAR(255) NULL,
    FechaRegistro        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FechaModificacion    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                          ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT UqCaninoCodigo UNIQUE (IdEntidad, CodigoUnico),
    CONSTRAINT UqCaninoChip   UNIQUE (ChipNumero),
    INDEX IxCaninoEntidadEstado (IdEntidad, Estado),
    INDEX IxCaninoPrograma (IdPrograma),
    INDEX IxCaninoGuia (IdGuiaActual),
    CONSTRAINT FkCaninoEntidad  FOREIGN KEY (IdEntidad)    REFERENCES Entidad(IdEntidad)      ON DELETE RESTRICT,
    CONSTRAINT FkCaninoPrograma FOREIGN KEY (IdPrograma)   REFERENCES ProgramaK9(IdPrograma)  ON DELETE SET NULL,
    CONSTRAINT FkCaninoGuia     FOREIGN KEY (IdGuiaActual) REFERENCES Usuario(IdUsuario)      ON DELETE SET NULL,
    CONSTRAINT CkCaninoBaja CHECK (Estado <> 'baja' OR FechaBaja IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS CaninoEstado (
    IdCaninoEstado    INT AUTO_INCREMENT PRIMARY KEY,
    IdCanino          INT          NOT NULL,
    EstadoAnterior    VARCHAR(20)  NULL,
    EstadoNuevo       VARCHAR(20)  NOT NULL,
    Motivo            VARCHAR(255) NULL,
    FechaCambio       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    IdUsuarioRegistra INT          NULL,
    INDEX IxCaninoEstadoCanino (IdCanino, FechaCambio),
    CONSTRAINT FkCaninoEstadoCanino  FOREIGN KEY (IdCanino)          REFERENCES Canino(IdCanino)   ON DELETE RESTRICT,
    CONSTRAINT FkCaninoEstadoUsuario FOREIGN KEY (IdUsuarioRegistra) REFERENCES Usuario(IdUsuario) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS GuiaCertificacion (
    IdGuiaCertificacion INT AUTO_INCREMENT PRIMARY KEY,
    IdUsuario        INT          NOT NULL,
    Nombre           VARCHAR(150) NOT NULL,
    EntidadEmisora   VARCHAR(150) NULL,
    FechaEmision     DATE         NULL,
    FechaVencimiento DATE         NULL,
    DocumentoPath    VARCHAR(255) NULL,
    FechaRegistro    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX IxGuiaCertUsuario (IdUsuario, FechaVencimiento),
    CONSTRAINT FkGuiaCertUsuario FOREIGN KEY (IdUsuario) REFERENCES Usuario(IdUsuario) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Tabla clave del modelo: convierte la relación guía-canino en una entidad
-- con vigencia temporal. La columna generada Vigente vale 1 mientras el
-- binomio esté abierto y NULL cuando se cierra; como los NULL no colisionan
-- en un índice UNIQUE, el motor garantiza un solo binomio abierto por canino.
CREATE TABLE IF NOT EXISTS Binomio (
    IdBinomio         INT AUTO_INCREMENT PRIMARY KEY,
    IdCanino          INT          NOT NULL,
    IdGuia            INT          NOT NULL,
    IdEntidad         INT          NOT NULL,
    FechaInicio       DATE         NOT NULL,
    FechaFin          DATE         NULL,
    MotivoFin         VARCHAR(255) NULL,
    Observaciones     TEXT         NULL,
    IdUsuarioRegistra INT          NULL,
    FechaRegistro     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    Vigente           TINYINT(1) GENERATED ALWAYS AS
                      (IF(FechaFin IS NULL, 1, NULL)) STORED,
    CONSTRAINT UqBinomioVigente UNIQUE (IdCanino, Vigente),
    INDEX IxBinomioGuia (IdGuia, FechaInicio),
    INDEX IxBinomioEntidad (IdEntidad),
    CONSTRAINT FkBinomioCanino  FOREIGN KEY (IdCanino)          REFERENCES Canino(IdCanino)   ON DELETE RESTRICT,
    CONSTRAINT FkBinomioGuia    FOREIGN KEY (IdGuia)            REFERENCES Usuario(IdUsuario) ON DELETE RESTRICT,
    CONSTRAINT FkBinomioEntidad FOREIGN KEY (IdEntidad)         REFERENCES Entidad(IdEntidad) ON DELETE RESTRICT,
    CONSTRAINT FkBinomioUsuario FOREIGN KEY (IdUsuarioRegistra) REFERENCES Usuario(IdUsuario) ON DELETE SET NULL,
    CONSTRAINT CkBinomioFechas CHECK (FechaFin IS NULL OR FechaFin >= FechaInicio)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- =====================================================================
--  SALUD Y BIENESTAR ANIMAL   (Ley 1774 de 2016, Ley 2454 de 2025)
-- =====================================================================

CREATE TABLE IF NOT EXISTS CaninoVacuna (
    IdCaninoVacuna   INT AUTO_INCREMENT PRIMARY KEY,
    IdCanino         INT          NOT NULL,
    NombreVacuna     VARCHAR(100) NOT NULL,
    Lote             VARCHAR(50)  NULL,
    FechaAplicacion  DATE         NOT NULL,
    FechaVencimiento DATE         NULL,
    Veterinario      VARCHAR(150) NULL,
    Notas            TEXT         NULL,
    ComprobantePath  VARCHAR(255) NULL,
    FechaRegistro    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX IxVacunaCanino (IdCanino, FechaAplicacion),
    INDEX IxVacunaVencimiento (FechaVencimiento),
    CONSTRAINT FkVacunaCanino FOREIGN KEY (IdCanino) REFERENCES Canino(IdCanino) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS AtencionVeterinaria (
    IdAtencionVeterinaria INT AUTO_INCREMENT PRIMARY KEY,
    IdCanino          INT          NOT NULL,
    Tipo              ENUM('consulta','urgencia','cirugia','tratamiento',
                           'control','desparasitacion','revision_bienestar') NOT NULL,
    Fecha             DATE         NOT NULL,
    Veterinario       VARCHAR(150) NULL,
    Diagnostico       TEXT         NULL,
    Tratamiento       TEXT         NULL,
    DiasIncapacidad   SMALLINT     NULL,
    PesoKg            DECIMAL(5,2) NULL,
    SoportePath       VARCHAR(255) NULL,
    IdUsuarioRegistra INT          NULL,
    FechaRegistro     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX IxAtencionCanino (IdCanino, Fecha),
    CONSTRAINT FkAtencionCanino  FOREIGN KEY (IdCanino)          REFERENCES Canino(IdCanino)   ON DELETE RESTRICT,
    CONSTRAINT FkAtencionUsuario FOREIGN KEY (IdUsuarioRegistra) REFERENCES Usuario(IdUsuario) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- =====================================================================
--  S3. TRAZABILIDAD OPERATIVA Y ACADÉMICA   (RF-13 a RF-16)
-- =====================================================================

CREATE TABLE IF NOT EXISTS Curso (
    IdCurso       INT AUTO_INCREMENT PRIMARY KEY,
    IdPrograma    INT          NOT NULL,
    IdEntidad     INT          NOT NULL,
    IdInstructor  INT          NULL,
    Nombre        VARCHAR(200) NOT NULL,
    FechaInicio   DATE         NOT NULL,
    FechaFin      DATE         NULL,
    Lugar         VARCHAR(200) NULL,
    Estado        ENUM('planificado','en_curso','finalizado','cancelado')
                  NOT NULL DEFAULT 'planificado',
    Descripcion   TEXT         NULL,
    FechaRegistro TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX IxCursoEntidad (IdEntidad, Estado),
    CONSTRAINT FkCursoPrograma   FOREIGN KEY (IdPrograma)   REFERENCES ProgramaK9(IdPrograma) ON DELETE RESTRICT,
    CONSTRAINT FkCursoEntidad    FOREIGN KEY (IdEntidad)    REFERENCES Entidad(IdEntidad)     ON DELETE RESTRICT,
    CONSTRAINT FkCursoInstructor FOREIGN KEY (IdInstructor) REFERENCES Usuario(IdUsuario)     ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS CursoInscripcion (
    IdCursoInscripcion INT AUTO_INCREMENT PRIMARY KEY,
    IdCurso            INT  NOT NULL,
    IdCanino           INT  NOT NULL,
    IdBinomio          INT  NULL,
    FechaInscripcion   DATE NOT NULL,
    Estado             ENUM('inscrito','en_curso','aprobado','no_aprobado','retirado')
                       NOT NULL DEFAULT 'inscrito',
    CalificacionFinal  DECIMAL(5,2) NULL,
    Observaciones      TEXT NULL,
    CONSTRAINT UqInscripcion UNIQUE (IdCurso, IdCanino),
    CONSTRAINT FkInscripcionCurso   FOREIGN KEY (IdCurso)   REFERENCES Curso(IdCurso)     ON DELETE RESTRICT,
    CONSTRAINT FkInscripcionCanino  FOREIGN KEY (IdCanino)  REFERENCES Canino(IdCanino)   ON DELETE RESTRICT,
    CONSTRAINT FkInscripcionBinomio FOREIGN KEY (IdBinomio) REFERENCES Binomio(IdBinomio) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Antes se llamaba cursos_sesiones. Se renombra a Sesion porque cada fila
-- es una sesión de entrenamiento, no un curso.
CREATE TABLE IF NOT EXISTS Sesion (
    IdSesion          INT AUTO_INCREMENT PRIMARY KEY,
    IdCurso           INT          NULL,
    IdCanino          INT          NOT NULL,
    IdBinomio         INT          NULL,
    IdEntidad         INT          NULL,
    IdPrograma        INT          NULL,
    IdInstructor      INT          NULL,
    Especialidad      VARCHAR(50)  NOT NULL,   -- espejo de ProgramaK9.Clave
    TipoActividad     ENUM('obediencia','adiestramiento','practica',
                           'evaluacion','socializacion','acondicionamiento') NULL,
    Fecha             DATE         NOT NULL,
    HoraInicio        TIME         NULL,
    DuracionMin       SMALLINT     NULL,
    Lugar             VARCHAR(200) NULL,
    Latitud           DECIMAL(10,8) NULL,
    Longitud          DECIMAL(11,8) NULL,
    Resultado         VARCHAR(30)  NULL,
    Instructor        VARCHAR(150) NULL,       -- texto libre heredado
    Observaciones     TEXT         NULL,
    IdUsuarioRegistra INT          NULL,
    FechaRegistro     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX IxSesionCanino (IdCanino, Fecha),
    INDEX IxSesionEspecialidad (Especialidad, Fecha),
    INDEX IxSesionEntidad (IdEntidad, Fecha),
    CONSTRAINT FkSesionCanino     FOREIGN KEY (IdCanino)     REFERENCES Canino(IdCanino)       ON DELETE RESTRICT,
    CONSTRAINT FkSesionCurso      FOREIGN KEY (IdCurso)      REFERENCES Curso(IdCurso)         ON DELETE SET NULL,
    CONSTRAINT FkSesionBinomio    FOREIGN KEY (IdBinomio)    REFERENCES Binomio(IdBinomio)     ON DELETE SET NULL,
    CONSTRAINT FkSesionEntidad    FOREIGN KEY (IdEntidad)    REFERENCES Entidad(IdEntidad)     ON DELETE RESTRICT,
    CONSTRAINT FkSesionPrograma   FOREIGN KEY (IdPrograma)   REFERENCES ProgramaK9(IdPrograma) ON DELETE SET NULL,
    CONSTRAINT FkSesionInstructor FOREIGN KEY (IdInstructor) REFERENCES Usuario(IdUsuario)     ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS Evaluacion (
    IdEvaluacion   INT AUTO_INCREMENT PRIMARY KEY,
    IdCanino       INT          NOT NULL,
    IdSesion       INT          NULL,
    IdCurso        INT          NULL,
    IdEvaluador    INT          NULL,
    Tipo           ENUM('diagnostica','parcial','final','recertificacion') NOT NULL,
    Fecha          DATE         NOT NULL,
    Puntaje        DECIMAL(5,2) NULL,
    PuntajeMaximo  DECIMAL(5,2) NULL DEFAULT 100.00,
    Aprobado       TINYINT(1)   NULL,
    Criterios      LONGTEXT     NULL CHECK (Criterios IS NULL OR JSON_VALID(Criterios)),
    Observaciones  TEXT         NULL,
    FechaRegistro  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX IxEvaluacionCanino (IdCanino, Fecha),
    CONSTRAINT FkEvaluacionCanino    FOREIGN KEY (IdCanino)    REFERENCES Canino(IdCanino)   ON DELETE RESTRICT,
    CONSTRAINT FkEvaluacionSesion    FOREIGN KEY (IdSesion)    REFERENCES Sesion(IdSesion)   ON DELETE SET NULL,
    CONSTRAINT FkEvaluacionCurso     FOREIGN KEY (IdCurso)     REFERENCES Curso(IdCurso)     ON DELETE SET NULL,
    CONSTRAINT FkEvaluacionEvaluador FOREIGN KEY (IdEvaluador) REFERENCES Usuario(IdUsuario) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS Certificacion (
    IdCertificacion   INT AUTO_INCREMENT PRIMARY KEY,
    IdCanino          INT          NOT NULL,
    IdPrograma        INT          NOT NULL,
    IdCurso           INT          NULL,
    IdUsuarioRegistra INT          NULL,
    CodigoCertificado VARCHAR(60)  NOT NULL,
    EntidadEmisora    VARCHAR(150) NULL,
    FechaEmision      DATE         NOT NULL,
    FechaVencimiento  DATE         NULL,
    Estado            ENUM('vigente','vencida','revocada','suspendida')
                      NOT NULL DEFAULT 'vigente',
    DocumentoPath     VARCHAR(255) NULL,
    FechaRegistro     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT UqCertificacionCodigo UNIQUE (CodigoCertificado),
    INDEX IxCertificacionCanino (IdCanino, Estado),
    INDEX IxCertificacionVencimiento (FechaVencimiento),
    CONSTRAINT FkCertificacionCanino   FOREIGN KEY (IdCanino)   REFERENCES Canino(IdCanino)       ON DELETE RESTRICT,
    CONSTRAINT FkCertificacionPrograma FOREIGN KEY (IdPrograma) REFERENCES ProgramaK9(IdPrograma) ON DELETE RESTRICT,
    CONSTRAINT FkCertificacionCurso    FOREIGN KEY (IdCurso)    REFERENCES Curso(IdCurso)         ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS Operacion (
    IdOperacion       INT AUTO_INCREMENT PRIMARY KEY,
    IdEntidad         INT          NOT NULL,
    IdCanino          INT          NOT NULL,
    IdBinomio         INT          NULL,
    IdUsuarioRegistra INT          NULL,
    TipoOperacion     ENUM('patrullaje','requisa','busqueda_rescate','deteccion',
                           'control_perimetral','escolta','apoyo_judicial','simulacro') NOT NULL,
    CodigoMision      VARCHAR(50)  NULL,
    FechaInicio       DATETIME     NOT NULL,
    FechaFin          DATETIME     NULL,
    Ubicacion         VARCHAR(255) NULL,
    Latitud           DECIMAL(10,8) NULL,
    Longitud          DECIMAL(11,8) NULL,
    Descripcion       TEXT         NULL,
    Resultado         ENUM('exitosa','parcial','sin_hallazgos','abortada') NULL,
    Hallazgos         TEXT         NULL,
    FechaRegistro     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX IxOperacionCanino (IdCanino, FechaInicio),
    INDEX IxOperacionEntidad (IdEntidad, FechaInicio),
    CONSTRAINT FkOperacionCanino  FOREIGN KEY (IdCanino)  REFERENCES Canino(IdCanino)   ON DELETE RESTRICT,
    CONSTRAINT FkOperacionBinomio FOREIGN KEY (IdBinomio) REFERENCES Binomio(IdBinomio) ON DELETE SET NULL,
    CONSTRAINT FkOperacionEntidad FOREIGN KEY (IdEntidad) REFERENCES Entidad(IdEntidad) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Línea de tiempo unificada del canino: toda acción relevante escribe aquí
-- una fila, de modo que el historial se consulta con una sola query.
CREATE TABLE IF NOT EXISTS Evento (
    IdEvento          INT AUTO_INCREMENT PRIMARY KEY,
    IdCanino          INT          NOT NULL,
    IdEntidad         INT          NOT NULL,
    IdBinomio         INT          NULL,
    Categoria         ENUM('administrativo','formativo','operativo',
                           'sanitario','geografico','documental') NOT NULL,
    Tipo              VARCHAR(50)  NOT NULL,
    Titulo            VARCHAR(200) NOT NULL,
    Descripcion       TEXT         NULL,
    FechaHora         DATETIME     NOT NULL,
    UbicacionTexto    VARCHAR(255) NULL,
    Latitud           DECIMAL(10,8) NULL,
    Longitud          DECIMAL(11,8) NULL,
    Resultado         VARCHAR(50)  NULL,
    IdSesion          INT          NULL,
    IdOperacion       INT          NULL,
    IdCertificacion   INT          NULL,
    IdRegistroDocumental INT       NULL,
    IdUsuarioRegistra INT          NULL,
    FechaRegistro     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX IxEventoCaninoFecha (IdCanino, FechaHora),
    INDEX IxEventoEntidadCategoria (IdEntidad, Categoria, FechaHora),
    CONSTRAINT FkEventoCanino    FOREIGN KEY (IdCanino)          REFERENCES Canino(IdCanino)     ON DELETE RESTRICT,
    CONSTRAINT FkEventoEntidad   FOREIGN KEY (IdEntidad)         REFERENCES Entidad(IdEntidad)   ON DELETE RESTRICT,
    CONSTRAINT FkEventoBinomio   FOREIGN KEY (IdBinomio)         REFERENCES Binomio(IdBinomio)   ON DELETE SET NULL,
    CONSTRAINT FkEventoSesion    FOREIGN KEY (IdSesion)          REFERENCES Sesion(IdSesion)     ON DELETE SET NULL,
    CONSTRAINT FkEventoOperacion FOREIGN KEY (IdOperacion)       REFERENCES Operacion(IdOperacion) ON DELETE SET NULL,
    CONSTRAINT FkEventoUsuario   FOREIGN KEY (IdUsuarioRegistra) REFERENCES Usuario(IdUsuario)   ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- =====================================================================
--  S4. GEOLOCALIZACIÓN                 (RF-17, RF-18)
-- =====================================================================

CREATE TABLE IF NOT EXISTS DispositivoGps (
    IdDispositivo   INT AUTO_INCREMENT PRIMARY KEY,
    IdEntidad       INT          NOT NULL,
    IdUsuario       INT          NULL,
    IdCanino        INT          NULL,
    Identificador   VARCHAR(100) NOT NULL,   -- IMEI / UUID / token de app
    Tipo            ENUM('smartphone','collar_gps','tablet','radio') NOT NULL DEFAULT 'smartphone',
    Modelo          VARCHAR(100) NULL,
    AsignadoA       ENUM('guia','canino','vehiculo') NOT NULL DEFAULT 'guia',
    ApiTokenHash    CHAR(64)     NULL,
    BateriaPct      TINYINT      NULL,
    UltimaConexion  DATETIME     NULL,
    Activo          TINYINT(1)   NOT NULL DEFAULT 1,
    FechaRegistro   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT UqDispositivoIdentificador UNIQUE (Identificador),
    INDEX IxDispositivoEntidad (IdEntidad, Activo),
    CONSTRAINT FkDispositivoEntidad FOREIGN KEY (IdEntidad) REFERENCES Entidad(IdEntidad) ON DELETE RESTRICT,
    CONSTRAINT FkDispositivoUsuario FOREIGN KEY (IdUsuario) REFERENCES Usuario(IdUsuario) ON DELETE SET NULL,
    CONSTRAINT FkDispositivoCanino  FOREIGN KEY (IdCanino)  REFERENCES Canino(IdCanino)   ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS Recorrido (
    IdRecorrido  INT AUTO_INCREMENT PRIMARY KEY,
    IdEntidad    INT      NOT NULL,
    IdBinomio    INT      NULL,
    IdCanino     INT      NULL,
    IdOperacion  INT      NULL,
    FechaInicio  DATETIME NOT NULL,
    FechaFin     DATETIME NULL,
    DistanciaKm  DECIMAL(8,3) NULL,
    DuracionMin  INT      NULL,
    NumPuntos    INT      NOT NULL DEFAULT 0,
    Estado       ENUM('en_curso','finalizado','interrumpido') NOT NULL DEFAULT 'en_curso',
    Notas        TEXT     NULL,
    INDEX IxRecorridoBinomio (IdBinomio, FechaInicio),
    INDEX IxRecorridoEntidad (IdEntidad, FechaInicio),
    CONSTRAINT FkRecorridoEntidad   FOREIGN KEY (IdEntidad)   REFERENCES Entidad(IdEntidad)     ON DELETE RESTRICT,
    CONSTRAINT FkRecorridoBinomio   FOREIGN KEY (IdBinomio)   REFERENCES Binomio(IdBinomio)     ON DELETE SET NULL,
    CONSTRAINT FkRecorridoCanino    FOREIGN KEY (IdCanino)    REFERENCES Canino(IdCanino)       ON DELETE SET NULL,
    CONSTRAINT FkRecorridoOperacion FOREIGN KEY (IdOperacion) REFERENCES Operacion(IdOperacion) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Tabla de mayor volumen: un binomio reportando cada 10 s genera unas
-- 8.600 filas por jornada. Por eso usa BIGINT y se indexa por tiempo.
CREATE TABLE IF NOT EXISTS Posicion (
    IdPosicion     BIGINT AUTO_INCREMENT PRIMARY KEY,
    IdDispositivo  INT           NOT NULL,
    IdEntidad      INT           NOT NULL,
    IdBinomio      INT           NULL,
    IdCanino       INT           NULL,
    IdUsuario      INT           NULL,
    IdRecorrido    INT           NULL,
    Latitud        DECIMAL(10,8) NOT NULL,
    Longitud       DECIMAL(11,8) NOT NULL,
    AltitudM       DECIMAL(7,2)  NULL,
    PrecisionM     DECIMAL(6,2)  NULL,
    VelocidadKmh   DECIMAL(6,2)  NULL,
    RumboGrados    SMALLINT      NULL,
    BateriaPct     TINYINT       NULL,
    FechaHora      DATETIME      NOT NULL,   -- hora del dispositivo
    RecibidoEn     TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX IxPosicionBinomio (IdBinomio, FechaHora),
    INDEX IxPosicionRecorrido (IdRecorrido, FechaHora),
    INDEX IxPosicionEntidad (IdEntidad, FechaHora),
    CONSTRAINT FkPosicionDispositivo FOREIGN KEY (IdDispositivo) REFERENCES DispositivoGps(IdDispositivo) ON DELETE RESTRICT,
    CONSTRAINT FkPosicionRecorrido   FOREIGN KEY (IdRecorrido)   REFERENCES Recorrido(IdRecorrido)       ON DELETE SET NULL,
    CONSTRAINT CkPosicionLatitud  CHECK (Latitud  BETWEEN -90  AND 90),
    CONSTRAINT CkPosicionLongitud CHECK (Longitud BETWEEN -180 AND 180)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS ZonaInteres (
    IdZona        INT AUTO_INCREMENT PRIMARY KEY,
    IdEntidad     INT          NOT NULL,
    Nombre        VARCHAR(150) NOT NULL,
    Tipo          ENUM('patrullaje','restringida','base','entrenamiento','riesgo') NOT NULL,
    CentroLat     DECIMAL(10,8) NULL,
    CentroLng     DECIMAL(11,8) NULL,
    RadioM        INT           NULL,
    Poligono      LONGTEXT      NULL CHECK (Poligono IS NULL OR JSON_VALID(Poligono)),
    Color         VARCHAR(20)   NULL,
    Activo        TINYINT(1)    NOT NULL DEFAULT 1,
    FechaRegistro TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX IxZonaEntidad (IdEntidad, Activo),
    CONSTRAINT FkZonaEntidad FOREIGN KEY (IdEntidad) REFERENCES Entidad(IdEntidad) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS Alerta (
    IdAlerta         INT AUTO_INCREMENT PRIMARY KEY,
    IdEntidad        INT NOT NULL,
    IdCanino         INT NULL,
    IdBinomio        INT NULL,
    IdZona           INT NULL,
    IdUsuarioLectura INT NULL,
    Tipo             ENUM('vacuna_por_vencer','vacuna_vencida','certificacion_por_vencer',
                          'salida_zona','entrada_zona_restringida','inmovilidad',
                          'sin_senal','estado_critico','documento_pendiente') NOT NULL,
    Severidad        ENUM('info','media','alta','critica') NOT NULL DEFAULT 'media',
    Mensaje          VARCHAR(255) NOT NULL,
    GeneradaEn       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    LeidaEn          DATETIME     NULL,
    Atendida         TINYINT(1)   NOT NULL DEFAULT 0,
    INDEX IxAlertaEntidad (IdEntidad, Atendida, GeneradaEn),
    INDEX IxAlertaCanino (IdCanino),
    CONSTRAINT FkAlertaEntidad FOREIGN KEY (IdEntidad) REFERENCES Entidad(IdEntidad)   ON DELETE CASCADE,
    CONSTRAINT FkAlertaCanino  FOREIGN KEY (IdCanino)  REFERENCES Canino(IdCanino)     ON DELETE CASCADE,
    CONSTRAINT FkAlertaZona    FOREIGN KEY (IdZona)    REFERENCES ZonaInteres(IdZona)  ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- =====================================================================
--  S5. REGISTRO DOCUMENTAL Y AUDIOVISUAL   (RF-19, RF-20)
-- =====================================================================

-- Sustituye a sesion_vision. Separa el archivo (metadatos y hash de
-- integridad) del contenido derivado (transcripción y resumen), y deja
-- constancia de si el resumen fue escrito por una persona o asistido.
CREATE TABLE IF NOT EXISTS RegistroDocumental (
    IdRegistroDocumental INT AUTO_INCREMENT PRIMARY KEY,
    IdEntidad        INT          NOT NULL,
    IdCanino         INT          NOT NULL,
    IdSesion         INT          NULL,
    IdOperacion      INT          NULL,
    IdInstructor     INT          NULL,
    IdUsuarioCarga   INT          NULL,
    Titulo           VARCHAR(200) NOT NULL,
    TipoActividad    VARCHAR(60)  NULL,
    FechaHora        DATETIME     NOT NULL,
    Lugar            VARCHAR(200) NULL,
    ArchivoPath      VARCHAR(255) NOT NULL,
    TipoArchivo      ENUM('video','audio','imagen','documento') NOT NULL DEFAULT 'video',
    NombreOriginal   VARCHAR(255) NULL,
    MimeType         VARCHAR(100) NULL,
    TamanoBytes      BIGINT       NULL,
    DuracionSeg      INT          NULL,
    HashSha256       CHAR(64)     NULL,
    Transcripcion    LONGTEXT     NULL,
    Resumen          TEXT         NULL,
    Observaciones    TEXT         NULL,
    GeneradoPor      ENUM('manual','ia','mixto') NOT NULL DEFAULT 'manual',
    ModeloIa         VARCHAR(80)  NULL,
    EstadoProceso    ENUM('pendiente','procesando','completado','error')
                     NOT NULL DEFAULT 'pendiente',
    FechaRegistro    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FechaModificacion TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP,
    INDEX IxRegistroDocCanino (IdCanino, FechaHora),
    INDEX IxRegistroDocSesion (IdSesion),
    INDEX IxRegistroDocEntidad (IdEntidad, FechaHora),
    CONSTRAINT FkRegistroDocEntidad   FOREIGN KEY (IdEntidad)   REFERENCES Entidad(IdEntidad)     ON DELETE RESTRICT,
    CONSTRAINT FkRegistroDocCanino    FOREIGN KEY (IdCanino)    REFERENCES Canino(IdCanino)       ON DELETE RESTRICT,
    CONSTRAINT FkRegistroDocSesion    FOREIGN KEY (IdSesion)    REFERENCES Sesion(IdSesion)       ON DELETE SET NULL,
    CONSTRAINT FkRegistroDocOperacion FOREIGN KEY (IdOperacion) REFERENCES Operacion(IdOperacion) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS Etiqueta (
    IdEtiqueta INT AUTO_INCREMENT PRIMARY KEY,
    IdEntidad  INT NULL,
    Nombre     VARCHAR(60) NOT NULL,
    Color      VARCHAR(20) NULL,
    CONSTRAINT UqEtiqueta UNIQUE (IdEntidad, Nombre),
    CONSTRAINT FkEtiquetaEntidad FOREIGN KEY (IdEntidad) REFERENCES Entidad(IdEntidad) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS RegistroEtiqueta (
    IdRegistroDocumental INT NOT NULL,
    IdEtiqueta           INT NOT NULL,
    PRIMARY KEY (IdRegistroDocumental, IdEtiqueta),
    CONSTRAINT FkRegistroEtiquetaDoc      FOREIGN KEY (IdRegistroDocumental) REFERENCES RegistroDocumental(IdRegistroDocumental) ON DELETE CASCADE,
    CONSTRAINT FkRegistroEtiquetaEtiqueta FOREIGN KEY (IdEtiqueta)           REFERENCES Etiqueta(IdEtiqueta)                     ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS RegistroIa (
    IdRegistroIa         INT AUTO_INCREMENT PRIMARY KEY,
    IdCanino             INT          NOT NULL,
    IdEntidad            INT          NULL,
    IdRegistroDocumental INT          NULL,
    Especialidad         VARCHAR(50)  NOT NULL,
    Fecha                DATE         NOT NULL,
    Resultado            VARCHAR(50)  NULL,
    Confianza            INT          NULL,
    Observaciones        TEXT         NULL,
    ArchivoPath          VARCHAR(255) NULL,
    FechaRegistro        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX IxRegistroIaCanino (IdCanino, Fecha),
    CONSTRAINT FkRegistroIaCanino FOREIGN KEY (IdCanino)             REFERENCES Canino(IdCanino) ON DELETE RESTRICT,
    CONSTRAINT FkRegistroIaDoc    FOREIGN KEY (IdRegistroDocumental) REFERENCES RegistroDocumental(IdRegistroDocumental) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- =====================================================================
--  VISTAS DE APOYO A REPORTES E INDICADORES   (RF-15, RF-16)
-- =====================================================================

CREATE OR REPLACE VIEW VwCaninoVacunacion AS
SELECT c.IdCanino,
       MAX(v.FechaAplicacion) AS UltimaVacunacion,
       MIN(CASE WHEN v.FechaVencimiento >= CURDATE()
                THEN v.FechaVencimiento END) AS ProximaVacunacion,
       SUM(CASE WHEN v.FechaVencimiento < CURDATE() THEN 1 ELSE 0 END) AS VacunasVencidas
FROM Canino c
LEFT JOIN CaninoVacuna v ON v.IdCanino = c.IdCanino
GROUP BY c.IdCanino;

CREATE OR REPLACE VIEW VwBinomioVigente AS
SELECT b.IdBinomio, b.IdCanino, b.IdGuia, b.IdEntidad, b.FechaInicio,
       u.Nombre AS NombreGuia, c.Nombre AS NombreCanino, c.CodigoUnico
FROM Binomio b
JOIN Usuario u ON u.IdUsuario = b.IdGuia
JOIN Canino  c ON c.IdCanino  = b.IdCanino
WHERE b.FechaFin IS NULL;

CREATE OR REPLACE VIEW VwTimelineCanino AS
SELECT e.IdCanino, e.FechaHora, e.Categoria, e.Tipo, e.Titulo, e.Descripcion,
       e.Resultado, e.UbicacionTexto, e.Latitud, e.Longitud,
       u.Nombre AS RegistradoPor
FROM Evento e
LEFT JOIN Usuario u ON u.IdUsuario = e.IdUsuarioRegistra;

CREATE OR REPLACE VIEW VwCaninoDetalle AS
SELECT c.IdCanino, c.CodigoUnico, c.Nombre, c.Raza, c.Genero, c.Estado,
       c.FechaNacimiento,
       TIMESTAMPDIFF(YEAR,  c.FechaNacimiento, CURDATE()) AS EdadAnios,
       TIMESTAMPDIFF(MONTH, c.FechaNacimiento, CURDATE()) % 12 AS EdadMesesResto,
       TIMESTAMPDIFF(MONTH, c.FechaNacimiento, CURDATE()) AS EdadMesesTotal,
       e.RazonSocial AS Entidad, p.Nombre AS Programa,
       u.Nombre AS GuiaActual, vv.UltimaVacunacion, vv.ProximaVacunacion,
       vv.VacunasVencidas
FROM Canino c
JOIN Entidad e            ON e.IdEntidad   = c.IdEntidad
LEFT JOIN ProgramaK9 p    ON p.IdPrograma  = c.IdPrograma
LEFT JOIN Usuario u       ON u.IdUsuario   = c.IdGuiaActual
LEFT JOIN VwCaninoVacunacion vv ON vv.IdCanino = c.IdCanino;

CREATE OR REPLACE VIEW VwIndicadorEntidad AS
SELECT e.IdEntidad, e.RazonSocial,
       SUM(c.Estado = 'activo')        AS CaninosActivos,
       SUM(c.Estado = 'entrenamiento') AS CaninosEntrenamiento,
       SUM(c.Estado = 'descanso')      AS CaninosDescanso,
       SUM(c.Estado = 'incapacitado')  AS CaninosIncapacitados,
       SUM(c.Estado = 'retirado')      AS CaninosRetirados,
       COUNT(c.IdCanino)               AS CaninosTotal
FROM Entidad e
LEFT JOIN Canino c ON c.IdEntidad = e.IdEntidad
GROUP BY e.IdEntidad, e.RazonSocial;

-- =====================================================================
--  DATOS SEMILLA
-- =====================================================================

INSERT IGNORE INTO Rol (Clave, Nombre, Descripcion, Ambito, EsFijo) VALUES
 ('super_admin',   'Super administrador',        'Administra todas las entidades del sistema.', 'global',  1),
 ('admin_entidad', 'Administrador institucional','Administra los recursos de su entidad.',      'entidad', 1),
 ('instructor',    'Instructor K9',              'Registra sesiones, evaluaciones y evidencia.','entidad', 1),
 ('guia_canino',   'Guia canino',                'Opera con su binomio y reporta actividad.',   'entidad', 1),
 ('veterinario',   'Veterinario',                'Registra atenciones y controles sanitarios.', 'entidad', 1);

INSERT IGNORE INTO ProgramaK9 (Clave, Nombre, Descripcion, Icono, Color, EsFijo) VALUES
 ('drogas','Deteccion de Drogas','Especializacion olfativa para identificacion de sustancias ilicitas.','bi-eyedropper-fill','#ef4444',1),
 ('explosivos','Deteccion de Explosivos','Deteccion de artefactos explosivos, municion y materiales peligrosos.','bi-lightning-charge-fill','#f97316',1),
 ('rescate','Busqueda y Rescate','Busqueda de personas en escombros, avalanchas y emergencias.','bi-life-preserver','#22c55e',1),
 ('seguridad','Seguridad y Proteccion','Patrullaje, proteccion de instalaciones y control de perimetros.','bi-shield-fill','#3b82f6',1),
 ('rastreo','Rastreo y Seguimiento','Seguimiento de rastros y apoyo en investigaciones.','bi-compass-fill','#8b5cf6',1),
 ('personas','Deteccion de Personas','Localizacion de personas vivas o fallecidas en grandes areas.','bi-people-fill','#06b6d4',1),
 ('multiple','Multiple / Integral','Combina mas de una especialidad operativa en un mismo binomio.','bi-collection-fill','#b8860b',1);

INSERT IGNORE INTO Etiqueta (IdEntidad, Nombre) VALUES
 (NULL,'Obediencia'), (NULL,'Salto'), (NULL,'Reporte de objeto'),
 (NULL,'Permanencia'), (NULL,'Socializacion'), (NULL,'Evaluacion');

SET FOREIGN_KEY_CHECKS = 1;
