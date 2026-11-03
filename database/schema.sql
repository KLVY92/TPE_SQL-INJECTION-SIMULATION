-- Esquema de base de datos para la plataforma Holidays Travel & Tourism
-- Diseñado para el laboratorio de Seguridad Informática (7° Semestre TI)

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS audit_logs;

-- Tabla principal de usuarios
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    password TEXT NOT NULL,           -- Almacenamiento en texto plano (modo vulnerable)
    password_hash TEXT NOT NULL,      -- Hash seguro PBKDF2/SHA256 (modo mitigado)
    role TEXT NOT NULL DEFAULT 'cliente',
    is_verified INTEGER DEFAULT 0,    -- 0: pendiente de confirmación, 1: verificado
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de tokens para recuperación de contraseña
CREATE TABLE password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tabla de auditoría de accesos e intentos
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    event_type TEXT,
    detail TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
