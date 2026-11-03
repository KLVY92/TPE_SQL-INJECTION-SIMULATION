"""
Inicializador y Seeder de la Base de Datos SQLite 'holidays.db'
Asignatura: Seguridad Informática - 7° Semestre TI
"""
import os
import sqlite3
from werkzeug.security import generate_password_hash

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "holidays.db")
SCHEMA_PATH = os.path.join(DB_DIR, "schema.sql")

def init_database():
    print(f"[*] Inicializando base de datos en: {DB_PATH}")
    
    # Conexión y ejecución de esquema DDL
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    
    cursor.executescript(schema_sql)
    
    # Usuarios demo para el entorno de pruebas
    # Nota didáctica: En el modo vulnerable se consulta 'password' en texto claro.
    # En el modo mitigado se evalúa 'password_hash' con PBKDF2/SHA256.
    demo_users = [
        (
            "admin",
            "admin@holidays.com",
            "Administrador Principal",
            "SuperAdmin2026!",
            generate_password_hash("SuperAdmin2026!"),
            "admin",
            1
        ),
        (
            "turista01",
            "turista01@holidays.com",
            "Carlos Mendoza (Turista)",
            "ViajeroSeguro#7",
            generate_password_hash("ViajeroSeguro#7"),
            "cliente",
            1
        ),
        (
            "agente_viajes",
            "agente@holidays.com",
            "Laura Valenzuela (Agente)",
            "ReservaVuelo2026$",
            generate_password_hash("ReservaVuelo2026$"),
            "agente",
            1
        ),
        (
            "usuario_nuevo",
            "nuevo@holidays.com",
            "Santiago Morales (Pendiente)",
            "ClaveTemporal123",
            generate_password_hash("ClaveTemporal123"),
            "cliente",
            0  # Cuenta no verificada
        )
    ]
    
    cursor.executemany(
        """
        INSERT INTO users (username, email, full_name, password, password_hash, role, is_verified)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        demo_users
    )
    
    # Log de inicialización
    cursor.execute(
        "INSERT INTO audit_logs (ip_address, event_type, detail) VALUES (?, ?, ?)",
        ("127.0.0.1", "DATABASE_INIT", "Base de datos inicializada con 4 usuarios demostrativos.")
    )
    
    conn.commit()
    conn.close()
    print("[+] Base de datos SQLite 'holidays.db' creada exitosamente.")
    print("    Usuarios creados:")
    for u in demo_users:
        print(f"    - Usuario: {u[0]} | Email: {u[1]} | Rol: {u[5]} | Verificado: {'Sí' if u[6] == 1 else 'No'}")

if __name__ == "__main__":
    init_database()
