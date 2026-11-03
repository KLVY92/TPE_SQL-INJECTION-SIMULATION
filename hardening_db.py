#!/usr/bin/env python3
"""
=============================================================================
MÓDULO DE ENDURECIMIENTO (HARDENING) Y AUDITORÍA DE BASES DE DATOS
Asignatura: Seguridad Informática - 7° Semestre TI
Carrera: Tecnologías de la Información

OBJETIVO DIDÁCTICO:
Auditar la base de datos relacional SQLite 'holidays.db' evaluando:
1. Almacenamiento seguro de credenciales (Detección de texto claro vs Hash).
2. Integridad estructural y parámetros de seguridad del motor PRAGMA.
3. Permisos en el sistema de archivos (Principio de menor privilegio).
4. Directrices de mitigación y endurecimiento para bases de datos relacionales.
=============================================================================
"""

import os
import sys
import stat
import sqlite3

# Configurar encoding seguro para terminales Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Colores de salida
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "holidays.db")


class DatabaseHardeningAuditor:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.findings = []
        self.score_penalties = 0

    def print_banner(self):
        print(f"{CYAN}{BOLD}")
        print("=" * 75)
        print("   MODULO DE HARDENING Y AUDITORIA DE BASES DE DATOS - HOLIDAYS")
        print("   Seguridad Informatica | 7mo Semestre TI")
        print("=" * 75)
        print(f"{RESET}")
        print(f"[*] Archivo de Base de Datos: {BOLD}{self.db_path}{RESET}\n")

    def audit_file_permissions(self):
        """Evalúa los permisos del archivo SQLite a nivel de sistema operativo."""
        print(f"{BOLD}[1] Auditoria de Permisos a Nivel de Sistema de Archivos{RESET}")
        if not os.path.exists(self.db_path):
            print(f"  {RED}[ERROR] El archivo de base de datos no existe.{RESET}")
            return

        file_stat = os.stat(self.db_path)
        file_size_kb = file_stat.st_size / 1024

        print(f"  [*] Tamano del archivo : {file_size_kb:.2f} KB")

        # Comprobación de permisos en sistemas Unix/Linux o lectura en Windows
        is_windows = os.name == "nt"
        if is_windows:
            print(f"  {YELLOW}[INFO]{RESET} Sistema operativo Windows detectado (control de acceso basado en ACLs NTFS).")
            print("  [OK] Verificacion: Asegurarse de que solo el usuario del servicio web tenga acceso NTFS.")
        else:
            mode = file_stat.st_mode
            world_readable = bool(mode & stat.S_IROTH)
            world_writable = bool(mode & stat.S_IWOTH)

            if world_writable:
                print(f"  {RED}[CRITICO] El archivo es modificable por cualquier usuario (World-Writable - chmod {oct(mode)[-3:]}).{RESET}")
                self.score_penalties += 30
            elif world_readable:
                print(f"  {YELLOW}[ADVERTENCIA] El archivo es legible por cualquier usuario local (chmod {oct(mode)[-3:]}).{RESET}")
                self.score_penalties += 15
            else:
                print(f"  {GREEN}[SEGURO] Permisos restringidos adecuadamente (chmod 600 recomendado).{RESET}")

    def audit_passwords_storage(self):
        """Analiza la tabla de usuarios en busca de credenciales en texto plano."""
        print(f"\n{BOLD}[2] Auditoria Criptografica de Almacenamiento de Contrasenas{RESET}")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT id, username, password, password_hash FROM users")
            users = cursor.fetchall()

            plaintext_count = 0
            hashed_count = 0

            for u in users:
                # Comprobar si 'password' contiene texto claro típico
                if u["password"] and not u["password"].startswith("pbkdf2:") and not u["password"].startswith("scrypt:"):
                    plaintext_count += 1
                if u["password_hash"] and (u["password_hash"].startswith("pbkdf2:") or u["password_hash"].startswith("scrypt:")):
                    hashed_count += 1

            if plaintext_count > 0:
                print(f"  {RED}[VULNERABILIDAD]{RESET} Se detectaron {plaintext_count} registros con contrasenas en texto claro en columna 'password'.")
                print("      Causa: Implementacion didactica para demostrar SQL Injection.")
                print(f"  {GREEN}[MITIGACION PRESENTE]{RESET} Se detectaron {hashed_count} hashes robustos (PBKDF2/SHA256) en columna 'password_hash'.")
                self.score_penalties += 20
            else:
                print(f"  {GREEN}[SEGURO] Todas las contrasenas utilizan funciones de hash unidireccional con salting.{RESET}")

        except Exception as e:
            print(f"  {RED}[ERROR] No se pudo auditar la tabla users: {str(e)}{RESET}")
        finally:
            conn.close()

    def audit_sqlite_pragmas(self):
        """Audita configuraciones de seguridad e integridad del motor SQLite."""
        print(f"\n{BOLD}[3] Auditoria de Parametros PRAGMA del Motor de Base de Datos{RESET}")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # 1. Comprobación de Integridad
            cursor.execute("PRAGMA integrity_check;")
            integrity_result = cursor.fetchone()[0]
            if integrity_result == "ok":
                print(f"  {GREEN}[CORRECTO]{RESET} Integridad estructural de la base de datos: {BOLD}OK{RESET}")
            else:
                print(f"  {RED}[FALLO]{RESET} Corrupcion de base de datos detectada: {integrity_result}")
                self.score_penalties += 40

            # 2. Modo de Journal
            cursor.execute("PRAGMA journal_mode;")
            journal_mode = cursor.fetchone()[0].upper()
            print(f"  [*] Modo de Journal: {BOLD}{journal_mode}{RESET}")

            # 3. Secure Delete (Sobrescritura de registros borrados con ceros)
            cursor.execute("PRAGMA secure_delete;")
            secure_delete = cursor.fetchone()[0]
            if secure_delete == 1:
                print(f"  {GREEN}[SEGURO]{RESET} 'secure_delete' habilitado (evita recuperacion forense de datos eliminados).")
            else:
                print(f"  {YELLOW}[RECOMENDADO]{RESET} 'secure_delete' deshabilitado (los registros borrados persisten en paginas libres).")
                print("      Sugerencia de Hardening: Ejecutar 'PRAGMA secure_delete = ON;'")

            # 4. Foreign Keys
            cursor.execute("PRAGMA foreign_keys;")
            fk_enabled = cursor.fetchone()[0]
            if fk_enabled == 1:
                print(f"  {GREEN}[SEGURO]{RESET} Claves foraneas habilitadas activamente.")
            else:
                print(f"  {YELLOW}[AVISO]{RESET} Claves foraneas no forzadas por defecto en SQLite (ejecutar 'PRAGMA foreign_keys = ON;').")

        except Exception as e:
            print(f"  {RED}[ERROR] Error durante la inspeccion de PRAGMAs: {str(e)}{RESET}")
        finally:
            conn.close()

    def print_hardening_recommendations(self):
        """Imprime la guía de endurecimiento profesional para bases de datos de producción."""
        print(f"\n{CYAN}{BOLD}===========================================================================")
        print("   GUIA DE BUENAS PRACTICAS Y HARDENING PARA BASES DE DATOS RELACIONALES")
        print("==========================================================================={RESET}")

        recommendations = [
            ("Principio de Menor Privilegio (PoLP)",
             "La aplicacion web nunca debe conectarse con el usuario 'root' o 'sa'. Crear usuarios especificos con permisos limitados (SELECT, INSERT, UPDATE) exclusivamente sobre sus esquemas."),
            ("Cifrado en Reposo (Encryption at Rest)",
             "Para SQLite en produccion, utilizar extensiones criptograficas como SQLCipher (cifrado AES-256 de todas las paginas de la base de datos). Para MySQL/PostgreSQL, habilitar TDE (Transparent Data Encryption) o dm-crypt/LUKS."),
            ("Separacion Estricta de Codigo y Datos",
             "Prohibir cualquier concatenacion de cadenas en consultas dinamicas. Emplear exclusivamente Sentencias Preparadas (Prepared Statements) o bibliotecas ORM seguras (SQLAlchemy / Django ORM)."),
            ("Gestion Criptografica de Credenciales",
             "Nunca almacenar contrasenas en texto claro ni con algoritmos obsoletos (MD5, SHA1). Utilizar algoritmos con factor de coste adaptativo: Argon2id, bcrypt o PBKDF2-HMAC-SHA256 con un minimo de 600,000 iteraciones."),
            ("Auditoria Continua y Respaldo",
             "Mantener un registro inmutable de transacciones criticas (audit trail) y configurar copias de seguridad periodicas cifradas fuera de banda.")
        ]

        for i, (title, desc) in enumerate(recommendations, 1):
            print(f"\n{BOLD}{i}. {title}:{RESET}")
            print(f"   {desc}")

        print("\n" + "=" * 75 + "\n")


def main():
    auditor = DatabaseHardeningAuditor()
    auditor.print_banner()
    auditor.audit_file_permissions()
    auditor.audit_passwords_storage()
    auditor.audit_sqlite_pragmas()
    auditor.print_hardening_recommendations()


if __name__ == "__main__":
    main()
