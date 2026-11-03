#!/usr/bin/env python3
"""
=============================================================================
MÓDULO DE ESCANEO BÁSICO DE RED Y ANÁLISIS DE SUPERFICIE DE ATAQUE
Asignatura: Seguridad Informática - 7° Semestre TI
Carrera: Tecnologías de la Información

OBJETIVO DIDÁCTICO:
Implementar un escáner de red basado en sockets nativos de Python para identificar
puertos abiertos, reconocer servicios activos mediante Banner Grabbing y auditar
las cabeceras HTTP de seguridad del servidor web del laboratorio.
=============================================================================
"""

import sys
import socket
import time
import argparse
from concurrent.futures import ThreadPoolExecutor

# Configurar encoding seguro para terminales Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Colores de presentación
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Diccionario de servicios estándar comunes
COMMON_PORTS = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Insecure Terminal)",
    25: "SMTP (Simple Mail Transfer)",
    53: "DNS (Domain Name System)",
    80: "HTTP (World Wide Web)",
    110: "POP3 (Post Office Protocol)",
    143: "IMAP (Internet Message Access)",
    443: "HTTPS (HTTP Seguro SSL/TLS)",
    445: "SMB (Server Message Block)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5000: "Flask Web Server (Holidays Lab)",
    5432: "PostgreSQL Database",
    8000: "HTTP-Alt / Dev Server",
    8080: "HTTP-Proxy / Dev Server",
    8443: "HTTPS-Alt",
    27017: "MongoDB Database"
}


class NetworkScanner:
    def __init__(self, target_host="127.0.0.1", timeout=0.8, max_threads=50):
        self.target_host = target_host
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []

    def resolve_target(self):
        """Resuelve el nombre de dominio a dirección IP."""
        try:
            ip = socket.gethostbyname(self.target_host)
            return ip
        except socket.gaierror:
            print(f"{RED}[!] Error: No se pudo resolver el host '{self.target_host}'.{RESET}")
            sys.exit(1)

    def scan_port(self, port):
        """Intenta establecer conexión TCP con el puerto especificado."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        start_time = time.time()

        try:
            result = s.connect_ex((self.target_ip, port))
            latency = (time.time() - start_time) * 1000

            if result == 0:
                service_desc = COMMON_PORTS.get(port, "Desconocido / Personalizado")
                banner = self.grab_banner(s, port)
                self.open_ports.append({
                    "port": port,
                    "service": service_desc,
                    "latency": latency,
                    "banner": banner
                })
        except socket.error:
            pass
        finally:
            s.close()

    def grab_banner(self, sock, port):
        """Intenta capturar el banner de identificación emitido por el servicio."""
        banner = ""
        try:
            # Enviar solicitud HTTP mínima si es puerto web
            if port in [80, 5000, 8000, 8080]:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")

            sock.settimeout(1.0)
            data = sock.recv(512)
            if data:
                # Filtrar caracteres imprimibles
                decoded = data.decode("utf-8", errors="replace").strip()
                first_line = decoded.splitlines()[0] if decoded else ""
                banner = first_line[:60]
        except Exception:
            banner = "(Sin respuesta de banner)"
        return banner

    def inspect_http_security_headers(self, port=5000):
        """Audita cabeceras de seguridad del servidor web mediante HTTP."""
        print(f"\n{CYAN}{BOLD}--- AUDITORIA DE CABECERAS HTTP DEL SERVIDOR (Puerto {port}) ---{RESET}")
        try:
            import urllib.request
            url = f"http://{self.target_ip}:{port}/"
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=2) as response:
                headers = dict(response.headers)

            print(f"[*] Codigo de Estado HTTP: {BOLD}200 OK{RESET}")
            print(f"[*] Servidor reportado   : {YELLOW}{headers.get('Server', 'Oculto / No reportado')}{RESET}")

            # Lista de cabeceras de seguridad recomendadas (OWASP)
            security_headers = {
                "X-Frame-Options": "Proteccion contra Clickjacking",
                "X-Content-Type-Options": "Prevencion de MIME-Sniffing",
                "X-XSS-Protection": "Filtro de Cross-Site Scripting",
                "Content-Security-Policy": "Control de politicas de origen y scripts",
                "Strict-Transport-Security": "Forzado de HTTPS (HSTS)"
            }

            for h, desc in security_headers.items():
                if h in headers:
                    print(f"  {GREEN}[PRESENTE]{RESET} {h}: {headers[h]} ({desc})")
                else:
                    print(f"  {RED}[AUSENTE]{RESET}  {h} ({desc}) - {YELLOW}Recomendado implementar{RESET}")

        except Exception as e:
            print(f"  {YELLOW}[-] No se pudo inspeccionar cabeceras en el puerto {port}: {str(e)}{RESET}")

    def run(self, ports_to_scan):
        self.target_ip = self.resolve_target()

        print(f"{CYAN}{BOLD}")
        print("=" * 72)
        print("   ESCANER DE RED Y RECONOCIMIENTO DE SUPERFICIE - HOLIDAYS")
        print("   Seguridad Informatica | 7mo Semestre TI")
        print("=" * 72)
        print(f"{RESET}")
        print(f"[*] Host Objetivo : {BOLD}{self.target_host}{RESET} ({self.target_ip})")
        print(f"[*] Total Puertos : {len(ports_to_scan)}")
        print(f"[*] Hilos / Concur: {self.max_threads}")
        print(f"[*] Timeout       : {self.timeout}s\n")
        print("[*] Iniciando escaneo de puertos TCP...")

        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(self.scan_port, ports_to_scan)

        total_time = time.time() - start_time

        # Ordenar puertos abiertos
        self.open_ports.sort(key=lambda x: x["port"])

        print(f"\n{BOLD}{'PUERTO':<10} {'ESTADO':<10} {'LATENCIA':<12} {'SERVICIO':<30} {'BANNER':<25}{RESET}")
        print("-" * 90)

        if not self.open_ports:
            print(f"{YELLOW}No se detectaron puertos abiertos en el rango evaluado.{RESET}")
        else:
            for item in self.open_ports:
                port_str = f"{item['port']}/TCP"
                status_str = f"{GREEN}ABIERTO{RESET}"
                latency_str = f"{item['latency']:.1f} ms"
                print(f"{port_str:<10} {status_str:<19} {latency_str:<12} {item['service']:<30} {item['banner']:<25}")

        print("-" * 90)
        print(f"[*] Escaneo completado en {total_time:.2f} segundos.")
        print(f"[*] Puertos abiertos encontrados: {BOLD}{len(self.open_ports)}{RESET}")

        # Si el puerto 5000 (Flask) o 80 está abierto, auditar cabeceras HTTP
        web_ports = [p["port"] for p in self.open_ports if p["port"] in [5000, 80, 8080]]
        if web_ports:
            self.inspect_http_security_headers(port=web_ports[0])


def parse_ports(port_arg):
    """Parsea rangos o listas de puertos como '80,443,5000' o '1-1000'."""
    if not port_arg:
        return list(COMMON_PORTS.keys())

    ports = set()
    parts = port_arg.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            subparts = part.split("-")
            start = int(subparts[0])
            end = int(subparts[1])
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(list(ports))


def main():
    parser = argparse.ArgumentParser(
        description="Escáner básico de red TCP y auditoría de cabeceras (Holidays Lab)"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Dirección IP o dominio a escanear (Por defecto: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--ports",
        help="Puertos a escanear (ej. '80,443,5000' o '1-1024'). Por defecto escanea puertos comunes."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.8,
        help="Tiempo de espera en segundos por puerto (Por defecto: 0.8s)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Número de hilos concurrentes (Por defecto: 50)"
    )

    args = parser.parse_args()
    ports_list = parse_ports(args.ports)

    scanner = NetworkScanner(
        target_host=args.host,
        timeout=args.timeout,
        max_threads=args.threads
    )
    scanner.run(ports_list)


if __name__ == "__main__":
    main()
