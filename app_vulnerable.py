#!/usr/bin/env python3
"""
=============================================================================
APLICACIÓN WEB SIMULADA - HOLIDAYS TRAVEL & TOURISM
Laboratorio de Seguridad Informática - 7° Semestre TI
Carrera: Tecnologías de la Información

Componentes principales:
1. Simulación de Vulnerabilidad de Inyección SQL (Concatenación insegura).
2. Mitigación y Defensa Activa (Sentencias preparadas + hashing PBKDF2).
3. Selector de modo pedagógico (Vulnerable vs Seguro).
4. Flujos completos de autenticación: Dual login, Mostrar/Ocultar clave,
   recuperación, registro, OAuth simulado, verificación y protección anti-enumeración.
=============================================================================
"""

import os
import sqlite3
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g
)
from werkzeug.security import generate_password_hash, check_password_hash

# Configuración base de la aplicación Flask
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "holidays_laboratorio_seguridad_2026_key")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "holidays.db")

# Estado pedagógico global: True = Mitigado / Seguro, False = Vulnerable a SQLi
# Puede alternarse en tiempo real desde la interfaz web o mediante la ruta /toggle-security
IS_SECURE_MODE = False


# =============================================================================
# GESTIÓN DE BASE DE DATOS Y CONEXIONES
# =============================================================================
def get_db():
    """Obtiene o crea una conexión SQLite por cada contexto de solicitud."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Cierra la conexión al finalizar la petición."""
    db = g.pop("db", None)
    if db is not None:
        db.close()

def ensure_db_initialized():
    """Verifica que la base de datos exista; si no, la inicializa."""
    if not os.path.exists(DB_PATH):
        from database.init_db import init_database
        init_database()


# =============================================================================
# CONTEXT PROCESSOR & CABECERAS DE SEGURIDAD
# =============================================================================
@app.context_processor
def inject_security_state():
    """Inyecta el estado de seguridad en todos los templates Jinja."""
    return {"is_secure": IS_SECURE_MODE}

@app.after_request
def apply_security_headers(response):
    """
    Demostración de endurecimiento en cabeceras HTTP:
    En modo seguro se aplican cabeceras defensivas para mitigar Clickjacking,
    MIME-sniffing y XSS.
    """
    if IS_SECURE_MODE:
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Server"] = "Holidays-SecureGateway/2.0"
    else:
        # En modo vulnerable se revelan cabeceras estándar con información del servidor
        response.headers["Server"] = "Werkzeug/Python-Lab-Vulnerable"
    return response


# =============================================================================
# RUTAS DE CONTROL PEDAGÓGICO
# =============================================================================
@app.route("/toggle-security")
def toggle_security():
    """Alterna entre el Modo Vulnerable y el Modo Seguro/Mitigado."""
    global IS_SECURE_MODE
    IS_SECURE_MODE = not IS_SECURE_MODE
    estado = "MODO SEGURO (Mitigado con Prepared Statements)" if IS_SECURE_MODE else "MODO VULNERABLE (Concatenación SQL activa)"
    tipo = "success" if IS_SECURE_MODE else "danger"
    flash(f"Entorno actualizado: {estado}", tipo)
    
    # Redirigir a la página previa o a login
    referrer = request.referrer or url_for("login")
    return redirect(referrer)


# =============================================================================
# RUTAS DE AUTENTICACIÓN Y NEGOCIO
# =============================================================================
@app.route("/")
def index():
    """Redirecciona al login si no hay sesión, o al dashboard si está autenticado."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Formulario de autenticación principal con doble comportamiento:
    - Modo Vulnerable: Concatenación directa de cadenas expuesta a Inyección SQL.
    - Modo Seguro: Sentencias preparadas con parámetros (?) y verificación criptográfica.
    """
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        user_input = request.form.get("username_or_email", "").strip()
        password_input = request.form.get("password", "")

        if not user_input or not password_input:
            flash("Por favor completa todos los campos del formulario.", "danger")
            return render_template("login.html", username_or_email=user_input)

        db = get_db()
        cursor = db.cursor()

        # ---------------------------------------------------------------------
        # ESCENARIO 1: MODO VULNERABLE (Demostración de Fallo SQLi)
        # ---------------------------------------------------------------------
        if not IS_SECURE_MODE:
            # VULNERABILIDAD INTENCIONAL (OWASP Top 10 A03:2021 - Injection):
            # La concatenación f-string permite inyectar sintaxis SQL arbitraria.
            # Ejemplo de Payload: ' OR '1'='1' --
            # Consulta resultante:
            # SELECT ... WHERE username = '' OR '1'='1' -- AND password = '...'
            if "@" in user_input:
                query_vulnerable = (
                    f"SELECT id, username, email, full_name, role, is_verified "
                    f"FROM users WHERE email = '{user_input}' AND password = '{password_input}'"
                )
            else:
                query_vulnerable = (
                    f"SELECT id, username, email, full_name, role, is_verified "
                    f"FROM users WHERE username = '{user_input}' AND password = '{password_input}'"
                )

            try:
                cursor.execute(query_vulnerable)
                user = cursor.fetchone()

                if user:
                    # Inyección SQL exitosa o credenciales válidas
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                    session["full_name"] = user["full_name"]
                    session["is_verified"] = user["is_verified"]

                    # Registrar log pedagógico
                    db.execute(
                        "INSERT INTO audit_logs (ip_address, event_type, detail) VALUES (?, ?, ?)",
                        (request.remote_addr, "LOGIN_VULNERABLE", f"Usuario {user['username']} autenticado.")
                    )
                    db.commit()

                    flash(f"Inicio de sesión exitoso como: {user['username']}", "success")
                    return redirect(url_for("dashboard"))
                else:
                    flash("Credenciales de acceso incorrectas.", "danger")

            except sqlite3.OperationalError as e:
                # Fuga de información en errores de base de datos
                flash(f"Error de Sintaxis SQL detectado: {str(e)}", "danger")

        # ---------------------------------------------------------------------
        # ESCENARIO 2: MODO SEGURO / DEFENSIVO (Mitigación mediante Sentencias Preparadas)
        # ---------------------------------------------------------------------
        else:
            # MITIGACIÓN RECOMENDADA:
            # 1. Parámetros (?) para garantizar separación estricta entre código y datos.
            # 2. Desacoplamiento de la clave en la consulta y verificación de hash con PBKDF2/SHA256.
            # 3. Respuesta genérica anti-enumeración para evitar sondeo de usuarios existentes.
            query_segura = (
                "SELECT id, username, email, full_name, password_hash, role, is_verified "
                "FROM users WHERE username = ? OR email = ?"
            )
            cursor.execute(query_segura, (user_input, user_input))
            user = cursor.fetchone()

            if user and check_password_hash(user["password_hash"], password_input):
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["full_name"] = user["full_name"]
                session["is_verified"] = user["is_verified"]

                db.execute(
                    "INSERT INTO audit_logs (ip_address, event_type, detail) VALUES (?, ?, ?)",
                    (request.remote_addr, "LOGIN_SECURE", f"Usuario {user['username']} autenticado de forma segura.")
                )
                db.commit()

                flash("Bienvenido de nuevo a Holidays.", "success")
                return redirect(url_for("dashboard"))
            else:
                # Política de seguridad: No revelar si el usuario o la contraseña fueron incorrectos
                flash("Credenciales de acceso incorrectas.", "danger")

    return render_template("login.html")


@app.route("/registro", methods=["GET", "POST"])
def registro():
    """Registro de nuevas cuentas con almacenamiento dual (texto para vulnerable y hash para seguro)."""
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not username or not email or not password:
            flash("Todos los campos son obligatorios.", "danger")
            return render_template("registro.html")

        if password != confirm_password:
            flash("Las contraseñas ingresadas no coinciden.", "danger")
            return render_template("registro.html")

        if len(password) < 8:
            flash("La contraseña debe tener al menos 8 caracteres.", "danger")
            return render_template("registro.html")

        db = get_db()
        cursor = db.cursor()

        # Verificar unicidad
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            flash("El nombre de usuario o correo electrónico ya se encuentra registrado.", "danger")
            return render_template("registro.html")

        # Almacenar contraseña
        password_hash = generate_password_hash(password)
        cursor.execute(
            """
            INSERT INTO users (username, email, full_name, password, password_hash, role, is_verified)
            VALUES (?, ?, ?, ?, ?, 'cliente', 0)
            """,
            (username, email, full_name, password, password_hash)
        )
        db.commit()

        flash("¡Registro exitoso! Por favor verifica tu cuenta o inicia sesión con tus credenciales.", "success")
        return redirect(url_for("login"))

    return render_template("registro.html")


@app.route("/recuperar-password", methods=["GET", "POST"])
def recuperar_password():
    """Módulo de solicitud para restablecer contraseña olvidada."""
    if request.method == "POST":
        recovery_input = request.form.get("recovery_input", "").strip()
        
        # En modo seguro se aplica el principio anti-enumeración:
        # Siempre devolver el mismo mensaje independientemente de si el correo existe o no.
        flash("Si la dirección o usuario está registrado, recibirás un correo con las instrucciones de restablecimiento.", "info")
        return redirect(url_for("login"))

    return render_template("recuperar.html")


@app.route("/verificar-cuenta", methods=["GET", "POST"])
def verificar_cuenta():
    """Simulación de confirmación y activación de cuenta."""
    if "user_id" not in session:
        flash("Inicia sesión primero para acceder al proceso de verificación.", "info")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if code in ["123456", "777888", "202607"]:
            db = get_db()
            db.execute("UPDATE users SET is_verified = 1 WHERE id = ?", (session["user_id"],))
            db.commit()
            session["is_verified"] = 1
            flash("¡Tu cuenta ha sido verificada exitosamente!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Código de verificación incorrecto. Intenta con '123456' para esta simulación.", "danger")

    return render_template("verificacion.html")


@app.route("/dashboard")
def dashboard():
    """Panel de usuario privado accesible tras autenticación."""
    if "user_id" not in session:
        flash("Debes identificarte antes de ingresar al panel.", "danger")
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=user)


@app.route("/logout")
def logout():
    """Cierra la sesión del usuario actual."""
    session.clear()
    flash("Has cerrado sesión correctamente. ¡Hasta pronto!", "info")
    return redirect(url_for("login"))


# =============================================================================
# INICIALIZACIÓN PRINCIPAL
# =============================================================================
if __name__ == "__main__":
    ensure_db_initialized()
    print("=" * 70)
    print("  SERVIDOR WEB HOLIDAYS - LABORATORIO DE SEGURIDAD INFORMÁTICA")
    print(f"  Modo actual: {'[SEGURO / MITIGADO]' if IS_SECURE_MODE else '[VULNERABLE A SQL INJECTION]'}")
    print("  Escuchando en: http://127.0.0.1:5000")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=True)
