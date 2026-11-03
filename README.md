# Holidays Travel & Tourism - Entorno Controlado de Pruebas de Seguridad Web
## Asignatura: Seguridad Informática (7° Semestre - Tecnologías de la Información)

![Holidays Logo](static/img/logo.svg)

---

## 1. Descripción del Proyecto

Este repositorio contiene un laboratorio práctico completo de **Seguridad Informática**, diseñado para estudiantes de **7° Semestre de la carrera de Tecnologías de la Información**.

El proyecto simula la plataforma web corporativa **"Holidays"** (servicios turísticos y de viajes), la cual cuenta con una arquitectura web en **Python (Flask)** y base de datos relacional **SQLite**. Integra un sistema dual que permite alternar en tiempo de ejecución entre un comportamiento **Vulnerable a Inyección SQL (SQLi)** por concatenación de cadenas y un comportamiento **Mitigado y Seguro** mediante consultas parametrizadas (*Prepared Statements*) y hashing criptográfico.

Adicionalmente, se incluyen herramientas complementarias de auditoría:
* Un script de pruebas de penetración automatizado para explotación y verificación de mitigación de SQLi (`ataque_sql_i.py`).
* Un escáner multihilo de red por sockets para reconocimiento de puertos y análisis de cabeceras HTTP de seguridad (`escaneo_red.py`).
* Un módulo de auditoría y endurecimiento (*hardening*) de la base de datos relacional (`hardening_db.py`).

---

## 2. Marco Ético y Legal

> [!IMPORTANT]
> **Aviso de Uso Ético y Responsable:**  
> Este entorno y las herramientas contenidas han sido diseñados con propósitos **estrictamente pedagógicos** para su ejecución en entornos locales aislados (`127.0.0.1` / `localhost`). El uso de técnicas de inyección SQL o escaneo contra sistemas de terceros sin autorización expresa es ilegal y está penado por las leyes de delitos informáticos.

---

## 3. Estructura del Repositorio

```text
TPE_SEGURIDAD_INFORMATICA/
│
├── app_vulnerable.py        # Servidor web Flask principal (Modo Vulnerable vs Seguro)
├── ataque_sql_i.py          # Script de auditoría y prueba de concepto de Inyección SQL
├── escaneo_red.py           # Escáner de red TCP y auditoría de cabeceras HTTP (sockets)
├── hardening_db.py          # Módulo de diagnóstico y directrices de hardening SQLite
│
├── database/
│   ├── holidays.db          # Base de datos relacional SQLite
│   ├── init_db.py           # Script de inicialización y carga de usuarios demo
│   └── schema.sql           # Esquema DDL de tablas (users, password_resets, audit_logs)
│
├── static/
│   ├── css/
│   │   └── styles.css       # Sistema de diseño moderno, variables CSS, temas Claro/Oscuro
│   ├── js/
│   │   └── main.js          # Lógica frontend (toggle de password, tema, modal, validación)
│   └── img/
│       ├── logo.svg         # Logotipo corporativo "Holidays" vectorizado
│       ├── google.svg       # Ícono oficial OAuth Google
│       └── microsoft.svg    # Ícono oficial OAuth Microsoft
│
├── templates/
│   ├── base.html            # Plantilla base con barra de estado y alternador didáctico
│   ├── login.html           # Formulario de login minimalista, responsive y accesible
│   ├── registro.html        # Formulario de registro de cuentas con validaciones
│   ├── recuperar.html       # Solicitud de restablecimiento de contraseña
│   ├── verificacion.html    # Confirmación y activación de cuenta (token)
│   └── dashboard.html       # Panel privado post-login con datos de auditoría
│
├── PROPUESTA_PROYECTO.md    # Documento formal de propuesta técnica inicial
├── README.md                # Ficha técnica y guía general del proyecto (este archivo)
└── MANUAL_USO.md            # Guía detallada paso a paso para docentes y estudiantes
```

---

## 4. Requisitos y Dependencias

* **Sistema Operativo:** Windows 10/11, Linux (Ubuntu/Debian) o macOS.
* **Lenguaje:** Python 3.10 o superior (validado en Python 3.14).
* **Dependencias de Python:**
  * `flask` (Framework web ligero)
  * `requests` (Cliente HTTP para el script de auditoría)
  * `werkzeug` (Utilidades criptográficas de hash PBKDF2/Scrypt)

### Instalación Rápida
```bash
pip install flask requests
```

---

## 5. Guía de Ejecución

### 5.1 Paso 1: Inicializar la Base de Datos
```bash
python database/init_db.py
```
*Crea la base de datos `database/holidays.db` con usuarios de demostración.*

### 5.2 Paso 2: Ejecutar el Servidor Web
```bash
python app_vulnerable.py
```
*Abre tu navegador en: [http://127.0.0.1:5000](http://127.0.0.1:5000)*

### 5.3 Paso 3: Ejecutar la Auditoría de Inyección SQL
En una segunda terminal:
```bash
python ataque_sql_i.py
```
*El script evaluará credenciales legítimas, incorrectas y los payloads de bypass `' OR '1'='1' --` y `admin' --`.*

### 5.4 Paso 4: Escanear la Superficie de Red
```bash
python escaneo_red.py --ports 80,443,5000,8080
```
*Detecta servicios activos, latencias y audita las cabeceras HTTP de respuesta del servidor.*

### 5.5 Paso 5: Auditar el Endurecimiento (Hardening) de la BD
```bash
python hardening_db.py
```
*Verifica almacenamiento seguro, integridad estructural SQLite y buenas prácticas relacionales.*

---

## 6. Usuarios de Demostración Preconfigurados

| Usuario (`username`) | Correo (`email`) | Contraseña Real | Rol | Estado |
| :--- | :--- | :--- | :--- | :--- |
| `admin` | `admin@holidays.com` | `SuperAdmin2026!` | `admin` | Verificado |
| `turista01` | `turista01@holidays.com` | `ViajeroSeguro#7` | `cliente` | Verificado |
| `agente_viajes` | `agente@holidays.com` | `ReservaVuelo2026$` | `agente` | Verificado |
| `usuario_nuevo` | `nuevo@holidays.com` | `ClaveTemporal123` | `cliente` | Pendiente de verificar |

---

## 7. Fundamentación Técnica: Vulnerabilidad vs Mitigación

### El Fallo: Concatenación Insegura de Cadenas
En el modo vulnerable (`app_vulnerable.py`), el servidor construye la consulta directamente mediante f-strings:
```python
query = f"SELECT * FROM users WHERE username = '{user_input}' AND password = '{password_input}'"
```
Al suministrar el payload `' OR '1'='1' --`, la consulta interpretada por SQLite se transforma en:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' -- AND password = '...'
```
La condición tautológica `'1'='1'` evalúa a Verdadero para todas las filas y `--` descarta la validación de contraseña, retornando el primer registro (`admin`) y evadiendo el mecanismo de autenticación.

### La Mitigación: Sentencias Preparadas (Prepared Statements)
En el modo seguro mitigado, el código delega la separación entre la lógica del comando SQL y los datos al motor de base de datos:
```python
query = "SELECT * FROM users WHERE username = ? OR email = ?"
cursor.execute(query, (user_input, user_input))
```
El motor trata la entrada del usuario estrictamente como un literal textual y no como código ejecutable, neutralizando de raíz cualquier intento de inyección. Posteriormente, la clave se valida contra el hash criptográfico mediante `check_password_hash`.
