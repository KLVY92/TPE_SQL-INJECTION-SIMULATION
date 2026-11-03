# MANUAL DE USO Y LABORATORIO PRÁCTICO PASO A PASO
## Asignatura: Seguridad Informática (7° Semestre - Tecnologías de la Información)
### Proyecto: Entorno Web Vulnerable Simulado "Holidays", Auditoría de Inyección SQL, Mitigación, Escaneo de Red y Hardening

---

## 1. Introducción y Objetivos de Aprendizaje

Este manual constituye la guía académica para la realización de las prácticas de laboratorio sobre la plataforma **"Holidays"**.

### Objetivos Específicos:
1. Comprender la naturaleza del fallo de seguridad **Inyección SQL (OWASP A03:2021)** derivado de la concatenación insegura de cadenas en consultas a bases de datos relacionales.
2. Comprobar de manera práctica cómo un atacante puede evadir mecanismos de autenticación (*Authentication Bypass*) sin conocer las credenciales reales de un usuario.
3. Aplicar y verificar la técnica de defensa mediante **Consultas Parametrizadas (Prepared Statements)** y almacenamiento de contraseñas con algoritmos de hashing adaptativos (PBKDF2).
4. Utilizar herramientas basadas en sockets para reconocer la superficie de ataque en red (puertos abiertos y cabeceras de respuesta HTTP).
5. Evaluar los parámetros de configuración y endurecimiento (*hardening*) a nivel de base de datos relacional y sistema de archivos.

---

## 2. Preparación del Entorno de Pruebas

### 2.1 Requisitos Previos
* Computadora con Python 3.10 o superior instalado.
* Navegador web moderno (Chrome, Edge, Firefox, Brave).
* Acceso a una terminal de comandos (PowerShell en Windows o Bash en Linux).

### 2.2 Instalación de Librerías
Abra su terminal en la carpeta del proyecto y ejecute:
```powershell
pip install flask requests
```

### 2.3 Inicialización de la Base de Datos
Antes de arrancar el servidor por primera vez, verifique la creación de la base de datos:
```powershell
python database/init_db.py
```
*Salida esperada:*
```text
[*] Inicializando base de datos en: ...\database\holidays.db
[+] Base de datos SQLite 'holidays.db' creada exitosamente.
    Usuarios creados:
    - Usuario: admin | Email: admin@holidays.com | Rol: admin | Verificado: Sí
    - Usuario: turista01 | Email: turista01@holidays.com | Rol: cliente | Verificado: Sí
    - Usuario: agente_viajes | Email: agente@holidays.com | Rol: agente | Verificado: Sí
    - Usuario: usuario_nuevo | Email: nuevo@holidays.com | Rol: cliente | Verificado: No
```

---

## 3. Guía de la Interfaz Web (UI/UX)

Inicie el servidor web:
```powershell
python app_vulnerable.py
```
Acceda a la URL: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

### 3.1 Componentes de la Interfaz
1. **Barra Superior de Control Didáctico:**
   * Muestra el estado activo: `MODO VULNERABLE (SQLi ACTIVO)` (en rojo) o `MODO SEGURO (MITIGADO)` (en verde).
   * Botón **"Cambiar a Modo Seguro / Vulnerable"**: Permite conmutar la lógica defensiva del backend sin necesidad de reiniciar el servidor.
   * Botón de **Modo Claro / Oscuro**: Alterna la paleta visual con persistencia automática en el navegador.
2. **Formulario de Autenticación "Holidays":**
   * Logotipo corporativo oficial vectorizado en SVG.
   * Campo dual **"Correo electrónico o usuario"**: Permite ingresar `admin` o `admin@holidays.com`.
   * Campo **"Contraseña"** con botón de visualización dinámica (ojo abierto / ojo tachado) para verificar la clave antes de enviarla.
   * Botón **"Iniciar Sesión"** con spinner de carga interactivo y bloqueo anti-doble clic.
   * Separador con botones sociales simulados (**Google** y **Microsoft**) que explican el funcionamiento del protocolo OAuth 2.0.
   * Enlace a **"¿Olvidaste tu contraseña?"** ([/recuperar-password](http://127.0.0.1:5000/recuperar-password)).
   * Enlace a **"Regístrate aquí"** ([/registro](http://127.0.0.1:5000/registro)).

---

## 4. Práctica 1: Explotación y Mitigación Manual de Inyección SQL

### Caso 1A: Inicio de Sesión Legítimo (Comportamiento Esperado)
1. Ingrese en el campo de usuario: `turista01`
2. Ingrese en el campo de contraseña: `ViajeroSeguro#7`
3. Haga clic en **"Iniciar Sesión"**.
4. **Resultado:** Redirección automática a `/dashboard`, mostrando los datos del cliente `Carlos Mendoza (Turista)` y su rol `cliente`.
5. Cierre la sesión presionando **"Cerrar Sesión"**.

---

### Caso 1B: Inicio de Sesión Fallido con Contraseña Inválida
1. Ingrese usuario: `turista01`
2. Ingrese contraseña: `ClaveErronea999`
3. Haga clic en **"Iniciar Sesión"**.
4. **Resultado:** Se muestra el mensaje de alerta `Credenciales de acceso incorrectas.` sin conceder acceso.

---

### Caso 1C: Explotación por Inyección SQL - Bypass Tautológico
> Asegúrese de que la barra superior indique **MODO VULNERABLE (SQLi ACTIVO)**.

1. En el campo **Correo electrónico o usuario**, ingrese exactamente el siguiente payload:
   ```sql
   ' OR '1'='1' --
   ```
2. En el campo **Contraseña**, ingrese cualquier texto ficticio (ej. `xyz`).
3. Haga clic en **"Iniciar Sesión"**.
4. **Resultado de la Explotación:**
   * La aplicación **inicia sesión inmediatamente** y redirige al panel privado `/dashboard`.
   * Observe el nombre del usuario autenticado: **`Administrador Principal`** y rol **`admin`**.
   * **Explicación Técnica:**
     La consulta vulnerable ejecutada en el servidor es:
     ```sql
     SELECT id, username, email, full_name, role, is_verified 
     FROM users WHERE username = '' OR '1'='1' -- AND password = 'xyz'
     ```
     La cláusula `'1'='1'` evalúa como verdadera para todos los registros de la tabla, y los caracteres de comentario `--` eliminan la verificación de la contraseña. SQLite devuelve el primer registro coincidente, que corresponde a la cuenta de mayor privilegio (`admin`).

---

### Caso 1D: Explotación por Inyección SQL - Suplantación de Cuenta Específica
1. Cierre sesión e ingrese en el campo de usuario:
   ```sql
   admin' --
   ```
2. Ingrese cualquier contraseña ficticia (ejemplo: `123`).
3. Presione **"Iniciar Sesión"**.
4. **Resultado:** Se fija el usuario `admin` omitiendo la comprobación de contraseña, obteniendo control de la cuenta administrativa.

---

### Caso 1E: Validación de la Mitigación (Modo Seguro)
1. En la barra superior, haga clic en **"Cambiar a Modo Seguro"**.
2. Verifique que la barra cambie a verde: **`MODO SEGURO (MITIGADO)`**.
3. Vuelva a intentar el ataque de inyección:
   * Usuario: `' OR '1'='1' --`
   * Contraseña: `cualquier_cosa`
4. Presione **"Iniciar Sesión"**.
5. **Resultado Defensivo:**
   * El sistema responde: `Credenciales de acceso incorrectas.` y **deniega el acceso**.
   * **Explicación Técnica:**
     El servidor ejecuta la sentencia preparada:
     ```python
     cursor.execute("SELECT ... WHERE username = ? OR email = ?", (user_input, user_input))
     ```
     El motor de base de datos busca literalmente un usuario cuyo nombre coincida exactamente con la cadena `' OR '1'='1' --`. Al no existir tal usuario, la consulta devuelve 0 filas, neutralizando por completo el vector de ataque.

---

## 5. Práctica 2: Auditoría Automatizada con `ataque_sql_i.py`

Abra una segunda terminal (manteniendo el servidor Flask en ejecución) y corra el script de auditoría:

```powershell
python ataque_sql_i.py
```

### Interpretación de la Auditoría:
* El script evalúa automáticamente 4 escenarios:
  1. Login válido con credenciales legítimas.
  2. Login inválido como línea base.
  3. Intento de bypass tautológico `' OR '1'='1' --`.
  4. Intento de suplantación de administrador `admin' --`.
* Si el servidor está en **Modo Vulnerable**, el script emitirá una alerta roja:
  `[!] ALERTA CRITICA: Se detecto vulnerabilidad activa de Inyeccion SQL.`
* Si el servidor está en **Modo Seguro**, el script reportará en verde:
  `[OK] ENTORNO SEGURO: Los intentos de Inyeccion SQL fueron neutralizados.`

### Prueba con un Payload Personalizado:
Puede probar cualquier payload SQLi manual mediante el argumento `--payload`:
```powershell
python ataque_sql_i.py --payload "turista01' --"
```

---

## 6. Práctica 3: Escaneo de Red con `escaneo_red.py`

Para analizar la superficie de ataque y los servicios expuestos en el entorno del laboratorio, ejecute:

```powershell
python escaneo_red.py --ports 80,443,5000,8080
```

### Funciones Evaluadas:
1. **Detección de Puertos TCP Abiertos:** Comprueba mediante sockets el estado (ABIERTO/CERRADO) y mide la latencia de respuesta en milisegundos.
2. **Banner Grabbing:** Envía solicitudes de sondeo iniciales para capturar la firma del servicio activo (ej. servidor web Flask/Werkzeug).
3. **Auditoría de Cabeceras HTTP de Seguridad:**
   * Evalúa la presencia de cabeceras de endurecimiento recomendadas por OWASP:
     * `X-Frame-Options` (Mitiga Clickjacking)
     * `X-Content-Type-Options` (Previene ataques de MIME-Sniffing)
     * `X-XSS-Protection` (Filtro XSS)
     * `Content-Security-Policy` (Restringe orígenes de scripts e imágenes)
     * `Strict-Transport-Security` (HSTS)
   * *Demostración en vivo:* Si alterna la aplicación web a **Modo Seguro**, observe cómo el servidor añade automáticamente las cabeceras defensivas configuradas en el middleware `after_request`.

---

## 7. Práctica 4: Auditoría y Endurecimiento de BD con `hardening_db.py`

Ejecute el módulo de diagnóstico de base de datos:

```powershell
python hardening_db.py
```

### Módulos de Inspección:
1. **Permisos en el Sistema de Archivos:**
   * Analiza los permisos de acceso sobre el archivo `holidays.db` (en Linux verifica que no sea `world-writable`; en Windows recomienda ACLs NTFS restrictivas).
2. **Almacenamiento Criptográfico de Contraseñas:**
   * Revisa la tabla de usuarios identificando la existencia de contraseñas en texto claro (columna didáctica `password`) frente a hashes robustos (columna mitigada `password_hash` con PBKDF2).
3. **Parámetros PRAGMA de SQLite:**
   * `PRAGMA integrity_check`: Valida que la estructura del árbol B y las páginas no presenten corrupción física ni lógica.
   * `PRAGMA secure_delete`: Verifica si las páginas de registros eliminados se sobrescriben con ceros para evitar técnicas de recuperación forense de datos.
   * `PRAGMA foreign_keys`: Comprueba si la integridad referencial está habilitada activamente.
4. **Recomendaciones para Entornos de Producción:**
   * Principio de Menor Privilegio (PoLP), Cifrado en Reposo (Transparent Data Encryption / SQLCipher), uso obligatorio de ORMs o Sentencias Preparadas y algoritmos adaptativos (Argon2id, PBKDF2 con mínimo 600,000 iteraciones).

---

## 8. Cuestionario de Evaluación y Análisis para el Estudiante

1. **¿Por qué el uso de funciones de sanitización como reemplazar comillas (`replace("'", "")`) suele ser insuficiente frente a sentencias preparadas?**
   * *R:* Porque existen técnicas de evasión avanzadas (codificación URL, Unicode, inyecciones numéricas donde no se requieren comillas, o truncamiento de cadenas) que superan los filtros manuales. Las sentencias preparadas resuelven el problema en la raíz garantizando que la estructura de la consulta esté precompilada antes de asociar los valores.
2. **¿Por qué la consulta vulnerable expuso la cuenta de `admin` y no la de otro usuario al ingresar `' OR '1'='1' --`?**
   * *R:* La instrucción `cursor.fetchone()` extrae el primer registro del conjunto de resultados. Dado que `1=1` es verdadero para todos los usuarios y `admin` tiene `id = 1` (primer registro insertado), es la primera fila devuelta.
3. **¿Cuál es la importancia de aplicar mensajes genéricos de error ("Credenciales incorrectas") en lugar de mensajes específicos como "El usuario no existe" o "Contraseña errónea"?**
   * *R:* Prevenir la **Enumeración de Usuarios**, técnica mediante la cual un atacante descubre cuentas válidas registradas en el sistema para luego lanzar ataques de fuerza bruta o ingeniería social dirigida.

---

## 9. Conclusión

El entorno **Holidays** demuestra de forma práctica e integral el ciclo completo de la seguridad de software: **Identificación de la vulnerabilidad -> Explotación controlada -> Análisis de impacto -> Implementación de mitigación técnica -> Auditoría automatizada de aseguramiento**.
