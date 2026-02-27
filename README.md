🖥️ Soporte Técnico - EXTENDIDO

Herramienta avanzada de soporte técnico desarrollada en Python con interfaz gráfica moderna basada en tkinter + ttkbootstrap.

Permite monitorear el sistema, diagnosticar red, administrar procesos, crear perfiles IP, generar reportes en PDF/CSV, realizar escaneo de puertos, monitoreo en tiempo real y envío de reportes por correo electrónico.

📌 Características Principales
🔹 1. Información del Sistema

Hostname

IP local

Plataforma (Windows / Linux / Mac)

Arquitectura del sistema

CPU (núcleos lógicos y uso %)

RAM total y disponible

Espacio en disco

Tiempo encendido (Uptime)

Estado de batería (si aplica)

Temperaturas del sistema

Información de GPU (opcional)

Interfaces de red activas

Exportable a:

📄 CSV

📄 PDF con gráfica incluida

🔹 2. Diagnóstico de Red

Ping a cualquier host

Traceroute

Speedtest (requiere speedtest-cli)

Escaneo de puertos por rango

Mostrar Gateway y DNS

Resolver DNS

Obtener IP pública

Escaneo WiFi (requiere pywifi)

🔹 3. Perfiles IP

Permite:

Guardar configuraciones IP estáticas

Aplicar perfiles guardados

Listar perfiles

Compatible con:

Windows (netsh)

Linux (nmcli)

Los perfiles se almacenan en:

~/.soporte_extendido/ip_profiles.json
🔹 4. Gestión de Procesos

Listar procesos activos

Mostrar:

PID

Nombre

Usuario

CPU %

Memoria %

Terminar procesos seleccionados

🔹 5. Monitoreo en Tiempo Real

Gráficas en vivo de:

CPU %

RAM %

Tráfico de red (KB/s)

Latencia de ping continuo

Permite:

Iniciar / detener monitoreo

Guardar imagen del gráfico

Ping continuo a un host específico

🔹 6. Autosave de Logs

Guarda métricas automáticamente cada X minutos

Archivo generado:

~/.soporte_extendido/autosave_logs.csv

Incluye:

Timestamp

CPU

RAM

Tráfico red

Ping

🔹 7. Reportes y Correo

Generar PDF con:

Información del sistema

Gráfica embebida

Enviar reporte por correo SMTP

Compatible con Gmail (puerto 587 TLS)

🛠️ Tecnologías Utilizadas

Python 3.x

tkinter

ttkbootstrap

psutil

matplotlib

reportlab (opcional)

requests (opcional)

speedtest-cli (opcional)

GPUtil (opcional)

netifaces (opcional)

pywifi (opcional)

📦 Instalación
1️⃣ Clonar repositorio
git clone https://github.com/tuusuario/soporte-extendido.git
cd soporte-extendido
2️⃣ Crear entorno virtual (recomendado)
python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows
3️⃣ Instalar dependencias

Instalación mínima:

pip install ttkbootstrap psutil matplotlib

Instalación completa:

pip install ttkbootstrap psutil matplotlib reportlab requests speedtest-cli gputil netifaces pywifi
▶️ Ejecución
python soporte_general.py

Se abrirá la interfaz gráfica automáticamente.

📂 Estructura de Carpetas Generadas
~/.soporte_extendido/
│
├── ip_profiles.json
└── autosave_logs.csv
🔐 Permisos y Seguridad

Algunas funciones requieren permisos de administrador (aplicar perfiles IP).

Las credenciales SMTP no se almacenan.

No se guardan contraseñas en archivos locales.

⚠️ Limitaciones

wmic puede no funcionar en versiones recientes de Windows.

nmcli es requerido en Linux para aplicar perfiles.

pywifi puede no ser compatible con todas las tarjetas WiFi.

Speedtest requiere conexión activa.

👨‍💻 Autor

Ing. Informático Erick Manuel Zapata Reque
Especialista en desarrollo de herramientas de soporte técnico, automatización y monitoreo de sistemas.

📜 Licencia

Uso educativo y profesional bajo responsabilidad del usuario. 

Login de Programa 
<img width="1341" height="704" alt="kIHTbXihVN" src="https://github.com/user-attachments/assets/af070807-84ba-49ee-9997-60b4b2c2bf64" />

