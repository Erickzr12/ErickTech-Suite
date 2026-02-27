# soporte_extendido.py
import os
import platform
import socket
import subprocess
import threading
import csv
import datetime
import time
import sys
import shutil
import json
from functools import wraps
from pathlib import Path
import tempfile
import getpass

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog, scrolledtext

import ttkbootstrap as tb
import psutil

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# -- Optional libs --
try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

try:
    import speedtest
    SPEEDTEST_AVAILABLE = True
except Exception:
    SPEEDTEST_AVAILABLE = False

try:
    from reportlab.pdfgen import canvas as pdfcanvas
    from reportlab.lib.pagesizes import letter
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

try:
    import GPUtil
    GPU_AVAILABLE = True
except Exception:
    GPU_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except Exception:
    NETIFACES_AVAILABLE = False

try:
    import pywifi
    from pywifi import const as WIFI_CONST
    PYWIFI_AVAILABLE = True
except Exception:
    PYWIFI_AVAILABLE = False

# ---------------------- Helpers ---------------------- #
def run_thread(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        t = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
        t.start()
        return t
    return wrapper

def safe_str(x):
    try:
        return str(x)
    except Exception:
        return repr(x)

def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def app_dir():
    p = Path.home() / ".soporte_extendido"
    p.mkdir(parents=True, exist_ok=True)
    return p

# ---------------------- Sistema ---------------------- #

def get_root_path():
    return os.path.abspath(os.sep)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_default_gateway_and_dns():
    """
    Intenta obtener puerta de enlace por defecto y servidores DNS.
    Usa netifaces si está disponible; si no, intenta comandos por plataforma.
    """
    gw = None
    dns = []
    system = platform.system().lower()
    if NETIFACES_AVAILABLE:
        try:
            import netifaces as ni
            gws = ni.gateways()
            default = gws.get('default', {})
            gw = default.get(ni.AF_INET, (None, None))[0]
            # DNS servers: netifaces no devuelve; leer /etc/resolv.conf en Unix
            if system in ('linux', 'darwin'):
                resolv = Path('/etc/resolv.conf')
                if resolv.exists():
                    for line in resolv.read_text().splitlines():
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                dns.append(parts[1])
        except Exception:
            gw = None
    if not gw:
        try:
            if 'windows' in system:
                out = subprocess.check_output(['ipconfig'], text=True, errors='ignore')
                cur_adapter = None
                for line in out.splitlines():
                    if line.strip().startswith('Adaptador') or line.strip().endswith(':'):
                        cur_adapter = line.strip()
                    if 'Puerta de enlace predeterminada' in line or 'Default Gateway' in line:
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            candidate = parts[1].strip()
                            if candidate:
                                gw = candidate
                                break
                # DNS from ipconfig /all
                out = subprocess.check_output(['ipconfig', '/all'], text=True, errors='ignore')
                for line in out.splitlines():
                    if 'Servidor DNS' in line or 'DNS Servers' in line:
                        parts = line.split(':',1)
                        if len(parts)>1:
                            dns.append(parts[1].strip())
            else:
                # linux / mac
                try:
                    out = subprocess.check_output(['ip', 'route'], text=True, errors='ignore')
                    for line in out.splitlines():
                        if line.startswith('default'):
                            parts = line.split()
                            if 'via' in parts:
                                gw = parts[parts.index('via') + 1]
                                break
                except Exception:
                    # fallback to netstat
                    try:
                        out = subprocess.check_output(['netstat', '-nr'], text=True, errors='ignore')
                        for line in out.splitlines():
                            if line.startswith('0.0.0.0') or line.startswith('default'):
                                parts = line.split()
                                if len(parts)>=2:
                                    gw = parts[1]
                                    break
                    except Exception:
                        gw = None
                # DNS
                resolv = Path('/etc/resolv.conf')
                if resolv.exists():
                    for line in resolv.read_text().splitlines():
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                dns.append(parts[1])
                # systemd-resolve
                try:
                    out = subprocess.check_output(['systemd-resolve', '--status'], text=True, errors='ignore')
                    for line in out.splitlines():
                        if 'DNS Servers' in line:
                            parts = line.split(':',1)
                            if len(parts)>1:
                                dns.append(parts[1].strip())
                except Exception:
                    pass
        except Exception:
            pass
    return gw, list(dict.fromkeys(dns))  # dedupe

def get_system_info():
    info = {}
    try:
        info['Hostname'] = socket.gethostname()
        info['Local IP'] = get_local_ip()
        info['Plataforma'] = platform.system()
        info['Versión Plataforma'] = platform.version()
        info['Release'] = platform.release()
        info['Arquitectura'] = platform.machine()
        info['Procesador'] = platform.processor()
        info['CPU (núcleos logical)'] = psutil.cpu_count(logical=True)
        info['Uso CPU % (instantáneo)'] = psutil.cpu_percent(interval=0.3)
        mem = psutil.virtual_memory()
        info['RAM total (GB)'] = round(mem.total / (1024 ** 3), 2)
        info['RAM disponible (GB)'] = round(mem.available / (1024 ** 3), 2)
        disk = shutil.disk_usage(get_root_path())
        info['Disco total (GB)'] = round(disk.total / (1024 ** 3), 2)
        info['Disco usado (GB)'] = round(disk.used / (1024 ** 3), 2)
        info['Uptime'] = str(datetime.timedelta(seconds=int(time.time() - psutil.boot_time())))
        # battery
        try:
            bat = psutil.sensors_battery()
            if bat:
                info['Batería %'] = bat.percent
                info['Batería cargando'] = bat.power_plugged
        except Exception:
            pass
        # temps
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                for k, entries in temps.items():
                    info[f"Temp {k}"] = "; ".join(f"{e.label or '':5}{e.current}°C" for e in entries)
        except Exception:
            pass
        # GPU
        if GPU_AVAILABLE:
            try:
                gpus = GPUtil.getGPUs()
                for i, g in enumerate(gpus):
                    info[f"GPU {i}"] = f"{g.name} load {g.load*100:.1f}% mem {g.memoryUsed}/{g.memoryTotal}MB"
            except Exception:
                pass
        # interfaces
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            info['Interfaces activas'] = ", ".join([f"{k}({'up' if stats.get(k) and stats[k].isup else 'down'})" for k in addrs.keys()])
        except Exception:
            pass
    except Exception as e:
        info['error'] = safe_str(e)
    return info

def export_info_csv(info: dict, filepath: str):
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Clave', 'Valor'])
        for k, v in info.items():
            writer.writerow([k, v])

def export_info_pdf_with_plot(info: dict, fig, filepath: str):
    """
    Genera un PDF con reporte textual y una imagen embebida del gráfico (matplotlib Figure).
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab no está instalado. Instalar con: pip install reportlab")
    tmp = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
    tmp.close()
    fig.savefig(tmp.name)
    c = pdfcanvas.Canvas(filepath, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica", 10)
    y = height - 40
    c.drawString(40, y, "Reporte Sistema - " + now_str())
    y -= 20
    for k, v in info.items():
        line = f"{k}: {v}"
        c.drawString(40, y, line[:120])
        y -= 12
        if y < 120:
            c.showPage()
            y = height - 40
    # insertar la imagen en la última página
    c.drawImage(tmp.name, 40, 40, width=width-80, preserveAspectRatio=True, mask='auto')
    c.save()
    try:
        os.unlink(tmp.name)
    except Exception:
        pass

# ---------------------- Red / Network ---------------------- #

def platform_ping_command(host: str, count: int = 4):
    if platform.system().lower() == 'windows':
        return ['ping', '-n', str(count), host]
    else:
        return ['ping', '-c', str(count), host]

@run_thread
def ping_host(host: str, count: int, callback):
    cmd = platform_ping_command(host, count)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = proc.stdout + proc.stderr
    except Exception as e:
        out = f"Error ejecutando ping: {e}"
    if callback:
        callback(out)

@run_thread
def traceroute_host(host: str, callback):
    system = platform.system().lower()
    if 'windows' in system:
        cmd = ['tracert', host]
    else:
        cmd = ['traceroute', host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        out = proc.stdout + proc.stderr
    except Exception as e:
        out = f"Error ejecutando traceroute: {e}"
    if callback:
        callback(out)

@run_thread
def run_speedtest(callback):
    if not SPEEDTEST_AVAILABLE:
        if callback:
            callback("speedtest-cli (python) no está instalado. Instale con: pip install speedtest-cli")
        return
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        down = st.download()
        up = st.upload()
        ping = st.results.ping
        out = (f"Download: {round(down / 1e6, 2)} Mbps\n"
               f"Upload: {round(up / 1e6, 2)} Mbps\n"
               f"Ping: {round(ping, 2)} ms\n"
               f"Server: {st.results.server}\n"
               f"Client: {st.results.client}\n")
    except Exception as e:
        out = f"Error ejecutando speedtest: {e}"
    if callback:
        callback(out)

@run_thread
def port_scan(host: str, start_port: int, end_port: int, timeout: float, callback):
    open_ports = []
    try:
        for port in range(start_port, end_port + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                res = sock.connect_ex((host, port))
                if res == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                continue
        out = f"Puertos abiertos en {host}: {open_ports}"
    except Exception as e:
        out = f"Error en escaneo: {e}"
    if callback:
        callback(out)

def resolve_dns(name):
    try:
        ips = socket.gethostbyname_ex(name)
        return ips
    except Exception as e:
        return f"Error resolviendo DNS: {e}"

def get_public_ip():
    if not REQUESTS_AVAILABLE:
        return "requests no está instalado (pip install requests)"
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=6)
        if r.ok:
            return r.json().get('ip')
        return f"Error HTTP: {r.status_code}"
    except Exception as e:
        return f"Error: {e}"

# WiFi scan (pywifi)
def scan_wifi_once(timeout=8):
    if not PYWIFI_AVAILABLE:
        return "pywifi no está instalado (pip install pywifi) o no disponible en esta plataforma."
    try:
        wifi = pywifi.PyWiFi()
        ifaces = wifi.interfaces()
        if not ifaces:
            return "No se encontraron interfaces WiFi."
        iface = ifaces[0]
        iface.scan()
        time.sleep(timeout)
        results = iface.scan_results()
        networks = []
        for r in results:
            networks.append({
                'ssid': r.ssid,
                'bssid': r.bssid,
                'signal': r.signal,
                'akm': r.akm,
                'cipher': r.cipher,
                'auth': r.auth
            })
        # dedupe per SSID
        unique = {}
        for n in networks:
            unique.setdefault(n['ssid'] or "<oculto>", n)
        return list(unique.values())
    except Exception as e:
        return f"Error escaneando WiFi: {e}"

# ---------------------- Procesos ---------------------- #

def list_processes():
    procs = []
    for p in psutil.process_iter(attrs=['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            info = p.info
            procs.append({
                'pid': info.get('pid'),
                'name': info.get('name'),
                'user': info.get('username'),
                'cpu': round(info.get('cpu_percent') or 0.0, 2),
                'mem': round(info.get('memory_percent') or 0.0, 2),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs.sort(key=lambda x: x['pid'])
    return procs

def kill_process(pid: int):
    try:
        p = psutil.Process(pid)
        p.terminate()
        try:
            p.wait(timeout=3)
            return True, "Proceso terminado correctamente."
        except psutil.TimeoutExpired:
            p.kill()
            return True, "Proceso forzado (kill)."
    except Exception as e:
        return False, f"Error al terminar proceso: {e}"

# ---------------------- IP Profiles (save/apply) ---------------------- #

PROFILES_FILE = app_dir() / "ip_profiles.json"

def load_profiles():
    if PROFILES_FILE.exists():
        try:
            return json.loads(PROFILES_FILE.read_text(encoding='utf-8'))
        except Exception:
            return {}
    return {}

def save_profiles(profiles):
    PROFILES_FILE.write_text(json.dumps(profiles, indent=2), encoding='utf-8')

def save_ip_profile(name, iface, ip, mask, gateway, dns_list):
    profiles = load_profiles()
    profiles[name] = {
        'iface': iface,
        'ip': ip,
        'mask': mask,
        'gateway': gateway,
        'dns': dns_list
    }
    save_profiles(profiles)
    return True

def apply_ip_profile(profile_name):
    profiles = load_profiles()
    if profile_name not in profiles:
        return False, "Perfil no encontrado."
    p = profiles[profile_name]
    system = platform.system().lower()
    try:
        if 'windows' in system:
            # netsh interface ip set address "NAME" static IP MASK GATEWAY
            cmd = ['netsh', 'interface', 'ip', 'set', 'address', f'name={p["iface"]}', 'static', p['ip'], p['mask'], p['gateway']]
            subprocess.run(cmd, check=True)
            # DNS
            # first set primary
            subprocess.run(['netsh','interface','ip','set','dns', f'name={p["iface"]}', 'static', p['dns'][0] if p['dns'] else '8.8.8.8'], check=False)
            for i, d in enumerate(p.get('dns',[])[1:], start=2):
                subprocess.run(['netsh','interface','ip','add','dns', f'name={p["iface"]}', d, str(i)], check=False)
            return True, "Perfil aplicado (Windows)."
        else:
            # attempt nmcli (NetworkManager) - common on many Linux distros
            if shutil.which('nmcli'):
                # set manual IPv4
                dns_join = ",".join(p.get('dns',[])) if p.get('dns') else ""
                subprocess.run(['nmcli','con','modify', p['iface'], 'ipv4.addresses', f"{p['ip']}/{p['mask']}"], check=False)
                subprocess.run(['nmcli','con','modify', p['iface'], 'ipv4.gateway', p['gateway']], check=False)
                subprocess.run(['nmcli','con','modify', p['iface'], 'ipv4.dns', dns_join], check=False)
                subprocess.run(['nmcli','con','modify', p['iface'], 'ipv4.method', 'manual'], check=False)
                subprocess.run(['nmcli','con','up', p['iface']], check=False)
                return True, "Perfil aplicado (nmcli)."
            else:
                return False, "Aplicar perfil no soportado en esta plataforma (se requiere nmcli o privilegios específicos)."
    except subprocess.CalledProcessError as e:
        return False, f"Error al aplicar perfil: {e}"
    except Exception as e:
        return False, f"Error: {e}"

# ---------------------- Monitoring / Graphs / Continuous ping ---------------------- #

class Monitor:
    def __init__(self, interval=1.0, max_points=120):
        self.interval = interval
        self.max_points = max_points
        self.cpu = []
        self.ram = []
        self.net_recv = []
        self.net_sent = []
        self.ping_lat = []
        self._running = False
        self._thread = None
        self._last_net = psutil.net_io_counters()
        self.lock = threading.Lock()
        self._ping_target = None
        self._ping_running = False

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        self._thread = None
        self.stop_continuous_ping()

    def _run(self):
        while self._running:
            try:
                with self.lock:
                    self.cpu.append(psutil.cpu_percent(interval=None))
                    self.ram.append(psutil.virtual_memory().percent)
                    now_net = psutil.net_io_counters()
                    recv = (now_net.bytes_recv - self._last_net.bytes_recv) / max(self.interval, 0.001)
                    sent = (now_net.bytes_sent - self._last_net.bytes_sent) / max(self.interval, 0.001)
                    self.net_recv.append(round(recv / 1024, 2))
                    self.net_sent.append(round(sent / 1024, 2))
                    self._last_net = now_net
                    if len(self.cpu) > self.max_points:
                        self.cpu = self.cpu[-self.max_points:]
                        self.ram = self.ram[-self.max_points:]
                        self.net_recv = self.net_recv[-self.max_points:]
                        self.net_sent = self.net_sent[-self.max_points:]
                        self.ping_lat = self.ping_lat[-self.max_points:]
            except Exception:
                pass
            time.sleep(self.interval)

    def start_continuous_ping(self, host):
        if self._ping_running:
            return
        self._ping_target = host
        self._ping_running = True
        threading.Thread(target=self._ping_loop, daemon=True).start()

    def stop_continuous_ping(self):
        self._ping_running = False

    def _ping_loop(self):
        cmd_template = platform_ping_command(self._ping_target, count=1)
        # adapt template for continuous single ping (execute one-by-one)
        while self._ping_running:
            try:
                cmd = cmd_template
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                out = proc.stdout + proc.stderr
                # buscar tiempo en ms
                lat = None
                for part in out.replace(',', '.').split():
                    if 'ms' in part:
                        try:
                            lat = float(part.replace('ms',''))
                            break
                        except:
                            pass
                # fallback parse lines like "time=12.3 ms"
                if lat is None:
                    for line in out.splitlines():
                        if 'time=' in line:
                            try:
                                part = line.split('time=')[-1].split()[0].replace('ms','')
                                lat = float(part)
                                break
                            except:
                                pass
                if lat is None:
                    lat = None
                with self.lock:
                    self.ping_lat.append(lat if lat is not None else float('nan'))
                    if len(self.ping_lat) > self.max_points:
                        self.ping_lat = self.ping_lat[-self.max_points:]
            except Exception:
                with self.lock:
                    self.ping_lat.append(float('nan'))
            time.sleep(max(self.interval, 0.5))

# ---------------------- Auto-logging ---------------------- #

class AutoLogger:
    def __init__(self, interval_minutes=5):
        self.interval = max(1, interval_minutes)
        self._running = False
        self._thread = None
        self.path = app_dir() / "autosave_logs.csv"
        # ensure header
        if not self.path.exists():
            with open(self.path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp','cpu','ram','net_recv_kb_s','net_sent_kb_s','ping_ms'])

    def start(self, monitor: Monitor):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, args=(monitor,), daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        self._thread = None

    def _run(self, monitor):
        while self._running:
            with monitor.lock:
                cpu = monitor.cpu[-1] if monitor.cpu else None
                ram = monitor.ram[-1] if monitor.ram else None
                net_recv = monitor.net_recv[-1] if monitor.net_recv else None
                net_sent = monitor.net_sent[-1] if monitor.net_sent else None
                ping = monitor.ping_lat[-1] if monitor.ping_lat else None
            with open(self.path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([now_str(), cpu, ram, net_recv, net_sent, ping])
            time.sleep(self.interval * 60)

# ---------------------- Reports / Email ---------------------- #

def send_email_with_attachment(smtp_host, smtp_port, username, password, sender, recipient, subject, body, attachment_path):
    """
    Envia un correo con adjunto usando smtplib.
    """
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient
    msg.set_content(body)
    # adjuntar
    try:
        with open(attachment_path, 'rb') as f:
            data = f.read()
        import mimetypes
        ctype, encoding = mimetypes.guess_type(attachment_path)
        if ctype is None:
            ctype = 'application/octet-stream'
        maintype, subtype = ctype.split('/',1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=os.path.basename(attachment_path))
    except Exception as e:
        return False, f"Error adjuntando fichero: {e}"
    try:
        server = smtplib.SMTP(smtp_host, int(smtp_port), timeout=15)
        server.starttls()
        server.login(username, password)
        server.send_message(msg)
        server.quit()
        return True, "Correo enviado correctamente."
    except Exception as e:
        return False, f"Error enviando correo: {e}"

# ---------------------- UI ---------------------- #

class SoporteApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Soporte Técnico - EXTENDIDO")
        self.root.geometry("1200x800")
        self.monitor = Monitor(interval=1.0, max_points=180)
        self.autologger = AutoLogger(interval_minutes=5)
        self._create_widgets()
        self._setup_graph()
        self._monitor_update_job = None
        self._start_time = time.time()
        self.log(f"Aplicación iniciada: {now_str()}")

        self._on_refresh_info()
        self._on_refresh_procs()

    def _create_widgets(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill='both', expand=True, padx=8, pady=8)

        # --- Tab Sistema --- #
        tab_sistema = ttk.Frame(nb)
        nb.add(tab_sistema, text="Sistema")
        left = ttk.Frame(tab_sistema)
        left.pack(side='left', fill='y', padx=8, pady=8)
        right = ttk.Frame(tab_sistema)
        right.pack(side='right', fill='both', expand=True, padx=8, pady=8)

        btn_refresh = tb.Button(left, text="Actualizar Info", bootstyle="success", command=self._on_refresh_info)
        btn_refresh.pack(fill='x', pady=6)
        btn_csv = tb.Button(left, text="Exportar CSV", bootstyle="info", command=self._on_export_csv)
        btn_csv.pack(fill='x', pady=6)
        btn_pdf = tb.Button(left, text="Exportar PDF con Gráfica", bootstyle="secondary", command=self._on_export_pdf)
        btn_pdf.pack(fill='x', pady=6)

        btn_gpu = tb.Button(left, text="Info GPU", bootstyle="info", command=self._on_gpu_info)
        btn_gpu.pack(fill='x', pady=6)
        btn_software = tb.Button(left, text="Listado Programas (Windows)", bootstyle="info", command=self._on_list_installed)
        btn_software.pack(fill='x', pady=6)

        self.text_info = scrolledtext.ScrolledText(right, height=30)
        self.text_info.pack(fill='both', expand=True)

        # --- Tab Red --- #
        tab_red = ttk.Frame(nb)
        nb.add(tab_red, text="Red")
        frm_top = ttk.Frame(tab_red)
        frm_top.pack(fill='x', padx=8, pady=8)

        ttk.Label(frm_top, text="Host / IP:").pack(side='left', padx=(0,6))
        self.entry_host = tb.Entry(frm_top)
        self.entry_host.pack(side='left', padx=(0,6))
        self.entry_host.insert(0, "8.8.8.8")

        btn_ping = tb.Button(frm_top, text="Ping", bootstyle="primary", command=self._on_ping)
        btn_ping.pack(side='left', padx=4)
        btn_tr = tb.Button(frm_top, text="Traceroute", bootstyle="primary", command=self._on_traceroute)
        btn_tr.pack(side='left', padx=4)
        btn_speed = tb.Button(frm_top, text="Speedtest", bootstyle="warning", command=self._on_speedtest)
        btn_speed.pack(side='left', padx=4)
        btn_pubip = tb.Button(frm_top, text="IP Pública", bootstyle="info", command=self._on_public_ip)
        btn_pubip.pack(side='left', padx=4)

        frm_scan = ttk.Frame(tab_red)
        frm_scan.pack(fill='x', padx=8, pady=6)
        ttk.Label(frm_scan, text="Puerto inicio:").pack(side='left')
        self.entry_port_start = tb.Entry(frm_scan, width=6)
        self.entry_port_start.pack(side='left', padx=4)
        self.entry_port_start.insert(0, "1")
        ttk.Label(frm_scan, text="Puerto fin:").pack(side='left', padx=(8,0))
        self.entry_port_end = tb.Entry(frm_scan, width=6)
        self.entry_port_end.pack(side='left', padx=4)
        self.entry_port_end.insert(0, "1024")
        ttk.Label(frm_scan, text="Timeout (s):").pack(side='left', padx=(8,0))
        self.entry_port_timeout = tb.Entry(frm_scan, width=6)
        self.entry_port_timeout.pack(side='left', padx=4)
        self.entry_port_timeout.insert(0, "0.2")
        btn_scan = tb.Button(frm_scan, text="Escanear Puertos", bootstyle="danger", command=self._on_port_scan)
        btn_scan.pack(side='left', padx=8)

        sub_net = ttk.Frame(tab_red)
        sub_net.pack(fill='x', padx=8, pady=6)
        btn_getgw = tb.Button(sub_net, text="Mostrar Gateway & DNS", bootstyle="secondary", command=self._on_get_gateway_dns)
        btn_getgw.pack(side='left', padx=6)
        btn_dnsres = tb.Button(sub_net, text="Resolver DNS", bootstyle="secondary", command=self._on_resolve_dns)
        btn_dnsres.pack(side='left', padx=6)
        btn_wifi = tb.Button(sub_net, text="Escanear WiFi (opcional)", bootstyle="secondary", command=self._on_scan_wifi)
        btn_wifi.pack(side='left', padx=6)

        self.text_net = scrolledtext.ScrolledText(tab_red, height=18)
        self.text_net.pack(fill='both', expand=True, padx=8, pady=6)

        # --- Tab IP Profiles --- #
        tab_profiles = ttk.Frame(nb)
        nb.add(tab_profiles, text="Perfiles IP")
        frm_profiles = ttk.Frame(tab_profiles)
        frm_profiles.pack(fill='x', padx=8, pady=8)
        btn_save_profile = tb.Button(frm_profiles, text="Guardar Perfil", bootstyle="info", command=self._on_save_profile)
        btn_save_profile.pack(side='left', padx=6)
        btn_apply_profile = tb.Button(frm_profiles, text="Aplicar Perfil", bootstyle="warning", command=self._on_apply_profile)
        btn_apply_profile.pack(side='left', padx=6)
        btn_list_profiles = tb.Button(frm_profiles, text="Listar Perfiles", bootstyle="secondary", command=self._on_list_profiles)
        btn_list_profiles.pack(side='left', padx=6)
        self.txt_profiles = scrolledtext.ScrolledText(tab_profiles, height=20)
        self.txt_profiles.pack(fill='both', expand=True, padx=8, pady=8)

        # --- Tab Procesos --- #
        tab_proc = ttk.Frame(nb)
        nb.add(tab_proc, text="Procesos")
        frm_proc_top = ttk.Frame(tab_proc)
        frm_proc_top.pack(fill='x', padx=8, pady=8)
        btn_refresh_proc = tb.Button(frm_proc_top, text="Actualizar Procesos", bootstyle="success", command=self._on_refresh_procs)
        btn_refresh_proc.pack(side='left')
        btn_kill_proc = tb.Button(frm_proc_top, text="Terminar Seleccionado", bootstyle="danger", command=self._on_kill_selected)
        btn_kill_proc.pack(side='left', padx=8)
        self.tree_procs = ttk.Treeview(tab_proc, columns=('pid', 'name', 'user', 'cpu', 'mem'), show='headings')
        for col, w in [('pid',70), ('name',400), ('user',150), ('cpu',70), ('mem',70)]:
            self.tree_procs.heading(col, text=col.upper())
            self.tree_procs.column(col, width=w, anchor='w')
        self.tree_procs.pack(fill='both', expand=True, padx=8, pady=8)

        # --- Tab Gráficos --- #
        tab_graph = ttk.Frame(nb)
        nb.add(tab_graph, text="Gráficos y Ping")
        frm_graph_top = ttk.Frame(tab_graph)
        frm_graph_top.pack(fill='x', padx=8, pady=8)
        btn_start_mon = tb.Button(frm_graph_top, text="Iniciar Monitoreo", bootstyle="success", command=self._on_start_monitor)
        btn_start_mon.pack(side='left', padx=4)
        btn_stop_mon = tb.Button(frm_graph_top, text="Detener Monitoreo", bootstyle="danger", command=self._on_stop_monitor)
        btn_stop_mon.pack(side='left', padx=4)
        btn_save_plot = tb.Button(frm_graph_top, text="Guardar Imagen Gráfico", bootstyle="info", command=self._on_save_plot)
        btn_save_plot.pack(side='left', padx=4)

        ttk.Label(frm_graph_top, text="Ping continuo a:").pack(side='left', padx=(10,4))
        self.entry_ping_target = tb.Entry(frm_graph_top, width=18)
        self.entry_ping_target.pack(side='left', padx=4)
        self.entry_ping_target.insert(0, "8.8.8.8")
        btn_start_ping = tb.Button(frm_graph_top, text="Iniciar Ping", bootstyle="primary", command=self._on_start_ping)
        btn_start_ping.pack(side='left', padx=4)
        btn_stop_ping = tb.Button(frm_graph_top, text="Detener Ping", bootstyle="danger", command=self._on_stop_ping)
        btn_stop_ping.pack(side='left', padx=4)

        self.frm_plot = ttk.Frame(tab_graph)
        self.frm_plot.pack(fill='both', expand=True, padx=8, pady=8)

        # --- Tab Logs / Reportes --- #
        tab_logs = ttk.Frame(nb)
        nb.add(tab_logs, text="Logs & Reportes")
        frm_logs = ttk.Frame(tab_logs)
        frm_logs.pack(fill='x', padx=8, pady=8)
        btn_export_report = tb.Button(frm_logs, text="Exportar Reporte Sistema (CSV)", bootstyle="info", command=self._on_export_csv)
        btn_export_report.pack(side='left', padx=6)
        btn_export_report_pdf = tb.Button(frm_logs, text="Generar PDF con gráficas", bootstyle="secondary", command=self._on_export_pdf)
        btn_export_report_pdf.pack(side='left', padx=6)
        btn_send_email = tb.Button(frm_logs, text="Enviar por correo (Adjuntar PDF)", bootstyle="warning", command=self._on_send_email)
        btn_send_email.pack(side='left', padx=6)

        ttk.Label(frm_logs, text="Autosave logs (min):").pack(side='left', padx=(10,4))
        self.entry_autosave_min = tb.Entry(frm_logs, width=5)
        self.entry_autosave_min.pack(side='left', padx=4)
        self.entry_autosave_min.insert(0, "5")
        btn_start_autosave = tb.Button(frm_logs, text="Iniciar Autosave", bootstyle="success", command=self._on_start_autosave)
        btn_start_autosave.pack(side='left', padx=4)
        btn_stop_autosave = tb.Button(frm_logs, text="Detener Autosave", bootstyle="danger", command=self._on_stop_autosave)
        btn_stop_autosave.pack(side='left', padx=4)

        self.text_logs = scrolledtext.ScrolledText(tab_logs, height=25)
        self.text_logs.pack(fill='both', expand=True, padx=8, pady=8)

        # Log inicial
        self.log(f"Aplicación lista. Directorio: {app_dir()}")

    # ------------------ Sistema callbacks ------------------ #
    def _on_refresh_info(self):
        info = get_system_info()
        self.text_info.delete('1.0', tk.END)
        for k, v in info.items():
            self.text_info.insert(tk.END, f"{k}: {v}\n")
        self.log("Información del sistema actualizada.")

    def _on_export_csv(self):
        info = get_system_info()
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')])
        if not path:
            return
        try:
            export_info_csv(info, path)
            messagebox.showinfo("Exportar CSV", f"Exportado: {path}")
            self.log(f"Exportado CSV: {path}")
        except Exception as e:
            messagebox.showerror("Error exportar CSV", str(e))
            self.log(f"Error exportar CSV: {e}")

    def _on_export_pdf(self):
        if not REPORTLAB_AVAILABLE:
            messagebox.showwarning("PDF no disponible", "reportlab no está instalado. Instale con: pip install reportlab")
            return
        info = get_system_info()
        path = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF', '*.pdf')])
        if not path:
            return
        try:
            export_info_pdf_with_plot(info, self.fig, path)
            messagebox.showinfo("Exportar PDF", f"Exportado: {path}")
            self.log(f"Exportado PDF: {path}")
        except Exception as e:
            messagebox.showerror("Error exportar PDF", str(e))
            self.log(f"Error exportar PDF: {e}")

    def _on_gpu_info(self):
        if not GPU_AVAILABLE:
            messagebox.showinfo("GPU", "GPUtil no está instalado (pip install gputil) o no se detectó GPU.")
            return
        try:
            gpus = GPUtil.getGPUs()
            s = "\n".join([f"{g.name} - load {g.load*100:.1f}% mem {g.memoryUsed}/{g.memoryTotal}MB" for g in gpus])
            messagebox.showinfo("GPU", s or "No se detectaron GPUs.")
            self.log("Info GPU consultada.")
        except Exception as e:
            messagebox.showerror("Error GPU", str(e))

    def _on_list_installed(self):
        system = platform.system().lower()
        try:
            if 'windows' in system:
                # wmic puede no estar presente en Windows más recientes (pero lo intentamos)
                try:
                    out = subprocess.check_output(['wmic','product','get','name,version'], text=True, errors='ignore', timeout=20)
                    messagebox.showinfo("Programas instalados", "Listado obtenido. Se volcará al área de texto.")
                    self.text_info.delete('1.0', tk.END)
                    self.text_info.insert(tk.END, out)
                    self.log("Listado programas instalado (wmic).")
                except Exception:
                    messagebox.showwarning("WMIC", "wmic no pudo listar programas o no está disponible en este sistema.")
            else:
                messagebox.showinfo("Programas instalados", "Listado programas solo implementado como intento en Windows (wmic).")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ------------------ Red callbacks ------------------ #
    def _on_ping(self):
        host = self.entry_host.get().strip()
        if not host:
            messagebox.showwarning("Host requerido", "Ingrese un host o IP para hacer ping.")
            return
        self.text_net.insert(tk.END, f"\n[{now_str()}] Ping a {host}...\n")
        self.text_net.see(tk.END)
        ping_host(host, 4, callback=self._append_net_text)

    def _on_traceroute(self):
        host = self.entry_host.get().strip()
        if not host:
            messagebox.showwarning("Host requerido", "Ingrese un host o IP para traceroute.")
            return
        self.text_net.insert(tk.END, f"\n[{now_str()}] Traceroute a {host}...\n")
        self.text_net.see(tk.END)
        traceroute_host(host, callback=self._append_net_text)

    def _on_speedtest(self):
        self.text_net.insert(tk.END, f"\n[{now_str()}] Ejecutando speedtest...\n")
        self.text_net.see(tk.END)
        run_speedtest(callback=self._append_net_text)

    def _on_port_scan(self):
        host = self.entry_host.get().strip()
        try:
            start = int(self.entry_port_start.get())
            end = int(self.entry_port_end.get())
            timeout = float(self.entry_port_timeout.get())
        except Exception:
            messagebox.showwarning("Valores inválidos", "Verifique puertos/timeout.")
            return
        if start < 1 or end < start:
            messagebox.showwarning("Rango inválido", "Rango de puertos inválido.")
            return
        self.text_net.insert(tk.END, f"\n[{now_str()}] Escaneando puertos {start}-{end} en {host}...\n")
        self.text_net.see(tk.END)
        port_scan(host, start, end, timeout, callback=self._append_net_text)

    def _on_get_gateway_dns(self):
        gw, dns = get_default_gateway_and_dns()
        self.text_net.insert(tk.END, f"[{now_str()}] Gateway: {gw} | DNS: {dns}\n")
        self.text_net.see(tk.END)
        self.log("Gateway & DNS consultados.")

    def _on_resolve_dns(self):
        name = simpledialog.askstring("Resolver DNS", "Ingrese nombre a resolver:", parent=self.root)
        if not name:
            return
        res = resolve_dns(name)
        self.text_net.insert(tk.END, f"[{now_str()}] Resolución {name}: {res}\n")
        self.text_net.see(tk.END)
        self.log(f"DNS: {name} resuelto.")

    def _on_public_ip(self):
        ip = get_public_ip()
        self.text_net.insert(tk.END, f"[{now_str()}] IP pública: {ip}\n")
        self.text_net.see(tk.END)
        self.log("IP pública consultada.")

    def _on_scan_wifi(self):
        self.text_net.insert(tk.END, f"[{now_str()}] Escaneando WiFi (esto puede tardar)...\n")
        self.text_net.see(tk.END)
        def cb():
            res = scan_wifi_once(timeout=5)
            self.root.after(0, lambda: self._append_net_text(str(res)))
        threading.Thread(target=cb, daemon=True).start()

    def _append_net_text(self, text):
        self.root.after(0, lambda: self._append_net_text_ui(text))

    def _append_net_text_ui(self, text):
        self.text_net.insert(tk.END, text + "\n")
        self.text_net.see(tk.END)
        # also log
        self.log("Red: " + (text.splitlines()[0] if text else "resultado"))

    # ------------------ IP Profiles callbacks ------------------ #
    def _on_save_profile(self):
        name = simpledialog.askstring("Guardar Perfil", "Nombre del perfil:", parent=self.root)
        if not name:
            return
        iface = simpledialog.askstring("Interfaz", "Nombre de interfaz (ej: Ethernet, eth0 o nombre en nmcli):", parent=self.root)
        ip = simpledialog.askstring("IP", "Dirección IP (ej: 192.168.1.100):", parent=self.root)
        mask = simpledialog.askstring("Máscara", "Máscara (ej: 24 o 255.255.255.0):", parent=self.root)
        gateway = simpledialog.askstring("Gateway", "Puerta de enlace (ej: 192.168.1.1):", parent=self.root)
        dns = simpledialog.askstring("DNS", "DNS separados por comas (ej: 8.8.8.8,8.8.4.4):", parent=self.root)
        if not (name and iface and ip and mask and gateway):
            messagebox.showwarning("Faltan datos", "Faltan datos requeridos para el perfil.")
            return
        dns_list = [d.strip() for d in (dns or "").split(',') if d.strip()]
        save_ip_profile(name, iface, ip, mask, gateway, dns_list)
        messagebox.showinfo("Perfil guardado", f"Perfil '{name}' guardado.")
        self.log(f"Perfil guardado: {name}")

    def _on_apply_profile(self):
        profiles = load_profiles()
        if not profiles:
            messagebox.showinfo("Perfiles", "No hay perfiles guardados.")
            return
        name = simpledialog.askstring("Aplicar Perfil", "Nombre del perfil a aplicar:", parent=self.root)
        if not name:
            return
        ok, msg = apply_ip_profile(name)
        if ok:
            messagebox.showinfo("Aplicar Perfil", msg)
            self.log(f"Perfil aplicado: {name}")
        else:
            messagebox.showerror("Error aplicar perfil", msg)
            self.log(f"Error aplicar perfil: {msg}")

    def _on_list_profiles(self):
        profiles = load_profiles()
        self.txt_profiles.delete('1.0', tk.END)
        if not profiles:
            self.txt_profiles.insert(tk.END, "No hay perfiles guardados.")
            return
        for k, v in profiles.items():
            self.txt_profiles.insert(tk.END, f"{k}: {v}\n")

    # ------------------ Procesos callbacks ------------------ #
    def _on_refresh_procs(self):
        self.tree_procs.delete(*self.tree_procs.get_children())
        procs = list_processes()
        for p in procs:
            self.tree_procs.insert('', tk.END, values=(p['pid'], p['name'], p.get('user',''), p['cpu'], p['mem']))
        self.log("Procesos actualizados.")

    def _on_kill_selected(self):
        sel = self.tree_procs.selection()
        if not sel:
            messagebox.showinfo("Seleccionar", "Seleccione un proceso en la lista.")
            return
        pid = int(self.tree_procs.item(sel[0])['values'][0])
        resp = messagebox.askyesno("Confirmar", f"Terminar proceso PID {pid}?")
        if not resp:
            return
        ok, msg = kill_process(pid)
        if ok:
            messagebox.showinfo("Terminar proceso", msg)
        else:
            messagebox.showerror("Error", msg)
        self._on_refresh_procs()
        self.log(f"Intento terminar PID {pid}: {msg}")

    # ------------------ Graphs ------------------ #
    def _setup_graph(self):
        self.fig = Figure(figsize=(10,6), dpi=100)
        # I'll use 4 subplots: cpu, ram, net, ping
        self.ax_cpu = self.fig.add_subplot(411)
        self.ax_ram = self.fig.add_subplot(412)
        self.ax_net = self.fig.add_subplot(413)
        self.ax_ping = self.fig.add_subplot(414)
        self.fig.tight_layout(pad=2.0)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.frm_plot)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill='both', expand=True)

    def _redraw_graph(self):
        with self.monitor.lock:
            cpu = list(self.monitor.cpu)
            ram = list(self.monitor.ram)
            net_recv = list(self.monitor.net_recv)
            net_sent = list(self.monitor.net_sent)
            ping = list(self.monitor.ping_lat)
        x = list(range(-len(cpu)+1, 1)) if cpu else []
        self.ax_cpu.clear()
        self.ax_ram.clear()
        self.ax_net.clear()
        self.ax_ping.clear()
        if cpu:
            self.ax_cpu.plot(x, cpu)
            self.ax_cpu.set_ylabel("CPU %")
            self.ax_cpu.set_ylim(0, 100)
        if ram:
            self.ax_ram.plot(x, ram)
            self.ax_ram.set_ylabel("RAM %")
            self.ax_ram.set_ylim(0, 100)
        if net_recv:
            self.ax_net.plot(x, net_recv, label='recv KB/s')
            self.ax_net.plot(x, net_sent, label='sent KB/s')
            self.ax_net.set_ylabel("KB/s")
            self.ax_net.legend(loc='upper right', fontsize='small')
        if ping:
            # convert None/nan to masked values
            try:
                import numpy as np
                y = [v if v is not None and (not isinstance(v, float) or not (v != v)) else float('nan') for v in ping]
            except Exception:
                y = ping
            self.ax_ping.plot(list(range(-len(y)+1,1)), y)
            self.ax_ping.set_ylabel("Ping ms")
        self.canvas.draw_idle()

    def _on_start_monitor(self):
        self.monitor.start()
        if not self._monitor_update_job:
            self._monitor_update()
        self.log("Monitoreo iniciado.")

    def _on_stop_monitor(self):
        self.monitor.stop()
        if self._monitor_update_job:
            self.root.after_cancel(self._monitor_update_job)
            self._monitor_update_job = None
        self.log("Monitoreo detenido.")

    def _monitor_update(self):
        self._redraw_graph()
        self._monitor_update_job = self.root.after(1000, self._monitor_update)

    def _on_save_plot(self):
        path = filedialog.asksaveasfilename(defaultextension='.png', filetypes=[('PNG', '*.png')])
        if not path:
            return
        try:
            self.fig.savefig(path)
            messagebox.showinfo("Guardar gráfico", f"Guardado: {path}")
            self.log(f"Gráfico guardado: {path}")
        except Exception as e:
            messagebox.showerror("Error guardar gráfico", str(e))
            self.log(f"Error guardar gráfico: {e}")

    def _on_start_ping(self):
        target = self.entry_ping_target.get().strip()
        if not target:
            messagebox.showwarning("Ping", "Ingrese host para ping continuo.")
            return
        self.monitor.start_continuous_ping(target)
        self.log(f"Ping continuo iniciado a {target}.")

    def _on_stop_ping(self):
        self.monitor.stop_continuous_ping()
        self.log("Ping continuo detenido.")

    # ------------------ Autosave ------------------ #
    def _on_start_autosave(self):
        try:
            m = int(self.entry_autosave_min.get())
        except Exception:
            messagebox.showwarning("Valor inválido", "Intervalo inválido.")
            return
        self.autologger.interval = max(1, m)
        self.autologger.start(self.monitor)
        self.log(f"Autosave iniciado cada {m} minutos. Archivo: {self.autologger.path}")

    def _on_stop_autosave(self):
        self.autologger.stop()
        self.log("Autosave detenido.")

    # ------------------ Email / Reports ------------------ #
    def _on_send_email(self):
        if not REPORTLAB_AVAILABLE:
            messagebox.showwarning("PDF", "reportlab no está instalado; no es posible generar PDF para adjuntar.")
            return
        # ask to generate PDF first
        path = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF', '*.pdf')], title="Guardar PDF antes de enviar")
        if not path:
            return
        info = get_system_info()
        try:
            export_info_pdf_with_plot(info, self.fig, path)
        except Exception as e:
            messagebox.showerror("Error generar PDF", str(e))
            return
        # ask smtp details
        smtp_host = simpledialog.askstring("SMTP", "Servidor SMTP (ej: smtp.gmail.com):", parent=self.root)
        smtp_port = simpledialog.askstring("SMTP", "Puerto SMTP (ej: 587):", parent=self.root)
        username = simpledialog.askstring("SMTP", "Usuario SMTP:", parent=self.root)
        password = simpledialog.askstring("SMTP", "Contraseña SMTP:", parent=self.root, show='*')
        sender = simpledialog.askstring("From", "Dirección remitente:", parent=self.root)
        recipient = simpledialog.askstring("To", "Dirección destinatario:", parent=self.root)
        subject = f"Reporte Soporte - {now_str()}"
        body = "Adjunto reporte generado con herramienta SoporteExtendido."
        if not all([smtp_host, smtp_port, username, password, sender, recipient]):
            messagebox.showwarning("Faltan datos", "Faltan datos SMTP o direcciones.")
            return
        ok, msg = send_email_with_attachment(smtp_host, smtp_port, username, password, sender, recipient, subject, body, path)
        if ok:
            messagebox.showinfo("Email", "Correo enviado correctamente.")
            self.log("Correo enviado con adjunto.")
        else:
            messagebox.showerror("Email error", msg)
            self.log(f"Error enviar correo: {msg}")

    # ------------------ Logs ------------------ #
    def log(self, msg):
        line = f"[{now_str()}] {msg}\n"
        self.text_logs.insert(tk.END, line)
        self.text_logs.see(tk.END)

    # ------------------ Cleanup ------------------ #
    def on_close(self):
        try:
            self.monitor.stop()
            self.autologger.stop()
        except Exception:
            pass
        self.root.destroy()

# ---------------------- Ejecutar ---------------------- #

def main():
    app = tb.Window(themename="darkly")
    root = app
    soporte = SoporteApp(root)
    root.protocol("WM_DELETE_WINDOW", soporte.on_close)
    root.mainloop()

if __name__ == "__main__":
    main()
