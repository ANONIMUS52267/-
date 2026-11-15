import os, sys, time, hashlib, json, pathlib, threading, shutil, winreg
import subprocess, string, ctypes, traceback, csv, zipfile, tarfile, math, random, base64, re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import customtkinter as ctk
from tkinter import messagebox, filedialog, simpledialog
from PIL import Image, ImageDraw, ImageTk

try: import requests
except: requests = None
try: from watchdog.observers import Observer; from watchdog.events import FileSystemEventHandler
except: Observer = None
try: import psutil
except: psutil = None
try: import pystray; from pystray import MenuItem as item
except: pystray = None
try: from plyer import notification
except: notification = None
try: import yara
except: yara = None
try: import pefile
except: pefile = None
try: from reportlab.pdfgen import canvas; from reportlab.lib.pagesizes import A4
except: canvas = None

# ---------- НАСТРОЙКИ ----------
CONFIG_FILE = "av_config.json"
QUARANTINE_DIR = pathlib.Path("quarantine"); QUARANTINE_DIR.mkdir(exist_ok=True)
LOG_FILE = "av_log.txt"; REPORT_JSON = "av_report.json"
HISTORY_FILE = "av_history.json"; STATS_FILE = "av_stats.json"

def load_json(f, default):
    if os.path.exists(f):
        try:
            with open(f, "r", encoding="utf-8") as fh: return json.load(fh)
        except: pass
    return default
def save_json(f, data):
    try:
        with open(f, "w", encoding="utf-8") as fh: json.dump(data, fh, ensure_ascii=False, indent=2)
    except: pass

def load_config():
    default = {
        "scan_paths": [str(pathlib.Path(os.environ.get("USERPROFILE","C:\\Users"))/"Downloads"),
                       str(pathlib.Path(os.environ.get("USERPROFILE","C:\\Users"))/"Desktop"),
                       str(os.environ.get("TEMP","C:\\Temp"))],
        "virustotal_api_key": "", "realtime": True, "quarantine": True,
        "theme": "dark", "notifications": True, "tray": True, "patrol": True,
        "sound": True, "paranoia": False, "password": "",
        "schedule": "", "schedule_time": "03:00", "auto_email": False,
        "smtp_server": "", "smtp_port": "465", "smtp_user": "",
        "smtp_pass": "", "smtp_to": "", "tg_token": "", "tg_chat": "",
    }
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE,"r",encoding="utf-8") as f:
            return {**default, **json.load(f)}
    return default
CONFIG = load_config()
def save_config(): save_json(CONFIG_FILE, CONFIG)

MALWARE_HASHES = {"44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File"}
SUSPICIOUS_EXT = {".exe",".scr",".bat",".cmd",".vbs",".js",".ps1",".hta",".jar",".msi",".dll"}
HEURISTIC = ["shutdown /s","reg add","powershell -enc","bitsadmin","certutil -decode",
             "mshta","wscript.shell","createobject","eval(","base64_decode","keylog","ransom"]
YARA_RULES = """
rule Suspicious_PS { strings: $a="powershell -enc" nocase $b="FromBase64String" nocase condition: any of them }
rule Ransomware { strings: $a="your files have been encrypted" nocase $b="bitcoin" nocase condition: 2 of them }
"""

STATS = load_json(STATS_FILE, {"scans":0,"files":0,"threats":0,"quarantined":0,"xp":0,"level":1,"achievements":[]})
HISTORY = load_json(HISTORY_FILE, [])

def log(msg):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    try:
        with open(LOG_FILE,"a",encoding="utf-8") as f: f.write(line+"\n")
    except: pass

def file_hash(path, algo="md5"):
    try:
        h = hashlib.new(algo)
        with open(path,"rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
        return h.hexdigest()
    except: return None

def beep(kind):
    if not CONFIG.get("sound",True): return
    try:
        code = {"threat":0x10,"scan":0x40,"done":0x30,"level":0x50}.get(kind,0x40)
        ctypes.windll.user32.MessageBeep(code)
    except: pass

def add_xp(amount):
    STATS["xp"] += amount
    new_level = 1 + STATS["xp"] // 100
    if new_level > STATS["level"]:
        STATS["level"] = new_level; beep("level")
        if notification:
            try: notification.notify(title="Уровень!", message=f"Уровень {new_level}", timeout=5)
            except: pass
    save_json(STATS_FILE, STATS)

def unlock_achievement(name):
    if name in STATS.get("achievements", []): return
    STATS.setdefault("achievements", []).append(name)
    save_json(STATS_FILE, STATS)
    if notification:
        try: notification.notify(title="Достижение!", message=name, timeout=5)
        except: pass

def load_ignore():
    f = "av_ignore.txt"
    if os.path.exists(f):
        with open(f,"r",encoding="utf-8") as fh: return [l.strip() for l in fh if l.strip()]
    return []
def save_ignore(lst):
    with open("av_ignore.txt","w",encoding="utf-8") as f: f.write("\n".join(lst))
IGNORE = load_ignore()

def is_ignored(path):
    p = str(path).lower()
    return any(ig.lower() in p for ig in IGNORE)

def check_signature(path):
    if pefile is None: return None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
            return True
        return False
    except: return None

# ---------- ЗАГРУЗКА ----------
class BootScreen(ctk.CTkToplevel):
    def __init__(self, master, on_done):
        super().__init__(master)
        self.attributes("-fullscreen", True)
        self.attributes("-topmost", True)
        self.configure(fg_color="#000000")
        self.on_done = on_done
        self.canvas = ctk.CTkCanvas(self, bg="#000000", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.particles = []
        self.text_items = []
        self.after(100, self.init_particles)
        self.after(800, self.draw_logo)
        self.after(1500, self.draw_text)
        self.after(2500, self.draw_progress)
        self.after(6000, self.finish)

    def init_particles(self):
        w = self.winfo_screenwidth()
        h = self.winfo_screenheight()
        for _ in range(60):
            x = random.randint(0, w)
            y = random.randint(0, h)
            r = random.randint(1, 3)
            speed = random.uniform(0.1, 0.4)
            p = self.canvas.create_oval(x-r, y-r, x+r, y+r,
                                         fill=random.choice(["#1a3a6a", "#0a2a5a", "#1a4a8a"]),
                                         outline="")
            self.particles.append({"id": p, "speed": speed, "x": x, "y": y})
        self.animate_particles()

    def animate_particles(self):
        if not self.winfo_exists(): return
        h = self.winfo_screenheight()
        for p in self.particles:
            p["y"] += p["speed"]
            if p["y"] > h:
                p["y"] = -5
                p["x"] = random.randint(0, self.winfo_screenwidth())
            self.canvas.coords(p["id"], p["x"]-2, p["y"]-2, p["x"]+2, p["y"]+2)
        self.after(50, self.animate_particles)

    def draw_logo(self):
        if not self.winfo_exists(): return
        w = self.winfo_screenwidth()
        h = self.winfo_screenheight()
        cx = w // 2
        cy = h // 2 - 120
        size = 48
        gap = 8
        positions = [(-size-gap//2, -size-gap//2), (gap//2, -size-gap//2),
                     (-size-gap//2, gap//2), (gap//2, gap//2)]
        for i, (x, y) in enumerate(positions):
            r = self.canvas.create_rectangle(
                cx + x, cy + y, cx + x + size, cy + y + size,
                fill="#0078d4", outline=""
            )
            self.canvas.itemconfig(r, state="hidden")
            self.after(i * 120, lambda r=r: self.canvas.itemconfig(r, state="normal"))

    def draw_text(self):
        if not self.winfo_exists(): return
        w = self.winfo_screenwidth()
        h = self.winfo_screenheight()
        cx = w // 2
        cy = h // 2 - 120
        t1 = self.canvas.create_text(cx, cy + 100, text="SUPER ANTIVIRUS",
                                     fill="#ffffff", font=("Segoe UI", 28, "bold"))
        t2 = self.canvas.create_text(cx, cy + 145, text="Защита вашего компьютера от вирусов и угроз",
                                     fill="#888888", font=("Segoe UI", 13))
        t3 = self.canvas.create_text(cx, cy + 180, text="Загрузка базы сигнатур...",
                                     fill="#6a8aaa", font=("Segoe UI", 11))
        self.text_items = [t1, t2, t3]
        self.fade_in_text(0)

    def fade_in_text(self, step):
        if not self.winfo_exists(): return
        if step > 10: return
        color = f"#{min(255, step*25):02x}{min(255, step*25):02x}{min(255, step*25):02x}"
        for t in self.text_items:
            try: self.canvas.itemconfig(t, fill=color)
            except: pass
        self.after(50, lambda: self.fade_in_text(step+1))

    def draw_progress(self):
        if not self.winfo_exists(): return
        w = self.winfo_screenwidth()
        h = self.winfo_screenheight()
        cx = w // 2
        cy = h // 2 - 120
        bar_w = 300
        bar_x = cx - bar_w // 2
        bar_y = cy + 210
        self.canvas.create_rectangle(bar_x, bar_y, bar_x + bar_w, bar_y + 6,
                                     fill="#1a1a2a", outline="")
        self.progress = self.canvas.create_rectangle(bar_x, bar_y, bar_x, bar_y + 6,
                                                     fill="#0078d4", outline="")
        self.bar_x = bar_x
        self.bar_w = bar_w
        self.bar_y = bar_y
        self.animate_progress(0)

    def animate_progress(self, step):
        if not self.winfo_exists(): return
        if step > 100: return
        x2 = self.bar_x + self.bar_w * step / 100
        self.canvas.coords(self.progress, self.bar_x, self.bar_y, x2, self.bar_y + 6)
        self.after(25, lambda: self.animate_progress(step + 1))

    def finish(self):
        if not self.winfo_exists(): return
        self.destroy()
        self.on_done()

# ---------- СКАНЕР ----------
class Scanner:
    def __init__(self, gui=None):
        self.gui = gui; self.stop_flag = False; self.found = []
        self.vt_key = CONFIG.get("virustotal_api_key","")
        self.yara_rules = None
        if yara:
            try: self.yara_rules = yara.compile(source=YARA_RULES)
            except: pass

    def status(self, m):
        if self.gui: self.gui.update_status(m)
        log(m)

    def check_pe_heuristics(self, path):
        if pefile is None: return None
        try:
            pe = pefile.PE(str(path), fast_load=True)
            suspicious = []
            if hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER.AddressOfEntryPoint > 0x10000000:
                suspicious.append("необычная точка входа")
            if pe.sections:
                for s in pe.sections:
                    name = s.Name.decode(errors="ignore").strip("\x00")
                    if name in ("UPX0", "UPX1", ".aspack", ".adata"):
                        suspicious.append(f"упаковщик: {name}")
            return suspicious
        except: return None

    def check_url(self, url):
        if not requests: return False
        try:
            r = requests.post("https://urlhaus-api.abuse.ch/v1/url/",
                              data={"url": url}, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "is_listed":
                    return True
        except: pass
        return False

    def block_ip(self, ip):
        hosts = pathlib.Path(os.environ.get("SystemRoot","C:\\Windows"))/"System32"/"drivers"/"etc"/"hosts"
        try:
            with open(hosts, "a", encoding="utf-8") as f:
                f.write(f"\n127.0.0.1 {ip}\n")
            log(f"[БЛОКИРОВКА] {ip}")
            return True
        except: return False

    def scan_file(self, p):
        if self.stop_flag: return
        if is_ignored(p): return
        try: size = p.stat().st_size
        except: return
        if size == 0: return
        md5 = file_hash(p,"md5"); sha = file_hash(p,"sha256")
        if md5 in MALWARE_HASHES:
            self.found.append({"path":str(p),"reason":f"Вирус: {MALWARE_HASHES[md5]}","hash":md5})
            self.status(f"[!] {p}"); beep("threat"); return
        if self.vt_key and sha and requests:
            try:
                r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha}",
                                 headers={"x-apikey":self.vt_key}, timeout=5)
                if r.status_code==200:
                    pos = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0)
                    if pos>0:
                        self.found.append({"path":str(p),"reason":f"VT: {pos}","hash":sha})
                        self.status(f"[!] VT {p}"); beep("threat"); return
            except: pass
        if self.yara_rules:
            try:
                m = self.yara_rules.match(str(p))
                if m:
                    self.found.append({"path":str(p),"reason":f"YARA: {m[0].rule}","hash":md5})
                    self.status(f"[!] YARA {p}"); beep("threat"); return
            except: pass
        sig = check_signature(p)
        if sig is False and p.suffix.lower() in {".exe",".dll"} and size > 1024*1024:
            self.found.append({"path":str(p),"reason":"PE без подписи","hash":md5})
            self.status(f"[?] {p}"); return
        pe_issues = self.check_pe_heuristics(p)
        if pe_issues:
            self.found.append({"path":str(p),"reason":f"PE: {', '.join(pe_issues)}","hash":md5})
            self.status(f"[?] PE {p}"); return
        if p.suffix.lower() in SUSPICIOUS_EXT and size < 10*1024*1024:
            try:
                with open(p,"rb") as f: c = f.read(8192).lower()
                for kw in HEURISTIC:
                    if kw.encode() in c:
                        self.found.append({"path":str(p),"reason":f"Эвристика: {kw}","hash":md5})
                        self.status(f"[?] {p}"); return
                if b"http" in c and len(c) < 5000:
                    urls = re.findall(rb'https?://[^\s"\']+', c)
                    for u in urls[:3]:
                        if self.check_url(u.decode(errors="ignore")):
                            self.found.append({"path":str(p),"reason":f"URLhaus: {u.decode(errors='ignore')}","hash":md5})
                            self.status(f"[!] URL {p}"); return
            except: pass

    def scan_archive(self, p):
        try:
            if p.suffix.lower()==".zip":
                with zipfile.ZipFile(p,"r") as z:
                    for n in z.namelist():
                        if n.endswith("/"): continue
                        tmp = pathlib.Path(os.environ.get("TEMP","C:\\Temp"))/f"av_tmp_{int(time.time())}_{n.split('/')[-1]}"
                        tmp.write_bytes(z.read(n)); self.scan_file(tmp); tmp.unlink(missing_ok=True)
            elif p.suffix.lower() in (".tar",".gz",".tgz"):
                with tarfile.open(p,"r:*") as t:
                    for m in t.getmembers():
                        if m.isfile():
                            f = t.extractfile(m)
                            if f:
                                tmp = pathlib.Path(os.environ.get("TEMP","C:\\Temp"))/f"av_tmp_{int(time.time())}_{m.name.split('/')[-1]}"
                                tmp.write_bytes(f.read()); self.scan_file(tmp); tmp.unlink(missing_ok=True)
        except: pass

    def scan_paths(self, paths):
        self.found = []; self.stop_flag = False; total = 0
        for base in paths:
            bp = pathlib.Path(base)
            if not bp.exists(): continue
            self.status(f"Сканирование: {base}")
            for root,_,files in os.walk(bp):
                if self.stop_flag: break
                for name in files:
                    if is_ignored(pathlib.Path(root)/name): continue
                    total += 1
                    p = pathlib.Path(root)/name
                    if p.suffix.lower() in (".zip",".tar",".gz",".tgz"): self.scan_archive(p)
                    else: self.scan_file(p)
        self.status(f"Готово. Проверено: {total}, найдено: {len(self.found)}")
        beep("done"); add_xp(total)
        if total >= 100: unlock_achievement("Сотня файлов")
        if total >= 1000: unlock_achievement("Тысяча файлов")
        if len(self.found) > 0: unlock_achievement("Первая угроза")
        if len(self.found) >= 10: unlock_achievement("Десяток угроз")
        return self.found

    def scan_autorun(self):
        res = []
        keys = [(winreg.HKEY_CURRENT_USER,r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE,r"Software\Microsoft\Windows\CurrentVersion\Run")]
        for hive,path in keys:
            try:
                k = winreg.OpenKey(hive,path); i = 0
                while True:
                    try:
                        n,v,_ = winreg.EnumValue(k,i); res.append({"name":n,"value":v}); i+=1
                    except OSError: break
                winreg.CloseKey(k)
            except: pass
        return res

    def scan_processes(self):
        res = []
        if psutil:
            for proc in psutil.process_iter(['name','pid','exe']):
                try: res.append({"name":proc.info['name'],"pid":proc.info['pid'],"exe":proc.info['exe']})
                except: pass
        return res

    def scan_usb(self):
        res = []; bm = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bm & 1:
                d = f"{letter}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(d)==2:
                    res.append({"drive":d})
                    a = os.path.join(d,"autorun.inf")
                    if os.path.exists(a): res[-1]["autorun"] = a
            bm >>= 1
        return res

    def scan_network(self):
        res = []
        if psutil:
            for conn in psutil.net_connections(kind="inet"):
                try:
                    res.append({"local":f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                                "remote":f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                                "status":conn.status,"pid":conn.pid})
                except: pass
        return res

    def scan_hosts(self):
        res = []
        p = pathlib.Path(os.environ.get("SystemRoot","C:\\Windows"))/"System32"/"drivers"/"etc"/"hosts"
        if p.exists():
            try:
                for line in p.read_text(encoding="utf-8",errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"): res.append(line)
            except: pass
        return res

    def scan_firewall(self):
        try:
            out = subprocess.check_output(["netsh","advfirewall","show","allprofiles","state"],
                                          encoding="cp866",errors="ignore")
            return out
        except: return "Не удалось проверить."

    def quarantine(self, path):
        if not CONFIG.get("quarantine",True): return
        try:
            p = pathlib.Path(path); dest = QUARANTINE_DIR/(p.name+".quarantined")
            data = p.read_bytes()
            encrypted = base64.b64encode(data)
            dest.write_bytes(encrypted)
            p.unlink()
            log(f"[КАРАНТИН+ШИФР] {p}")
            STATS["quarantined"] += 1; save_json(STATS_FILE, STATS); unlock_achievement("Первый карантин")
        except Exception as e: log(f"[!] {e}")

    def restore(self, qpath, orig):
        try:
            data = qpath.read_bytes()
            decrypted = base64.b64decode(data)
            orig.write_bytes(decrypted)
            qpath.unlink()
            log(f"[ВОССТАНОВЛЕНИЕ] {qpath}"); return True
        except: return False

# ---------- ПАТРУЛЬ ----------
class Patrol:
    def __init__(self, scanner, gui):
        self.scanner = scanner; self.gui = gui; self.running = False
    def start(self):
        if self.running: return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log("[ПАТРУЛЬ] Запущен")
    def stop(self): self.running = False
    def _loop(self):
        while self.running:
            try:
                for item in self.scanner.scan_autorun():
                    if any(k in item["value"].lower() for k in ["powershell -enc","cmd /c","wscript"]):
                        self.gui.patrol_alert(f"Автозагрузка: {item['name']}")
                for p in self.scanner.scan_processes():
                    if p["name"] and any(k in p["name"].lower() for k in ["keylog","ransom","miner"]):
                        self.gui.patrol_alert(f"Процесс: {p['name']}")
                if CONFIG.get("paranoia", False):
                    self._paranoia_scan()
            except Exception as e: log(f"[ПАТРУЛЬ] {e}")
            time.sleep(10)
    def _paranoia_scan(self):
        for base in CONFIG["scan_paths"]:
            bp = pathlib.Path(base)
            if not bp.exists(): continue
            for root,_,files in os.walk(bp):
                for name in files:
                    p = pathlib.Path(root)/name
                    if p.suffix.lower() in SUSPICIOUS_EXT and not is_ignored(p):
                        self.scanner.scan_file(p)

# ---------- ЗАЩИТА ОТ ШИФРОВАЛЬЩИКОВ ----------
class RansomwareGuard:
    def __init__(self, gui):
        self.gui = gui
        self.running = False
    def start(self):
        if self.running: return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
    def stop(self):
        self.running = False
    def _loop(self):
        while self.running:
            try:
                if psutil:
                    for proc in psutil.process_iter(['name','pid']):
                        try:
                            files = proc.open_files()
                            if len(files) > 100:
                                self.gui.patrol_alert(f"Подозрительная активность: {proc.info['name']} ({len(files)} файлов)")
                                proc.kill()
                        except: pass
            except Exception as e: log(f"[ШИФРОВАЛЬЩИК] {e}")
            time.sleep(5)

# ---------- МОНИТОРИНГ ----------
if Observer:
    class RT(FileSystemEventHandler):
        def __init__(self, scanner, gui): self.scanner = scanner; self.gui = gui
        def on_created(self, event):
            if not event.is_directory:
                self.scanner.scan_file(pathlib.Path(event.src_path))
                if self.scanner.found:
                    self.gui.update_status(f"[!] {event.src_path}")
                    if CONFIG.get("notifications",True) and notification:
                        try: notification.notify(title="Антивирус",message=f"Обнаружен: {event.src_path}",timeout=5)
                        except: pass

# ---------- GUI ----------
class AntivirusGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Super Antivirus")
        self.geometry("1100x800")
        try: self.state("zoomed")
        except: self.attributes("-fullscreen",True)
        self.scanner = Scanner(self); self.observer = None
        self.patrol = Patrol(self.scanner, self); self.tray_icon = None
        self.ransom_guard = RansomwareGuard(self)
        self.dash_particles = []
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        if CONFIG.get("realtime",True): self.start_realtime()
        if CONFIG.get("tray",True): self.tray_icon = self._create_tray()
        self.patrol.start()
        self.ransom_guard.start()
        self.bind("<Control-Shift-S>", lambda e: self.start_scan(quick=True))
        self.after(1000, self._check_schedule)

    def _build_ui(self):
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#0a0a1a")
        self.sidebar.pack(side="left", fill="y"); self.sidebar.pack_propagate(False)
        ctk.CTkLabel(self.sidebar, text="🛡  SUPER\nANTIVIRUS", font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#ffffff", justify="center").pack(pady=(30,20))
        self.level_label = ctk.CTkLabel(self.sidebar, text=f"Уровень {STATS['level']}  |  XP: {STATS['xp']}",
                                         font=ctk.CTkFont(size=11), text_color="#6a8aaa")
        self.level_label.pack(pady=(0,10))
        self.nav_buttons = {}
        for name, icon in [("Дашборд","🏠"),("Сканер","🔍"),("Автозагрузка","🔄"),
                           ("Процессы","📋"),("USB","💾"),("Сеть","🌐"),
                           ("Система","⚙️"),("Карантин","🦠"),("Настройки","⚙"),
                           ("Отчёт","📊"),("Достижения","🏆"),("История","📜")]:
            btn = ctk.CTkButton(self.sidebar, text=f"  {icon}  {name}", anchor="w", height=38,
                                corner_radius=8, fg_color="transparent", hover_color="#1a1a3a",
                                text_color="#a0b0d0", font=ctk.CTkFont(size=13),
                                command=lambda n=name: self.show_tab(n))
            btn.pack(fill="x", padx=8, pady=2); self.nav_buttons[name] = btn
        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color="#0f0f25")
        self.content.pack(side="right", fill="both", expand=True)
        self.top = ctk.CTkFrame(self.content, height=50, corner_radius=0, fg_color="#0f0f25")
        self.top.pack(fill="x"); self.top.pack_propagate(False)
        self.title_label = ctk.CTkLabel(self.top, text="Дашборд", font=ctk.CTkFont(size=18, weight="bold"), text_color="#ffffff")
        self.title_label.pack(side="left", padx=20)
        self.status_label = ctk.CTkLabel(self.top, text="Готов", font=ctk.CTkFont(size=11), text_color="#6a8aaa")
        self.status_label.pack(side="right", padx=20)
        self.pages = {}
        self._build_dashboard(); self._build_scanner(); self._build_autorun()
        self._build_processes(); self._build_usb(); self._build_network()
        self._build_system(); self._build_quarantine(); self._build_settings()
        self._build_report(); self._build_achievements(); self._build_history()
        self.show_tab("Дашборд")

    def _create_tray(self):
        if not pystray: return None
        def show(icon,item): self.deiconify(); self.focus_force()
        def quick(icon,item): self.start_scan(quick=True)
        def quit_(icon,item): icon.stop(); self.on_close()
        img = Image.new("RGB",(64,64),"#1a6fff")
        d = ImageDraw.Draw(img); d.text((20,18),"🛡",fill="#fff")
        icon = pystray.Icon("av",img,"Super Antivirus",
                            pystray.Menu(item("Открыть",show),item("Быстрое сканирование",quick),item("Выход",quit_)))
        threading.Thread(target=icon.run,daemon=True).start(); return icon

    def show_tab(self, name):
        self.title_label.configure(text=name)
        for k,btn in self.nav_buttons.items():
            btn.configure(fg_color="#1a1a3a" if k==name else "transparent")
        for k,page in self.pages.items():
            if k==name: page.pack(fill="both",expand=True)
            else: page.pack_forget()

    def update_status(self, msg):
        self.status_label.configure(text=msg[:80])
        if hasattr(self,"log_box") and self.log_box.winfo_exists():
            self.log_box.insert("end",msg+"\n"); self.log_box.see("end")

    def patrol_alert(self, msg):
        self.update_status(f"[ПАТРУЛЬ] {msg}"); beep("threat")
        if CONFIG.get("notifications",True) and notification:
            try: notification.notify(title="Патруль",message=msg,timeout=5)
            except: pass

    def _check_schedule(self):
        sched = CONFIG.get("schedule","")
        if sched and CONFIG.get("schedule_time","") == datetime.now().strftime("%H:%M"):
            self.start_scan(quick=True)
        self.after(60000, self._check_schedule)

    # ---------- СТРАНИЦЫ ----------
    def _build_dashboard(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25")
        self.pages["Дашборд"] = p
        self.dash_canvas = ctk.CTkCanvas(p, bg="#0f0f25", highlightthickness=0)
        self.dash_canvas.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._init_dash_particles()
        card = ctk.CTkFrame(p, corner_radius=16, fg_color="#151530")
        card.pack(fill="both", expand=True, padx=24, pady=24)
        self.shield_canvas = ctk.CTkCanvas(card, width=120, height=120, bg="#151530", highlightthickness=0)
        self.shield_canvas.pack(pady=(30,0))
        self._draw_shield()
        self.dash_status = ctk.CTkLabel(card, text="Система защищена", font=ctk.CTkFont(size=26, weight="bold"), text_color="#00cc66")
        self.dash_status.pack(pady=8)
        self.dash_info = ctk.CTkLabel(card, text="Пассивный патруль активен", font=ctk.CTkFont(size=12), text_color="#6a8aaa")
        self.dash_info.pack()
        ctk.CTkButton(card, text="▶  Быстрое сканирование", width=260, height=46, corner_radius=10,
                      font=ctk.CTkFont(size=14, weight="bold"), fg_color="#1a6fff", hover_color="#2a7fff",
                      command=lambda: self.start_scan(quick=True)).pack(pady=24)
        self.dash_last = ctk.CTkLabel(card, text="Последнее сканирование: —", font=ctk.CTkFont(size=11), text_color="#6a8aaa")
        self.dash_last.pack(pady=2)
        self.dash_threats = ctk.CTkLabel(card, text="Найдено угроз: 0", font=ctk.CTkFont(size=11), text_color="#6a8aaa")
        self.dash_threats.pack(pady=2)

    def _init_dash_particles(self):
        w = self.winfo_screenwidth()
        h = self.winfo_screenheight()
        for _ in range(50):
            x = random.randint(0, w)
            y = random.randint(0, h)
            r = random.randint(1, 2)
            speed = random.uniform(0.1, 0.5)
            p = self.dash_canvas.create_oval(x-r, y-r, x+r, y+r,
                                              fill=random.choice(["#1a6fff", "#2a7fff", "#0078d4"]),
                                              outline="")
            self.dash_particles.append({"id": p, "speed": speed, "x": x, "y": y})
        self._animate_dash_particles()

    def _animate_dash_particles(self):
        if not self.dash_canvas.winfo_exists(): return
        h = self.winfo_screenheight()
        for p in self.dash_particles:
            p["y"] += p["speed"]
            if p["y"] > h:
                p["y"] = -5
            self.dash_canvas.coords(p["id"], p["x"]-2, p["y"]-2, p["x"]+2, p["y"]+2)
        self.after(50, self._animate_dash_particles)

    def _draw_shield(self):
        c = self.shield_canvas; c.delete("all")
        color = "#00cc66" if not self.scanner.found else "#ff4444"
        c.create_polygon(60,10, 100,30, 100,80, 60,110, 20,80, 20,30, fill=color, outline="#2a7fff", width=2)
        c.create_text(60,60, text="🛡", font=("Segoe UI",28), fill="#ffffff")

    def _build_scanner(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25"); self.pages["Сканер"] = p
        ctk.CTkLabel(p, text="Выберите папки:", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=24, pady=(20,6))
        self.path_vars = []
        for path in CONFIG["scan_paths"]:
            v = ctk.BooleanVar(value=True); self.path_vars.append((path,v))
            ctk.CTkCheckBox(p, text=path, variable=v).pack(anchor="w", padx=24, pady=2)
        btn = ctk.CTkFrame(p, fg_color="transparent"); btn.pack(anchor="w", padx=24, pady=12)
        ctk.CTkButton(btn, text="▶  Сканировать", command=self.start_scan, width=160).pack(side="left", padx=4)
        ctk.CTkButton(btn, text="■  Стоп", command=self.stop_scan, width=100, fg_color="#c42b1c").pack(side="left", padx=4)
        ctk.CTkButton(btn, text="＋  Папка", command=self.add_path, width=120).pack(side="left", padx=4)
        self.progress = ctk.CTkProgressBar(p, height=8, progress_color="#1a6fff"); self.progress.pack(fill="x", padx=24, pady=8); self.progress.set(0)
        self.scan_pct = ctk.CTkLabel(p, text="0%", font=ctk.CTkFont(size=11)); self.scan_pct.pack()
        self.log_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#00ff88", font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box.pack(fill="both", expand=True, padx=24, pady=12)

    def _build_autorun(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25"); self.pages["Автозагрузка"] = p
        self.ar_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#ffffff", font=ctk.CTkFont(family="Consolas", size=12))
        self.ar_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Обновить", command=self.refresh_autorun).pack(pady=8)

    def _build_processes(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25"); self.pages["Процессы"] = p
        self.pr_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#ffffff", font=ctk.CTkFont(family="Consolas", size=12))
        self.pr_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Обновить", command=self.refresh_processes).pack(pady=8)

    def _build_usb(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25"); self.pages["USB"] = p
        self.usb_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#ffffff", font=ctk.CTkFont(family="Consolas", size=12))
        self.usb_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Проверить USB", command=self.refresh_usb).pack(pady=8)

    def _build_network(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25"); self.pages["Сеть"] = p
        self.net_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#ffffff", font=ctk.CTkFont(family="Consolas", size=12))
        self.net_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Обновить", command=self.refresh_network).pack(pady=8)

    def _build_system(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25"); self.pages["Система"] = p
        self.sys_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#ffffff", font=ctk.CTkFont(family="Consolas", size=12))
        self.sys_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Проверить систему", command=self.refresh_system).pack(pady=8)

    def _build_quarantine(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25"); self.pages["Карантин"] = p
        search_frame = ctk.CTkFrame(p, fg_color="transparent"); search_frame.pack(fill="x", padx=24, pady=(20,0))
        self.q_search = ctk.CTkEntry(search_frame, placeholder_text="Поиск по имени...", text_color="#ffffff", fg_color="#1a1a3a")
        self.q_search.pack(side="left", fill="x", expand=True, padx=(0,8))
        ctk.CTkButton(search_frame, text="Найти", command=self.search_quarantine, width=80).pack(side="left")
        self.q_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#ffffff", font=ctk.CTkFont(family="Consolas", size=12))
        self.q_box.pack(fill="both", expand=True, padx=24, pady=12)
        bf = ctk.CTkFrame(p, fg_color="transparent"); bf.pack(pady=8)
        ctk.CTkButton(bf, text="Обновить", command=self.refresh_quarantine).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="Восстановить выбранный", command=self.restore_selected).pack(side="left", padx=4)

    def _build_settings(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25"); self.pages["Настройки"] = p
        scroll = ctk.CTkScrollableFrame(p, fg_color="transparent"); scroll.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkLabel(scroll, text="VirusTotal API Key:", font=ctk.CTkFont(size=13), text_color="#ffffff").pack(anchor="w", pady=(0,6))
        self.vt_entry = ctk.CTkEntry(scroll, width=400, text_color="#ffffff", fg_color="#1a1a3a")
        self.vt_entry.insert(0,CONFIG.get("virustotal_api_key",""))
        self.vt_entry.pack(anchor="w", pady=4)
        ctk.CTkButton(scroll, text="Сохранить ключ", command=self.save_vt).pack(anchor="w", pady=4)
        self.rt_var = ctk.BooleanVar(value=CONFIG.get("realtime",True))
        ctk.CTkSwitch(scroll, text="Мониторинг в реальном времени", variable=self.rt_var, command=self.toggle_rt, text_color="#ffffff").pack(anchor="w", pady=6)
        self.q_var = ctk.BooleanVar(value=CONFIG.get("quarantine",True))
        ctk.CTkSwitch(scroll, text="Карантин", variable=self.q_var, command=lambda: self.save_setting("quarantine",self.q_var.get()), text_color="#ffffff").pack(anchor="w", pady=6)
        self.theme_var = ctk.BooleanVar(value=CONFIG.get("theme","dark")=="light")
        ctk.CTkSwitch(scroll, text="Светлая тема", variable=self.theme_var, command=self.toggle_theme, text_color="#ffffff").pack(anchor="w", pady=6)
        self.notif_var = ctk.BooleanVar(value=CONFIG.get("notifications",True))
        ctk.CTkSwitch(scroll, text="Уведомления", variable=self.notif_var, command=lambda: self.save_setting("notifications",self.notif_var.get()), text_color="#ffffff").pack(anchor="w", pady=6)
        self.patrol_var = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(scroll, text="Пассивный патруль", variable=self.patrol_var, command=self.toggle_patrol, text_color="#ffffff").pack(anchor="w", pady=6)
        self.sound_var = ctk.BooleanVar(value=CONFIG.get("sound",True))
        ctk.CTkSwitch(scroll, text="Звуки", variable=self.sound_var, command=lambda: self.save_setting("sound",self.sound_var.get()), text_color="#ffffff").pack(anchor="w", pady=6)
        self.paranoia_var = ctk.BooleanVar(value=CONFIG.get("paranoia",False))
        ctk.CTkSwitch(scroll, text="Режим паранойи", variable=self.paranoia_var, command=lambda: self.save_setting("paranoia",self.paranoia_var.get()), text_color="#ffffff").pack(anchor="w", pady=6)
        ctk.CTkLabel(scroll, text="Автозапуск при старте Windows:", font=ctk.CTkFont(size=12), text_color="#ffffff").pack(anchor="w", pady=(10,4))
        ctk.CTkButton(scroll, text="Добавить в автозагрузку", command=self.add_to_startup).pack(anchor="w", pady=4)
        ctk.CTkLabel(scroll, text="Пароль на настройки:", font=ctk.CTkFont(size=12), text_color="#ffffff").pack(anchor="w", pady=(10,4))
        self.pwd_entry = ctk.CTkEntry(scroll, placeholder_text="Новый пароль", show="*", width=200, text_color="#ffffff", fg_color="#1a1a3a")
        self.pwd_entry.pack(anchor="w", pady=4)
        ctk.CTkButton(scroll, text="Установить пароль", command=self.set_password).pack(anchor="w", pady=4)
        ctk.CTkLabel(scroll, text="Расписание (ЧЧ:ММ):", font=ctk.CTkFont(size=12), text_color="#ffffff").pack(anchor="w", pady=(10,4))
        self.schedule_entry = ctk.CTkEntry(scroll, placeholder_text="03:00", width=100, text_color="#ffffff", fg_color="#1a1a3a")
        self.schedule_entry.insert(0, CONFIG.get("schedule_time","03:00"))
        self.schedule_entry.pack(anchor="w", pady=4)
        ctk.CTkButton(scroll, text="Сохранить расписание", command=self.save_schedule).pack(anchor="w", pady=4)
        ctk.CTkLabel(scroll, text="Отправка отчёта на почту:", font=ctk.CTkFont(size=13, weight="bold"), text_color="#ffffff").pack(anchor="w", pady=(20,4))
        ctk.CTkLabel(scroll, text="SMTP сервер:", font=ctk.CTkFont(size=11), text_color="#ffffff").pack(anchor="w")
        self.smtp_server_entry = ctk.CTkEntry(scroll, placeholder_text="smtp.gmail.com", width=300, text_color="#ffffff", fg_color="#1a1a3a")
        self.smtp_server_entry.pack(anchor="w", pady=2)
        ctk.CTkLabel(scroll, text="Порт:", font=ctk.CTkFont(size=11), text_color="#ffffff").pack(anchor="w")
        self.smtp_port_entry = ctk.CTkEntry(scroll, placeholder_text="465", width=100, text_color="#ffffff", fg_color="#1a1a3a")
        self.smtp_port_entry.insert(0, CONFIG.get("smtp_port","465"))
        self.smtp_port_entry.pack(anchor="w", pady=2)
        ctk.CTkLabel(scroll, text="Логин (email):", font=ctk.CTkFont(size=11), text_color="#ffffff").pack(anchor="w")
        self.smtp_user_entry = ctk.CTkEntry(scroll, placeholder_text="you@gmail.com", width=300, text_color="#ffffff", fg_color="#1a1a3a")
        self.smtp_user_entry.insert(0, CONFIG.get("smtp_user",""))
        self.smtp_user_entry.pack(anchor="w", pady=2)
        ctk.CTkLabel(scroll, text="Пароль (приложения):", font=ctk.CTkFont(size=11), text_color="#ffffff").pack(anchor="w")
        self.smtp_pass_entry = ctk.CTkEntry(scroll, placeholder_text="пароль", show="*", width=300, text_color="#ffffff", fg_color="#1a1a3a")
        self.smtp_pass_entry.pack(anchor="w", pady=2)
        ctk.CTkLabel(scroll, text="Кому отправить:", font=ctk.CTkFont(size=11), text_color="#ffffff").pack(anchor="w")
        self.smtp_to_entry = ctk.CTkEntry(scroll, placeholder_text="recipient@example.com", width=300, text_color="#ffffff", fg_color="#1a1a3a")
        self.smtp_to_entry.insert(0, CONFIG.get("smtp_to",""))
        self.smtp_to_entry.pack(anchor="w", pady=2)
        ctk.CTkButton(scroll, text="📧 Отправить отчёт", command=self.send_report_email).pack(anchor="w", pady=8)
        self.auto_email_var = ctk.BooleanVar(value=CONFIG.get("auto_email",False))
        ctk.CTkSwitch(scroll, text="Автоотправка после сканирования", variable=self.auto_email_var, command=lambda: self.save_setting("auto_email", self.auto_email_var.get()), text_color="#ffffff").pack(anchor="w", pady=4)
        ctk.CTkLabel(scroll, text="Telegram токен:", font=ctk.CTkFont(size=11), text_color="#ffffff").pack(anchor="w")
        self.tg_token_entry = ctk.CTkEntry(scroll, width=300, text_color="#ffffff", fg_color="#1a1a3a")
        self.tg_token_entry.pack(anchor="w", pady=2)
        ctk.CTkLabel(scroll, text="Telegram chat_id:", font=ctk.CTkFont(size=11), text_color="#ffffff").pack(anchor="w")
        self.tg_chat_entry = ctk.CTkEntry(scroll, width=300, text_color="#ffffff", fg_color="#1a1a3a")
        self.tg_chat_entry.pack(anchor="w", pady=2)

    def _build_report(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25"); self.pages["Отчёт"] = p
        self.rep_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#ffffff", font=ctk.CTkFont(family="Consolas", size=12))
        self.rep_box.pack(fill="both", expand=True, padx=24, pady=(20,0))
        bf = ctk.CTkFrame(p, fg_color="transparent"); bf.pack(pady=8)
        ctk.CTkButton(bf, text="JSON", command=self.load_json).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="HTML", command=self.save_html).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="CSV", command=self.save_csv).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="PDF", command=self.save_pdf).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="📧 На почту", command=self.send_report_email).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="📱 В Telegram", command=self.send_report_telegram).pack(side="left", padx=4)

    def _build_achievements(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25"); self.pages["Достижения"] = p
        self.ach_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#ffffff", font=ctk.CTkFont(family="Consolas", size=12))
        self.ach_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Обновить", command=self.refresh_achievements).pack(pady=8)

    def _build_history(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25"); self.pages["История"] = p
        self.hist_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#ffffff", font=ctk.CTkFont(family="Consolas", size=12))
        self.hist_box.pack(fill="both", expand=True, padx=24, pady=20)
        bf = ctk.CTkFrame(p, fg_color="transparent"); bf.pack(pady=8)
        ctk.CTkButton(bf, text="Обновить", command=self.refresh_history).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="Показать график", command=self.show_chart).pack(side="left", padx=4)

    # ---------- ДЕЙСТВИЯ ----------
    def add_path(self):
        d = filedialog.askdirectory()
        if d:
            CONFIG["scan_paths"].append(d); save_config()
            v = ctk.BooleanVar(value=True); self.path_vars.append((d,v))
            ctk.CTkCheckBox(self.pages["Сканер"], text=d, variable=v).pack(anchor="w", padx=24, pady=2)

    def start_scan(self, quick=False):
        if CONFIG.get("password") and not self._ask_password(): return
        paths = CONFIG["scan_paths"][:2] if quick else [p for p,v in self.path_vars if v.get()]
        if not paths:
            messagebox.showwarning("Сканер","Выбери папку."); return
        self.show_tab("Сканер"); self.log_box.delete("1.0","end")
        threading.Thread(target=self._scan, args=(paths,), daemon=True).start()

    def _scan(self, paths):
        self.dash_status.configure(text="Сканирование...", text_color="#ffaa00")
        self.scanner.scan_paths(paths)
        self.progress.set(1); self.scan_pct.configure(text="100%")
        STATS["scans"] += 1; STATS["files"] += len(paths); STATS["threats"] += len(self.scanner.found)
        save_json(STATS_FILE, STATS)
        if self.scanner.found:
            for f in self.scanner.found:
                if CONFIG.get("quarantine",True): self.scanner.quarantine(f["path"])
            self.dash_status.configure(text="Обнаружены угрозы!", text_color="#ff4444")
            self.dash_threats.configure(text=f"Найдено: {len(self.scanner.found)}")
            messagebox.showwarning("Угрозы", f"Найдено: {len(self.scanner.found)}")
            if notification:
                try: notification.notify(title="Угроза!", message=f"Найдено: {len(self.scanner.found)}. Файлы в карантине.", timeout=10)
                except: pass
        else:
            self.dash_status.configure(text="Система защищена", text_color="#00cc66")
            self.dash_threats.configure(text="Найдено: 0")
            messagebox.showinfo("Сканер","Угроз нет.")
        self.dash_last.configure(text=f"Последнее: {datetime.now().strftime('%H:%M %d.%m.%Y')}")
        self._draw_shield()
        HISTORY.append({"time": str(datetime.now()), "files": len(paths), "threats": len(self.scanner.found)})
        save_json(HISTORY_FILE, HISTORY)
        with open(REPORT_JSON,"w",encoding="utf-8") as f:
            json.dump({"found":self.scanner.found,"time":str(datetime.now())},f,ensure_ascii=False,indent=2)
        self.level_label.configure(text=f"Уровень {STATS['level']}  |  XP: {STATS['xp']}")
        if CONFIG.get("auto_email", False):
            self.send_report_email()
        if hasattr(self,"tg_token_entry") and self.tg_token_entry.get().strip():
            self.send_report_telegram()

    def stop_scan(self):
        self.scanner.stop_flag = True; self.update_status("Остановлено.")

    def refresh_autorun(self):
        self.ar_box.delete("1.0","end")
        for it in self.scanner.scan_autorun():
            self.ar_box.insert("end",f"{it['name']} -> {it['value']}\n")

    def refresh_processes(self):
        self.pr_box.delete("1.0","end")
        for it in self.scanner.scan_processes():
            self.pr_box.insert("end",f"{it['name']:40s} PID: {str(it['pid']):6s}  {it.get('exe','')}\n")

    def refresh_usb(self):
        self.usb_box.delete("1.0","end")
        for it in self.scanner.scan_usb():
            self.usb_box.insert("end",f"Флешка: {it['drive']}\n")
            if "autorun" in it: self.usb_box.insert("end",f"  [!] {it['autorun']}\n")

    def refresh_network(self):
        self.net_box.delete("1.0","end")
        for it in self.scanner.scan_network():
            self.net_box.insert("end",f"{it['local']:30s} -> {it['remote']:30s} {it['status']} PID:{it['pid']}\n")
        self.net_box.insert("end", "\n--- Hosts ---\n")
        for h in self.scanner.scan_hosts():
            self.net_box.insert("end", h + "\n")

    def refresh_system(self):
        self.sys_box.delete("1.0","end")
        self.sys_box.insert("end","--- Firewall ---\n")
        self.sys_box.insert("end", self.scanner.scan_firewall())
        self.sys_box.insert("end","\n--- Windows Updates ---\n")
        try:
            out = subprocess.check_output(["wmic","qfe","get","HotFixID"],encoding="cp866",errors="ignore")
            self.sys_box.insert("end",out)
        except: pass
        self.sys_box.insert("end","\n--- Users ---\n")
        try:
            out = subprocess.check_output(["net","user"],encoding="cp866",errors="ignore")
            self.sys_box.insert("end",out)
        except: pass
        self.sys_box.insert("end","\n--- USB Policy ---\n")
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR")
            val,_ = winreg.QueryValueEx(k, "Start")
            self.sys_box.insert("end", f"USBSTOR Start = {val} (3 = allowed, 4 = disabled)\n")
            winreg.CloseKey(k)
        except: self.sys_box.insert("end","Не удалось проверить.\n")

    def refresh_quarantine(self):
        self.q_box.delete("1.0","end")
        for f in QUARANTINE_DIR.glob("*.quarantined"):
            self.q_box.insert("end",f"{f.name}\n")

    def search_quarantine(self):
        q = self.q_search.get().lower()
        self.q_box.delete("1.0","end")
        for f in QUARANTINE_DIR.glob("*.quarantined"):
            if q in f.name.lower(): self.q_box.insert("end",f"{f.name}\n")

    def restore_selected(self):
        sel = self.q_box.get("sel.first","sel.last").strip()
        if not sel: messagebox.showwarning("Карантин","Выбери файл."); return
        qpath = QUARANTINE_DIR / sel
        orig = pathlib.Path(os.environ.get("USERPROFILE","C:\\Users"))/"Desktop"/sel.replace(".quarantined","")
        if self.scanner.restore(qpath, orig):
            messagebox.showinfo("OK","Восстановлено.")
            self.refresh_quarantine()

    def save_vt(self):
        CONFIG["virustotal_api_key"] = self.vt_entry.get().strip(); save_config()
        self.scanner.vt_key = CONFIG["virustotal_api_key"]; messagebox.showinfo("OK","Сохранено.")

    def save_setting(self, k, v): CONFIG[k] = v; save_config()

    def toggle_theme(self):
        m = "light" if self.theme_var.get() else "dark"
        ctk.set_appearance_mode(m); CONFIG["theme"] = m; save_config()

    def toggle_rt(self):
        self.save_setting("realtime", self.rt_var.get())
        if self.rt_var.get(): self.start_realtime()
        else: self.stop_realtime()

    def toggle_patrol(self):
        if self.patrol_var.get(): self.patrol.start(); self.dash_info.configure(text="Патруль активен")
        else: self.patrol.stop(); self.dash_info.configure(text="Патруль отключён")

    def add_to_startup(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "SuperAntivirus", 0, winreg.REG_SZ, sys.executable)
            winreg.CloseKey(key)
            messagebox.showinfo("OK","Добавлено в автозагрузку.")
            unlock_achievement("Автозапуск")
        except Exception as e: messagebox.showerror("Ошибка", str(e))

    def set_password(self):
        CONFIG["password"] = self.pwd_entry.get().strip(); save_config()
        messagebox.showinfo("OK","Пароль установлен.")

    def save_schedule(self):
        CONFIG["schedule"] = "daily"; CONFIG["schedule_time"] = self.schedule_entry.get().strip(); save_config()
        messagebox.showinfo("OK","Расписание сохранено.")

    def _ask_password(self):
        pwd = simpledialog.askstring("Пароль","Введи пароль:", show="*")
        return pwd == CONFIG.get("password","")

    def refresh_achievements(self):
        self.ach_box.delete("1.0","end")
        all_ach = ["Первое сканирование","Сотня файлов","Тысяча файлов","Первая угроза","Десяток угроз","Первый карантин","Автозапуск"]
        for a in all_ach:
            mark = "✅" if a in STATS.get("achievements",[]) else "❌"
            self.ach_box.insert("end",f"{mark}  {a}\n")

    def refresh_history(self):
        self.hist_box.delete("1.0","end")
        for h in HISTORY[-50:]:
            self.hist_box.insert("end",f"{h['time']}  файлов: {h['files']}  угроз: {h['threats']}\n")

    def show_chart(self):
        try:
            import matplotlib
            matplotlib.use("Agg")
            from matplotlib.figure import Figure
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            fig = Figure(figsize=(6,3), facecolor="#0f0f25")
            ax = fig.add_subplot(111)
            ax.set_facecolor("#0f0f25")
            ax.tick_params(colors="#ffffff")
            dates = [h["time"][:10] for h in HISTORY[-30:]]
            threats = [h["threats"] for h in HISTORY[-30:]]
            ax.plot(dates, threats, color="#1a6fff")
            ax.set_title("Угрозы по дням", color="#ffffff")
            win = ctk.CTkToplevel(self); win.title("График"); win.geometry("600x400")
            canvas = FigureCanvasTkAgg(fig, master=win)
            canvas.draw(); canvas.get_tk_widget().pack(fill="both", expand=True)
        except Exception as e:
            messagebox.showerror("График", str(e))

    def send_report_email(self):
        if not os.path.exists(REPORT_JSON):
            messagebox.showwarning("Почта", "Сначала выполни сканирование."); return
        smtp_server = CONFIG.get("smtp_server","")
        smtp_port = CONFIG.get("smtp_port","465")
        smtp_user = CONFIG.get("smtp_user","")
        smtp_pass = CONFIG.get("smtp_pass","")
        to_addr = CONFIG.get("smtp_to","")
        if hasattr(self, "smtp_server_entry") and not smtp_server:
            smtp_server = self.smtp_server_entry.get().strip()
        if hasattr(self, "smtp_port_entry") and not smtp_port:
            smtp_port = self.smtp_port_entry.get().strip()
        if hasattr(self, "smtp_user_entry") and not smtp_user:
            smtp_user = self.smtp_user_entry.get().strip()
        if hasattr(self, "smtp_pass_entry") and not smtp_pass:
            smtp_pass = self.smtp_pass_entry.get().strip()
        if hasattr(self, "smtp_to_entry") and not to_addr:
            to_addr = self.smtp_to_entry.get().strip()
        if not all([smtp_server, smtp_port, smtp_user, smtp_pass, to_addr]):
            messagebox.showwarning("Почта", "Заполни все поля SMTP в настройках."); return
        try:
            with open(REPORT_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
            body = f"Отчёт антивируса\nВремя: {data.get('time','')}\n\n"
            for it in data.get("found", []):
                body += f"{it.get('path','')} — {it.get('reason','')}\n"
            if not data.get("found"):
                body += "Угроз не найдено.\n"
            msg = MIMEMultipart()
            msg["From"] = smtp_user
            msg["To"] = to_addr
            msg["Subject"] = "Super Antivirus — отчёт"
            msg.attach(MIMEText(body, "plain", "utf-8"))
            if int(smtp_port) == 465:
                server = smtplib.SMTP_SSL(smtp_server, int(smtp_port))
            else:
                server = smtplib.SMTP(smtp_server, int(smtp_port))
                server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
            server.quit()
            messagebox.showinfo("Почта", "Отчёт отправлен.")
        except Exception as e:
            messagebox.showerror("Почта", f"Ошибка: {e}")

    def send_report_telegram(self):
        if not os.path.exists(REPORT_JSON): return
        token = self.tg_token_entry.get().strip() if hasattr(self,"tg_token_entry") else ""
        chat_id = self.tg_chat_entry.get().strip() if hasattr(self,"tg_chat_entry") else ""
        if not token or not chat_id: return
        try:
            import requests
            with open(REPORT_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
            text = f"🛡 Super Antivirus\nУгроз: {len(data.get('found',[]))}\nВремя: {data.get('time','')}"
            requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                          data={"chat_id": chat_id, "text": text}, timeout=10)
        except Exception as e: log(f"[TG] {e}")

    def start_realtime(self):
        if not Observer or self.observer: return
        try:
            h = RT(self.scanner, self); self.observer = Observer()
            for p in CONFIG["scan_paths"]:
                if pathlib.Path(p).exists(): self.observer.schedule(h,p,recursive=True)
            self.observer.start()
        except: pass

    def stop_realtime(self):
        if self.observer: self.observer.stop(); self.observer.join(); self.observer = None

    def load_json(self):
        self.rep_box.delete("1.0","end")
        if os.path.exists(REPORT_JSON):
            with open(REPORT_JSON,"r",encoding="utf-8") as f: self.rep_box.insert("end",f.read())
        else: self.rep_box.insert("end","Нет отчёта.\n")

    def save_html(self):
        if not os.path.exists(REPORT_JSON): return
        with open(REPORT_JSON,"r",encoding="utf-8") as f: d = json.load(f)
        h = f"<html><head><meta charset='utf-8'><title>Отчёт</title></head><body><h1>Отчёт антивируса</h1>"
        for it in d.get("found",[]): h += f"<p>{it.get('path','')} — {it.get('reason','')}</p>"
        h += "</body></html>"
        with open("av_report.html","w",encoding="utf-8") as f: f.write(h)

    def save_csv(self):
        if not os.path.exists(REPORT_JSON): return
        with open(REPORT_JSON,"r",encoding="utf-8") as f: d = json.load(f)
        with open("av_report.csv","w",newline="",encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["Файл","Причина","Хеш"])
            for it in d.get("found",[]): w.writerow([it.get("path",""),it.get("reason",""),it.get("hash","")])

    def save_pdf(self):
        if not canvas or not os.path.exists(REPORT_JSON): return
        with open(REPORT_JSON,"r",encoding="utf-8") as f: d = json.load(f)
        c = canvas.Canvas("av_report.pdf",pagesize=A4)
        c.drawString(50,800,"Super Antivirus Report"); y = 770
        for it in d.get("found",[]):
            c.drawString(50,y,f"{it.get('path','')[:80]}"); y -= 15
            if y<50: c.showPage(); y = 800
        c.save()

    def on_close(self):
        self.stop_realtime(); self.patrol.stop(); self.ransom_guard.stop()
        if self.tray_icon: self.tray_icon.stop()
        self.destroy()

# ---------- ГЛАВНАЯ ----------
if __name__ == "__main__":
    try:
        app = AntivirusGUI()
        app.withdraw()
        BootScreen(app, lambda: (app.deiconify(), app.focus_force()))
        app.mainloop()
    except Exception:
        traceback.print_exc()
        input("Enter...")