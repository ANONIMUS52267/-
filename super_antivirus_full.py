import os, sys, time, hashlib, json, pathlib, threading, shutil, winreg
import subprocess, string, ctypes, traceback, csv, zipfile, tarfile
from datetime import datetime
import customtkinter as ctk
from tkinter import messagebox, filedialog
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

def load_config():
    default = {
        "scan_paths": [str(pathlib.Path(os.environ.get("USERPROFILE","C:\\Users"))/"Downloads"),
                       str(pathlib.Path(os.environ.get("USERPROFILE","C:\\Users"))/"Desktop"),
                       str(os.environ.get("TEMP","C:\\Temp"))],
        "virustotal_api_key": "", "realtime": True, "quarantine": True,
        "theme": "dark", "notifications": True, "tray": True, "patrol": True,
    }
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE,"r",encoding="utf-8") as f:
            return {**default, **json.load(f)}
    return default
def save_config(cfg):
    with open(CONFIG_FILE,"w",encoding="utf-8") as f:
        json.dump(cfg,f,ensure_ascii=False,indent=2)
CONFIG = load_config()

MALWARE_HASHES = {"44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File"}
SUSPICIOUS_EXT = {".exe",".scr",".bat",".cmd",".vbs",".js",".ps1",".hta",".jar",".msi",".dll"}
HEURISTIC = ["shutdown /s","reg add","powershell -enc","bitsadmin","certutil -decode",
             "mshta","wscript.shell","createobject","eval(","base64_decode","keylog","ransom"]
YARA_RULES = """
rule Suspicious_PS { strings: $a="powershell -enc" nocase $b="FromBase64String" nocase condition: any of them }
rule Ransomware { strings: $a="your files have been encrypted" nocase $b="bitcoin" nocase condition: 2 of them }
"""

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
        code = {"threat":0x10,"scan":0x40,"done":0x30}.get(kind,0x40)
        ctypes.windll.user32.MessageBeep(code)
    except: pass

# ---------- ЗАГРУЗКА КАК В WINDOWS 11 ----------
class BootScreen(ctk.CTkToplevel):
    def __init__(self, master, on_done):
        super().__init__(master)
        self.attributes("-fullscreen", True)
        self.attributes("-topmost", True)
        self.configure(fg_color="#000000")
        self.on_done = on_done
        self.canvas = ctk.CTkCanvas(self, bg="#000000", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.after(100, self.draw)
        self.after(4200, self.finish)

    def draw(self):
        w = self.winfo_screenwidth(); h = self.winfo_screenheight()
        cx, cy = w//2, h//2 - 60
        # логотип Windows — 4 квадрата
        size = 32; gap = 6
        positions = [(-size-gap//2, -size-gap//2), (gap//2, -size-gap//2),
                     (-size-gap//2, gap//2), (gap//2, gap//2)]
        self.squares = []
        for i,(x,y) in enumerate(positions):
            rect = self.canvas.create_rectangle(cx+x, cy+y, cx+x+size, cy+y+size,
                                                 fill="#0078d4", outline="")
            self.squares.append(rect)
            self.canvas.itemconfig(rect, state="hidden")
            self.after(i*90, lambda r=rect: self.canvas.itemconfig(r, state="normal"))
        # точки загрузки
        self.dots = []
        dot_y = cy + 120
        for i in range(5):
            d = self.canvas.create_oval(cx-55+i*25, dot_y, cx-45+i*25, dot_y+10,
                                         fill="#ffffff", outline="")
            self.dots.append(d)
        self.animate_dots(0)

    def animate_dots(self, step):
        if not self.winfo_exists(): return
        for i,d in enumerate(self.dots):
            phase = (step+i)%5
            r = 5 if phase==0 else 3
            cx = self.canvas.coords(d)[0]; cy = self.canvas.coords(d)[1]
            self.canvas.coords(d, cx-r, cy-r, cx+r, cy+r)
            self.canvas.itemconfig(d, fill="#ffffff" if phase==0 else "#444444")
        self.after(220, lambda: self.animate_dots(step+1))

    def finish(self):
        if not self.winfo_exists(): return
        self.destroy(); self.on_done()

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

    def scan_file(self, p):
        if self.stop_flag: return
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
        if p.suffix.lower() in SUSPICIOUS_EXT and size < 10*1024*1024:
            try:
                with open(p,"rb") as f: c = f.read(8192).lower()
                for kw in HEURISTIC:
                    if kw.encode() in c:
                        self.found.append({"path":str(p),"reason":f"Эвристика: {kw}","hash":md5})
                        self.status(f"[?] {p}"); return
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
                    total += 1
                    p = pathlib.Path(root)/name
                    if p.suffix.lower() in (".zip",".tar",".gz",".tgz"): self.scan_archive(p)
                    else: self.scan_file(p)
        self.status(f"Готово. Проверено: {total}, найдено: {len(self.found)}")
        beep("done")
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
            for proc in psutil.process_iter(['name','pid']):
                try: res.append({"name":proc.info['name'],"pid":proc.info['pid']})
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

    def quarantine(self, path):
        if not CONFIG.get("quarantine",True): return
        try:
            p = pathlib.Path(path); dest = QUARANTINE_DIR/(p.name+".quarantined")
            shutil.move(str(p),str(dest)); log(f"[КАРАНТИН] {p}")
        except Exception as e: log(f"[!] {e}")

# ---------- ПАТРУЛЬ ----------
class Patrol:
    def __init__(self, scanner, gui):
        self.scanner = scanner; self.gui = gui; self.running = False
    def start(self):
        if self.running: return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log("[ПАТРУЛЬ] Запущен")
    def stop(self):
        self.running = False
    def _loop(self):
        while self.running:
            try:
                for item in self.scanner.scan_autorun():
                    if any(k in item["value"].lower() for k in ["powershell -enc","cmd /c","wscript"]):
                        self.gui.patrol_alert(f"Подозрительная автозагрузка: {item['name']}")
                for p in self.scanner.scan_processes():
                    if p["name"] and any(k in p["name"].lower() for k in ["keylog","ransom","miner"]):
                        self.gui.patrol_alert(f"Процесс: {p['name']}")
            except Exception as e: log(f"[ПАТРУЛЬ] {e}")
            time.sleep(10)

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
        self.scanner = Scanner(self)
        self.observer = None
        self.patrol = Patrol(self.scanner, self)
        self.tray_icon = None

        # Боковая панель
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#0a0a1a")
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        ctk.CTkLabel(self.sidebar, text="🛡  SUPER\nANTIVIRUS",
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#ffffff", justify="center").pack(pady=(30,30))
        self.nav_buttons = {}
        for name, icon in [("Дашборд","🏠"),("Сканер","🔍"),("Автозагрузка","🔄"),
                           ("Процессы","📋"),("USB","💾"),("Сеть","🌐"),
                           ("Система","⚙️"),("Карантин","🦠"),("Настройки","⚙"),("Отчёт","📊")]:
            btn = ctk.CTkButton(self.sidebar, text=f"  {icon}  {name}", anchor="w",
                                height=38, corner_radius=8, fg_color="transparent",
                                hover_color="#1a1a3a", text_color="#a0b0d0",
                                font=ctk.CTkFont(size=13),
                                command=lambda n=name: self.show_tab(n))
            btn.pack(fill="x", padx=8, pady=2)
            self.nav_buttons[name] = btn

        # Контент
        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color="#0f0f25")
        self.content.pack(side="right", fill="both", expand=True)

        self.top = ctk.CTkFrame(self.content, height=50, corner_radius=0, fg_color="#0f0f25")
        self.top.pack(fill="x")
        self.top.pack_propagate(False)
        self.title_label = ctk.CTkLabel(self.top, text="Дашборд",
                                         font=ctk.CTkFont(size=18, weight="bold"),
                                         text_color="#ffffff")
        self.title_label.pack(side="left", padx=20)
        self.status_label = ctk.CTkLabel(self.top, text="Готов",
                                          font=ctk.CTkFont(size=11), text_color="#6a8aaa")
        self.status_label.pack(side="right", padx=20)

        self.pages = {}
        self._build_dashboard()
        self._build_scanner()
        self._build_autorun()
        self._build_processes()
        self._build_usb()
        self._build_network()
        self._build_system()
        self._build_quarantine()
        self._build_settings()
        self._build_report()

        self.show_tab("Дашборд")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        if CONFIG.get("realtime",True): self.start_realtime()
        if CONFIG.get("tray",True): self.tray_icon = self._create_tray()
        self.patrol.start()

    def _create_tray(self):
        if not pystray: return None
        def show(icon,item): self.deiconify(); self.focus_force()
        def quit_(icon,item): icon.stop(); self.on_close()
        img = Image.new("RGB",(64,64),"#1a6fff")
        d = ImageDraw.Draw(img); d.text((20,18),"🛡",fill="#fff")
        icon = pystray.Icon("av",img,"Super Antivirus",
                            pystray.Menu(item("Открыть",show),item("Выход",quit_)))
        threading.Thread(target=icon.run,daemon=True).start()
        return icon

    def show_tab(self, name):
        self.title_label.configure(text=name)
        for k,btn in self.nav_buttons.items():
            btn.configure(fg_color="#1a1a3a" if k==name else "transparent")
        for k,page in self.pages.items():
            if k==name: page.pack(fill="both",expand=True)
            else: page.pack_forget()

    def update_status(self, msg):
        self.status_label.configure(text=msg[:80])
        if "log_box" in self.__dict__ and self.log_box.winfo_exists():
            self.log_box.insert("end",msg+"\n"); self.log_box.see("end")

    def patrol_alert(self, msg):
        self.update_status(f"[ПАТРУЛЬ] {msg}"); beep("threat")
        if CONFIG.get("notifications",True) and notification:
            try: notification.notify(title="Патруль",message=msg,timeout=5)
            except: pass

    # ---------- СТРАНИЦЫ ----------
    def _build_dashboard(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25")
        self.pages["Дашборд"] = p
        card = ctk.CTkFrame(p, corner_radius=16, fg_color="#151530")
        card.pack(fill="both", expand=True, padx=24, pady=24)
        ctk.CTkLabel(card, text="🛡", font=ctk.CTkFont(size=96)).pack(pady=(30,0))
        self.dash_status = ctk.CTkLabel(card, text="Система защищена",
                                         font=ctk.CTkFont(size=26, weight="bold"),
                                         text_color="#00cc66")
        self.dash_status.pack(pady=8)
        self.dash_info = ctk.CTkLabel(card, text="Пассивный патруль активен",
                                       font=ctk.CTkFont(size=12), text_color="#6a8aaa")
        self.dash_info.pack()
        ctk.CTkButton(card, text="▶  Быстрое сканирование", width=260, height=46,
                      corner_radius=10, font=ctk.CTkFont(size=14, weight="bold"),
                      fg_color="#1a6fff", hover_color="#2a7fff",
                      command=lambda: self.start_scan(quick=True)).pack(pady=24)
        self.dash_last = ctk.CTkLabel(card, text="Последнее сканирование: —",
                                       font=ctk.CTkFont(size=11), text_color="#6a8aaa")
        self.dash_last.pack(pady=2)
        self.dash_threats = ctk.CTkLabel(card, text="Найдено угроз: 0",
                                          font=ctk.CTkFont(size=11), text_color="#6a8aaa")
        self.dash_threats.pack(pady=2)

    def _build_scanner(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25")
        self.pages["Сканер"] = p
        ctk.CTkLabel(p, text="Выберите папки:", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=24, pady=(20,6))
        self.path_vars = []
        for path in CONFIG["scan_paths"]:
            v = ctk.BooleanVar(value=True)
            self.path_vars.append((path,v))
            ctk.CTkCheckBox(p, text=path, variable=v).pack(anchor="w", padx=24, pady=2)
        btn = ctk.CTkFrame(p, fg_color="transparent"); btn.pack(anchor="w", padx=24, pady=12)
        ctk.CTkButton(btn, text="▶  Сканировать", command=self.start_scan, width=160).pack(side="left", padx=4)
        ctk.CTkButton(btn, text="■  Стоп", command=self.stop_scan, width=100, fg_color="#c42b1c").pack(side="left", padx=4)
        ctk.CTkButton(btn, text="＋  Папка", command=self.add_path, width=120).pack(side="left", padx=4)
        self.progress = ctk.CTkProgressBar(p, height=8, progress_color="#1a6fff")
        self.progress.pack(fill="x", padx=24, pady=8)
        self.progress.set(0)
        self.scan_pct = ctk.CTkLabel(p, text="0%", font=ctk.CTkFont(size=11)); self.scan_pct.pack()
        self.log_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#00ff88",
                                       font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box.pack(fill="both", expand=True, padx=24, pady=12)

    def _build_autorun(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25")
        self.pages["Автозагрузка"] = p
        self.ar_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#fff",
                                      font=ctk.CTkFont(family="Consolas", size=12))
        self.ar_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Обновить", command=self.refresh_autorun).pack(pady=8)

    def _build_processes(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25")
        self.pages["Процессы"] = p
        self.pr_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#fff",
                                      font=ctk.CTkFont(family="Consolas", size=12))
        self.pr_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Обновить", command=self.refresh_processes).pack(pady=8)

    def _build_usb(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25")
        self.pages["USB"] = p
        self.usb_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#fff",
                                       font=ctk.CTkFont(family="Consolas", size=12))
        self.usb_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Проверить USB", command=self.refresh_usb).pack(pady=8)

    def _build_network(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25")
        self.pages["Сеть"] = p
        self.net_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#fff",
                                       font=ctk.CTkFont(family="Consolas", size=12))
        self.net_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Обновить", command=self.refresh_network).pack(pady=8)

    def _build_system(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25")
        self.pages["Система"] = p
        self.sys_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#fff",
                                       font=ctk.CTkFont(family="Consolas", size=12))
        self.sys_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Проверить систему", command=self.refresh_system).pack(pady=8)

    def _build_quarantine(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25")
        self.pages["Карантин"] = p
        self.q_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#fff",
                                     font=ctk.CTkFont(family="Consolas", size=12))
        self.q_box.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkButton(p, text="Обновить", command=self.refresh_quarantine).pack(pady=8)

    def _build_settings(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25")
        self.pages["Настройки"] = p
        ctk.CTkLabel(p, text="VirusTotal API Key:", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=24, pady=(20,6))
        self.vt_entry = ctk.CTkEntry(p, width=400)
        self.vt_entry.insert(0,CONFIG.get("virustotal_api_key",""))
        self.vt_entry.pack(anchor="w", padx=24, pady=4)
        ctk.CTkButton(p, text="Сохранить ключ", command=self.save_vt).pack(anchor="w", padx=24, pady=4)
        self.rt_var = ctk.BooleanVar(value=CONFIG.get("realtime",True))
        ctk.CTkSwitch(p, text="Мониторинг в реальном времени", variable=self.rt_var,
                      command=self.toggle_rt).pack(anchor="w", padx=24, pady=6)
        self.q_var = ctk.BooleanVar(value=CONFIG.get("quarantine",True))
        ctk.CTkSwitch(p, text="Карантин", variable=self.q_var,
                      command=lambda: self.save_setting("quarantine",self.q_var.get())).pack(anchor="w", padx=24, pady=6)
        self.theme_var = ctk.BooleanVar(value=CONFIG.get("theme","dark")=="light")
        ctk.CTkSwitch(p, text="Светлая тема", variable=self.theme_var,
                      command=self.toggle_theme).pack(anchor="w", padx=24, pady=6)
        self.notif_var = ctk.BooleanVar(value=CONFIG.get("notifications",True))
        ctk.CTkSwitch(p, text="Уведомления", variable=self.notif_var,
                      command=lambda: self.save_setting("notifications",self.notif_var.get())).pack(anchor="w", padx=24, pady=6)
        self.patrol_var = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(p, text="Пассивный патруль", variable=self.patrol_var,
                      command=self.toggle_patrol).pack(anchor="w", padx=24, pady=6)

    def _build_report(self):
        p = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#0f0f25")
        self.pages["Отчёт"] = p
        self.rep_box = ctk.CTkTextbox(p, fg_color="#080812", text_color="#fff",
                                       font=ctk.CTkFont(family="Consolas", size=12))
        self.rep_box.pack(fill="both", expand=True, padx=24, pady=(20,0))
        bf = ctk.CTkFrame(p, fg_color="transparent"); bf.pack(pady=8)
        ctk.CTkButton(bf, text="JSON", command=self.load_json).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="HTML", command=self.save_html).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="CSV", command=self.save_csv).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="PDF", command=self.save_pdf).pack(side="left", padx=4)

    # ---------- ДЕЙСТВИЯ ----------
    def add_path(self):
        d = filedialog.askdirectory()
        if d:
            CONFIG["scan_paths"].append(d); save_config(CONFIG)
            v = ctk.BooleanVar(value=True); self.path_vars.append((d,v))
            ctk.CTkCheckBox(self.pages["Сканер"], text=d, variable=v).pack(anchor="w", padx=24, pady=2)

    def start_scan(self, quick=False):
        paths = CONFIG["scan_paths"][:2] if quick else [p for p,v in self.path_vars if v.get()]
        if not paths:
            messagebox.showwarning("Сканер","Выбери папку."); return
        self.show_tab("Сканер"); self.log_box.delete("1.0","end")
        threading.Thread(target=self._scan, args=(paths,), daemon=True).start()

    def _scan(self, paths):
        self.dash_status.configure(text="Сканирование...", text_color="#ffaa00")
        self.scanner.scan_paths(paths)
        self.progress.set(1); self.scan_pct.configure(text="100%")
        if self.scanner.found:
            for f in self.scanner.found:
                if CONFIG.get("quarantine",True): self.scanner.quarantine(f["path"])
            self.dash_status.configure(text="Обнаружены угрозы!", text_color="#ff4444")
            self.dash_threats.configure(text=f"Найдено: {len(self.scanner.found)}")
            messagebox.showwarning("Угрозы", f"Найдено: {len(self.scanner.found)}")
        else:
            self.dash_status.configure(text="Система защищена", text_color="#00cc66")
            self.dash_threats.configure(text="Найдено: 0")
            messagebox.showinfo("Сканер","Угроз нет.")
        self.dash_last.configure(text=f"Последнее: {datetime.now().strftime('%H:%M %d.%m.%Y')}")
        with open(REPORT_JSON,"w",encoding="utf-8") as f:
            json.dump({"found":self.scanner.found,"time":str(datetime.now())},f,ensure_ascii=False,indent=2)

    def stop_scan(self):
        self.scanner.stop_flag = True; self.update_status("Остановлено.")

    def refresh_autorun(self):
        self.ar_box.delete("1.0","end")
        for it in self.scanner.scan_autorun():
            self.ar_box.insert("end",f"{it['name']} -> {it['value']}\n")

    def refresh_processes(self):
        self.pr_box.delete("1.0","end")
        for it in self.scanner.scan_processes():
            self.pr_box.insert("end",f"{it['name']:40s} PID: {str(it['pid']):6s}\n")

    def refresh_usb(self):
        self.usb_box.delete("1.0","end")
        for it in self.scanner.scan_usb():
            self.usb_box.insert("end",f"Флешка: {it['drive']}\n")
            if "autorun" in it: self.usb_box.insert("end",f"  [!] {it['autorun']}\n")

    def refresh_network(self):
        self.net_box.delete("1.0","end")
        if psutil:
            for c in psutil.net_connections(kind="inet"):
                try: self.net_box.insert("end",f"{c.laddr} -> {c.raddr} {c.status}\n")
                except: pass

    def refresh_system(self):
        self.sys_box.delete("1.0","end")
        self.sys_box.insert("end","--- Firewall ---\n")
        try:
            out = subprocess.check_output(["netsh","advfirewall","show","allprofiles","state"],encoding="cp866",errors="ignore")
            self.sys_box.insert("end",out)
        except: pass

    def refresh_quarantine(self):
        self.q_box.delete("1.0","end")
        for f in QUARANTINE_DIR.glob("*.quarantined"):
            self.q_box.insert("end",f"{f.name}\n")

    def save_vt(self):
        CONFIG["virustotal_api_key"] = self.vt_entry.get().strip(); save_config(CONFIG)
        self.scanner.vt_key = CONFIG["virustotal_api_key"]; messagebox.showinfo("OK","Сохранено.")

    def save_setting(self, k, v): CONFIG[k] = v; save_config(CONFIG)

    def toggle_theme(self):
        m = "light" if self.theme_var.get() else "dark"
        ctk.set_appearance_mode(m); CONFIG["theme"] = m; save_config(CONFIG)

    def toggle_rt(self):
        self.save_setting("realtime", self.rt_var.get())
        if self.rt_var.get(): self.start_realtime()
        else: self.stop_realtime()

    def toggle_patrol(self):
        if self.patrol_var.get(): self.patrol.start(); self.dash_info.configure(text="Патруль активен")
        else: self.patrol.stop(); self.dash_info.configure(text="Патруль отключён")

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
        self.stop_realtime(); self.patrol.stop()
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