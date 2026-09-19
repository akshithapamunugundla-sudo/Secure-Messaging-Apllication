import os
import sys
import socket
import threading
import json
import base64
import datetime
import ctypes
import tkinter as tk
from tkinter import scrolledtext, messagebox, font, simpledialog
import webbrowser

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ===================== THEME =====================

THEME = {
    "bg_main": "#050816",
    "bg_panel": "#0f172a",
    "bg_panel_alt": "#020617",
    "accent_cyan": "#22d3ee",
    "accent_magenta": "#ec4899",
    "accent_green": "#22c55e",
    "accent_orange": "#fb923c",
    "accent_red": "#f97373",
    "text_primary": "#e5e7eb",
    "text_muted": "#9ca3af",
    "text_dim": "#6b7280",
    "entry_bg": "#020617",
    "entry_fg": "#e5e7eb",
    "entry_border": "#1e293b",
    "button_bg": "#22c55e",
    "button_fg": "#020617",
    "button_bg_hover": "#16a34a",
    "chip_bg": "#1f2937",
}

# ===================== CONFIG & GLOBALS =====================

APP_NAME = "secured.msg 🔒"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(BASE_DIR, "server_config.json")

DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "port": 65432,
    "max_clients": 50,
    "max_msg_size": 8192,
    "log_dir": os.path.join(BASE_DIR, "logs"),
    "auth_required": False
}

def load_config():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = DEFAULT_CONFIG.copy()
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    return cfg

CONFIG = load_config()
SERVER_HOST = CONFIG["host"]
SERVER_PORT = int(CONFIG["port"])
MAX_CLIENTS = int(CONFIG["max_clients"])
MAX_MSG_SIZE = int(CONFIG["max_msg_size"])
LOG_DIR = CONFIG["log_dir"]
AUTH_REQUIRED = bool(CONFIG["auth_required"])

os.makedirs(LOG_DIR, exist_ok=True)

server_clients = {}
server_lock = threading.Lock()

client_incidents = {}
BLOCK_THRESHOLD = 10

KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537
PROTOCOL_STR = "RSA-2048 / OAEP-SHA256"

# ===================== LOGGING & INCIDENT FORENSICS =====================

SERVER_LOG_FILE = os.path.join(LOG_DIR, "server.log")
CLIENT_LOG_FILE = os.path.join(LOG_DIR, "client.log")
INCIDENT_LOG_FILE = os.path.join(LOG_DIR, "incidents.log")

def _write_log(path: str, msg: str):
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}\n"
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
    print(line, end="")

def server_log(msg: str):
    _write_log(SERVER_LOG_FILE, msg)

def client_log(msg: str):
    _write_log(CLIENT_LOG_FILE, msg)

def log_incident(ip: str, reason: str):
    _write_log(INCIDENT_LOG_FILE, f"[INCIDENT] {ip} :: {reason}")

def record_client_incident(ip: str, reason: str):
    count = client_incidents.get(ip, 0) + 1
    client_incidents[ip] = count
    log_incident(ip, f"{reason} (count={count})")
    return count >= BLOCK_THRESHOLD

# ===================== PROJECT INFO HTML (YOUR VERSION) =====================

INFO_HTML_PATH = os.path.join(BASE_DIR, "info.html")

PROJECT_INFO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Project Information</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 40px;
      background: linear-gradient(135deg, #050816 0%, #0f172a 50%, #020617 100%);
      color: #e5e7eb;
    }

    h1, h2 {
      color: #22d3ee;
    }

    h1 {
      font-size: 2.5em;
      text-align: center;
      margin-bottom: 20px;
      text-shadow: 0 0 20px rgba(34, 211, 238, 0.5);
    }

    h2 {
      color: #ec4899;
      font-size: 1.8em;
      margin-top: 40px;
      border-bottom: 2px solid #22d3ee;
      padding-bottom: 10px;
    }

    .paragraph {
      margin-bottom: 20px;
      line-height: 1.6;
      font-size: 1.1em;
      background: rgba(15, 23, 42, 0.8);
      padding: 20px;
      border-radius: 10px;
      border-left: 4px solid #22c55e;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 30px;
      background: rgba(7, 8, 22, 0.8);
      border-radius: 10px;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }

    th, td {
      border: 1px solid #334155;
      padding: 15px;
      text-align: left;
    }

    th {
      background: linear-gradient(45deg, #22c55e, #16a34a);
      color: white;
      font-weight: bold;
      text-transform: uppercase;
      font-size: 0.9em;
      letter-spacing: 1px;
    }

    tr:nth-child(even) {
      background: rgba(34, 197, 94, 0.1);
    }

    tr:hover {
      background: rgba(34, 211, 238, 0.2);
      transform: scale(1.01);
      transition: all 0.3s ease;
    }

    .logo {
      float: right;
      margin-top: -80px;
      margin-right: 20px;
    }

    .logo img {
      width: 120px;
      height: 120px;
      border-radius: 50%;
      border: 3px solid #22d3ee;
      box-shadow: 0 0 30px rgba(34, 211, 238, 0.5);
    }

    .status-completed {
      color: #22c55e;
      font-weight: bold;
      text-shadow: 0 0 10px rgba(34, 197, 94, 0.5);
    }

    .team-highlight {
      background: linear-gradient(90deg, rgba(236, 72, 153, 0.2), rgba(34, 211, 238, 0.2));
      padding: 15px;
      border-radius: 8px;
      margin: 10px 0;
    }
  </style>
</head>
<body>

  <h1>🔒 secured.msg 🔒</h1>
  
  <div class="logo">
    <img src="logo.png" alt="Logo" style="width: 200px; height: 120px;">
  </div>

  <p class="paragraph">
    This project was developed by <strong>Sofia Falak, Pamunugundla Akshitha, Annu Vaishnavi Reddy, Shaik Ashraf, Ukkadapu Hithesh, Shinde Bhoomika</strong> as part of a <strong>Cyber Security Internship</strong>. This project is designed to <strong>Secure the Organizations in Real World from Cyber Frauds performed by Hackers</strong>.
  </p>

  <h2>Project Details</h2>
  <table>
    <tr>
      <th>Project Details</th>
      <th>Value</th>
    </tr>
    <tr>
      <td>Project Name</td>
      <td><strong>Secure Messaging Application</strong></td>
    </tr>
    <tr>
      <td>Project Description</td>
      <td>A Secure Messaging Application allows users to send and receive messages safely using end-to-end asymmetric encryption (RSA-2048). It includes a simple GUI, digital signatures for authenticity, secure storage and authentication, and logging for incident analysis. The system also supports a cross-platform web interface with backend server support and provides network security enhancements to protect communication from attacks.</td>
    </tr>
    <tr>
      <td>Project Start Date</td>
      <td>16-NOV-2025</td>
    </tr>
    <tr>
      <td>Project End Date</td>
      <td>20-DEC-2025</td>
    </tr>
    <tr>
      <td>Project Status</td>
      <td><span class="status-completed">✅ Completed</span></td>
    </tr>
  </table>

  <h2>Developer Details</h2>
  <table>
    <tr>
      <th>Name</th>
      <th>Employee ID</th>
      <th>Email</th>
    </tr>
    <tr>
      <td>Sofia Falak</td>
      <td>ST#IS#7503</td>
      <td>sofiafalak689@gmail.com</td>
    </tr>
    <tr>
      <td>Pamunugundla Akshitha</td>
      <td>ST#IS#7504</td>
      <td>akshithapamunugundla@gmail.com</td>
    </tr>
     <tr>
      <td>Annu Vaishnavi Reddy</td>
      <td>ST#IS#7505</td>
      <td>sirivaishnavi111@gmail.com</td>
    </tr>
     <tr>
      <td>Shaik Ashraf</td>
      <td>ST#IS#7506</td>
      <td>shaik.ashraf1028@gmail.com</td>
    </tr>
     <tr>
      <td>Ukkadapu Hithesh</td>
      <td>ST#IS#7507</td>
      <td>ukkadapuhitesh@gmail.com</td>
    </tr>
    <tr>
      <td>Shinde Bhoomika</td>
      <td>ST#IS#7528</td>
      <td>shindebhoomika084@gmail.com</td>
    </tr>
  </table>

  <h2>Company Details</h2>
  <table>
    <tr>
      <th>Company</th>
      <th>Value</th>
    </tr>
    <tr>
      <td>Name</td>
      <td><strong>Supraja Technologies</strong></td>
    </tr>
    <tr>
      <td>Email</td>
      <td>contact@suprajatechnologies.com</td>
    </tr>
  </table>

</body>
</html>"""

def ensure_info_html():
    """Ensure info.html exists with YOUR project information"""
    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        with open(INFO_HTML_PATH, "w", encoding="utf-8") as f:
            f.write(PROJECT_INFO_HTML)
    except Exception:
        pass

# ===================== CRYPTO / KEY MANAGEMENT =====================

def ensure_user_keypair(username: str, passphrase: bytes | None = None):
    user_dir = os.path.join(BASE_DIR, f"data_{username}")
    os.makedirs(user_dir, exist_ok=True)

    priv_path = os.path.join(user_dir, "private_key.pem")
    pub_path = os.path.join(user_dir, "public_key.pem")

    if not (os.path.exists(priv_path) and os.path.exists(pub_path)):
        private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT,
            key_size=KEY_SIZE,
        )
        public_key = private_key.public_key()

        server_log(f"Generating new RSA key pair for DATA {username.upper()}...")

        if passphrase:
            enc_alg = serialization.BestAvailableEncryption(passphrase)
        else:
            enc_alg = serialization.NoEncryption()

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_alg,
        )
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with open(priv_path, "wb") as f:
            f.write(pem_private)
        with open(pub_path, "wb") as f:
            f.write(pem_public)
    else:
        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=passphrase
            )
        with open(pub_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key, priv_path, pub_path

def load_public_key_from_file(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def encrypt_for_recipient(message: str, recipient_public_key):
    return recipient_public_key.encrypt(
        message.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def decrypt_with_private(ciphertext: bytes, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8")

def sign_message(message: str, private_key):
    return private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def verify_signature(message: str, signature: bytes, public_key):
    try:
        public_key.verify(
            signature,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False

# ===================== SERVER (MULTITHREADED RELAY) =====================

def broadcast(message: dict, sender_socket: socket.socket):
    recipient_name = message.get("recipient")
    if not recipient_name:
        return

    with server_lock:
        for sock, info in list(server_clients.items()):
            if info["username"] == recipient_name:
                try:
                    sock.sendall(json.dumps(message).encode("utf-8"))
                except Exception as e:
                    server_log(f"Broadcast error: {e}")
                break

def handle_client(client_socket: socket.socket, addr):
    ip, port = addr
    username = None
    try:
        try:
            raw = client_socket.recv(1024)
        except ConnectionResetError:
            client_socket.close()
            return

        if not raw:
            client_socket.close()
            return

        try:
            hello = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            if record_client_incident(ip, "Invalid hello JSON"):
                server_log(f"Blocking {ip} for repeated malformed hellos")
            client_socket.close()
            return

        username = str(hello.get("username", "unknown")).strip()
        if not username or len(username) > 32:
            record_client_incident(ip, "Suspicious username")
            client_socket.close()
            return

        with server_lock:
            if len(server_clients) >= MAX_CLIENTS:
                server_log("Max clients reached, rejecting new connection")
                client_socket.close()
                return
            server_clients[client_socket] = {"username": username, "addr": addr}

        server_log(f"Connection accepted: {username.upper()} @ {ip}:{port}")

        while True:
            try:
                data = client_socket.recv(MAX_MSG_SIZE)
            except (ConnectionResetError, OSError):
                break

            if not data:
                break

            if len(data) > MAX_MSG_SIZE:
                if record_client_incident(ip, "Message too large"):
                    server_log(f"Blocking {ip} due to oversized messages")
                break
                continue

            try:
                msg = json.loads(data.decode("utf-8"))
            except json.JSONDecodeError:
                if record_client_incident(ip, "Invalid JSON payload"):
                    server_log(f"Blocking {ip} due to repeated invalid JSON")
                break
                continue

            server_log(
                f"{msg.get('sender')} -> {msg.get('recipient')} "
                f"(cipher_len={len(msg.get('ciphertext', ''))})"
            )

            broadcast(msg, client_socket)
    finally:
        with server_lock:
            info = server_clients.pop(client_socket, None)
            if info:
                server_log(
                    f"Client disconnected: {info['username'].upper()} @ {ip}:{port}"
                )
        try:
            client_socket.close()
        except OSError:
            pass

def start_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((SERVER_HOST, SERVER_PORT))
    except OSError as e:
        server_log(f"Server bind failed on {SERVER_HOST}:{SERVER_PORT} :: {e}")
        srv.bind(("127.0.0.1", 0))
        host, port = srv.getsockname()
        server_log(f"Server fallback bind @ {host}:{port}")
    srv.listen(5)
    host, port = srv.getsockname()
    server_log(f"Server ONLINE @ {host}:{port}")

    while True:
        client_socket, addr = srv.accept()
        ip, _ = addr
        if client_incidents.get(ip, 0) >= BLOCK_THRESHOLD:
            log_incident(ip, "Rejected due to prior incidents")
            client_socket.close()
            continue
        t = threading.Thread(
            target=handle_client, args=(client_socket, addr), daemon=True
        )
        t.start()

# ===================== CLIENT GUI (SECURE TERMINAL) =====================

def is_admin():
    if sys.platform != "win32":
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

class SecureMessagingApp(tk.Toplevel):
    def __init__(
        self,
        master,
        username: str,
        recipient: str,
        passphrase: bytes | None = None,
        auth_token: str | None = None,
    ):
        super().__init__(master)
        self.username = username
        self.recipient = recipient
        self.auth_token = auth_token

        self.title(f"{APP_NAME} – Terminal [{self.username}]")
        self.geometry("1040x670")
        self.configure(bg=THEME["bg_main"])
        self.minsize(900, 600)

        self.private_key, self.public_key, self.priv_path, self.pub_path = (
            ensure_user_keypair(self.username, passphrase=passphrase)
        )

        recipient_dir = os.path.join(BASE_DIR, f"data_{self.recipient}")
        recipient_pub_path = os.path.join(recipient_dir, "public_key.pem")
        if os.path.exists(recipient_pub_path):
            self.recipient_public_key = load_public_key_from_file(recipient_pub_path)
        else:
            messagebox.showerror(
                "Key Error",
                f"No public key found for recipient '{self.recipient}'.\n"
                f"Have them open a terminal once so their keypair is generated.",
            )
            self.destroy()
            return

        self.sock = None
        self.running = False
        self.status_labels = {}

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.connect_to_server()

    # ----- UI BUILD -----

    def _build_ui(self):
        default_font = font.nametofont("TkDefaultFont")
        default_font.configure(size=10)

        top_bar = tk.Frame(self, bg=THEME["bg_panel"])
        top_bar.pack(fill="x")

        title_lbl = tk.Label(
            top_bar,
            text=":: SECURE TRANSMISSION CHANNEL ::",
            bg=THEME["bg_panel"],
            fg=THEME["accent_cyan"],
            font=("Consolas", 17, "bold"),
        )
        title_lbl.pack(side="left", padx=12, pady=8)

        info_btn = tk.Button(
            top_bar,
            text="ℹ️ INFO",
            command=self.show_project_info,
            bg=THEME["accent_orange"],
            fg=THEME["button_fg"],
            activebackground="#f59e0b",
            activeforeground=THEME["button_fg"],
            font=("Consolas", 10, "bold"),
            relief="flat",
            padx=12,
            pady=4,
        )
        info_btn.pack(side="right", padx=10, pady=8)

        id_chip = tk.Label(
            top_bar,
            text=f"SRC {self.username.upper()} → DEST {self.recipient.upper()}",
            bg=THEME["chip_bg"],
            fg=THEME["accent_magenta"],
            font=("Consolas", 10),
            padx=10,
            pady=3,
        )
        id_chip.pack(side="right", padx=(0, 10), pady=8)

        main_frame = tk.Frame(self, bg=THEME["bg_main"])
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        left_frame = tk.Frame(main_frame, bg=THEME["bg_panel"], bd=0, relief="ridge")
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 8))

        right_frame = tk.Frame(main_frame, bg=THEME["bg_panel_alt"], bd=0, relief="ridge", width=260)
        right_frame.pack(side="right", fill="y")

        self.chat_area = scrolledtext.ScrolledText(
            left_frame,
            state="disabled",
            wrap="word",
            bg="#020617",
            fg=THEME["text_primary"],
            insertbackground=THEME["accent_cyan"],
            relief="flat",
            borderwidth=0,
        )
        self.chat_area.pack(fill="both", expand=True, padx=6, pady=6)

        bottom = tk.Frame(self, bg=THEME["bg_main"])
        bottom.pack(fill="x", padx=10, pady=(0, 10))

        self.entry = tk.Entry(
            bottom,
            bg=THEME["entry_bg"],
            fg=THEME["entry_fg"],
            insertbackground=THEME["accent_cyan"],
            highlightthickness=1,
            highlightbackground=THEME["entry_border"],
            highlightcolor=THEME["accent_cyan"],
            relief="flat",
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=4)
        self.entry.bind("<Return>", lambda e: self.send_message())

        send_btn = tk.Button(
            bottom,
            text="TRANSMIT ▷",
            command=self.send_message,
            bg=THEME["button_bg"],
            fg=THEME["button_fg"],
            activebackground=THEME["button_bg_hover"],
            activeforeground=THEME["button_fg"],
            font=("Consolas", 11, "bold"),
            relief="flat",
            padx=16,
            pady=4,
        )
        send_btn.pack(side="right")

        header = tk.Label(
            right_frame,
            text="SYSTEM STATUS",
            bg=THEME["bg_panel_alt"],
            fg=THEME["accent_cyan"],
            font=("Consolas", 12, "bold"),
        )
        header.pack(pady=(10, 6))

        underline = tk.Frame(right_frame, bg=THEME["accent_cyan"], height=1)
        underline.pack(fill="x", padx=10, pady=(0, 8))

        def add_status_row(label_text, key, accent=False):
            row = tk.Frame(right_frame, bg=THEME["bg_panel_alt"])
            row.pack(anchor="w", padx=10, pady=3, fill="x")
            tk.Label(
                row,
                text=f"{label_text}",
                bg=THEME["bg_panel_alt"],
                fg=THEME["text_dim"],
                font=("Consolas", 9),
            ).pack(side="left")
            val_lbl = tk.Label(
                row,
                text="",
                bg=THEME["bg_panel_alt"],
                fg=(THEME["accent_cyan"] if accent else THEME["text_primary"]),
                font=("Consolas", 9, "bold"),
                anchor="e",
            )
            val_lbl.pack(side="right", fill="x", expand=True)
            self.status_labels[key] = val_lbl

        add_status_row("SOURCE NODE", "agent", True)
        add_status_row("DEST NODE", "target", True)
        add_status_row("NODE", "node")
        add_status_row("CONNECTION", "connection", True)
        add_status_row("PROTOCOL", "protocol")
        add_status_row("E2EE", "e2ee", True)

        sec_header = tk.Label(
            right_frame,
            text="SECURITY",
            bg=THEME["bg_panel_alt"],
            fg=THEME["accent_magenta"],
            font=("Consolas", 11, "bold"),
        )
        sec_header.pack(pady=(14, 4))

        self.sec_info = tk.Label(
            right_frame,
            text="RSA‑2048 · OAEP‑SHA256\nPSS signatures · local key vault",
            bg=THEME["bg_panel_alt"],
            fg=THEME["text_muted"],
            justify="left",
            font=("Consolas", 9),
        )
        self.sec_info.pack(padx=10, pady=4, anchor="w")

        self.status_labels["agent"].config(text=self.username.upper())
        self.status_labels["target"].config(text=self.recipient.upper())
        self.status_labels["node"].config(text=f"{SERVER_HOST}:{SERVER_PORT}")
        self.status_labels["connection"].config(text="[PENDING]", fg=THEME["accent_orange"])
        self.status_labels["protocol"].config(text=PROTOCOL_STR)
        self.status_labels["e2ee"].config(text="[PENDING]", fg=THEME["accent_orange"])

        self.status_var = tk.StringVar(value="Disconnected")
        status_bar = tk.Label(
            self,
            textvariable=self.status_var,
            anchor="w",
            bg="#020617",
            fg=THEME["accent_cyan"],
            font=("Consolas", 9),
        )
        status_bar.pack(fill="x")

    def show_project_info(self):
        """Open project info HTML in default browser"""
        ensure_info_html()
        webbrowser.open(f"file://{os.path.abspath(INFO_HTML_PATH)}")

    # ----- SAFE UI HELPERS -----

    def _safe_set_status_label(self, key, text=None, fg=None):
        lbl = self.status_labels.get(key)
        if not lbl or not self.winfo_exists() or not lbl.winfo_exists():
            return
        cfg = {}
        if text is not None:
            cfg["text"] = text
        if fg is not None:
            cfg["fg"] = fg
        lbl.config(**cfg)

    def _safe_set_status_text(self, text):
        if not self.winfo_exists():
            return
        self.status_var.set(text)

    def _safe_log(self, text, log_cipher=None):
        if not self.winfo_exists():
            return
        self.chat_area.configure(state="normal")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.chat_area.insert("end", f"[{ts}] {text}\n")
        self.chat_area.configure(state="disabled")
        self.chat_area.see("end")
        if log_cipher is not None:
            client_log(f"{self.username} (cipher): {log_cipher}")
        else:
            client_log(f"{self.username}: {text}")

    # ----- NETWORK -----

    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_HOST, SERVER_PORT))
            hello_payload = {"username": self.username}
            if self.auth_token:
                hello_payload["auth"] = self.auth_token
            hello = json.dumps(hello_payload).encode("utf-8")
            self.sock.sendall(hello)
            self.running = True
            threading.Thread(target=self.recv_loop, daemon=True).start()
            self.after(0, self._safe_set_status_text, f"Online – {APP_NAME}")
            self.after(
                0,
                self._safe_log,
                "Quantum channel secured. Target key acquisition pending.",
            )
            self.after(
                0,
                self._safe_set_status_label,
                "connection",
                "[CONNECTED]",
                THEME["accent_green"],
            )
            self.after(
                0,
                self._safe_set_status_label,
                "e2ee",
                "[ACTIVE]",
                THEME["accent_green"],
            )
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect: {e}")
            self.destroy()

    def recv_loop(self):
        while self.running:
            try:
                data = self.sock.recv(MAX_MSG_SIZE)
            except (ConnectionResetError, OSError):
                break

            if not data:
                break

            try:
                msg = json.loads(data.decode("utf-8"))
            except Exception:
                continue

            if msg.get("recipient") != self.username:
                continue

            cipher_b64 = msg.get("ciphertext")
            sig_b64 = msg.get("signature")
            sender = msg.get("sender")

            try:
                ciphertext = base64.b64decode(cipher_b64.encode("utf-8"))
                signature = base64.b64decode(sig_b64.encode("utf-8"))
                plaintext = decrypt_with_private(ciphertext, self.private_key)

                sender_dir = os.path.join(BASE_DIR, f"data_{sender}")
                sender_pub_path = os.path.join(sender_dir, "public_key.pem")
                if os.path.exists(sender_pub_path):
                    sender_pub = load_public_key_from_file(sender_pub_path)
                else:
                    sender_pub = self.public_key

                if verify_signature(plaintext, signature, sender_pub):
                    self.after(
                        0, self._safe_log, f"{sender}: {plaintext}", cipher_b64
                    )
                else:
                    self.after(
                        0,
                        self._safe_log,
                        f"WARNING: Invalid signature from {sender}",
                    )
                    log_incident("remote", f"Invalid signature claimed from {sender}")
            except Exception as e:
                self.after(
                    0,
                    self._safe_log,
                    f"Decrypt error from {sender}: {type(e).__name__}: {e}",
                )
                log_incident("remote", f"Decrypt error from {sender}: {e}")

        self.after(0, self._safe_set_status_text, "Disconnected")
        self.after(
            0,
            self._safe_set_status_label,
            "connection",
            "[OFFLINE]",
            THEME["accent_orange"],
        )
        self.after(
            0,
            self._safe_set_status_label,
            "e2ee",
            "[INACTIVE]",
            THEME["accent_orange"],
        )

    def send_message(self):
        text = self.entry.get().strip()
        if not text:
            return

        try:
            ciphertext = encrypt_for_recipient(text, self.recipient_public_key)
            signature = sign_message(text, self.private_key)

            cipher_b64 = base64.b64encode(ciphertext).decode("utf-8")
            payload = {
                "sender": self.username,
                "recipient": self.recipient,
                "ciphertext": cipher_b64,
                "signature": base64.b64encode(signature).decode("utf-8"),
            }
            self.sock.sendall(json.dumps(payload).encode("utf-8"))
            self.after(0, self._safe_log, f"You: {text}", cipher_b64)
            self.entry.delete(0, "end")
        except Exception as e:
            self.after(0, self._safe_log, f"Send failed: {e}")

    def on_close(self):
        self.running = False
        try:
            if self.sock:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.sock.close()
        finally:
            if self.winfo_exists():
                self.destroy()

# ===================== SPLASH SCREEN =====================

class SplashScreen(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.overrideredirect(True)
        self.configure(bg=THEME["bg_main"])

        self.update_idletasks()
        w, h = 420, 260
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 3
        self.geometry(f"{w}x{h}+{x}+{y}")

        title = tk.Label(
            self,
            text=APP_NAME,
            fg=THEME["accent_cyan"],
            bg=THEME["bg_main"],
            font=("Consolas", 26, "bold"),
        )
        title.pack(pady=(40, 8))

        tagline = tk.Label(
            self,
            text="initialising secure relay node...",
            fg=THEME["text_muted"],
            bg=THEME["bg_main"],
            font=("Consolas", 11),
        )
        tagline.pack(pady=(0, 10))

        bar = tk.Label(
            self,
            text="■■■■■■■■■■",
            fg=THEME["accent_magenta"],
            bg=THEME["bg_main"],
            font=("Consolas", 11, "bold"),
        )
        bar.pack(pady=(10, 0))

        self.attributes("-alpha", 0.0)
        self._fade_in_step(0.0)
        self.after(2500, self._start_close)

    def _fade_in_step(self, alpha):
        if alpha >= 1.0:
            self.attributes("-alpha", 1.0)
            return
        self.attributes("-alpha", alpha)
        self.after(40, self._fade_in_step, alpha + 0.08)

    def _start_close(self):
        self._fade_out_step(1.0)

    def _fade_out_step(self, alpha):
        if alpha <= 0.0:
            self.destroy()
            self.parent.deiconify()
            return
        self.attributes("-alpha", alpha)
        self.after(40, self._fade_out_step, alpha - 0.08)

# ===================== LAUNCHER GUI (SERVER + LAUNCH) =====================

class LauncherApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("640x430")
        self.configure(bg=THEME["bg_main"])
        self.resizable(False, False)

        threading.Thread(target=start_server, daemon=True).start()

        self._build_ui()
        self.after(1000, self.update_status)

    def _build_ui(self):
        title_lbl = tk.Label(
            self,
            text=f"{APP_NAME}",
            fg=THEME["accent_cyan"],
            bg=THEME["bg_main"],
            font=("Consolas", 26, "bold"),
        )
        title_lbl.pack(pady=16)

        frame_status = tk.Frame(self, bg=THEME["bg_panel"], bd=0, relief="ridge")
        frame_status.pack(fill="x", padx=20, pady=8)

        self.status_var = tk.StringVar(value="Server OFFLINE")
        lbl_status = tk.Label(
            frame_status,
            textvariable=self.status_var,
            fg=THEME["accent_green"],
            bg=THEME["bg_panel"],
            font=("Consolas", 13),
        )
        lbl_status.pack(side="left", padx=12, pady=10)

        info_btn = tk.Button(
            frame_status,
            text="ℹ️ INFO",
            command=self.show_project_info,
            bg=THEME["accent_orange"],
            fg=THEME["button_fg"],
            activebackground="#f59e0b",
            activeforeground=THEME["button_fg"],
            font=("Consolas", 10, "bold"),
            relief="flat",
            padx=12,
            pady=3,
        )
        info_btn.pack(side="right", padx=12)

        self.online_btn = tk.Label(
            frame_status,
            text="OFFLINE",
            fg=THEME["button_fg"],
            bg=THEME["accent_orange"],
            font=("Consolas", 11, "bold"),
            width=10,
            padx=4,
            pady=3,
        )
        self.online_btn.pack(side="right", padx=(0, 12))

        frame_inputs = tk.Frame(self, bg=THEME["bg_panel"], bd=0, relief="ridge")
        frame_inputs.pack(fill="x", padx=20, pady=14)

        lbl_deploy = tk.Label(
            frame_inputs,
            text="DEPLOY SECURED TERMINAL",
            fg=THEME["accent_magenta"],
            bg=THEME["bg_panel"],
            font=("Consolas", 14, "bold"),
        )
        lbl_deploy.pack(pady=(10, 10))

        inner = tk.Frame(frame_inputs, bg=THEME["bg_panel"])
        inner.pack(pady=5, padx=10, fill="x")

        tk.Label(
            inner, text="SOURCE NODE", fg=THEME["text_muted"], bg=THEME["bg_panel"],
            font=("Consolas", 11)
        ).grid(row=0, column=0, sticky="w", pady=5)
        tk.Label(
            inner, text="DESTINATION NODE", fg=THEME["text_muted"], bg=THEME["bg_panel"],
            font=("Consolas", 11)
        ).grid(row=1, column=0, sticky="w", pady=5)

        self.agent_entry = tk.Entry(
            inner,
            fg=THEME["entry_fg"],
            bg=THEME["entry_bg"],
            insertbackground=THEME["accent_cyan"],
            font=("Consolas", 11),
            width=26,
            relief="flat",
            highlightthickness=1,
            highlightbackground=THEME["entry_border"],
            highlightcolor=THEME["accent_cyan"],
        )
        self.agent_entry.grid(row=0, column=1, pady=5, padx=10)
        self.target_entry = tk.Entry(
            inner,
            fg=THEME["entry_fg"],
            bg=THEME["entry_bg"],
            insertbackground=THEME["accent_cyan"],
            font=("Consolas", 11),
            width=26,
            relief="flat",
            highlightthickness=1,
            highlightbackground=THEME["entry_border"],
            highlightcolor=THEME["accent_cyan"],
        )
        self.target_entry.grid(row=1, column=1, pady=5, padx=10)

        self.passphrase_enabled = tk.BooleanVar(value=False)
        chk_pass = tk.Checkbutton(
            frame_inputs,
            text="Protect keys with passphrase",
            variable=self.passphrase_enabled,
            fg=THEME["text_primary"],
            bg=THEME["bg_panel"],
            activebackground=THEME["bg_panel"],
            selectcolor=THEME["bg_panel"],
            font=("Consolas", 10),
        )
        chk_pass.pack(pady=(4, 2), anchor="w", padx=14)

        self.auth_enabled = tk.BooleanVar(value=AUTH_REQUIRED)
        chk_auth = tk.Checkbutton(
            frame_inputs,
            text="Require launcher auth token",
            variable=self.auth_enabled,
            fg=THEME["text_primary"],
            bg=THEME["bg_panel"],
            activebackground=THEME["bg_panel"],
            selectcolor=THEME["bg_panel"],
            font=("Consolas", 10),
        )
        chk_auth.pack(pady=(0, 6), anchor="w", padx=14)

        launch_btn = tk.Button(
            frame_inputs,
            text="LAUNCH TERMINAL ▷",
            command=self.launch_terminal,
            fg=THEME["button_fg"],
            bg=THEME["button_bg"],
            activebackground=THEME["button_bg_hover"],
            activeforeground=THEME["button_fg"],
            font=("Consolas", 13, "bold"),
            width=22,
            relief="flat",
            pady=4,
        )
        launch_btn.pack(pady=(10, 12))

        lbl_logs = tk.Label(
            self,
            text=f"Logs: {LOG_DIR}",
            fg=THEME["text_dim"],
            bg=THEME["bg_main"],
            font=("Consolas", 9),
            anchor="w",
        )
        lbl_logs.pack(fill="x", padx=20, pady=(0, 8))

    def show_project_info(self):
        """Open project info HTML in default browser"""
        ensure_info_html()
        webbrowser.open(f"file://{os.path.abspath(INFO_HTML_PATH)}")

    def update_status(self):
        self.status_var.set(f"Server ONLINE @ {SERVER_HOST}:{SERVER_PORT} 🔒")
        self.online_btn.config(text="ONLINE", bg=THEME["accent_green"])

    def launch_terminal(self):
        agent = self.agent_entry.get().strip()
        target = self.target_entry.get().strip()

        if not agent or not target:
            messagebox.showerror("Input Required", "Enter both SOURCE and DESTINATION nodes.")
            return

        if len(agent) > 32 or len(target) > 32:
            messagebox.showerror("Input Error", "IDs must be <= 32 characters.")
            return

        passphrase_bytes = None
        if self.passphrase_enabled.get():
            passphrase = simpledialog.askstring(
                "Key Passphrase",
                "Enter passphrase to protect/load your private key:",
                show="*",
                parent=self,
            )
            if passphrase is None:
                return
            passphrase_bytes = passphrase.encode("utf-8")

        auth_token = None
        if self.auth_enabled.get():
            auth_token = simpledialog.askstring(
                "Launcher Auth",
                "Enter launcher auth token:",
                show="*",
                parent=self,
            )
            if auth_token is None or not auth_token.strip():
                messagebox.showerror("Auth Required", "Auth token is required.")
                return

        win = SecureMessagingApp(
            self, agent, target, passphrase=passphrase_bytes, auth_token=auth_token
        )
        win.transient(self)
        win.lift()

# ===================== ENTRY POINT =====================

def main():
    ensure_info_html()  # Ensure YOUR info.html exists on startup
    
    if sys.platform == "win32" and not is_admin():
        messagebox.showerror(
            "Administrator Privileges Recommended",
            "Administrator privileges may be required to bind to\n"
            "the configured network port or write logs in some directories.\n"
            "Run the script or IDE as administrator if you encounter issues.",
        )

    launcher = LauncherApp()
    launcher.withdraw()
    SplashScreen(launcher)
    launcher.mainloop()

if __name__ == "__main__":
    main()