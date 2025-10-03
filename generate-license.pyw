import os, sys, time, socket, subprocess, webbrowser, json
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter import font as tkfont

try:
    # Python 3
    from urllib.request import urlopen, Request
except Exception:
    urlopen = None
    Request = None

ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(ROOT, 'backend.log')
DEFAULT_PORT = int(os.environ.get('PORT', '3000') or '3000')

# UI colors to match site style (dark + neon accents)
BG = '#0b0f1a'
PANEL = '#0e1424'
FIELD_BG = '#0e1424'
FG = '#e2e8f0'
MUTED = '#94a3b8'
ACCENT = '#22d3ee'   # cyan
ACCENT_ALT = '#7c3aed'  # violet


def load_env_file(path):
    data = {}
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                if '=' in s:
                    k, v = s.split('=', 1)
                    data[k.strip()] = v.strip()
    except Exception:
        pass
    return data


def port_in_use(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.25)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except Exception:
        return False


def find_port():
    for p in range(DEFAULT_PORT, DEFAULT_PORT + 6):
        if not port_in_use(p):
            return p
    return DEFAULT_PORT


def wait_health(base_url, timeout=20):
    """Check service health using common endpoints, tolerating cold starts."""
    if urlopen is None:
        return False
    start = time.time()
    base = base_url.rstrip('/')
    paths = ['/health', '/healthz', '/status']
    per_req_timeout = 2.0
    while time.time() - start < timeout:
        for p in paths:
            url = base + p
            try:
                with urlopen(url, timeout=per_req_timeout) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                # try next path
                pass
        time.sleep(0.6)
    return False


def have_cmd(cmd):
    try:
        subprocess.check_call(f'where {cmd}', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
        return True
    except Exception:
        return False


def ensure_npm_install():
    backend_dir = os.path.join(ROOT, 'backend')
    if os.path.exists(os.path.join(backend_dir, 'package.json')) and not os.path.exists(os.path.join(backend_dir, 'node_modules')):
        try:
            subprocess.check_call(['npm', 'install', '--no-audit', '--no-fund'], cwd=backend_dir, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception:
            pass


def node_version_ok():
    try:
        out = subprocess.check_output('node -v', shell=True, stderr=subprocess.STDOUT)
        v = out.decode().strip().lstrip('v')
        major = int(v.split('.')[0])
        return (major >= 18, v)
    except Exception:
        return (False, None)


def start_backend(port, admin_secret, loaded_env):
    env = os.environ.copy()
    for k, v in (loaded_env or {}).items():
        env[k] = v
    env['PORT'] = str(port)
    if admin_secret:
        env['ADMIN_SECRET'] = admin_secret
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    logf = None
    try:
        logf = open(LOG_FILE, 'a', encoding='utf-8', errors='ignore')
        try:
            logf.write(f"\n=== License Generator Launch {time.strftime('%Y-%m-%d %H:%M:%S')} PORT={port} ===\n")
            logf.flush()
        except Exception:
            pass
    except Exception:
        logf = None
    return subprocess.Popen(
        ['node', os.path.join(ROOT, 'backend', 'server.js')],
        cwd=ROOT,
        env=env,
        creationflags=flags,
        stdout=(logf or subprocess.DEVNULL),
        stderr=(logf or subprocess.DEVNULL)
    )


def http_post_json(url, body, headers):
    if urlopen is None or Request is None:
        raise RuntimeError('Python stdlib HTTP not available')
    data = json.dumps(body).encode('utf-8')
    hdrs = {'Content-Type': 'application/json'}
    if headers:
        hdrs.update(headers)
    req = Request(url, data=data, headers=hdrs, method='POST')
    with urlopen(req, timeout=15) as resp:
        text = resp.read().decode('utf-8', errors='ignore')
        return resp.getcode(), text


class App:
    def __init__(self, root):
        self.root = root
        root.title('Generate AuraSync License Code')
        root.geometry('640x400')
        root.minsize(620, 380)
        root.resizable(True, True)

        # Global styles
        root.configure(bg=BG)
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure('.', background=BG, foreground=FG)
        style.configure('Neon.TLabel', background=BG, foreground=FG)
        style.configure('Muted.TLabel', background=BG, foreground=MUTED)
        style.configure('Neon.TEntry', fieldbackground=FIELD_BG, foreground=FG)
        style.configure('Neon.TCombobox', fieldbackground=FIELD_BG, foreground=FG)
        style.map('Neon.TButton', background=[('active', '#172133')], foreground=[('disabled', '#64748b')])
        style.configure('Neon.TButton', padding=8)

        # Tweak default font a bit larger
        try:
            base_font = tkfont.nametofont('TkDefaultFont')
            base_font.configure(size=10)
            root.option_add('*Font', base_font)
        except Exception:
            pass

        # Window icon (if present)
        try:
            icon_path = None
            for p in [os.path.join(ROOT, 'logo', 'icon_only.png'), os.path.join(ROOT, 'icon_only.png'), os.path.join(ROOT, 'icons transparent', 'icon_16.png')]:
                if os.path.exists(p):
                    icon_path = p
                    break
            if icon_path:
                img = tk.PhotoImage(file=icon_path)
                root.iconphoto(True, img)
        except Exception:
            pass

        env = load_env_file(os.path.join(ROOT, '.env'))
        # Default testing credentials so you don't have to type them each run
        self.admin_secret = tk.StringVar(value=env.get('ADMIN_SECRET', '') or 'mick-aurasync')
        # Default to production API; can switch to localhost if desired
        default_base = 'https://api.aurasync.info'
        self.api_base = tk.StringVar(value=default_base)
        # Prefill a test customer email for convenience
        self.email = tk.StringVar(value='slotman.chiel@gmail.com')
        self.plan = tk.StringVar(value='premium')
        self.code_out = tk.StringVar(value='')

        # Card container
        card = tk.Frame(root, bg=PANEL, bd=0, highlightthickness=1, highlightbackground='#1f2937')
        card.pack(padx=16, pady=16, fill=tk.BOTH, expand=True)
        # Make middle column expand
        try:
            for i in range(3):
                card.grid_columnconfigure(i, weight=(1 if i == 1 else 0))
        except Exception:
            pass

        title = tk.Label(card, text='Generate License Code', bg=PANEL, fg=FG, font=('Segoe UI', 13, 'bold'))
        title.grid(row=0, column=0, columnspan=3, sticky='w', padx=12, pady=(12, 6))

        # API Base
        tk.Label(card, text='API Base URL', bg=PANEL, fg=FG).grid(row=1, column=0, sticky='w', padx=12)
        self.api_entry = ttk.Entry(card, textvariable=self.api_base, style='Neon.TEntry')
        self.api_entry.grid(row=1, column=1, sticky='we', pady=4)
        ttk.Button(card, text='Health', command=self.check_health, style='Neon.TButton', width=10).grid(row=1, column=2, padx=10)

        # Admin secret
        tk.Label(card, text='Admin Secret', bg=PANEL, fg=FG).grid(row=2, column=0, sticky='w', padx=12)
        self.secret_entry = ttk.Entry(card, textvariable=self.admin_secret, show='*', style='Neon.TEntry')
        self.secret_entry.grid(row=2, column=1, sticky='we', pady=4)
        ttk.Button(card, text='Show', command=self.toggle_secret, style='Neon.TButton', width=10).grid(row=2, column=2, padx=10)

        # Email
        tk.Label(card, text='Customer Email', bg=PANEL, fg=FG).grid(row=3, column=0, sticky='w', padx=12)
        ttk.Entry(card, textvariable=self.email, style='Neon.TEntry').grid(row=3, column=1, sticky='we', pady=4)

        # Plan
        tk.Label(card, text='Plan', bg=PANEL, fg=FG).grid(row=4, column=0, sticky='w', padx=12)
        cb = ttk.Combobox(card, textvariable=self.plan, values=['premium','monthly','yearly','lifetime','extra'], state='readonly', style='Neon.TCombobox')
        cb.grid(row=4, column=1, sticky='we', pady=4)
        cb.current(0)

        # Buttons
        btn_row = tk.Frame(card, bg=PANEL)
        btn_row.grid(row=5, column=0, columnspan=3, pady=12, sticky='w', padx=12)
        ttk.Button(btn_row, text='Generate Code', command=self.generate_code, style='Neon.TButton').pack(side=tk.LEFT, padx=(0,8))
        ttk.Button(btn_row, text='Start Local Server', command=self.start_local, style='Neon.TButton').pack(side=tk.LEFT)

        # Output
        tk.Label(card, text='Generated Code', bg=PANEL, fg=FG).grid(row=6, column=0, sticky='w', padx=12)
        self.code_entry = ttk.Entry(card, textvariable=self.code_out, style='Neon.TEntry')
        try:
            mono = tkfont.Font(family='Consolas', size=12, weight='bold')
            self.code_entry.configure(font=mono)
        except Exception:
            pass
        self.code_entry.grid(row=6, column=1, sticky='we', pady=4)
        ttk.Button(card, text='Copy', command=self.copy_code, style='Neon.TButton', width=10).grid(row=6, column=2, padx=10, sticky='w')

        # Footer
        tk.Label(card, text='Uses production API by default: https://api.aurasync.info  •  Keep the admin secret safe.', bg=PANEL, fg=MUTED, anchor='w').grid(row=7, column=0, columnspan=3, sticky='we', padx=12, pady=(8,12))

        # Track if we started a local server to stop it on close
        self.proc = None
        root.protocol('WM_DELETE_WINDOW', self.on_close)

    def toggle_secret(self):
        # Toggle masking of the specific admin secret entry
        try:
            cur = self.secret_entry.cget('show')
            self.secret_entry.configure(show='' if cur == '*' else '*')
        except Exception:
            pass

    def check_health(self):
        base = self.api_base.get().strip()
        # Give Render a bit more time in case of cold start
        is_local = base.startswith('http://127.0.0.1') or base.startswith('http://localhost')
        ok = wait_health(base, timeout=(5 if is_local else 12))
        messagebox.showinfo('Health', f'{base}/health -> {"OK" if ok else "Not reachable"}')

    def start_local(self):
        base = self.api_base.get().strip()
        if not base.startswith('http://127.0.0.1') and not base.startswith('http://localhost'):
            messagebox.showinfo('AuraSync', 'Local start is only for http://localhost or http://127.0.0.1. Change API Base first.')
            return
        # Ensure Node/npm present
        if not have_cmd('node'):
            messagebox.showerror('AuraSync', 'Node.js is required to run the local server. Install from https://nodejs.org/')
            return
        if not have_cmd('npm'):
            messagebox.showerror('AuraSync', 'npm is required. It comes with the Node.js installer.')
            return
        ok_ver, node_ver = node_version_ok()
        if not ok_ver:
            messagebox.showerror('AuraSync', f'Node 18+ is required. Detected: {node_ver or "unknown"}.')
            return
        ensure_npm_install()
        # Determine port from base URL
        try:
            port = int(base.rsplit(':', 1)[-1])
        except Exception:
            port = DEFAULT_PORT
        env = load_env_file(os.path.join(ROOT, '.env'))
        secret = self.admin_secret.get().strip() or env.get('ADMIN_SECRET') or 'changeme'
        self.proc = start_backend(port, secret, env)
        if wait_health(base, timeout=25):
            messagebox.showinfo('AuraSync', f'Local server running on {base}')
        else:
            try:
                self.proc.terminate()
            except Exception:
                pass
            self.proc = None
            # Surface last log lines
            tail = ''
            try:
                with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    tail = ''.join(f.readlines()[-20:])
            except Exception:
                pass
            messagebox.showerror('AuraSync', 'Failed to start local server. See backend.log for details.\n\n' + (tail[-800:] if tail else ''))

    def generate_code(self):
        base = self.api_base.get().strip().rstrip('/')
        email = (self.email.get() or '').strip()
        plan = (self.plan.get() or 'premium').strip().lower()
        secret = (self.admin_secret.get() or '').strip()
        if not email or '@' not in email:
            messagebox.showerror('AuraSync', 'Enter a valid customer email.')
            return
        if not base:
            messagebox.showerror('AuraSync', 'Enter the API Base URL.')
            return
        if not secret:
            messagebox.showerror('AuraSync', 'Enter the Admin Secret.')
            return
        # Ensure server reachable (allow longer for production cold starts)
        is_local = base.startswith('http://127.0.0.1') or base.startswith('http://localhost')
        if not wait_health(base, timeout=(5 if is_local else 15)):
            if base.startswith('http://127.0.0.1') or base.startswith('http://localhost'):
                if messagebox.askyesno('AuraSync', 'Local server not reachable. Start it now?'):
                    self.start_local()
                    if not wait_health(base, timeout=5):
                        return
                else:
                    return
            else:
                # For production, offer a longer wait in case the service is cold starting
                if messagebox.askyesno('AuraSync', f'Server not reachable at {base} yet. Wait up to 30s and try again?'):
                    if not wait_health(base, timeout=30):
                        messagebox.showerror('AuraSync', f'Server not reachable at {base}.')
                        return
                else:
                    return
        url = base + '/admin/grant-license'
        body = { 'email': email, 'plan': plan }
        headers = { 'X-Admin-Secret': secret }
        try:
            status, text = http_post_json(url, body, headers)
            data = json.loads(text or '{}') if text else {}
        except Exception as e:
            messagebox.showerror('AuraSync', f'HTTP error: {e}')
            return
        if status != 200:
            err = (data.get('error') if isinstance(data, dict) else None) or f'status {status}'
            messagebox.showerror('AuraSync', f'Failed: {err}')
            return
        code = (data or {}).get('code')
        if not code:
            message = (data.get('error') if isinstance(data, dict) else None) or 'No code returned.'
            messagebox.showerror('AuraSync', f'Failed: {message}')
            return
        self.code_out.set(code)
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(code)
        except Exception:
            pass
        messagebox.showinfo('AuraSync', 'License code generated and copied to clipboard.')

    def copy_code(self):
        code = self.code_out.get().strip()
        if not code:
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(code)
            messagebox.showinfo('AuraSync', 'Copied to clipboard.')
        except Exception:
            pass

    def on_close(self):
        try:
            if self.proc:
                self.proc.terminate()
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == '__main__':
    main()
