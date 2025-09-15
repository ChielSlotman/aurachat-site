import os, sys, time, socket, subprocess, threading, webbrowser, random, string
import tkinter as tk
from tkinter import messagebox
try:
    import urllib.request
except Exception:
    urllib = None

ROOT = os.path.dirname(os.path.abspath(__file__))
PORT_START = int(os.environ.get('PORT', '3000'))

def rand_hex(n=32):
    return ''.join(random.choice('0123456789abcdef') for _ in range(n))

def port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        return s.connect_ex(('127.0.0.1', port)) == 0

def find_port():
    for p in range(PORT_START, PORT_START + 6):
        if not port_in_use(p):
            return p
    return PORT_START

def wait_health(port, timeout=15):
    start = time.time()
    url = f'http://127.0.0.1:{port}/health'
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=0.8) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.4)
    return False

def have_cmd(cmd):
    try:
        # Use shell for Windows built-in 'where' command; pass as string
        subprocess.check_call(f'where {cmd}', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
        return True
    except Exception:
        return False

def ensure_npm_install():
    backend_dir = os.path.join(ROOT, 'backend')
    if os.path.exists(os.path.join(backend_dir, 'package.json')) and not os.path.exists(os.path.join(backend_dir, 'node_modules')):
        try:
            subprocess.check_call(['npm', 'install'], cwd=backend_dir, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception:
            pass

def start_backend(port, secret):
    env = os.environ.copy()
    env['PORT'] = str(port)
    env['ADMIN_SECRET'] = secret
    # Keep window hidden
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    return subprocess.Popen(['node', os.path.join(ROOT, 'backend', 'server.js')], cwd=ROOT, env=env, creationflags=flags)

def main():
    if not have_cmd('node'):
        messagebox.showerror('AuraSync', 'Node.js is required. Install from https://nodejs.org/')
        return
    if not have_cmd('npm'):
        messagebox.showerror('AuraSync', 'npm is required. It comes with Node.js installer.')
        return
    ensure_npm_install()

    port = find_port()
    secret = os.environ.get('ADMIN_SECRET') or rand_hex(24)
    proc = start_backend(port, secret)
    ok = wait_health(port, timeout=18)
    if not ok:
        try:
            proc.terminate()
        except Exception:
            pass
        messagebox.showerror('AuraSync', 'Backend did not start. Check your internet or try again.')
        return

    root = tk.Tk()
    root.title('AuraSync Admin Server')
    root.geometry('380x150')
    root.resizable(False, False)

    lbl = tk.Label(root, text=f'Server running on http://localhost:{port}', padx=10, pady=10)
    lbl.pack()

    def open_admin():
        url = f'http://localhost:{port}/admin/?sec={secret}'
        webbrowser.open(url, new=1)

    btn_row = tk.Frame(root)
    btn_row.pack(pady=6)
    tk.Button(btn_row, text='Open Admin', width=14, command=open_admin).pack(side=tk.LEFT, padx=6)
    def do_quit():
        try:
            proc.terminate()
        except Exception:
            pass
        root.destroy()
    tk.Button(btn_row, text='Quit', width=10, command=do_quit).pack(side=tk.LEFT, padx=6)

    # Auto-open once
    root.after(400, open_admin)
    root.mainloop()

if __name__ == '__main__':
    main()
