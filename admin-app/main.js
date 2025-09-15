// Minimal Electron wrapper to run the backend and open the Admin UI
const { app, BrowserWindow, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
require('dotenv').config();

const PORT = process.env.PORT || 3000;
let serverProc = null;

async function waitForHealth(url, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return true;
    } catch (_) {}
    await new Promise(r => setTimeout(r, 500));
  }
  return false;
}

function startServer() {
  const nodePath = process.execPath; // current Node used by Electron
  const script = path.join(__dirname, '..', 'backend', 'server.js');
  serverProc = spawn(nodePath, [script], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT) },
    stdio: 'ignore',
    windowsHide: true,
    detached: false,
  });
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: { nodeIntegration: false, contextIsolation: true },
    title: 'AuraSync Admin',
    show: false,
  });
  const url = `http://localhost:${PORT}/admin/`;
  win.loadURL(url);
  win.once('ready-to-show', () => win.show());
  win.on('closed', () => { /* noop */ });
}

app.whenReady().then(async () => {
  startServer();
  const ok = await waitForHealth(`http://localhost:${PORT}/health`);
  if (!ok) {
    dialog.showErrorBox('AuraSync', 'Backend did not start in time. Please check logs or run backend/server.js manually.');
  }
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  try { if (serverProc && !serverProc.killed) serverProc.kill(); } catch (_) {}
});
