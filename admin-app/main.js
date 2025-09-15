// Minimal Electron wrapper to run the backend and open the Admin UI
const { app, BrowserWindow, dialog } = require('electron');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

// Ensure fetch exists in this process
const _fetch = (typeof fetch !== 'undefined') ? fetch : (...args) => import('node-fetch').then(({default: f}) => f(...args));

const PORT = process.env.PORT || 3000;
let runtimeSecret = process.env.ADMIN_SECRET || '';

async function waitForHealth(url, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await _fetch(url);
      if (res.ok) return true;
    } catch (_) {}
    await new Promise(r => setTimeout(r, 500));
  }
  return false;
}

function startServerInline() {
  if (!runtimeSecret) runtimeSecret = crypto.randomBytes(16).toString('hex');
  // Set env before requiring the backend so it picks up the secret and port
  process.env.PORT = String(PORT);
  process.env.ADMIN_SECRET = runtimeSecret;
  // Require the backend in-process
  const serverPath = path.join(__dirname, '..', 'backend', 'server.js');
  // eslint-disable-next-line global-require, import/no-dynamic-require
  require(serverPath);
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: { nodeIntegration: false, contextIsolation: true },
    title: 'AuraSync Admin',
    show: false,
  });
  const url = `http://localhost:${PORT}/admin/?sec=${encodeURIComponent(runtimeSecret)}`;
  win.loadURL(url);
  win.once('ready-to-show', () => win.show());
  win.on('closed', () => { /* noop */ });
}

app.whenReady().then(async () => {
  startServerInline();
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
  // No child process to kill when running inline
});
