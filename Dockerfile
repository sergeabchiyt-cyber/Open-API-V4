FROM python:3.11-slim

# syntax=docker/dockerfile:1.4

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn[standard] httpx pycryptodome jinja2

RUN mkdir -p /app/templates

# ==== decrypt.py ====
RUN cat <<'PYEOF' > /app/decrypt.py
import json
import gzip
import base64
import time
import logging
from typing import Any, Dict
from urllib.parse import urlparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_KEY_TABLE = {
    "55": "170b070da9654622",
    "66": "d6537d845a964081",
    "77": "863f08689c97435b",
}

def _derive_key0(v: str, url: str = "") -> str:
    if v == "1":
        constant = urlparse(url).path or url.split("?")[0]
    else:
        constant = _KEY_TABLE.get(v)
        if constant is None:
            raise ValueError(f"Unknown v={v}")
    return base64.b64encode(constant.encode()).decode()[:16]

def decrypt(encrypted_body: str, user_token_b64: str, v: str, url: str = "") -> Dict[str, Any]:
    outer = json.loads(encrypted_body)
    payload = base64.b64decode(outer["data"])
    token = base64.b64decode(user_token_b64)
    key0 = _derive_key0(v, url)
    step1 = unpad(AES.new(key0.encode(), AES.MODE_ECB).decrypt(token), 16)
    actual_key = gzip.decompress(step1).decode()
    step2 = unpad(AES.new(actual_key.encode(), AES.MODE_ECB).decrypt(payload), 16)
    plain = gzip.decompress(step2).decode()
    return json.loads(plain)

async def fetch_and_decrypt(url: str, params: dict = None, timeout: int = 10.0) -> Dict[str, Any]:
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "cache-ts-v2": str(int(time.time() * 1000)),
        "encryption": "true",
        "language": "en",
        "Origin": "https://www.coinglass.com",
        "Referer": "https://www.coinglass.com",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0.0.0 Safari/537.36",
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(url, params=params or {}, headers=headers)
        resp.raise_for_status()
        
        user = resp.headers.get("user")
        v = resp.headers.get("v")
        
        if not user or not v:
            try:
                return resp.json()
            except Exception:
                return {"raw": resp.text}
                
        return decrypt(resp.text, user, v, url)
PYEOF

# ==== main.py ====
RUN cat <<'PYEOF' > /app/main.py
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from decrypt import fetch_and_decrypt
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Crypto Terminal Pro")
templates = Jinja2Templates(directory="/app/templates")

def extract_data(raw):
    if isinstance(raw, list): return raw
    if isinstance(raw, dict):
        for key in ["list", "topInflowList", "inflowList", "rankList", "coins"]:
            if key in raw and isinstance(raw[key], list):
                return raw[key]
        if "data" in raw:
            d = raw["data"]
            if isinstance(d, list): return d
            if isinstance(d, dict):
                for key in ["list", "topInflowList", "inflowList", "rankList", "coins"]:
                    if key in d and isinstance(d[key], list):
                        return d[key]
    return []

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {"active_page": "dashboard"})

@app.get("/api-docs", response_class=HTMLResponse)
async def api_docs(request: Request):
    return templates.TemplateResponse(request, "docs.html", {"active_page": "docs"})

@app.get("/api/rsi")
async def get_rsi():
    try:
        data = await fetch_and_decrypt("https://capi.coinglass.com/api/spot/rsi/list", {"pageSize": 500, "pageNum": 1})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/funding")
async def get_funding():
    try:
        data = await fetch_and_decrypt("https://capi.coinglass.com/api/fundingRate/list", {"pageSize": 100, "pageNum": 1})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/liquidation")
async def get_liquidation():
    try:
        data = await fetch_and_decrypt("https://capi.coinglass.com/api/futures/liquidation/today", {"symbol": "BTC"})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/openinterest")
async def get_oi():
    try:
        data = await fetch_and_decrypt("https://capi.coinglass.com/api/openInterest/statistics", {})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/etf")
async def get_etf():
    try:
        data = await fetch_and_decrypt("https://capi.coinglass.com/api/etf/overview", {})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/marketcap")
async def get_marketcap():
    try:
        data = await fetch_and_decrypt("https://capi.coinglass.com/api/marketCapRank", {"pageSize": 100})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
PYEOF

# ==== templates/dashboard.html ====
RUN cat <<'HTMLEOF' > /app/templates/dashboard.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Crypto Terminal Pro</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #05070d; --bg-elev: #0a0d16; --bg-card: rgba(17, 21, 34, 0.6);
  --border: rgba(255, 255, 255, 0.08); --border-hover: rgba(0, 229, 192, 0.3);
  --accent: #00f0a8; --accent-2: #3b82f6; 
  --text: #f8fafc; --text-muted: #64748b;
  --danger: #ff4757; --success: #2ed573; --warning: #ffa502;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); overflow-x: hidden; -webkit-font-smoothing: antialiased; }
.mono { font-family: 'JetBrains Mono', monospace; }
.mesh-bg { position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background: radial-gradient(ellipse 60% 40% at 10% 20%, rgba(0,240,168,0.05) 0%, transparent 50%), 
              radial-gradient(ellipse 50% 30% at 90% 80%, rgba(59,130,246,0.05) 0%, transparent 50%); }
.glass { background: var(--bg-card); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid var(--border); border-radius: 16px; transition: all 0.3s ease; }
.glass:hover { border-color: var(--border-hover); box-shadow: 0 8px 32px rgba(0, 240, 168, 0.05); }
@keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
.skeleton { background: linear-gradient(90deg, rgba(255,255,255,0.03) 25%, rgba(255,255,255,0.06) 50%, rgba(255,255,255,0.03) 75%); background-size: 200% 100%; animation: shimmer 1.5s infinite; border-radius: 8px; }
.nav-link { padding: 8px 16px; border-radius: 10px; font-size: 13px; font-weight: 500; color: var(--text-muted); transition: all 0.2s; }
.nav-link:hover { color: var(--text); background: rgba(255,255,255,0.05); }
.nav-link.active { color: var(--accent); background: rgba(0,240,168,0.1); }
.tab-btn { padding: 8px 16px; border-radius: 10px; font-size: 12px; font-weight: 600; color: var(--text-muted); background: transparent; border: 1px solid transparent; cursor: pointer; transition: all 0.2s; }
.tab-btn:hover { color: var(--text); background: rgba(255,255,255,0.03); }
.tab-btn.active { color: var(--accent); background: rgba(0,240,168,0.08); border-color: rgba(0,240,168,0.2); }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; padding: 14px 16px; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); border-bottom: 1px solid var(--border); position: sticky; top: 0; background: var(--bg-elev); }
td { padding: 12px 16px; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,0.04); }
tr:hover td { background: rgba(255,255,255,0.02); }
.badge { padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; display: inline-block; }
.badge-red { background: rgba(255,71,87,0.1); color: var(--danger); }
.badge-green { background: rgba(46,213,115,0.1); color: var(--success); }
.badge-neutral { background: rgba(255,255,255,0.05); color: var(--text-muted); }
.panel { display: none; animation: fadeIn 0.3s ease; }
.panel.active { display: block; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
input[type="text"] { background: var(--bg-elev); border: 1px solid var(--border); border-radius: 10px; padding: 8px 14px; color: var(--text); outline: none; font-size: 13px; width: 100%; }
input[type="text"]:focus { border-color: var(--accent); }
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
::-webkit-scrollbar-track { background: transparent; }
.debug-pre { background: #05070d; border: 1px solid var(--border); border-radius: 8px; padding: 16px; font-size: 11px; color: #8b95a8; max-height: 400px; overflow: auto; }
.collapse-btn { cursor: pointer; transition: transform 0.2s; }
.collapse-btn.open { transform: rotate(180deg); }
</style>
</head>
<body>
<div class="mesh-bg"></div>

<nav class="sticky top-0 z-50 border-b border-[var(--border)]" style="background: rgba(5,7,13,0.85); backdrop-filter: blur(20px);">
  <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
    <div class="flex items-center gap-8">
      <div class="flex items-center gap-2.5">
        <div class="w-8 h-8 rounded-lg flex items-center justify-center" style="background: linear-gradient(135deg, var(--accent), var(--accent-2));">
          <svg class="w-5 h-5 text-black" fill="currentColor" viewBox="0 0 24 24"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        </div>
        <span class="text-lg font-bold tracking-tight">Crypto<span style="color: var(--accent);">Terminal</span></span>
      </div>
      <div class="flex items-center gap-2">
        <a href="/" class="nav-link {{ 'active' if active_page == 'dashboard' else '' }}">Dashboard</a>
        <a href="/api-docs" class="nav-link {{ 'active' if active_page == 'docs' else '' }}">API Reference</a>
      </div>
    </div>
    <div class="flex items-center gap-4">
      <div class="flex items-center gap-2 text-xs mono">
        <span class="w-2 h-2 rounded-full bg-[var(--success)] animate-pulse"></span>
        <span style="color: var(--success);">LIVE</span>
      </div>
    </div>
  </div>
</nav>

<main class="max-w-7xl mx-auto px-6 py-8 relative z-10">
  
  <div class="flex items-center justify-between mb-8">
    <div>
      <h1 class="text-3xl font-bold tracking-tight mb-1">Crypto Market Overview</h1>
      <p class="text-sm text-[var(--text-muted)]">Real-time decrypted crypto intelligence. Pure async. No caching.</p>
    </div>
    <div class="mono text-xs text-[var(--text-muted)]" id="lastUpdate">--:--:--</div>
  </div>

  <div class="flex gap-2 mb-6 overflow-x-auto pb-2">
    <button onclick="switchTab('rsi')" id="tab-rsi" class="tab-btn active">RSI Matrix</button>
    <button onclick="switchTab('funding')" id="tab-funding" class="tab-btn">Funding Rates</button>
    <button onclick="switchTab('liquidation')" id="tab-liquidation" class="tab-btn">Liquidations</button>
    <button onclick="switchTab('openinterest')" id="tab-openinterest" class="tab-btn">Open Interest</button>
    <button onclick="switchTab('etf')" id="tab-etf" class="tab-btn">ETF Flows</button>
    <button onclick="switchTab('marketcap')" id="tab-marketcap" class="tab-btn">Market Cap</button>
  </div>

  <!-- RSI Tab -->
  <div id="panel-rsi" class="panel active">
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
      <div class="glass p-6 lg:col-span-2">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-base font-semibold">RSI 4h Extremes (Top 15 Overbought / Oversold)</h2>
          <input type="text" id="rsiSearch" placeholder="Search asset..." class="w-48" oninput="filterRsi()">
        </div>
        <div style="height: 360px;"><canvas id="rsiChart"></canvas></div>
      </div>
      <div class="glass p-6">
        <h2 class="text-base font-semibold mb-4">Market Stats</h2>
        <div class="space-y-4" id="rsiStats">
          <div class="skeleton h-12"></div><div class="skeleton h-12"></div><div class="skeleton h-12"></div>
        </div>
      </div>
    </div>
    <div class="glass overflow-hidden mb-6">
      <div class="p-4 border-b border-[var(--border)] flex justify-between items-center">
        <h2 class="text-base font-semibold">All Assets</h2>
        <span class="mono text-xs text-[var(--text-muted)]" id="rsiCount">0 assets</span>
      </div>
      <div class="overflow-x-auto" style="max-height: 400px;">
        <table>
          <thead><tr><th>#</th><th>Asset</th><th class="text-right">Price</th><th class="text-right">RSI 1h</th><th class="text-right">RSI 4h</th><th class="text-right">RSI 24h</th></tr></thead>
          <tbody id="rsiTable"><tr><td colspan="6" class="p-8 text-center text-[var(--text-muted)]">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>
    <div class="glass p-4">
      <div class="flex items-center gap-3 cursor-pointer" onclick="toggleDebug('rsiDebug')">
        <svg class="w-4 h-4 collapse-btn open" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
        <span class="text-sm font-semibold">Raw JSON Network Response</span>
      </div>
      <pre id="rsiDebug" class="debug-pre mt-4"></pre>
    </div>
  </div>

  <!-- Funding Tab -->
  <div id="panel-funding" class="panel">
    <div class="glass p-6 mb-6">
      <h2 class="text-base font-semibold mb-4">Funding Rate Extremes (Top 50)</h2>
      <div style="height: 360px;"><canvas id="fundingChart"></canvas></div>
    </div>
    <div class="glass overflow-hidden mb-6">
      <div class="p-4 border-b border-[var(--border)]"><h2 class="text-base font-semibold">All Funding Rates</h2></div>
      <div class="overflow-x-auto" style="max-height: 400px;">
        <table>
          <thead><tr><th>Exchange</th><th>Asset</th><th class="text-right">Rate</th><th class="text-right">Next Funding</th></tr></thead>
          <tbody id="fundingTable"><tr><td colspan="4" class="p-8 text-center text-[var(--text-muted)]">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>
    <div class="glass p-4">
      <div class="flex items-center gap-3 cursor-pointer" onclick="toggleDebug('fundingDebug')">
        <svg class="w-4 h-4 collapse-btn open" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
        <span class="text-sm font-semibold">Raw JSON Network Response</span>
      </div>
      <pre id="fundingDebug" class="debug-pre mt-4"></pre>
    </div>
  </div>

  <!-- Liquidation Tab -->
  <div id="panel-liquidation" class="panel">
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
      <div class="glass p-6"><h2 class="text-base font-semibold mb-4">Long vs Short</h2><div style="height: 350px;"><canvas id="liqChart"></canvas></div></div>
      <div class="glass p-6"><h2 class="text-base font-semibold mb-4">Details</h2><div id="liqRaw" class="text-xs mono overflow-auto h-80 p-4 rounded-lg" style="background: var(--bg-elev); border: 1px solid var(--border);"></div></div>
    </div>
    <div class="glass p-4">
      <div class="flex items-center gap-3 cursor-pointer" onclick="toggleDebug('liqDebug')">
        <svg class="w-4 h-4 collapse-btn open" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
        <span class="text-sm font-semibold">Raw JSON Network Response</span>
      </div>
      <pre id="liqDebug" class="debug-pre mt-4"></pre>
    </div>
  </div>

  <!-- Open Interest Tab -->
  <div id="panel-openinterest" class="panel">
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
      <div class="glass p-6"><h2 class="text-base font-semibold mb-4">Open Interest History</h2><div style="height: 350px;"><canvas id="oiChart"></canvas></div></div>
      <div class="glass p-6"><h2 class="text-base font-semibold mb-4">Details</h2><div id="oiRaw" class="text-xs mono overflow-auto h-80 p-4 rounded-lg" style="background: var(--bg-elev); border: 1px solid var(--border);"></div></div>
    </div>
    <div class="glass p-4">
      <div class="flex items-center gap-3 cursor-pointer" onclick="toggleDebug('oiDebug')">
        <svg class="w-4 h-4 collapse-btn open" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
        <span class="text-sm font-semibold">Raw JSON Network Response</span>
      </div>
      <pre id="oiDebug" class="debug-pre mt-4"></pre>
    </div>
  </div>

  <!-- ETF Tab -->
  <div id="panel-etf" class="panel">
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
      <div class="glass p-6"><h2 class="text-base font-semibold mb-4">ETF Inflow/Outflow Distribution</h2><div style="height: 350px;"><canvas id="etfChart"></canvas></div></div>
      <div class="glass overflow-hidden">
        <div class="p-4 border-b border-[var(--border)]"><h2 class="text-base font-semibold">ETF Details</h2></div>
        <div class="overflow-x-auto" style="max-height: 350px;">
          <table>
            <thead><tr><th>Logo</th><th>Ticker</th><th>Coin</th><th class="text-right">Change (USD)</th></tr></thead>
            <tbody id="etfTable"><tr><td colspan="4" class="p-8 text-center text-[var(--text-muted)]">Loading...</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>
    <div class="glass p-4">
      <div class="flex items-center gap-3 cursor-pointer" onclick="toggleDebug('etfDebug')">
        <svg class="w-4 h-4 collapse-btn open" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
        <span class="text-sm font-semibold">Raw JSON Network Response</span>
      </div>
      <pre id="etfDebug" class="debug-pre mt-4"></pre>
    </div>
  </div>

  <!-- Market Cap Tab -->
  <div id="panel-marketcap" class="panel">
    <div class="glass p-6 mb-6"><h2 class="text-base font-semibold mb-4">Crypto Market Cap (Top 20)</h2><div style="height: 350px;"><canvas id="mcChart"></canvas></div></div>
    <div class="glass overflow-hidden mb-6">
      <div class="p-4 border-b border-[var(--border)]"><h2 class="text-base font-semibold">Crypto Market Cap Rankings</h2></div>
      <div class="overflow-x-auto" style="max-height: 400px;">
        <table>
          <thead><tr><th>#</th><th>Asset</th><th class="text-right">Price</th><th class="text-right">Market Cap</th><th class="text-right">24h Vol</th></tr></thead>
          <tbody id="mcTable"><tr><td colspan="5" class="p-8 text-center text-[var(--text-muted)]">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>
    <div class="glass p-4">
      <div class="flex items-center gap-3 cursor-pointer" onclick="toggleDebug('mcDebug')">
        <svg class="w-4 h-4 collapse-btn open" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
        <span class="text-sm font-semibold">Raw JSON Network Response</span>
      </div>
      <pre id="mcDebug" class="debug-pre mt-4"></pre>
    </div>
  </div>

</main>

<script>
const charts = {};
let allRsi = [];

function toggleDebug(id) {
  const el = document.getElementById(id);
  const btn = el.previousElementSibling.querySelector('.collapse-btn');
  if (el.style.display === 'none' || el.style.display === '') {
    el.style.display = 'block';
    btn.classList.add('open');
  } else {
    el.style.display = 'none';
    btn.classList.remove('open');
  }
}

function switchTab(tab) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.add('active');
  document.getElementById('panel-' + tab).classList.add('active');
  
  if (tab === 'rsi') loadRsi();
  if (tab === 'funding') loadFunding();
  if (tab === 'liquidation') loadLiq();
  if (tab === 'openinterest') loadOI();
  if (tab === 'etf') loadETF();
  if (tab === 'marketcap') loadMC();
}

function gv(obj, keys, fb) { for (const k of keys) if (obj && obj[k] !== undefined) return obj[k]; return fb; }
function fmtP(p) { p = parseFloat(p); if (isNaN(p)) return '--'; if (p >= 1000) return '$' + p.toLocaleString('en', {maximumFractionDigits: 2}); if (p >= 1) return '$' + p.toFixed(2); return '$' + p.toFixed(6); }
function fmtN(n) { n = parseFloat(n); if (isNaN(n)) return '--'; if (n >= 1e12) return (n/1e12).toFixed(2) + 'T'; if (n >= 1e9) return (n/1e9).toFixed(2) + 'B'; if (n >= 1e6) return (n/1e6).toFixed(2) + 'M'; if (n >= 1e3) return (n/1e3).toFixed(2) + 'K'; return n.toFixed(2); }
function badge(v, t) { v = parseFloat(v); if (isNaN(v)) return '<span class="badge badge-neutral">--</span>'; if (t==='rsi') return v >= 70 ? `<span class="badge badge-red">${v.toFixed(1)}</span>` : v <= 30 ? `<span class="badge badge-green">${v.toFixed(1)}</span>` : `<span class="badge badge-neutral">${v.toFixed(1)}</span>`; if (t==='ch') return v > 0 ? `<span class="badge badge-green">+${v.toFixed(2)}%</span>` : `<span class="badge badge-red">${v.toFixed(2)}%</span>`; if (t==='fr') return v > 0 ? `<span class="badge badge-red">${(v*100).toFixed(4)}%</span>` : `<span class="badge badge-green">${(v*100).toFixed(4)}%</span>`; }
function extractArr(d) { if (Array.isArray(d)) return d; if (d && d.list) return d.list; if (d && d.topInflowList) return d.topInflowList; if (d && d.data && Array.isArray(d.data)) return d.data; return []; }

async function loadRsi() {
  try {
    const res = await fetch('/api/rsi');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    
    document.getElementById('rsiDebug').innerText = JSON.stringify(json.data, null, 2);
    allRsi = extractArr(json.data);
    document.getElementById('rsiCount').innerText = allRsi.length + ' assets';
    
    const high = allRsi.filter(c => parseFloat(gv(c, ['rsi4h','rsi_4h'], 0)) >= 70).slice(0, 15);
    const low = allRsi.filter(c => parseFloat(gv(c, ['rsi4h','rsi_4h'], 0)) <= 30).slice(0, 15);
    
    document.getElementById('rsiStats').innerHTML = `
      <div class="p-4 rounded-xl border border-[var(--border)] flex justify-between items-center"><span class="text-sm text-[var(--text-muted)]">Overbought (>=70)</span><span class="mono text-lg" style="color: var(--danger);">${high.length}</span></div>
      <div class="p-4 rounded-xl border border-[var(--border)] flex justify-between items-center"><span class="text-sm text-[var(--text-muted)]">Oversold (<=30)</span><span class="mono text-lg" style="color: var(--success);">${low.length}</span></div>
      <div class="p-4 rounded-xl border border-[var(--border)] flex justify-between items-center"><span class="text-sm text-[var(--text-muted)]">Total Tracked</span><span class="mono text-lg">${allRsi.length}</span></div>
    `;
    
    filterRsi();
    
    if (charts.rsi) charts.rsi.destroy();
    charts.rsi = new Chart(document.getElementById('rsiChart'), {
      type: 'bar',
      data: {
        labels: [...high, ...low].map(c => gv(c, ['symbol','s'], '?')),
        datasets: [{
          label: 'RSI 4h',
          data: [...high, ...low].map(c => parseFloat(gv(c, ['rsi4h','rsi_4h'], 0))),
          backgroundColor: [...high, ...low].map(c => parseFloat(gv(c, ['rsi4h','rsi_4h'], 0)) >= 70 ? 'rgba(255,71,87,0.6)' : 'rgba(46,213,115,0.6)'),
          borderRadius: 6
        }]
      },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { max: 100, min: 0, grid: { color: 'rgba(255,255,255,0.05)' } }, x: { grid: { display: false }, ticks: { font: { size: 10 } } } } }
    });
    
    document.getElementById('lastUpdate').innerText = new Date().toLocaleTimeString();
  } catch(e) { console.error(e); }
}

function filterRsi() {
  const q = document.getElementById('rsiSearch').value.toLowerCase();
  const f = allRsi.filter(c => gv(c, ['symbol','s'], '').toLowerCase().includes(q)).slice(0, 100);
  document.getElementById('rsiTable').innerHTML = f.map((c, i) => `
    <tr><td class="mono text-xs text-[var(--text-muted)]">${i+1}</td><td class="font-medium">${gv(c, ['symbol','s'], '??')}</td><td class="text-right mono">${fmtP(gv(c, ['price','p'], 0))}</td><td class="text-right">${badge(gv(c, ['rsi1h','rsi_1h'], 0), 'rsi')}</td><td class="text-right">${badge(gv(c, ['rsi4h','rsi_4h'], 0), 'rsi')}</td><td class="text-right">${badge(gv(c, ['rsi24h','rsi_24h'], 0), 'rsi')}</td></tr>
  `).join('');
}

async function loadFunding() {
  try {
    const res = await fetch('/api/funding');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    document.getElementById('fundingDebug').innerText = JSON.stringify(json.data, null, 2);
    const coins = extractArr(json.data);
    let rows = [];
    coins.forEach(c => { Object.values(c).forEach(v => { if (Array.isArray(v)) v.forEach(e => { if (e && 'fundingRate' in e) rows.push(e); }); }); });
    
    document.getElementById('fundingTable').innerHTML = rows.slice(0,100).map(e => `
      <tr><td class="font-medium">${gv(e, ['exName'], '??')}</td><td>${gv(e, ['symbol'], '??')}</td><td class="text-right">${badge(gv(e, ['fundingRate'], 0), 'fr')}</td><td class="text-right mono text-xs text-[var(--text-muted)]">${e.nextFundingTime ? new Date(e.nextFundingTime).toLocaleString() : '--'}</td></tr>
    `).join('');
    
    const top = [...rows].sort((a,b) => Math.abs(parseFloat(b.fundingRate)) - Math.abs(parseFloat(a.fundingRate))).slice(0, 50);
    if (charts.funding) charts.funding.destroy();
    charts.funding = new Chart(document.getElementById('fundingChart'), {
      type: 'bar',
      data: { labels: top.map(e => gv(e,['symbol'],'?')), datasets: [{ data: top.map(e => parseFloat(e.fundingRate)*100), backgroundColor: top.map(e => parseFloat(e.fundingRate) > 0 ? 'rgba(255,71,87,0.6)' : 'rgba(46,213,115,0.6)'), borderRadius: 4 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { callback: v => v + '%' } }, x: { grid: { display: false }, ticks: { font: { size: 10 } } } } }
    });
  } catch(e) { console.error(e); }
}

async function loadLiq() {
  try {
    const res = await fetch('/api/liquidation');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const d = json.data;
    document.getElementById('liqRaw').innerText = JSON.stringify(d, null, 2);
    document.getElementById('liqDebug').innerText = JSON.stringify(d, null, 2);
    if (charts.liq) charts.liq.destroy();
    charts.liq = new Chart(document.getElementById('liqChart'), {
      type: 'doughnut',
      data: { labels: ['Long', 'Short'], datasets: [{ data: [gv(d, ['longLiquidationUsd'], 1), gv(d, ['shortLiquidationUsd'], 1)], backgroundColor: ['rgba(46,213,115,0.6)', 'rgba(255,71,87,0.6)'], borderColor: 'transparent' }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '70%' }
    });
  } catch(e) { console.error(e); }
}

async function loadOI() {
  try {
    const res = await fetch('/api/openinterest');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const d = json.data;
    document.getElementById('oiRaw').innerText = JSON.stringify(d, null, 2);
    document.getElementById('oiDebug').innerText = JSON.stringify(d, null, 2);
    if (charts.oi) charts.oi.destroy();
    charts.oi = new Chart(document.getElementById('oiChart'), {
      type: 'line',
      data: { labels: (d.dateList||[]).map(t => new Date(t).toLocaleDateString()), datasets: [{ label: 'OI (USD)', data: d.openInterestList||[], borderColor: 'var(--accent)', backgroundColor: 'rgba(0,240,168,0.1)', fill: true, tension: 0.3, pointRadius: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, scales: { y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { callback: v => '$' + fmtN(v) } }, x: { grid: { display: false } } } }
    });
  } catch(e) { console.error(e); }
}

async function loadETF() {
  try {
    const res = await fetch('/api/etf');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const d = json.data;
    document.getElementById('etfDebug').innerText = JSON.stringify(d, null, 2);
    const etfList = extractArr(d);
    
    document.getElementById('etfTable').innerHTML = etfList.map(e => `
      <tr>
        <td><img src="${gv(e, ['coinLogo'], '')}" alt="logo" class="w-6 h-6 rounded-full" onerror="this.style.display='none'"></td>
        <td class="font-bold mono">${gv(e, ['ticker'], '??')}</td>
        <td>${gv(e, ['coinName'], '??')} (${gv(e, ['coinSymbol'], '??')})</td>
        <td class="text-right mono ${parseFloat(gv(e, ['changeUsd'], 0)) > 0 ? 'text-[var(--success)]' : 'text-[var(--danger)]'}">${fmtN(gv(e, ['changeUsd'], 0))}</td>
      </tr>
    `).join('');
    
    if (charts.etf) charts.etf.destroy();
    charts.etf = new Chart(document.getElementById('etfChart'), {
      type: 'bar',
      data: { labels: etfList.slice(0, 10).map(d => gv(d,['ticker'], '?')), datasets: [{ label: 'Change USD', data: etfList.slice(0, 10).map(d => parseFloat(gv(d,['changeUsd'], 0))), backgroundColor: etfList.slice(0, 10).map(d => parseFloat(gv(d,['changeUsd'], 0)) > 0 ? 'rgba(46,213,115,0.6)' : 'rgba(255,71,87,0.6)'), borderRadius: 4 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { ticks: { callback: v => '$' + fmtN(v) }, grid: { color: 'rgba(255,255,255,0.05)' } }, x: { grid: { display: false } } } }
    });
  } catch(e) { console.error(e); }
}

async function loadMC() {
  try {
    const res = await fetch('/api/marketcap');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    document.getElementById('mcDebug').innerText = JSON.stringify(json.data, null, 2);
    let d = extractArr(json.data);
    
    // Filter out traditional assets (Gold, NVDA, AAPL, etc.) that CoinGlass includes for comparison
    const blacklist = ['Gold', 'Silver', 'Apple', 'Microsoft', 'NVIDIA', 'Amazon', 'Google', 'Meta', 'Tesla', 'S&P 500', 'SPY', 'Alphabet', 'Berkshire'];
    d = d.filter(c => {
      const name = gv(c, ['name', 'symbol', 'code', 's'], '').toLowerCase();
      return !blacklist.some(b => name.includes(b.toLowerCase()));
    });
    
    document.getElementById('mcTable').innerHTML = d.map((c,i) => `
      <tr><td class="mono text-xs text-[var(--text-muted)]">${i+1}</td><td class="font-medium">${gv(c,['symbol','code','s','name'], '??')}</td><td class="text-right mono">${fmtP(gv(c,['price','p'], 0))}</td><td class="text-right mono">$${fmtN(gv(c,['marketCap','market_cap','mc'], 0))}</td><td class="text-right mono text-[var(--text-muted)]">$${fmtN(gv(c,['volume24h','vol'], 0))}</td></tr>
    `).join('');
    
    if (charts.mc) charts.mc.destroy();
    charts.mc = new Chart(document.getElementById('mcChart'), {
      type: 'bar',
      data: { labels: d.slice(0,20).map(c => gv(c,['symbol','code','s','name'],'?')), datasets: [{ data: d.slice(0,20).map(c => parseFloat(gv(c,['marketCap','market_cap','mc'], 0))), backgroundColor: 'rgba(0,240,168,0.6)', borderRadius: 4 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { ticks: { callback: v => '$' + fmtN(v) }, grid: { color: 'rgba(255,255,255,0.05)' } }, x: { grid: { display: false } } } }
    });
  } catch(e) { console.error(e); }
}

// Initial load
loadRsi();
setInterval(() => { if(document.getElementById('panel-rsi').classList.contains('active')) loadRsi(); }, 60000);
</script>
</body>
</html>
HTMLEOF

# ==== templates/docs.html ====
RUN cat <<'HTMLEOF' > /app/templates/docs.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Reference - Crypto Terminal</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root { --bg: #05070d; --bg-card: rgba(17, 21, 34, 0.6); --border: rgba(255, 255, 255, 0.08); --accent: #00f0a8; --text: #f8fafc; --text-muted: #64748b; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); }
.mono { font-family: 'JetBrains Mono', monospace; }
.glass { background: var(--bg-card); backdrop-filter: blur(16px); border: 1px solid var(--border); border-radius: 16px; }
.nav-link { padding: 8px 16px; border-radius: 10px; font-size: 13px; font-weight: 500; color: var(--text-muted); transition: all 0.2s; }
.nav-link:hover { color: var(--text); background: rgba(255,255,255,0.05); }
.nav-link.active { color: var(--accent); background: rgba(0,240,168,0.1); }
.endpoint-card { transition: all 0.3s ease; }
.endpoint-card:hover { border-color: rgba(0,240,168,0.3); }
.method-get { background: rgba(46, 213, 115, 0.1); color: #2ed573; border: 1px solid rgba(46, 213, 115, 0.2); }
::-webkit-scrollbar { width: 6px; height: 6px; } ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
</style>
</head>
<body>

<nav class="sticky top-0 z-50 border-b border-[var(--border)]" style="background: rgba(5,7,13,0.7); backdrop-filter: blur(20px);">
  <div class="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between">
    <div class="flex items-center gap-8">
      <div class="flex items-center gap-2.5">
        <div class="w-8 h-8 rounded-lg flex items-center justify-center" style="background: linear-gradient(135deg, var(--accent), #3b82f6);">
          <svg class="w-5 h-5 text-black" fill="currentColor" viewBox="0 0 24 24"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        </div>
        <span class="text-lg font-bold tracking-tight">Crypto<span style="color: var(--accent);">Terminal</span></span>
      </div>
      <div class="flex items-center gap-2">
        <a href="/" class="nav-link {{ 'active' if active_page == 'dashboard' else '' }}">Dashboard</a>
        <a href="/api-docs" class="nav-link {{ 'active' if active_page == 'docs' else '' }}">API Reference</a>
      </div>
    </div>
  </div>
</nav>

<main class="max-w-5xl mx-auto px-6 py-12">
  <div class="mb-12">
    <h1 class="text-4xl font-bold tracking-tight mb-3">API Reference</h1>
    <p class="text-[var(--text-muted)] text-lg">Real-time decrypted crypto endpoints. Native async Python. No caching layer.</p>
  </div>

  <div class="space-y-6">
    <div class="glass p-6 endpoint-card">
      <div class="flex items-center gap-3 mb-3">
        <span class="method-get mono text-xs font-bold px-2 py-1 rounded">GET</span>
        <code class="mono text-sm text-[var(--accent)]">/api/rsi</code>
      </div>
      <p class="text-sm text-[var(--text-muted)] mb-4">Returns RSI (Relative Strength Index) data for 500+ crypto assets across multiple timeframes (1h, 4h, 24h).</p>
    </div>

    <div class="glass p-6 endpoint-card">
      <div class="flex items-center gap-3 mb-3">
        <span class="method-get mono text-xs font-bold px-2 py-1 rounded">GET</span>
        <code class="mono text-sm text-[var(--accent)]">/api/funding</code>
      </div>
      <p class="text-sm text-[var(--text-muted)] mb-4">Perpetual futures funding rates aggregated across all major exchanges.</p>
    </div>

    <div class="glass p-6 endpoint-card">
      <div class="flex items-center gap-3 mb-3">
        <span class="method-get mono text-xs font-bold px-2 py-1 rounded">GET</span>
        <code class="mono text-sm text-[var(--accent)]">/api/liquidation</code>
      </div>
      <p class="text-sm text-[var(--text-muted)] mb-4">24-hour liquidation volumes for BTC, broken down by long and short positions.</p>
    </div>

    <div class="glass p-6 endpoint-card">
      <div class="flex items-center gap-3 mb-3">
        <span class="method-get mono text-xs font-bold px-2 py-1 rounded">GET</span>
        <code class="mono text-sm text-[var(--accent)]">/api/openinterest</code>
      </div>
      <p class="text-sm text-[var(--text-muted)] mb-4">Total open interest statistics and historical chart data.</p>
    </div>

    <div class="glass p-6 endpoint-card">
      <div class="flex items-center gap-3 mb-3">
        <span class="method-get mono text-xs font-bold px-2 py-1 rounded">GET</span>
        <code class="mono text-sm text-[var(--accent)]">/api/etf</code>
      </div>
      <p class="text-sm text-[var(--text-muted)] mb-4">Spot Bitcoin ETF flow data, including tickers, logos, and USD change.</p>
    </div>

    <div class="glass p-6 endpoint-card">
      <div class="flex items-center gap-3 mb-3">
        <span class="method-get mono text-xs font-bold px-2 py-1 rounded">GET</span>
        <code class="mono text-sm text-[var(--accent)]">/api/marketcap</code>
      </div>
      <p class="text-sm text-[var(--text-muted)] mb-4">Market cap rankings for the top 100 cryptocurrencies (traditional assets like Gold/NVDA are filtered out).</p>
    </div>
  </div>
</main>

</body>
</html>
HTMLEOF

EXPOSE 10000
CMD ["python", "/app/main.py"]