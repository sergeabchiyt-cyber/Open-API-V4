FROM python:3.11-slim

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
RUN pip install --no-cache-dir fastapi uvicorn[standard] requests pycryptodome jinja2

# ==== decrypt.py (from the repo) ====
RUN cat <<'PYEOF' > /app/decrypt.py
import json
import gzip
import base64
import time
from typing import Any, Dict
from urllib.parse import urlparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

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
            raise ValueError(f"Unknown v={v}, known: {list(_KEY_TABLE)} + [1]")
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

def fetch_and_decrypt(url: str, params: dict = None, timeout: int = 30) -> Dict[str, Any]:
    import requests
    resp = requests.get(
        url,
        params=params or {},
        headers={
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "cache-ts-v2": str(int(time.time() * 1000)),
            "encryption": "true",
            "language": "en",
            "Origin": "https://www.coinglass.com",
            "Referer": "https://www.coinglass.com",
            "Sec-Ch-Ua": '"Google Chrome";v="125", "Chromium";v="125"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0.0.0 Safari/537.36",
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    user = resp.headers.get("user")
    v = resp.headers.get("v")
    if not user or not v:
        raise ValueError("Missing user/v headers")
    return decrypt(resp.text, user, v, url)
PYEOF

# ==== FastAPI backend ====
RUN cat <<'PYEOF' > /app/main.py
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import json
from decrypt import fetch_and_decrypt
import asyncio
from concurrent.futures import ThreadPoolExecutor

app = FastAPI(title="CoinGlass Decrypt Dashboard")
executor = ThreadPoolExecutor(max_workers=4)

app.mount("/static", StaticFiles(directory="/app/static", check_dir=False), name="static")
templates = Jinja2Templates(directory="/app/templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/rsi")
async def get_rsi():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/spot/rsi/list",
            {"pageSize": 500, "pageNum": 1})
        return {"success": True, "data": data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/funding")
async def get_funding():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/fundingRate/list",
            {"pageSize": 100, "pageNum": 1})
        return {"success": True, "data": data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/liquidation")
async def get_liquidation():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/futures/liquidation/today", {})
        return {"success": True, "data": data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/openinterest")
async def get_oi():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/openInterest/statistics", {})
        return {"success": True, "data": data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/etf")
async def get_etf():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/etf/overview", {})
        return {"success": True, "data": data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/marketcap")
async def get_marketcap():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/marketCapRank",
            {"pageSize": 100})
        return {"success": True, "data": data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/futures-stats")
async def get_futures_stats():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/futures/home/statistics", {})
        return {"success": True, "data": data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
PYEOF

# ==== Create directories ====
RUN mkdir -p /app/static /app/templates

# ==== Beautiful Frontend HTML ====
RUN cat <<'HTMLEOF' > /app/templates/index.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CoinGlass Decrypt Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-primary: #0a0e1a;
    --bg-secondary: #111827;
    --bg-card: #1a1f2e;
    --bg-card-hover: #232a3b;
    --border: #2d3748;
    --accent: #00d4aa;
    --accent-dim: #00d4aa33;
    --accent-glow: #00d4aa66;
    --text-primary: #f0f4f8;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --danger: #ef4444;
    --danger-dim: #ef444433;
    --warning: #f59e0b;
    --warning-dim: #f59e0b33;
    --success: #22c55e;
    --success-dim: #22c55e33;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    overflow-x: hidden;
  }
  .mono { font-family: 'JetBrains Mono', monospace; }
  .bg-grid {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image:
      linear-gradient(rgba(0,212,170,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,170,0.03) 1px, transparent 1px);
    background-size: 50px 50px;
    pointer-events: none;
    z-index: 0;
  }
  .bg-glow {
    position: fixed;
    width: 600px; height: 600px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(0,212,170,0.08) 0%, transparent 70%);
    top: -200px; left: -200px;
    pointer-events: none;
    z-index: 0;
    animation: float 20s ease-in-out infinite;
  }
  .bg-glow-2 {
    position: fixed;
    width: 500px; height: 500px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(99,102,241,0.06) 0%, transparent 70%);
    bottom: -150px; right: -150px;
    pointer-events: none;
    z-index: 0;
    animation: float 25s ease-in-out infinite reverse;
  }
  @keyframes float {
    0%, 100% { transform: translate(0, 0); }
    50% { transform: translate(30px, 30px); }
  }
  .glass-card {
    background: rgba(26, 31, 46, 0.7);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(45, 55, 72, 0.6);
    border-radius: 16px;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .glass-card:hover {
    border-color: rgba(0, 212, 170, 0.3);
    box-shadow: 0 0 30px rgba(0, 212, 170, 0.08), 0 8px 32px rgba(0,0,0,0.3);
    transform: translateY(-2px);
  }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: #2d3748; border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: #4a5568; }
  @keyframes fadeInUp {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .animate-in { animation: fadeInUp 0.6s ease-out forwards; }
  .delay-1 { animation-delay: 0.1s; }
  .delay-2 { animation-delay: 0.2s; }
  .delay-3 { animation-delay: 0.3s; }
  .delay-4 { animation-delay: 0.4s; }
  @keyframes shimmer {
    0% { background-position: -200% 0; }
    100% { background-position: 200% 0; }
  }
  .shimmer {
    background: linear-gradient(90deg, #1a1f2e 25%, #232a3b 50%, #1a1f2e 75%);
    background-size: 200% 100%;
    animation: shimmer 1.5s infinite;
  }
  .tab-active {
    background: rgba(0, 212, 170, 0.15);
    color: var(--accent);
    border: 1px solid rgba(0, 212, 170, 0.3);
  }
  .table-row {
    transition: background 0.2s;
    border-bottom: 1px solid rgba(45, 55, 72, 0.4);
  }
  .table-row:hover {
    background: rgba(0, 212, 170, 0.04);
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
  .pulse-dot { animation: pulse 2s ease-in-out infinite; }
  .count-up { transition: all 0.5s ease-out; }
  .gradient-text {
    background: linear-gradient(135deg, #00d4aa 0%, #6366f1 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  .tooltip { position: relative; }
  .tooltip::after {
    content: attr(data-tip);
    position: absolute;
    bottom: 100%;
    left: 50%;
    transform: translateX(-50%);
    padding: 4px 8px;
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 6px;
    font-size: 11px;
    white-space: nowrap;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.2s;
    z-index: 100;
  }
  .tooltip:hover::after { opacity: 1; }
  @media (max-width: 768px) {
    .hide-mobile { display: none; }
  }
</style>
</head>
<body>
<div class="bg-grid"></div>
<div class="bg-glow"></div>
<div class="bg-glow-2"></div>

<div class="relative z-10 min-h-screen">
  <header class="border-b border-[#2d3748]/60 backdrop-blur-xl sticky top-0 z-50" style="background: rgba(10,14,26,0.8);">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-[#00d4aa] to-[#6366f1] flex items-center justify-center shadow-lg shadow-[#00d4aa]/20">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        </div>
        <div>
          <h1 class="text-xl font-bold tracking-tight">CoinGlass<span class="gradient-text">Decrypt</span></h1>
          <p class="text-xs text-[#64748b] mono">AES-128-ECB · 280+ Endpoints</p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#00d4aa]/10 border border-[#00d4aa]/20">
          <span class="w-2 h-2 rounded-full bg-[#00d4aa] pulse-dot"></span>
          <span class="text-xs text-[#00d4aa] font-medium mono">LIVE</span>
        </div>
        <div class="text-xs text-[#64748b] mono" id="lastUpdate">--:--:--</div>
      </div>
    </div>
  </header>

  <main class="max-w-7xl mx-auto px-4 sm:px-6 py-6">
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      <div class="glass-card p-4 animate-in">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-[#64748b] uppercase tracking-wider font-medium">Total Coins</span>
          <div class="w-8 h-8 rounded-lg bg-[#00d4aa]/10 flex items-center justify-center">
            <svg class="w-4 h-4 text-[#00d4aa]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l-3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3"/></svg>
          </div>
        </div>
        <div class="text-2xl font-bold mono" id="statTotalCoins">--</div>
        <div class="text-xs text-[#64748b] mt-1">Tracked by RSI</div>
      </div>
      <div class="glass-card p-4 animate-in delay-1">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-[#64748b] uppercase tracking-wider font-medium">Overbought</span>
          <div class="w-8 h-8 rounded-lg bg-[#ef4444]/10 flex items-center justify-center">
            <svg class="w-4 h-4 text-[#ef4444]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/></svg>
          </div>
        </div>
        <div class="text-2xl font-bold mono text-[#ef4444]" id="statOverbought">--</div>
        <div class="text-xs text-[#64748b] mt-1">RSI 4h ≥ 70</div>
      </div>
      <div class="glass-card p-4 animate-in delay-2">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-[#64748b] uppercase tracking-wider font-medium">Oversold</span>
          <div class="w-8 h-8 rounded-lg bg-[#22c55e]/10 flex items-center justify-center">
            <svg class="w-4 h-4 text-[#22c55e]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 17h8m0 0V9m0 8l-8-8-4 4-6-6"/></svg>
          </div>
        </div>
        <div class="text-2xl font-bold mono text-[#22c55e]" id="statOversold">--</div>
        <div class="text-xs text-[#64748b] mt-1">RSI 4h ≤ 30</div>
      </div>
      <div class="glass-card p-4 animate-in delay-3">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-[#64748b] uppercase tracking-wider font-medium">Neutral</span>
          <div class="w-8 h-8 rounded-lg bg-[#f59e0b]/10 flex items-center justify-center">
            <svg class="w-4 h-4 text-[#f59e0b]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 12H4"/></svg>
          </div>
        </div>
        <div class="text-2xl font-bold mono text-[#f59e0b]" id="statNeutral">--</div>
        <div class="text-xs text-[#64748b] mt-1">30 < RSI < 70</div>
      </div>
    </div>

    <div class="flex gap-2 mb-6 overflow-x-auto pb-2">
      <button onclick="switchTab('rsi')" id="tab-rsi" class="tab-active px-4 py-2 rounded-xl text-sm font-medium transition-all whitespace-nowrap">RSI Dashboard</button>
      <button onclick="switchTab('funding')" id="tab-funding" class="px-4 py-2 rounded-xl text-sm font-medium text-[#94a3b8] hover:text-white hover:bg-[#232a3b] transition-all whitespace-nowrap">Funding Rates</button>
      <button onclick="switchTab('liquidation')" id="tab-liquidation" class="px-4 py-2 rounded-xl text-sm font-medium text-[#94a3b8] hover:text-white hover:bg-[#232a3b] transition-all whitespace-nowrap">Liquidations</button>
      <button onclick="switchTab('marketcap')" id="tab-marketcap" class="px-4 py-2 rounded-xl text-sm font-medium text-[#94a3b8] hover:text-white hover:bg-[#232a3b] transition-all whitespace-nowrap">Market Cap</button>
      <button onclick="switchTab('futures')" id="tab-futures" class="px-4 py-2 rounded-xl text-sm font-medium text-[#94a3b8] hover:text-white hover:bg-[#232a3b] transition-all whitespace-nowrap">Futures Stats</button>
      <button onclick="switchTab('etf')" id="tab-etf" class="px-4 py-2 rounded-xl text-sm font-medium text-[#94a3b8] hover:text-white hover:bg-[#232a3b] transition-all whitespace-nowrap">ETF Flows</button>
    </div>

    <div id="panel-rsi" class="tab-panel">
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="lg:col-span-2 glass-card p-6">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-semibold">RSI 4h Distribution</h2>
            <div class="flex gap-2">
              <button onclick="sortRsi('rsi4h')" class="text-xs px-3 py-1 rounded-lg bg-[#232a3b] hover:bg-[#2d3748] transition">Sort 4h</button>
              <button onclick="sortRsi('rsi1h')" class="text-xs px-3 py-1 rounded-lg bg-[#232a3b] hover:bg-[#2d3748] transition">Sort 1h</button>
              <button onclick="sortRsi('rsi15m')" class="text-xs px-3 py-1 rounded-lg bg-[#232a3b] hover:bg-[#2d3748] transition">Sort 15m</button>
            </div>
          </div>
          <div class="h-64">
            <canvas id="rsiChart"></canvas>
          </div>
        </div>
        <div class="glass-card p-6">
          <h2 class="text-lg font-semibold mb-4">Extreme RSI</h2>
          <div class="space-y-3" id="extremeRsi">
            <div class="shimmer h-12 rounded-lg"></div>
            <div class="shimmer h-12 rounded-lg"></div>
            <div class="shimmer h-12 rounded-lg"></div>
          </div>
        </div>
      </div>
      <div class="glass-card mt-6 overflow-hidden">
        <div class="p-4 border-b border-[#2d3748]/60 flex items-center justify-between">
          <h2 class="text-lg font-semibold">All Coins RSI</h2>
          <div class="flex items-center gap-3">
            <input type="text" id="rsiSearch" placeholder="Search coin..." 
              class="bg-[#111827] border border-[#2d3748] rounded-lg px-3 py-1.5 text-sm text-white placeholder-[#64748b] focus:outline-none focus:border-[#00d4aa] transition w-48"
              oninput="filterRsiTable()">
            <span class="text-xs text-[#64748b]" id="rsiCount">0 coins</span>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-[#64748b] text-xs uppercase tracking-wider border-b border-[#2d3748]/60">
                <th class="px-4 py-3 text-left font-medium">#</th>
                <th class="px-4 py-3 text-left font-medium">Coin</th>
                <th class="px-4 py-3 text-right font-medium">Price</th>
                <th class="px-4 py-3 text-right font-medium">RSI 15m</th>
                <th class="px-4 py-3 text-right font-medium">RSI 1h</th>
                <th class="px-4 py-3 text-right font-medium">RSI 4h</th>
                <th class="px-4 py-3 text-right font-medium">RSI 24h</th>
                <th class="px-4 py-3 text-right font-medium hide-mobile">Change 24h</th>
              </tr>
            </thead>
            <tbody id="rsiTableBody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <div id="panel-funding" class="tab-panel hidden">
      <div class="glass-card overflow-hidden">
        <div class="p-4 border-b border-[#2d3748]/60">
          <h2 class="text-lg font-semibold">Funding Rates</h2>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-[#64748b] text-xs uppercase tracking-wider border-b border-[#2d3748]/60">
                <th class="px-4 py-3 text-left font-medium">Exchange</th>
                <th class="px-4 py-3 text-left font-medium">Coin</th>
                <th class="px-4 py-3 text-right font-medium">Rate</th>
                <th class="px-4 py-3 text-right font-medium">Annualized</th>
              </tr>
            </thead>
            <tbody id="fundingTableBody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <div id="panel-liquidation" class="tab-panel hidden">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="glass-card p-6">
          <h2 class="text-lg font-semibold mb-4">Today's Liquidations</h2>
          <div id="liquidationContent"></div>
        </div>
        <div class="glass-card p-6">
          <h2 class="text-lg font-semibold mb-4">Liquidation Chart</h2>
          <div class="h-64">
            <canvas id="liqChart"></canvas>
          </div>
        </div>
      </div>
    </div>

    <div id="panel-marketcap" class="tab-panel hidden">
      <div class="glass-card overflow-hidden">
        <div class="p-4 border-b border-[#2d3748]/60">
          <h2 class="text-lg font-semibold">Market Cap Rankings</h2>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-[#64748b] text-xs uppercase tracking-wider border-b border-[#2d3748]/60">
                <th class="px-4 py-3 text-left font-medium">#</th>
                <th class="px-4 py-3 text-left font-medium">Coin</th>
                <th class="px-4 py-3 text-right font-medium">Price</th>
                <th class="px-4 py-3 text-right font-medium">Market Cap</th>
                <th class="px-4 py-3 text-right font-medium">24h Change</th>
                <th class="px-4 py-3 text-right font-medium hide-mobile">Volume</th>
              </tr>
            </thead>
            <tbody id="marketcapTableBody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <div id="panel-futures" class="tab-panel hidden">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="futuresStatsGrid"></div>
    </div>

    <div id="panel-etf" class="tab-panel hidden">
      <div class="glass-card p-6">
        <h2 class="text-lg font-semibold mb-4">ETF Overview</h2>
        <div id="etfContent"></div>
      </div>
    </div>
  </main>
</div>

<script>
let allRsiData = [];
let currentRsiSort = 'rsi4h';
let charts = {};

function switchTab(tab) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
  document.getElementById('panel-' + tab).classList.remove('hidden');
  document.querySelectorAll('[id^="tab-"]').forEach(t => {
    t.classList.remove('tab-active');
    t.classList.add('text-[#94a3b8]');
  });
  document.getElementById('tab-' + tab).classList.add('tab-active');
  document.getElementById('tab-' + tab).classList.remove('text-[#94a3b8]');
  if (tab === 'funding' && !window.fundingLoaded) { loadFunding(); window.fundingLoaded = true; }
  if (tab === 'liquidation' && !window.liqLoaded) { loadLiquidation(); window.liqLoaded = true; }
  if (tab === 'marketcap' && !window.mcLoaded) { loadMarketcap(); window.mcLoaded = true; }
  if (tab === 'futures' && !window.futuresLoaded) { loadFutures(); window.futuresLoaded = true; }
  if (tab === 'etf' && !window.etfLoaded) { loadEtf(); window.etfLoaded = true; }
}

function getRsiColor(val) {
  const v = parseFloat(val);
  if (v >= 70) return '#ef4444';
  if (v <= 30) return '#22c55e';
  return '#94a3b8';
}
function getRsiBg(val) {
  const v = parseFloat(val);
  if (v >= 70) return 'rgba(239,68,68,0.15)';
  if (v <= 30) return 'rgba(34,197,94,0.15)';
  return 'transparent';
}
function getChangeColor(val) {
  const v = parseFloat(val);
  if (v > 0) return '#22c55e';
  if (v < 0) return '#ef4444';
  return '#94a3b8';
}
function formatPrice(p) {
  const price = parseFloat(p);
  if (price >= 1000) return '$' + price.toLocaleString('en', {minimumFractionDigits: 2, maximumFractionDigits: 2});
  if (price >= 1) return '$' + price.toFixed(4);
  return '$' + price.toFixed(6);
}
function formatNumber(n) {
  const num = parseFloat(n);
  if (num >= 1e12) return (num/1e12).toFixed(2) + 'T';
  if (num >= 1e9) return (num/1e9).toFixed(2) + 'B';
  if (num >= 1e6) return (num/1e6).toFixed(2) + 'M';
  if (num >= 1e3) return (num/1e3).toFixed(2) + 'K';
  return num.toFixed(2);
}

async function loadRsi() {
  try {
    const res = await fetch('/api/rsi');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    allRsiData = json.data.list || [];
    document.getElementById('statTotalCoins').textContent = allRsiData.length;
    const high = allRsiData.filter(c => parseFloat(c.rsi4h || 0) >= 70);
    const low = allRsiData.filter(c => parseFloat(c.rsi4h || 0) <= 30);
    const neutral = allRsiData.filter(c => {
      const v = parseFloat(c.rsi4h || 0);
      return v > 30 && v < 70;
    });
    document.getElementById('statOverbought').textContent = high.length;
    document.getElementById('statOversold').textContent = low.length;
    document.getElementById('statNeutral').textContent = neutral.length;
    renderRsiTable(allRsiData);
    renderExtremeRsi(high.slice(0, 5), low.slice(0, 5));
    renderRsiChart(allRsiData);
    document.getElementById('rsiCount').textContent = allRsiData.length + ' coins';
    const now = new Date();
    document.getElementById('lastUpdate').textContent = now.toLocaleTimeString();
  } catch (e) {
    console.error('RSI load error:', e);
    document.getElementById('rsiTableBody').innerHTML = '<tr><td colspan="8" class="px-4 py-8 text-center text-[#ef4444]">Failed to load data. Retrying in 5s...</td></tr>';
    setTimeout(loadRsi, 5000);
  }
}

function renderRsiTable(data) {
  const tbody = document.getElementById('rsiTableBody');
  tbody.innerHTML = data.slice(0, 100).map((coin, i) => {
    const change = coin.priceChangePercent24h || 0;
    return `<tr class="table-row">
      <td class="px-4 py-3 text-[#64748b] mono">${coin.rank || i+1}</td>
      <td class="px-4 py-3">
        <div class="flex items-center gap-2">
          <div class="w-7 h-7 rounded-full bg-gradient-to-br from-[#232a3b] to-[#1a1f2e] flex items-center justify-center text-xs font-bold">${(coin.symbol || '??').slice(0,2)}</div>
          <span class="font-medium">${coin.symbol || 'Unknown'}</span>
        </div>
      </td>
      <td class="px-4 py-3 text-right mono font-medium">${formatPrice(coin.price)}</td>
      <td class="px-4 py-3 text-right">
        <span class="inline-block px-2 py-0.5 rounded-md text-xs font-medium mono" style="color:${getRsiColor(coin.rsi15m)};background:${getRsiBg(coin.rsi15m)}">${coin.rsi15m || '--'}</span>
      </td>
      <td class="px-4 py-3 text-right">
        <span class="inline-block px-2 py-0.5 rounded-md text-xs font-medium mono" style="color:${getRsiColor(coin.rsi1h)};background:${getRsiBg(coin.rsi1h)}">${coin.rsi1h || '--'}</span>
      </td>
      <td class="px-4 py-3 text-right">
        <span class="inline-block px-2 py-0.5 rounded-md text-xs font-bold mono" style="color:${getRsiColor(coin.rsi4h)};background:${getRsiBg(coin.rsi4h)}">${coin.rsi4h || '--'}</span>
      </td>
      <td class="px-4 py-3 text-right">
        <span class="inline-block px-2 py-0.5 rounded-md text-xs font-medium mono" style="color:${getRsiColor(coin.rsi24h)};background:${getRsiBg(coin.rsi24h)}">${coin.rsi24h || '--'}</span>
      </td>
      <td class="px-4 py-3 text-right hide-mobile">
        <span class="text-xs font-medium mono" style="color:${getChangeColor(change)}">${change > 0 ? '+' : ''}${parseFloat(change).toFixed(2)}%</span>
      </td>
    </tr>`;
  }).join('');
}

function renderExtremeRsi(high, low) {
  const container = document.getElementById('extremeRsi');
  let html = '';
  if (high.length > 0) {
    html += '<div class="text-xs text-[#ef4444] font-medium uppercase tracking-wider mb-2">Overbought (RSI ≥ 70)</div>';
    html += high.map(c => `
      <div class="flex items-center justify-between p-2 rounded-lg bg-[#ef4444]/5 border border-[#ef4444]/10">
        <div class="flex items-center gap-2">
          <span class="font-medium text-sm">${c.symbol}</span>
          <span class="text-xs text-[#64748b] mono">${formatPrice(c.price)}</span>
        </div>
        <span class="text-sm font-bold mono text-[#ef4444]">${c.rsi4h}</span>
      </div>
    `).join('');
  }
  if (low.length > 0) {
    html += '<div class="text-xs text-[#22c55e] font-medium uppercase tracking-wider mb-2 mt-4">Oversold (RSI ≤ 30)</div>';
    html += low.map(c => `
      <div class="flex items-center justify-between p-2 rounded-lg bg-[#22c55e]/5 border border-[#22c55e]/10">
        <div class="flex items-center gap-2">
          <span class="font-medium text-sm">${c.symbol}</span>
          <span class="text-xs text-[#64748b] mono">${formatPrice(c.price)}</span>
        </div>
        <span class="text-sm font-bold mono text-[#22c55e]">${c.rsi4h}</span>
      </div>
    `).join('');
  }
  container.innerHTML = html || '<div class="text-[#64748b] text-sm">No extreme values</div>';
}

function renderRsiChart(data) {
  const ctx = document.getElementById('rsiChart').getContext('2d');
  const sorted = [...data].sort((a,b) => parseFloat(b.rsi4h || 0) - parseFloat(a.rsi4h || 0)).slice(0, 20);
  if (charts.rsi) charts.rsi.destroy();
  charts.rsi = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: sorted.map(c => c.symbol),
      datasets: [{
        label: 'RSI 4h',
        data: sorted.map(c => parseFloat(c.rsi4h || 0)),
        backgroundColor: sorted.map(c => {
          const v = parseFloat(c.rsi4h || 0);
          if (v >= 70) return 'rgba(239,68,68,0.7)';
          if (v <= 30) return 'rgba(34,197,94,0.7)';
          return 'rgba(0,212,170,0.5)';
        }),
        borderColor: sorted.map(c => {
          const v = parseFloat(c.rsi4h || 0);
          if (v >= 70) return '#ef4444';
          if (v <= 30) return '#22c55e';
          return '#00d4aa';
        }),
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#1a1f2e',
          borderColor: '#2d3748',
          borderWidth: 1,
          titleColor: '#f0f4f8',
          bodyColor: '#94a3b8',
          padding: 10,
          cornerRadius: 8,
        }
      },
      scales: {
        x: {
          ticks: { color: '#64748b', font: { size: 10 } },
          grid: { display: false }
        },
        y: {
          ticks: { color: '#64748b', font: { size: 10 } },
          grid: { color: 'rgba(45,55,72,0.3)' },
          min: 0,
          max: 100,
        }
      }
    }
  });
}

function sortRsi(field) {
  currentRsiSort = field;
  const sorted = [...allRsiData].sort((a,b) => parseFloat(b[field] || 0) - parseFloat(a[field] || 0));
  renderRsiTable(sorted);
  renderRsiChart(sorted);
}

function filterRsiTable() {
  const query = document.getElementById('rsiSearch').value.toLowerCase();
  const filtered = allRsiData.filter(c => (c.symbol || '').toLowerCase().includes(query));
  renderRsiTable(filtered);
  document.getElementById('rsiCount').textContent = filtered.length + ' coins';
}

async function loadFunding() {
  try {
    const res = await fetch('/api/funding');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const tbody = document.getElementById('fundingTableBody');
    const data = json.data.list || [];
    tbody.innerHTML = data.slice(0, 50).map(item => {
      const rate = parseFloat(item.fundingRate || 0);
      const annual = rate * 3 * 365;
      return `<tr class="table-row">
        <td class="px-4 py-3 font-medium">${item.exName || 'Unknown'}</td>
        <td class="px-4 py-3">${item.symbol || '--'}</td>
        <td class="px-4 py-3 text-right mono font-medium" style="color:${rate > 0 ? '#ef4444' : rate < 0 ? '#22c55e' : '#94a3b8'}">${(rate*100).toFixed(4)}%</td>
        <td class="px-4 py-3 text-right mono text-[#64748b]">${(annual*100).toFixed(2)}%</td>
      </tr>`;
    }).join('');
  } catch (e) {
    console.error('Funding error:', e);
  }
}

async function loadLiquidation() {
  try {
    const res = await fetch('/api/liquidation');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const data = json.data;
    const container = document.getElementById('liquidationContent');
    container.innerHTML = `<pre class="text-xs text-[#94a3b8] mono overflow-auto max-h-96">${JSON.stringify(data, null, 2)}</pre>`;
  } catch (e) {
    console.error('Liquidation error:', e);
  }
}

async function loadMarketcap() {
  try {
    const res = await fetch('/api/marketcap');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const tbody = document.getElementById('marketcapTableBody');
    const data = json.data.list || [];
    tbody.innerHTML = data.slice(0, 50).map((item, i) => {
      const change = item.priceChangePercent24h || 0;
      return `<tr class="table-row">
        <td class="px-4 py-3 text-[#64748b] mono">${item.rank || i+1}</td>
        <td class="px-4 py-3">
          <div class="flex items-center gap-2">
            <div class="w-7 h-7 rounded-full bg-gradient-to-br from-[#232a3b] to-[#1a1f2e] flex items-center justify-center text-xs font-bold">${(item.symbol || '??').slice(0,2)}</div>
            <span class="font-medium">${item.symbol || 'Unknown'}</span>
          </div>
        </td>
        <td class="px-4 py-3 text-right mono font-medium">${formatPrice(item.price)}</td>
        <td class="px-4 py-3 text-right mono">$${formatNumber(item.marketCap)}</td>
        <td class="px-4 py-3 text-right mono font-medium" style="color:${getChangeColor(change)}">${change > 0 ? '+' : ''}${parseFloat(change).toFixed(2)}%</td>
        <td class="px-4 py-3 text-right mono text-[#64748b] hide-mobile">$${formatNumber(item.volume24h)}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    console.error('Marketcap error:', e);
  }
}

async function loadFutures() {
  try {
    const res = await fetch('/api/futures-stats');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const data = json.data;
    const grid = document.getElementById('futuresStatsGrid');
    grid.innerHTML = Object.entries(data).map(([key, val]) => `
      <div class="glass-card p-4">
        <div class="text-xs text-[#64748b] uppercase tracking-wider font-medium mb-2">${key}</div>
        <div class="text-lg font-bold mono">${typeof val === 'number' ? formatNumber(val) : JSON.stringify(val).slice(0, 50)}</div>
      </div>
    `).join('');
  } catch (e) {
    console.error('Futures stats error:', e);
  }
}

async function loadEtf() {
  try {
    const res = await fetch('/api/etf');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const container = document.getElementById('etfContent');
    container.innerHTML = `<pre class="text-xs text-[#94a3b8] mono overflow-auto max-h-96">${JSON.stringify(json.data, null, 2)}</pre>`;
  } catch (e) {
    console.error('ETF error:', e);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadRsi();
  setInterval(loadRsi, 60000);
});
</script>
</body>
</html>
HTMLEOF

EXPOSE 8000
CMD ["python", "/app/main.py"]
