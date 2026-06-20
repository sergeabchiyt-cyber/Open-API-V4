FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn[standard] requests pycryptodome jinja2

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
        logger.warning(f"Missing user/v headers at {url}. Headers: {dict(resp.headers)}")
        raise ValueError(f"Missing user/v headers at {url}")
    return decrypt(resp.text, user, v, url)
PYEOF

# ==== main.py ====
RUN cat <<'PYEOF' > /app/main.py
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import json
from decrypt import fetch_and_decrypt
import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="CoinGlass Decrypt Dashboard")
executor = ThreadPoolExecutor(max_workers=4)

templates = Jinja2Templates(directory="/app/templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {})

def extract_data(raw):
    """Flexible data extraction - handles .list, .data, and root array"""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        if "list" in raw:
            return raw["list"]
        if "data" in raw:
            d = raw["data"]
            return d if isinstance(d, list) else [d]
    return raw if isinstance(raw, list) else []

@app.get("/api/rsi")
async def get_rsi():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/spot/rsi/list",
            {"pageSize": 500, "pageNum": 1})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        logger.error(f"RSI error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/funding")
async def get_funding():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/fundingRate/list",
            {"pageSize": 100, "pageNum": 1})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        logger.error(f"Funding error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/liquidation")
async def get_liquidation():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/futures/liquidation/today", {})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        logger.error(f"Liquidation error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/openinterest")
async def get_oi():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/openInterest/statistics", {})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        logger.error(f"OI error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/etf")
async def get_etf():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/etf/overview", {})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        logger.error(f"ETF error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/marketcap")
async def get_marketcap():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/marketCapRank",
            {"pageSize": 100})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        logger.error(f"Marketcap error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get("/api/futures-stats")
async def get_futures_stats():
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(executor, fetch_and_decrypt,
            "https://capi.coinglass.com/api/futures/home/statistics", {})
        return {"success": True, "data": data, "extracted": extract_data(data)}
    except Exception as e:
        logger.error(f"Futures stats error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
PYEOF

RUN mkdir -p /app/templates

# ==== index.html ====
RUN cat <<'HTMLEOF' > /app/templates/index.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CoinGlass Analytics</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #070a12; --bg-elevated: #0d111f; --bg-card: #131829; --bg-card-hover: #1a2035;
  --border: #1e2740; --border-hover: #2a3560; --accent: #00e5c0; --accent-dim: rgba(0,229,192,0.08);
  --text: #e8ecf4; --text-secondary: #8b95a8; --text-muted: #4a5568;
  --danger: #ff4757; --danger-bg: rgba(255,71,87,0.08);
  --success: #2ed573; --success-bg: rgba(46,213,115,0.08);
  --warning: #ffa502; --warning-bg: rgba(255,165,2,0.08);
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; overflow-x: hidden; -webkit-font-smoothing: antialiased; }
.mono { font-family: 'JetBrains Mono', monospace; }
.mesh-bg { position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background: radial-gradient(ellipse 80% 50% at 20% 40%, rgba(0,229,192,0.04) 0%, transparent 50%), radial-gradient(ellipse 60% 40% at 80% 80%, rgba(55,66,250,0.03) 0%, transparent 50%); }
.grid-overlay { position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background-image: linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px); background-size: 60px 60px;
  mask-image: radial-gradient(ellipse 80% 80% at 50% 50%, black 20%, transparent 70%); }
@keyframes slideUp { from { opacity: 0; transform: translateY(30px) scale(0.98); } to { opacity: 1; transform: translateY(0) scale(1); } }
@keyframes countUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
@keyframes pulse-ring { 0% { transform: scale(0.8); opacity: 1; } 100% { transform: scale(2.2); opacity: 0; } }
@keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
.enter { animation: slideUp 0.7s cubic-bezier(0.16, 1, 0.3, 1) forwards; opacity: 0; }
.enter-d1 { animation-delay: 0.08s; } .enter-d2 { animation-delay: 0.16s; } .enter-d3 { animation-delay: 0.24s; }
.enter-d4 { animation-delay: 0.32s; } .enter-d5 { animation-delay: 0.40s; } .enter-d6 { animation-delay: 0.48s; }
.skeleton { background: linear-gradient(90deg, var(--bg-card) 25%, #1a2035 50%, var(--bg-card) 75%); background-size: 200% 100%; animation: shimmer 1.8s infinite; border-radius: 8px; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; transition: all 0.35s cubic-bezier(0.16, 1, 0.3, 1); position: relative; overflow: hidden; }
.card::before { content: ''; position: absolute; inset: 0; border-radius: 16px; padding: 1px; background: linear-gradient(135deg, rgba(0,229,192,0.1), transparent 40%); -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0); -webkit-mask-composite: xor; mask-composite: exclude; opacity: 0; transition: opacity 0.35s; pointer-events: none; }
.card:hover::before { opacity: 1; }
.card:hover { border-color: var(--border-hover); transform: translateY(-3px); box-shadow: 0 20px 40px rgba(0,0,0,0.4), 0 0 0 1px rgba(0,229,192,0.06); }
.status-live { position: relative; width: 8px; height: 8px; border-radius: 50%; background: var(--success); }
.status-live::after { content: ''; position: absolute; inset: -4px; border-radius: 50%; border: 1px solid var(--success); animation: pulse-ring 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
.tab { position: relative; padding: 10px 18px; border-radius: 12px; font-size: 13px; font-weight: 500; color: var(--text-secondary); background: transparent; border: 1px solid transparent; cursor: pointer; transition: all 0.25s; white-space: nowrap; display: flex; align-items: center; gap: 8px; }
.tab:hover { color: var(--text); background: rgba(255,255,255,0.03); }
.tab.active { color: var(--accent); background: var(--accent-dim); border-color: rgba(0,229,192,0.15); }
.tab .tab-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; opacity: 0.5; }
.tab.active .tab-dot { opacity: 1; box-shadow: 0 0 8px currentColor; }
.panel { opacity: 0; transform: translateY(12px); transition: opacity 0.4s ease, transform 0.4s ease; display: none; }
.panel.active { display: block; opacity: 1; transform: translateY(0); }
.data-table { width: 100%; border-collapse: separate; border-spacing: 0; }
.data-table th { padding: 14px 16px; text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); border-bottom: 1px solid var(--border); }
.data-table td { padding: 12px 16px; font-size: 13px; border-bottom: 1px solid rgba(30,39,64,0.5); transition: background 0.15s; }
.data-table tbody tr:hover td { background: rgba(0,229,192,0.02); }
.data-table tbody tr:last-child td { border-bottom: none; }
.badge { display: inline-flex; align-items: center; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; }
.badge-red { background: var(--danger-bg); color: var(--danger); }
.badge-green { background: var(--success-bg); color: var(--success); }
.badge-amber { background: var(--warning-bg); color: var(--warning); }
.badge-neutral { background: rgba(255,255,255,0.05); color: var(--text-secondary); }
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
::-webkit-scrollbar-thumb:hover { background: #2a3560; }
.chart-wrap { position: relative; height: 280px; }
.mini-chart-wrap { position: relative; height: 180px; }
.section-title { font-size: 15px; font-weight: 700; letter-spacing: -0.01em; display: flex; align-items: center; gap: 10px; }
.section-title::before { content: ''; width: 4px; height: 18px; border-radius: 2px; background: linear-gradient(180deg, var(--accent), transparent); }
.search-input { background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 10px; padding: 8px 14px; font-size: 13px; color: var(--text); outline: none; transition: all 0.2s; width: 220px; }
.search-input:focus { border-color: rgba(0,229,192,0.3); box-shadow: 0 0 0 3px rgba(0,229,192,0.05); }
.search-input::placeholder { color: var(--text-muted); }
.error-state { padding: 40px; text-align: center; color: var(--danger); }
.error-state svg { width: 48px; height: 48px; margin: 0 auto 16px; opacity: 0.5; }
.num-anim { display: inline-block; animation: countUp 0.5s ease-out; }
.api-ref { background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
.api-ref-header { padding: 12px 16px; border-bottom: 1px solid var(--border); font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary); display: flex; align-items: center; gap: 8px; cursor: pointer; transition: background 0.2s; }
.api-ref-header:hover { background: rgba(255,255,255,0.02); }
.api-ref-content { max-height: 0; overflow: hidden; transition: max-height 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
.api-ref-content.open { max-height: 800px; }
.api-endpoint { padding: 10px 16px; border-bottom: 1px solid rgba(30,39,64,0.5); font-size: 12px; display: flex; align-items: center; gap: 12px; }
.api-endpoint:last-child { border-bottom: none; }
.api-method { font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 4px; background: rgba(0,229,192,0.1); color: var(--accent); flex-shrink: 0; }
.api-path { font-family: 'JetBrains Mono', monospace; color: var(--text); font-size: 12px; }
.api-desc { color: var(--text-muted); margin-left: auto; font-size: 11px; }
@media (max-width: 768px) { .hide-mobile { display: none; } .search-input { width: 140px; } }
</style>
</head>
<body>
<div class="mesh-bg"></div>
<div class="grid-overlay"></div>

<div class="relative z-10 min-h-screen">
  <header class="sticky top-0 z-50 border-b border-[#1e2740]/80" style="background: rgba(7,10,18,0.85); backdrop-filter: blur(20px);">
    <div class="max-w-7xl mx-auto px-5 py-4 flex items-center justify-between">
      <div class="flex items-center gap-3.5">
        <div class="w-10 h-10 rounded-xl flex items-center justify-center" style="background: linear-gradient(135deg, #00e5c0, #3742fa); box-shadow: 0 4px 20px rgba(0,229,192,0.2);">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        </div>
        <div>
          <h1 class="text-lg font-bold tracking-tight" style="letter-spacing: -0.02em;">CoinGlass<span style="background: linear-gradient(135deg, #00e5c0, #3742fa); -webkit-background-clip: text; -webkit-text-fill-color: transparent;"> Analytics</span></h1>
          <p class="text-[11px] text-[#4a5568] mono mt-0.5">Real-time Decrypted Market Intelligence</p>
        </div>
      </div>
      <div class="flex items-center gap-4">
        <div class="flex items-center gap-2.5 px-3.5 py-1.5 rounded-full" style="background: rgba(46,213,115,0.08); border: 1px solid rgba(46,213,115,0.15);">
          <span class="status-live"></span>
          <span class="text-[11px] font-semibold mono" style="color: var(--success);">LIVE</span>
        </div>
        <div class="text-[11px] text-[#4a5568] mono" id="lastUpdate">--:--:--</div>
      </div>
    </div>
  </header>

  <main class="max-w-7xl mx-auto px-5 py-6">
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      <div class="card p-5 enter">
        <div class="flex items-center justify-between mb-3">
          <span class="text-[11px] font-semibold uppercase tracking-wider text-[#4a5568]">Tracked Assets</span>
          <div class="w-8 h-8 rounded-lg flex items-center justify-center" style="background: rgba(0,229,192,0.08);"><svg class="w-4 h-4" style="color: var(--accent);" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l-3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3"/></svg></div>
        </div>
        <div class="text-2xl font-bold mono num-anim" id="statTotal">--</div>
        <div class="text-[11px] text-[#4a5568] mt-1.5">Across all exchanges</div>
      </div>
      <div class="card p-5 enter enter-d1">
        <div class="flex items-center justify-between mb-3">
          <span class="text-[11px] font-semibold uppercase tracking-wider text-[#4a5568]">Overbought</span>
          <div class="w-8 h-8 rounded-lg flex items-center justify-center" style="background: var(--danger-bg);"><svg class="w-4 h-4" style="color: var(--danger);" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/></svg></div>
        </div>
        <div class="text-2xl font-bold mono num-anim" style="color: var(--danger);" id="statOverbought">--</div>
        <div class="text-[11px] text-[#4a5568] mt-1.5">RSI 4h >= 70</div>
      </div>
      <div class="card p-5 enter enter-d2">
        <div class="flex items-center justify-between mb-3">
          <span class="text-[11px] font-semibold uppercase tracking-wider text-[#4a5568]">Oversold</span>
          <div class="w-8 h-8 rounded-lg flex items-center justify-center" style="background: var(--success-bg);"><svg class="w-4 h-4" style="color: var(--success);" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 17h8m0 0V9m0 8l-8-8-4 4-6-6"/></svg></div>
        </div>
        <div class="text-2xl font-bold mono num-anim" style="color: var(--success);" id="statOversold">--</div>
        <div class="text-[11px] text-[#4a5568] mt-1.5">RSI 4h <= 30</div>
      </div>
      <div class="card p-5 enter enter-d3">
        <div class="flex items-center justify-between mb-3">
          <span class="text-[11px] font-semibold uppercase tracking-wider text-[#4a5568]">Neutral Zone</span>
          <div class="w-8 h-8 rounded-lg flex items-center justify-center" style="background: var(--warning-bg);"><svg class="w-4 h-4" style="color: var(--warning);" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 12H4"/></svg></div>
        </div>
        <div class="text-2xl font-bold mono num-anim" style="color: var(--warning);" id="statNeutral">--</div>
        <div class="text-[11px] text-[#4a5568] mt-1.5">30 < RSI < 70</div>
      </div>
    </div>

    <div class="flex gap-2 mb-6 overflow-x-auto pb-1 enter enter-d4" style="scrollbar-width: none;">
      <button onclick="switchTab('rsi')" id="tab-rsi" class="tab active"><span class="tab-dot"></span>RSI Dashboard</button>
      <button onclick="switchTab('funding')" id="tab-funding" class="tab"><span class="tab-dot"></span>Funding Rates</button>
      <button onclick="switchTab('liquidation')" id="tab-liquidation" class="tab"><span class="tab-dot"></span>Liquidations</button>
      <button onclick="switchTab('openinterest')" id="tab-openinterest" class="tab"><span class="tab-dot"></span>Open Interest</button>
      <button onclick="switchTab('marketcap')" id="tab-marketcap" class="tab"><span class="tab-dot"></span>Market Cap</button>
      <button onclick="switchTab('futures')" id="tab-futures" class="tab"><span class="tab-dot"></span>Futures</button>
      <button onclick="switchTab('etf')" id="tab-etf" class="tab"><span class="tab-dot"></span>ETF Flows</button>
    </div>

    <div id="panel-rsi" class="panel active">
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">
        <div class="card p-5 lg:col-span-2 enter enter-d4">
          <div class="flex items-center justify-between mb-4">
            <h2 class="section-title">RSI 4h Distribution</h2>
            <div class="flex gap-2">
              <button onclick="sortRsi('rsi4h')" class="text-[11px] px-3 py-1.5 rounded-lg font-medium transition hover:bg-[#1a2035]" style="background: var(--bg-elevated); border: 1px solid var(--border); color: var(--text-secondary);">Sort 4h</button>
              <button onclick="sortRsi('rsi1h')" class="text-[11px] px-3 py-1.5 rounded-lg font-medium transition hover:bg-[#1a2035]" style="background: var(--bg-elevated); border: 1px solid var(--border); color: var(--text-secondary);">Sort 1h</button>
            </div>
          </div>
          <div class="chart-wrap"><canvas id="rsiChart"></canvas></div>
        </div>
        <div class="card p-5 enter enter-d5">
          <h2 class="section-title mb-4">Extreme Signals</h2>
          <div id="extremeRsi" class="space-y-3">
            <div class="skeleton h-14"></div><div class="skeleton h-14"></div><div class="skeleton h-14"></div>
          </div>
        </div>
      </div>
      <div class="card overflow-hidden enter enter-d5">
        <div class="p-4 border-b flex items-center justify-between" style="border-color: var(--border);">
          <h2 class="section-title">All Coins</h2>
          <div class="flex items-center gap-3">
            <input type="text" id="rsiSearch" placeholder="Search symbol..." class="search-input" oninput="filterRsiTable()">
            <span class="text-[11px] text-[#4a5568] mono" id="rsiCount">0 assets</span>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="data-table">
            <thead><tr><th>#</th><th>Asset</th><th class="text-right">Price</th><th class="text-right">RSI 15m</th><th class="text-right">RSI 1h</th><th class="text-right">RSI 4h</th><th class="text-right">RSI 24h</th><th class="text-right hide-mobile">24h Change</th></tr></thead>
            <tbody id="rsiTableBody"><tr><td colspan="8" class="p-8 text-center text-[#4a5568]"><div class="skeleton h-8 mx-auto max-w-md"></div></td></tr></tbody>
          </table>
        </div>
      </div>
    </div>

    <div id="panel-funding" class="panel">
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">
        <div class="card p-5 lg:col-span-2">
          <h2 class="section-title mb-4">Funding Rate Distribution</h2>
          <div class="chart-wrap"><canvas id="fundingChart"></canvas></div>
        </div>
        <div class="card p-5">
          <h2 class="section-title mb-4">Highest Rates</h2>
          <div id="fundingTop" class="space-y-2.5"><div class="skeleton h-10"></div><div class="skeleton h-10"></div><div class="skeleton h-10"></div></div>
        </div>
      </div>
      <div class="card overflow-hidden">
        <div class="p-4 border-b flex items-center justify-between" style="border-color: var(--border);">
          <h2 class="section-title">All Funding Rates</h2>
          <span class="text-[11px] text-[#4a5568] mono" id="fundingCount">0 rates</span>
        </div>
        <div class="overflow-x-auto">
          <table class="data-table">
            <thead><tr><th>Exchange</th><th>Asset</th><th class="text-right">Rate</th><th class="text-right">Annualized</th><th class="text-right hide-mobile">Timestamp</th></tr></thead>
            <tbody id="fundingTableBody"><tr><td colspan="5" class="p-8 text-center text-[#4a5568]"><div class="skeleton h-8 mx-auto max-w-md"></div></td></tr></tbody>
          </table>
        </div>
      </div>
    </div>

    <div id="panel-liquidation" class="panel">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
        <div class="card p-5">
          <h2 class="section-title mb-4">Liquidation Distribution</h2>
          <div class="mini-chart-wrap"><canvas id="liqChart"></canvas></div>
        </div>
        <div class="card p-5">
          <h2 class="section-title mb-4">Long vs Short</h2>
          <div class="mini-chart-wrap"><canvas id="liqLongShortChart"></canvas></div>
        </div>
      </div>
      <div class="card p-5">
        <h2 class="section-title mb-4">Liquidation Details</h2>
        <div id="liquidationContent" class="overflow-auto max-h-96"><div class="skeleton h-32"></div></div>
      </div>
    </div>

    <div id="panel-openinterest" class="panel">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
        <div class="card p-5">
          <h2 class="section-title mb-4">OI by Exchange</h2>
          <div class="chart-wrap"><canvas id="oiChart"></canvas></div>
        </div>
        <div class="card p-5">
          <h2 class="section-title mb-4">OI Change 24h</h2>
          <div class="chart-wrap"><canvas id="oiChangeChart"></canvas></div>
        </div>
      </div>
      <div class="card overflow-hidden">
        <div class="p-4 border-b" style="border-color: var(--border);"><h2 class="section-title">Open Interest Statistics</h2></div>
        <div id="oiContent" class="p-5 overflow-auto max-h-96"><div class="skeleton h-32"></div></div>
      </div>
    </div>

    <div id="panel-marketcap" class="panel">
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">
        <div class="card p-5 lg:col-span-2">
          <h2 class="section-title mb-4">Market Cap vs Volume</h2>
          <div class="chart-wrap"><canvas id="mcChart"></canvas></div>
        </div>
        <div class="card p-5">
          <h2 class="section-title mb-4">Top Gainers</h2>
          <div id="mcGainers" class="space-y-2.5"><div class="skeleton h-10"></div><div class="skeleton h-10"></div><div class="skeleton h-10"></div></div>
        </div>
      </div>
      <div class="card overflow-hidden">
        <div class="p-4 border-b flex items-center justify-between" style="border-color: var(--border);">
          <h2 class="section-title">Market Cap Rankings</h2>
          <span class="text-[11px] text-[#4a5568] mono" id="mcCount">0 assets</span>
        </div>
        <div class="overflow-x-auto">
          <table class="data-table">
            <thead><tr><th>#</th><th>Asset</th><th class="text-right">Price</th><th class="text-right">Market Cap</th><th class="text-right">24h Change</th><th class="text-right hide-mobile">Volume</th></tr></thead>
            <tbody id="mcTableBody"><tr><td colspan="6" class="p-8 text-center text-[#4a5568]"><div class="skeleton h-8 mx-auto max-w-md"></div></td></tr></tbody>
          </table>
        </div>
      </div>
    </div>

    <div id="panel-futures" class="panel">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-5" id="futuresStatsGrid">
        <div class="card p-5"><div class="skeleton h-16"></div></div>
        <div class="card p-5"><div class="skeleton h-16"></div></div>
        <div class="card p-5"><div class="skeleton h-16"></div></div>
        <div class="card p-5"><div class="skeleton h-16"></div></div>
      </div>
      <div class="card p-5">
        <h2 class="section-title mb-4">Futures Overview</h2>
        <div id="futuresContent" class="overflow-auto max-h-96"><div class="skeleton h-32"></div></div>
      </div>
    </div>

    <div id="panel-etf" class="panel">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
        <div class="card p-5">
          <h2 class="section-title mb-4">ETF Flow Distribution</h2>
          <div class="chart-wrap"><canvas id="etfChart"></canvas></div>
        </div>
        <div class="card p-5">
          <h2 class="section-title mb-4">Daily Flow Trend</h2>
          <div class="chart-wrap"><canvas id="etfTrendChart"></canvas></div>
        </div>
      </div>
      <div class="card p-5">
        <h2 class="section-title mb-4">ETF Details</h2>
        <div id="etfContent" class="overflow-auto max-h-96"><div class="skeleton h-32"></div></div>
      </div>
    </div>

    <div class="mt-8 enter enter-d6">
      <div class="api-ref">
        <div class="api-ref-header" onclick="this.nextElementSibling.classList.toggle('open'); this.querySelector('svg').style.transform = this.nextElementSibling.classList.contains('open') ? 'rotate(180deg)' : 'rotate(0deg)';">
          <svg class="w-4 h-4 transition-transform duration-300" style="color: var(--accent);" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
          <span>API Reference</span>
          <span style="margin-left: auto; color: var(--text-muted); font-size: 11px; font-weight: 400;">Click to expand</span>
        </div>
        <div class="api-ref-content">
          <div class="api-endpoint"><span class="api-method">GET</span><span class="api-path">/api/rsi</span><span class="api-desc">RSI indicators for 500+ assets</span></div>
          <div class="api-endpoint"><span class="api-method">GET</span><span class="api-path">/api/funding</span><span class="api-desc">Perpetual funding rates by exchange</span></div>
          <div class="api-endpoint"><span class="api-method">GET</span><span class="api-path">/api/liquidation</span><span class="api-desc">24h liquidation volumes</span></div>
          <div class="api-endpoint"><span class="api-method">GET</span><span class="api-path">/api/openinterest</span><span class="api-desc">Open interest statistics</span></div>
          <div class="api-endpoint"><span class="api-method">GET</span><span class="api-path">/api/marketcap</span><span class="api-desc">Market cap rankings (top 100)</span></div>
          <div class="api-endpoint"><span class="api-method">GET</span><span class="api-path">/api/futures-stats</span><span class="api-desc">Aggregate futures statistics</span></div>
          <div class="api-endpoint"><span class="api-method">GET</span><span class="api-path">/api/etf</span><span class="api-desc">Spot Bitcoin ETF flow data</span></div>
          <div style="padding: 12px 16px; border-top: 1px solid var(--border); font-size: 11px; color: var(--text-muted);">
            All endpoints return <code style="background: var(--bg-card); padding: 2px 6px; border-radius: 4px; color: var(--accent);">{ "success": true, "data": {...}, "extracted": [...] }</code>. Data is decrypted in real-time from CoinGlass.
          </div>
        </div>
      </div>
    </div>
  </main>
</div>
<script>
const charts = {};
let allRsiData = [];
let currentRsiSort = 'rsi4h';

function getDataArray(json) {
  if (json.extracted && Array.isArray(json.extracted)) return json.extracted;
  if (json.data && Array.isArray(json.data)) return json.data;
  if (json.data && json.data.list && Array.isArray(json.data.list)) return json.data.list;
  if (Array.isArray(json)) return json;
  return [];
}

function getDataObj(json) {
  if (json.data && typeof json.data === 'object' && !Array.isArray(json.data)) return json.data;
  if (json && typeof json === 'object' && !Array.isArray(json)) return json;
  return {};
}

function switchTab(tab) {
  document.querySelectorAll('.panel').forEach(p => { p.classList.remove('active'); setTimeout(() => { if(!p.classList.contains('active')) p.style.display='none'; }, 400); });
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.add('active');
  const panel = document.getElementById('panel-' + tab);
  panel.style.display = 'block';
  requestAnimationFrame(() => panel.classList.add('active'));
  const loaders = { funding: loadFunding, liquidation: loadLiquidation, openinterest: loadOI, marketcap: loadMarketcap, futures: loadFutures, etf: loadEtf };
  if (loaders[tab] && !window[tab + 'Loaded']) { loaders[tab](); window[tab + 'Loaded'] = true; }
}

function getRsiColor(v) { v = parseFloat(v); if (v >= 70) return '#ff4757'; if (v <= 30) return '#2ed573'; return '#8b95a8'; }
function getRsiBg(v) { v = parseFloat(v); if (v >= 70) return 'rgba(255,71,87,0.12)'; if (v <= 30) return 'rgba(46,213,115,0.12)'; return 'rgba(255,255,255,0.04)'; }
function getChangeColor(v) { v = parseFloat(v); if (v > 0) return '#2ed573'; if (v < 0) return '#ff4757'; return '#8b95a8'; }
function fmtPrice(p) { p = parseFloat(p); if (p >= 1000) return '$' + p.toLocaleString('en', {minimumFractionDigits: 2, maximumFractionDigits: 2}); if (p >= 1) return '$' + p.toFixed(4); return '$' + p.toFixed(6); }
function fmtNum(n) { n = parseFloat(n); if (n >= 1e12) return (n/1e12).toFixed(2) + 'T'; if (n >= 1e9) return (n/1e9).toFixed(2) + 'B'; if (n >= 1e6) return (n/1e6).toFixed(2) + 'M'; if (n >= 1e3) return (n/1e3).toFixed(2) + 'K'; return n.toFixed(2); }
function fmtPct(n) { n = parseFloat(n); return (n > 0 ? '+' : '') + n.toFixed(2) + '%'; }

function badge(val, type) {
  const v = parseFloat(val);
  if (type === 'rsi') {
    if (v >= 70) return '<span class="badge badge-red">' + v.toFixed(1) + '</span>';
    if (v <= 30) return '<span class="badge badge-green">' + v.toFixed(1) + '</span>';
    return '<span class="badge badge-neutral">' + v.toFixed(1) + '</span>';
  }
  if (type === 'change') {
    if (v > 0) return '<span class="badge badge-green">+' + v.toFixed(2) + '%</span>';
    if (v < 0) return '<span class="badge badge-red">' + v.toFixed(2) + '%</span>';
    return '<span class="badge badge-neutral">0.00%</span>';
  }
  if (type === 'funding') {
    if (v > 0) return '<span class="badge badge-red">' + (v*100).toFixed(4) + '%</span>';
    if (v < 0) return '<span class="badge badge-green">' + (v*100).toFixed(4) + '%</span>';
    return '<span class="badge badge-neutral">0.0000%</span>';
  }
}

async function loadRsi() {
  try {
    const res = await fetch('/api/rsi');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    allRsiData = getDataArray(json);
    document.getElementById('statTotal').textContent = allRsiData.length;
    const high = allRsiData.filter(c => parseFloat(c.rsi4h || 0) >= 70);
    const low = allRsiData.filter(c => parseFloat(c.rsi4h || 0) <= 30);
    document.getElementById('statOverbought').textContent = high.length;
    document.getElementById('statOversold').textContent = low.length;
    document.getElementById('statNeutral').textContent = allRsiData.length - high.length - low.length;
    renderRsiTable(allRsiData);
    renderExtremeRsi(high.slice(0, 5), low.slice(0, 5));
    renderRsiChart(allRsiData);
    document.getElementById('rsiCount').textContent = allRsiData.length + ' assets';
    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
  } catch (e) {
    console.error('RSI error:', e);
    document.getElementById('rsiTableBody').innerHTML = '<tr><td colspan="8" class="p-8 text-center"><div class="error-state"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg><div class="text-sm font-medium mb-1">Failed to load RSI data</div><div class="text-xs opacity-60">' + e.message + '</div></div></td></tr>';
  }
}

function renderRsiTable(data) {
  const tbody = document.getElementById('rsiTableBody');
  tbody.innerHTML = data.slice(0, 100).map((c, i) => {
    const ch = c.priceChangePercent24h || 0;
    return '<tr class="enter" style="animation-delay:' + (i*0.02) + 's;animation-fill-mode:both;"><td class="text-[#4a5568] mono text-xs">' + (c.rank || i+1) + '</td><td><div class="flex items-center gap-2.5"><div class="w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-bold" style="background: linear-gradient(135deg, #1a2035, #0d111f);">' + (c.symbol || '??').slice(0,2) + '</div><span class="font-medium text-sm">' + (c.symbol || 'Unknown') + '</span></div></td><td class="text-right mono font-medium text-sm">' + fmtPrice(c.price) + '</td><td class="text-right">' + badge(c.rsi15m, 'rsi') + '</td><td class="text-right">' + badge(c.rsi1h, 'rsi') + '</td><td class="text-right">' + badge(c.rsi4h, 'rsi') + '</td><td class="text-right">' + badge(c.rsi24h, 'rsi') + '</td><td class="text-right hide-mobile">' + badge(ch, 'change') + '</td></tr>';
  }).join('');
}

function renderExtremeRsi(high, low) {
  const el = document.getElementById('extremeRsi');
  let html = '';
  if (high.length) {
    html += '<div class="text-[10px] font-bold uppercase tracking-widest mb-2" style="color: var(--danger);">Overbought</div>';
    html += high.map(c => '<div class="flex items-center justify-between p-3 rounded-xl enter" style="background: var(--danger-bg); border: 1px solid rgba(255,71,87,0.1); animation-delay:0.05s;"><div class="flex items-center gap-2"><span class="font-semibold text-sm">' + c.symbol + '</span><span class="text-[11px] text-[#4a5568] mono">' + fmtPrice(c.price) + '</span></div><span class="font-bold mono text-sm" style="color: var(--danger);">' + c.rsi4h + '</span></div>').join('');
  }
  if (low.length) {
    html += '<div class="text-[10px] font-bold uppercase tracking-widest mb-2 mt-4" style="color: var(--success);">Oversold</div>';
    html += low.map(c => '<div class="flex items-center justify-between p-3 rounded-xl enter" style="background: var(--success-bg); border: 1px solid rgba(46,213,115,0.1); animation-delay:0.1s;"><div class="flex items-center gap-2"><span class="font-semibold text-sm">' + c.symbol + '</span><span class="text-[11px] text-[#4a5568] mono">' + fmtPrice(c.price) + '</span></div><span class="font-bold mono text-sm" style="color: var(--success);">' + c.rsi4h + '</span></div>').join('');
  }
  el.innerHTML = html || '<div class="text-[#4a5568] text-sm py-4 text-center">No extreme values detected</div>';
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
        backgroundColor: sorted.map(c => { const v = parseFloat(c.rsi4h || 0); if (v >= 70) return 'rgba(255,71,87,0.7)'; if (v <= 30) return 'rgba(46,213,115,0.7)'; return 'rgba(0,229,192,0.5)'; }),
        borderColor: sorted.map(c => { const v = parseFloat(c.rsi4h || 0); if (v >= 70) return '#ff4757'; if (v <= 30) return '#2ed573'; return '#00e5c0'; }),
        borderWidth: 1, borderRadius: 6, borderSkipped: false,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { backgroundColor: '#131829', borderColor: '#1e2740', borderWidth: 1, titleColor: '#e8ecf4', bodyColor: '#8b95a8', padding: 12, cornerRadius: 10, displayColors: false } },
      scales: {
        x: { ticks: { color: '#4a5568', font: { size: 10, family: 'JetBrains Mono' } }, grid: { display: false } },
        y: { ticks: { color: '#4a5568', font: { size: 10 } }, grid: { color: 'rgba(30,39,64,0.4)' }, min: 0, max: 100 }
      }
    }
  });
}

function sortRsi(field) { currentRsiSort = field; const sorted = [...allRsiData].sort((a,b) => parseFloat(b[field] || 0) - parseFloat(a[field] || 0)); renderRsiTable(sorted); renderRsiChart(sorted); }
function filterRsiTable() { const q = document.getElementById('rsiSearch').value.toLowerCase(); const filtered = allRsiData.filter(c => (c.symbol || '').toLowerCase().includes(q)); renderRsiTable(filtered); document.getElementById('rsiCount').textContent = filtered.length + ' assets'; }

async function loadFunding() {
  try {
    const res = await fetch('/api/funding');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const data = getDataArray(json);
    document.getElementById('fundingCount').textContent = data.length + ' rates';
    const tbody = document.getElementById('fundingTableBody');
    tbody.innerHTML = data.slice(0, 50).map((item, i) => {
      const rate = parseFloat(item.fundingRate || 0);
      const annual = rate * 3 * 365;
      return '<tr class="enter" style="animation-delay:' + (i*0.02) + 's;animation-fill-mode:both;"><td class="font-medium text-sm">' + (item.exName || 'Unknown') + '</td><td class="text-sm">' + (item.symbol || '--') + '</td><td class="text-right">' + badge(rate, 'funding') + '</td><td class="text-right mono text-[#8b95a8] text-sm">' + (annual*100).toFixed(2) + '%</td><td class="text-right hide-mobile text-[#4a5568] text-xs mono">' + (item.time || '--') + '</td></tr>';
    }).join('');
    const pos = data.filter(d => parseFloat(d.fundingRate || 0) > 0).length;
    const neg = data.filter(d => parseFloat(d.fundingRate || 0) < 0).length;
    const neu = data.length - pos - neg;
    const ctx = document.getElementById('fundingChart').getContext('2d');
    if (charts.funding) charts.funding.destroy();
    charts.funding = new Chart(ctx, {
      type: 'doughnut',
      data: { labels: ['Positive', 'Negative', 'Neutral'], datasets: [{ data: [pos, neg, neu], backgroundColor: ['rgba(255,71,87,0.7)', 'rgba(46,213,115,0.7)', 'rgba(139,149,168,0.3)'], borderColor: ['#ff4757', '#2ed573', '#8b95a8'], borderWidth: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'right', labels: { color: '#8b95a8', font: { size: 11 }, boxWidth: 12 } } } }
    });
    const top = [...data].sort((a,b) => parseFloat(b.fundingRate || 0) - parseFloat(a.fundingRate || 0)).slice(0, 5);
    document.getElementById('fundingTop').innerHTML = top.map((item, i) => '<div class="flex items-center justify-between p-3 rounded-xl enter" style="background: var(--bg-elevated); border: 1px solid var(--border); animation-delay:' + (i*0.05) + 's;"><div class="flex items-center gap-2"><span class="text-[#4a5568] mono text-xs w-5">' + (i+1) + '</span><span class="font-medium text-sm">' + item.symbol + '</span><span class="text-[11px] text-[#4a5568]">' + item.exName + '</span></div>' + badge(item.fundingRate, 'funding') + '</div>').join('');
  } catch (e) { console.error('Funding error:', e); document.getElementById('fundingTableBody').innerHTML = '<tr><td colspan="5" class="p-8 text-center text-[#ff4757]">Error: ' + e.message + '</td></tr>'; }
}

async function loadLiquidation() {
  try {
    const res = await fetch('/api/liquidation');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const data = getDataObj(json);
    document.getElementById('liquidationContent').innerHTML = '<pre class="text-xs mono overflow-auto max-h-96 p-4 rounded-xl" style="background: var(--bg-elevated); color: #8b95a8; border: 1px solid var(--border);">' + JSON.stringify(data, null, 2) + '</pre>';
    let longVal = 0, shortVal = 0;
    if (data.longLiquidationUsd) longVal = parseFloat(data.longLiquidationUsd);
    if (data.shortLiquidationUsd) shortVal = parseFloat(data.shortLiquidationUsd);
    if (data.buyLiquidationUsd) longVal = parseFloat(data.buyLiquidationUsd);
    if (data.sellLiquidationUsd) shortVal = parseFloat(data.sellLiquidationUsd);
    const ctx1 = document.getElementById('liqChart').getContext('2d');
    if (charts.liq) charts.liq.destroy();
    charts.liq = new Chart(ctx1, {
      type: 'doughnut',
      data: { labels: ['Long', 'Short'], datasets: [{ data: [longVal || 1, shortVal || 1], backgroundColor: ['rgba(46,213,115,0.6)', 'rgba(255,71,87,0.6)'], borderColor: ['#2ed573', '#ff4757'], borderWidth: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '60%', plugins: { legend: { position: 'bottom', labels: { color: '#8b95a8' } } } }
    });
    const ctx2 = document.getElementById('liqLongShortChart').getContext('2d');
    if (charts.liqLS) charts.liqLS.destroy();
    charts.liqLS = new Chart(ctx2, {
      type: 'bar',
      data: { labels: ['Long Liquidations', 'Short Liquidations'], datasets: [{ data: [longVal || 0, shortVal || 0], backgroundColor: ['#2ed573', '#ff4757'], borderRadius: 8 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { grid: { color: 'rgba(30,39,64,0.4)' }, ticks: { color: '#4a5568', callback: v => fmtNum(v) } }, x: { grid: { display: false }, ticks: { color: '#8b95a8' } } } }
    });
  } catch (e) { console.error('Liquidation error:', e); document.getElementById('liquidationContent').innerHTML = '<div class="error-state"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg><div class="text-sm font-medium mb-1">Liquidation data unavailable</div><div class="text-xs opacity-60">' + e.message + '</div></div>'; }
}

async function loadOI() {
  try {
    const res = await fetch('/api/openinterest');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const data = getDataArray(json);
    document.getElementById('oiContent').innerHTML = '<pre class="text-xs mono overflow-auto max-h-96 p-4 rounded-xl" style="background: var(--bg-elevated); color: #8b95a8; border: 1px solid var(--border);">' + JSON.stringify(data.slice(0, 20), null, 2) + '</pre>';
    const exchanges = {};
    data.forEach(d => { const ex = d.exchange || d.exName || 'Other'; exchanges[ex] = (exchanges[ex] || 0) + parseFloat(d.openInterest || d.oi || 0); });
    const ctx1 = document.getElementById('oiChart').getContext('2d');
    if (charts.oi) charts.oi.destroy();
    charts.oi = new Chart(ctx1, {
      type: 'polarArea',
      data: { labels: Object.keys(exchanges).slice(0, 8), datasets: [{ data: Object.values(exchanges).slice(0, 8), backgroundColor: ['rgba(0,229,192,0.5)', 'rgba(55,66,250,0.5)', 'rgba(255,71,87,0.5)', 'rgba(46,213,115,0.5)', 'rgba(255,165,2,0.5)', 'rgba(139,149,168,0.4)', 'rgba(0,229,192,0.3)', 'rgba(55,66,250,0.3)'] }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#8b95a8', font: { size: 10 } } } }, scales: { r: { grid: { color: 'rgba(30,39,64,0.4)' }, ticks: { color: '#4a5568', backdropColor: 'transparent' } } } }
    });
    const ctx2 = document.getElementById('oiChangeChart').getContext('2d');
    const changeData = data.slice(0, 10).map(d => parseFloat(d.oiChange || d.change24h || d.change || 0));
    if (charts.oiCh) charts.oiCh.destroy();
    charts.oiCh = new Chart(ctx2, {
      type: 'line',
      data: { labels: data.slice(0, 10).map(d => d.symbol || d.coin || '??'), datasets: [{ label: 'OI Change %', data: changeData, borderColor: '#00e5c0', backgroundColor: 'rgba(0,229,192,0.1)', fill: true, tension: 0.4, pointRadius: 4, pointBackgroundColor: '#00e5c0' }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { grid: { color: 'rgba(30,39,64,0.4)' }, ticks: { color: '#4a5568' } }, x: { grid: { display: false }, ticks: { color: '#4a5568', font: { size: 10 } } } } }
    });
  } catch (e) { console.error('OI error:', e); document.getElementById('oiContent').innerHTML = '<div class="error-state"><div class="text-sm font-medium">Open Interest data unavailable</div><div class="text-xs opacity-60">' + e.message + '</div></div>'; }
}

async function loadMarketcap() {
  try {
    const res = await fetch('/api/marketcap');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const data = getDataArray(json);
    document.getElementById('mcCount').textContent = data.length + ' assets';
    const tbody = document.getElementById('mcTableBody');
    tbody.innerHTML = data.slice(0, 50).map((item, i) => {
      const ch = item.priceChangePercent24h || 0;
      return '<tr class="enter" style="animation-delay:' + (i*0.02) + 's;animation-fill-mode:both;"><td class="text-[#4a5568] mono text-xs">' + (item.rank || i+1) + '</td><td><div class="flex items-center gap-2.5"><div class="w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-bold" style="background: linear-gradient(135deg, #1a2035, #0d111f);">' + (item.symbol || '??').slice(0,2) + '</div><span class="font-medium text-sm">' + (item.symbol || 'Unknown') + '</span></div></td><td class="text-right mono font-medium text-sm">' + fmtPrice(item.price) + '</td><td class="text-right mono text-sm">$' + fmtNum(item.marketCap) + '</td><td class="text-right">' + badge(ch, 'change') + '</td><td class="text-right hide-mobile mono text-[#8b95a8] text-sm">$' + fmtNum(item.volume24h) + '</td></tr>';
    }).join('');
    const ctx = document.getElementById('mcChart').getContext('2d');
    const top20 = data.slice(0, 20);
    if (charts.mc) charts.mc.destroy();
    charts.mc = new Chart(ctx, {
      type: 'bar',
      data: { labels: top20.map(d => d.symbol), datasets: [
        { label: 'Market Cap', data: top20.map(d => parseFloat(d.marketCap || 0)), backgroundColor: 'rgba(0,229,192,0.5)', borderColor: '#00e5c0', borderWidth: 1, borderRadius: 6, yAxisID: 'y' },
        { label: 'Volume 24h', data: top20.map(d => parseFloat(d.volume24h || 0)), backgroundColor: 'rgba(55,66,250,0.4)', borderColor: '#3742fa', borderWidth: 1, borderRadius: 6, yAxisID: 'y1' }
      ]},
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#8b95a8' } } }, scales: { x: { ticks: { color: '#4a5568', font: { size: 10 } }, grid: { display: false } }, y: { type: 'logarithmic', position: 'left', grid: { color: 'rgba(30,39,64,0.4)' }, ticks: { color: '#4a5568', callback: v => fmtNum(v) } }, y1: { type: 'logarithmic', position: 'right', grid: { display: false }, ticks: { color: '#4a5568', callback: v => fmtNum(v) } } } }
    });
    const gainers = [...data].sort((a,b) => parseFloat(b.priceChangePercent24h || 0) - parseFloat(a.priceChangePercent24h || 0)).slice(0, 5);
    document.getElementById('mcGainers').innerHTML = gainers.map((c, i) => '<div class="flex items-center justify-between p-3 rounded-xl enter" style="background: var(--bg-elevated); border: 1px solid var(--border); animation-delay:' + (i*0.05) + 's;"><div class="flex items-center gap-2"><span class="text-[#4a5568] mono text-xs w-5">' + (i+1) + '</span><span class="font-medium text-sm">' + c.symbol + '</span></div>' + badge(c.priceChangePercent24h, 'change') + '</div>').join('');
  } catch (e) { console.error('Marketcap error:', e); document.getElementById('mcTableBody').innerHTML = '<tr><td colspan="6" class="p-8 text-center text-[#ff4757]">Error: ' + e.message + '</td></tr>'; }
}

async function loadFutures() {
  try {
    const res = await fetch('/api/futures-stats');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const data = getDataObj(json);
    const grid = document.getElementById('futuresStatsGrid');
    const entries = Object.entries(data).slice(0, 8);
    grid.innerHTML = entries.map(([key, val], i) => '<div class="card p-5 enter" style="animation-delay:' + (i*0.06) + 's;"><div class="text-[10px] font-bold uppercase tracking-widest text-[#4a5568] mb-2">' + key.replace(/([A-Z])/g, ' $1').trim() + '</div><div class="text-xl font-bold mono">' + (typeof val === 'number' ? fmtNum(val) : JSON.stringify(val).slice(0, 30)) + '</div></div>').join('');
    document.getElementById('futuresContent').innerHTML = '<pre class="text-xs mono overflow-auto max-h-96 p-4 rounded-xl" style="background: var(--bg-elevated); color: #8b95a8; border: 1px solid var(--border);">' + JSON.stringify(data, null, 2) + '</pre>';
  } catch (e) { console.error('Futures error:', e); document.getElementById('futuresContent').innerHTML = '<div class="error-state"><div class="text-sm font-medium">Futures data unavailable</div><div class="text-xs opacity-60">' + e.message + '</div></div>'; }
}

async function loadEtf() {
  try {
    const res = await fetch('/api/etf');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const data = getDataObj(json);
    document.getElementById('etfContent').innerHTML = '<pre class="text-xs mono overflow-auto max-h-96 p-4 rounded-xl" style="background: var(--bg-elevated); color: #8b95a8; border: 1px solid var(--border);">' + JSON.stringify(data, null, 2) + '</pre>';
    const etfList = getDataArray(json);
    if (etfList.length > 0) {
      const ctx1 = document.getElementById('etfChart').getContext('2d');
      if (charts.etf) charts.etf.destroy();
      charts.etf = new Chart(ctx1, {
        type: 'doughnut',
        data: { labels: etfList.slice(0, 6).map(d => d.name || d.ticker || 'ETF'), datasets: [{ data: etfList.slice(0, 6).map(d => parseFloat(d.flow || d.dailyFlow || d.value || 0)), backgroundColor: ['rgba(0,229,192,0.7)', 'rgba(55,66,250,0.7)', 'rgba(255,71,87,0.7)', 'rgba(46,213,115,0.7)', 'rgba(255,165,2,0.7)', 'rgba(139,149,168,0.5)'], borderColor: ['#00e5c0', '#3742fa', '#ff4757', '#2ed573', '#ffa502', '#8b95a8'], borderWidth: 2 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '60%', plugins: { legend: { position: 'right', labels: { color: '#8b95a8', font: { size: 10 } } } } }
      });
    }
    const ctx2 = document.getElementById('etfTrendChart').getContext('2d');
    if (charts.etfTrend) charts.etfTrend.destroy();
    charts.etfTrend = new Chart(ctx2, {
      type: 'line',
      data: { labels: etfList.slice(0, 10).map((d,i) => d.date || d.day || ('Day ' + (i+1))), datasets: [{ label: 'Flow ($M)', data: etfList.slice(0, 10).map(d => parseFloat(d.flow || d.dailyFlow || d.value || 0) / 1e6), borderColor: '#00e5c0', backgroundColor: 'rgba(0,229,192,0.1)', fill: true, tension: 0.4, pointRadius: 3 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { grid: { color: 'rgba(30,39,64,0.4)' }, ticks: { color: '#4a5568' } }, x: { grid: { display: false }, ticks: { color: '#4a5568', font: { size: 10 } } } } }
    });
  } catch (e) { console.error('ETF error:', e); document.getElementById('etfContent').innerHTML = '<div class="error-state"><div class="text-sm font-medium">ETF data unavailable</div><div class="text-xs opacity-60">' + e.message + '</div></div>'; }
}

document.addEventListener('DOMContentLoaded', () => {
  loadRsi();
  setInterval(loadRsi, 60000);
});
</script>
</body>
</html>
HTMLEOF

EXPOSE 10000
CMD ["python", "/app/main.py"]