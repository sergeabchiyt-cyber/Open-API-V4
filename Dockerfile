FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] httpx pycryptodome jinja2
RUN mkdir -p /app/templates

# ============================================================
# decrypt.py – unchanged, handles encryption
# ============================================================
RUN cat <<'PYEOF' > /app/decrypt.py
import os, json, gzip, base64, time, logging
from urllib.parse import urlparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import httpx

logger = logging.getLogger(__name__)

_KEY_TABLE = {
    "55": "170b070da9654622",
    "66": "d6537d845a964081",
    "77": "863f08689c97435b",
}

for _pair in os.environ.get("CAPI_EXTRA_KEYS", "").split(","):
    if "=" in _pair:
        _k, _v = _pair.strip().split("=", 1)
        _KEY_TABLE[_k.strip()] = _v.strip()

def _derive_key0(v, url="", outer=None):
    if v == "0":
        constant = url
    elif v == "1":
        constant = urlparse(url).path or url
    elif v == "2":
        constant = str((outer or {}).get("time", ""))
    else:
        constant = _KEY_TABLE.get(v)
        if constant is None:
            raise ValueError(
                f"Unknown encryption v={v}. "
                f"Inject new key via CAPI_EXTRA_KEYS env var: '{v}=<16-char-hex>'"
            )
    return base64.b64encode(constant.encode()).decode()[:16]

def decrypt(body, user_b64, v, url=""):
    outer = json.loads(body)
    if "data" not in outer:
        return outer
    payload = base64.b64decode(outer["data"])
    token   = base64.b64decode(user_b64)
    key0    = _derive_key0(v, url, outer)
    step1   = unpad(AES.new(key0.encode(), AES.MODE_ECB).decrypt(token), 16)
    akey    = gzip.decompress(step1).decode()
    step2   = unpad(AES.new(akey.encode(), AES.MODE_ECB).decrypt(payload), 16)
    return json.loads(gzip.decompress(step2).decode())

async def fetch_and_decrypt(url, params=None, timeout=15):
    headers = {
        "Accept": "application/json, text/plain, */*",
        "cache-ts-v2": str(int(time.time() * 1000)),
        "encryption": "true",
        "language": "en",
        "Origin": "https://www.coinglass.com",
        "Referer": "https://www.coinglass.com",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0.0.0 Safari/537.36",
    }
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.get(url, params=params or {}, headers=headers)
        r.raise_for_status()
        user = r.headers.get("user")
        v    = r.headers.get("v")
        if not user or not v:
            try:
                return r.json()
            except:
                return {"raw": r.text}
        return decrypt(r.text, user, v, url)
PYEOF

# ============================================================
# main.py – FastAPI with clean data registry
# ============================================================
RUN cat <<'PYEOF' > /app/main.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from decrypt import fetch_and_decrypt
import json, logging, traceback

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app  = FastAPI(title="CoinGlass Terminal")
T    = Jinja2Templates(directory="/app/templates")
BASE = "https://capi.coinglass.com"

REGISTRY = [
    {"id":"hot_exs",       "cat":"Market", "label":"Hot Exchanges",       "path":"/api/coin/hot/exs", "params":{}},
    {"id":"liq_heatmap",   "cat":"Market", "label":"Liquidation Heatmap", "path":"/api/coin/liq/heatmap", "params":{"time":"h1","type":"coin"}},
    {"id":"coin_liq",      "cat":"Market", "label":"Coin Liquidations",   "path":"/api/coin/liquidation","params":{}},
    {"id":"etf_flow_all",  "cat":"ETF",    "label":"ETF Overall Flow",    "path":"/api/etf/flow","params":{}},
    {"id":"etf_flow_eth",  "cat":"ETF",    "label":"ETF ETH Flow",        "path":"/api/etf/eth/flow","params":{}},
    {"id":"etf_flow_sol",  "cat":"ETF",    "label":"ETF SOL Flow",        "path":"/api/etf/sol/flow","params":{}},
    {"id":"fr_avg",        "cat":"Funding","label":"Funding Avg",         "path":"/api/fundingRate/avg","params":{}},
    {"id":"fr_rank",       "cat":"Funding","label":"Funding Rank",        "path":"/api/fundingRate/rank","params":{}},
    {"id":"fr_btc",        "cat":"Funding","label":"Funding BTC History", "path":"/api/fundingRate/v2/history/chart","params":{"symbol":"BTC","type":"U","interval":"h8"}},
    {"id":"fr_eth",        "cat":"Funding","label":"Funding ETH History", "path":"/api/fundingRate/v2/history/chart","params":{"symbol":"ETH","type":"U","interval":"h8"}},
    {"id":"fr_sol",        "cat":"Funding","label":"Funding SOL History", "path":"/api/fundingRate/v2/history/chart","params":{"symbol":"SOL","type":"U","interval":"h8"}},
    {"id":"fr_home",       "cat":"Funding","label":"Funding Home",        "path":"/api/fundingRate/v2/home","params":{}},
    {"id":"fut_price_change","cat":"Futures","label":"Price Change (all)","path":"/api/futures/coins/priceChange","params":{"ex":"all"}},
    {"id":"fut_home_stats", "cat":"Futures","label":"Futures Stats",       "path":"/api/futures/home/statistics","params":{}},
    {"id":"fut_liq_chart",  "cat":"Futures","label":"Liquidation Chart",  "path":"/api/futures/liquidation/chart","params":{"symbol":"","timeType":"4","range":"90d"}},
    {"id":"fut_liq_ex",     "cat":"Futures","label":"Liq by Exchange",    "path":"/api/futures/liquidation/ex/info","params":{"time":"h4","symbol":""}},
    {"id":"fut_liq_max",    "cat":"Futures","label":"Largest Liq Orders", "path":"/api/futures/liquidation/maxOrder","params":{}},
    {"id":"fut_liq_orders", "cat":"Futures","label":"Liquidation Orders", "path":"/api/futures/liquidation/order","params":{"volUsd":"","symbol":"","exName":"","pageNum":1,"pageSize":1000}},
    {"id":"fut_markets",    "cat":"Futures","label":"Futures Markets",    "path":"/api/futures/v2/coins/markets","params":{}},
    {"id":"oi_gains",      "cat":"OI",     "label":"OI Gainers (1h)",      "path":"/api/openInterest/change","params":{"time":"h1","gains":"gains"}},
    {"id":"oi_losers",     "cat":"OI",     "label":"OI Losers (1h)",       "path":"/api/openInterest/change","params":{"time":"h1","gains":"loser"}},
    {"id":"oi_ex_btc",     "cat":"OI",     "label":"OI Exchange (BTC)",    "path":"/api/openInterest/ex/info","params":{"symbol":"BTC"}},
    {"id":"oi_ex_eth",     "cat":"OI",     "label":"OI Exchange (ETH)",    "path":"/api/openInterest/ex/info","params":{"symbol":"ETH"}},
    {"id":"oi_ex_sol",     "cat":"OI",     "label":"OI Exchange (SOL)",    "path":"/api/openInterest/ex/info","params":{"symbol":"SOL"}},
    {"id":"oi_history",    "cat":"OI",     "label":"OI History (all)",     "path":"/api/openInterest/history/all","params":{}},
    {"id":"oi_vol_ratio",  "cat":"OI",     "label":"OI/Vol Ratio",         "path":"/api/openInterest/oiVolRadio","params":{}},
    {"id":"oi_chart_btc",  "cat":"OI",     "label":"OI Chart (BTC)",       "path":"/api/openInterest/v3/chart","params":{"symbol":"BTC","timeType":0,"exchangeName":"","currency":"USD","type":0}},
    {"id":"oi_chart_eth",  "cat":"OI",     "label":"OI Chart (ETH)",       "path":"/api/openInterest/v3/chart","params":{"symbol":"ETH","timeType":0,"exchangeName":"","currency":"USD","type":0}},
    {"id":"mkt_rsi",       "cat":"Market", "label":"Top RSI",            "path":"/api/home/v2/coinMarkets","params":{"sort":"rsi4h","order":"desc","pageNum":1,"pageSize":20,"ex":"all"}},
    {"id":"mkt_price_chg", "cat":"Market", "label":"Top Price Change",  "path":"/api/home/v2/coinMarkets","params":{"sort":"h4PriceChangePercent","order":"desc","pageNum":1,"pageSize":20,"ex":"all"}},
    {"id":"mkt_oi_chg",    "cat":"Market", "label":"Top OI Change",     "path":"/api/home/v2/coinMarkets","params":{"sort":"h4OiChangePercent","order":"desc","pageNum":1,"pageSize":20,"ex":"all"}},
    {"id":"mkt_liq",       "cat":"Market", "label":"Top Liquidations",  "path":"/api/home/v2/coinMarkets","params":{"sort":"h1LiquidationUsd","order":"desc","pageNum":1,"pageSize":20,"ex":"all"}},
    {"id":"mkt_all",       "cat":"Market", "label":"All Markets",       "path":"/api/home/v2/coinMarkets","params":{"sort":"","order":"","keyword":"","pageNum":1,"pageSize":50,"ex":"all"}},
    {"id":"cgdi",          "cat":"Index",  "label":"CGDI",              "path":"/api/index/cgdi","params":{}},
    {"id":"rsi_map",       "cat":"Index",  "label":"RSI Map",           "path":"/api/index/rsiMap","params":{}},
    {"id":"symbols",       "cat":"Info",   "label":"Support Symbols",   "path":"/api/support/symbol","params":{}},
    {"id":"symbols_v2",    "cat":"Info",   "label":"Symbols V2",        "path":"/api/v2/support/symbol","params":{}},
]

def extract(d):
    if isinstance(d, list): return d
    if isinstance(d, dict):
        for k in ["list","topInflowList","inflowList","rankList","coins","data"]:
            if k not in d: continue
            v = d[k]
            if isinstance(v, list): return v
            if isinstance(v, dict):
                for kk in ["list","topInflowList","rankList"]:
                    if kk in v and isinstance(v[kk], list): return v[kk]
    return []

@app.get("/", response_class=HTMLResponse)
async def root(req: Request):
    return T.TemplateResponse(req, "dashboard.html", {})

@app.get("/api/registry")
async def registry():
    return {"endpoints": REGISTRY}

@app.get("/api/{eid}")
async def endpoint(eid: str):
    ep = next((e for e in REGISTRY if e["id"] == eid), None)
    if not ep: raise HTTPException(404, f"Unknown endpoint: {eid}")
    try:
        d = await fetch_and_decrypt(f"{BASE}{ep['path']}", ep["params"])
        return {"success": True, "data": d, "extracted": extract(d)}
    except Exception as e:
        logger.error(traceback.format_exc())
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.post("/api/explore")
async def explore(req: Request):
    b    = await req.json()
    path = b.get("path", "")
    prms = b.get("params", {})
    if not path.startswith("/"): path = "/" + path
    url  = f"{BASE}{path}"
    try:
        d = await fetch_and_decrypt(url, prms)
        return {"success": True, "url": url, "data": d}
    except Exception as e:
        logger.error(traceback.format_exc())
        return JSONResponse(status_code=500, content={"success": False, "url": url, "error": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
PYEOF

# ============================================================
# dashboard.html – Uber‑sleek UI with dynamic sidebar & cards
# ============================================================
RUN cat <<'HTMLEOF' > /app/templates/dashboard.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CoinGlass Terminal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg: #070b14;
  --panel: #0b1124;
  --card: rgba(14, 20, 40, 0.85);
  --border: rgba(255,255,255,0.07);
  --accent: #f0b429;
  --accent-dim: rgba(240, 180, 41, 0.12);
  --blue: #4f9fff;
  --green: #3ddc84;
  --red: #ff4d6d;
  --text: #c8d2e8;
  --text-bright: #edf2fa;
  --muted: #4a5b7a;
  --radius: 14px;
  --shadow: 0 12px 40px rgba(0,0,0,0.6);
}
* { margin:0; padding:0; box-sizing:border-box }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Inter', sans-serif;
  font-size: 13px;
  height: 100vh;
  overflow: hidden;
}
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-thumb { background: var(--muted); border-radius: 10px; }
::-webkit-scrollbar-track { background: transparent; }

/* Layout */
.shell { display: flex; height: 100vh; }
.sidebar {
  width: 200px;
  flex-shrink: 0;
  background: var(--panel);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  padding-bottom: 16px;
}
.main {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.topbar {
  height: 44px;
  flex-shrink: 0;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 20px;
  background: rgba(7,11,20,0.92);
  backdrop-filter: blur(8px);
}
.content {
  flex: 1;
  overflow-y: auto;
  padding: 20px 24px 32px;
}

/* Sidebar */
.sb-logo {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 16px 14px 12px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.sb-logo-text span { font-weight: 700; font-size: 15px; color: var(--text-bright); letter-spacing: -0.3px; }
.sb-logo-text small { font-family: 'JetBrains Mono', monospace; font-size: 9px; color: var(--accent); letter-spacing: 0.12em; text-transform: uppercase; }

.sb-cat {
  padding: 16px 14px 4px;
  font-size: 9px;
  font-weight: 700;
  color: var(--muted);
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.sb-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 14px;
  font-size: 12px;
  font-weight: 500;
  color: var(--text);
  border-left: 2px solid transparent;
  cursor: pointer;
  transition: all 0.15s;
  user-select: none;
}
.sb-item:hover { background: rgba(255,255,255,0.03); color: var(--text-bright); }
.sb-item.active { color: var(--accent); border-left-color: var(--accent); background: var(--accent-dim); }
.sb-item .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--muted); flex-shrink: 0; transition: background 0.15s; }
.sb-item.active .dot { background: var(--accent); }
.sb-item .badge {
  margin-left: auto;
  background: rgba(255,255,255,0.06);
  padding: 0 8px;
  border-radius: 10px;
  font-size: 9px;
  color: var(--muted);
  font-weight: 600;
}

/* Topbar */
.tb-status { display: flex; align-items: center; gap: 5px; font-size: 11px; color: var(--green); font-weight: 500; }
.tb-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); animation: pulse 2s infinite; }
@keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:0.35 } }
.tb-chip { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--muted); }
.tb-chip b { color: var(--text); font-weight: 500; }
.tb-time { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--muted); margin-left: auto; }
.tb-refresh {
  padding: 4px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 11px;
  color: var(--muted);
  font-family: 'Inter', sans-serif;
  transition: all 0.15s;
  background: transparent;
}
.tb-refresh:hover { border-color: var(--accent); color: var(--accent); }

/* Cards */
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 18px 20px;
  backdrop-filter: blur(4px);
  transition: border-color 0.2s;
}
.card:hover { border-color: rgba(255,255,255,0.12); }
.card-title {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
  margin-bottom: 10px;
}
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-bottom: 18px; }
.stat-box {
  background: rgba(255,255,255,0.02);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 12px 14px;
}
.stat-box .label { font-size: 9px; font-weight: 600; text-transform: uppercase; color: var(--muted); letter-spacing: 0.06em; margin-bottom: 4px; }
.stat-box .value { font-family: 'JetBrains Mono', monospace; font-size: 20px; font-weight: 600; color: var(--text-bright); }
.stat-box .sub { font-size: 11px; color: var(--muted); margin-top: 2px; }

.chart-container { height: 220px; position: relative; margin-bottom: 16px; }

/* Tables */
.table-wrap {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  margin-bottom: 16px;
}
.table-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
}
.table-head .title { font-weight: 600; font-size: 12px; color: var(--text-bright); }
.table-head .meta { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--muted); }
.table-scroll { overflow-x: auto; max-height: 400px; overflow-y: auto; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
thead th {
  position: sticky;
  top: 0;
  background: rgba(7,11,20,0.97);
  backdrop-filter: blur(8px);
  padding: 8px 12px;
  font-size: 9px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  text-align: left;
  white-space: nowrap;
  cursor: pointer;
  user-select: none;
  transition: color 0.15s;
}
thead th:hover { color: var(--text); }
thead th.sorted-asc::after { content: " ↑"; color: var(--accent); }
thead th.sorted-desc::after { content: " ↓"; color: var(--accent); }
tbody td { padding: 7px 12px; border-bottom: 1px solid rgba(255,255,255,0.03); }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover td { background: rgba(255,255,255,0.02); }

/* Badges */
.badge {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 4px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  font-weight: 600;
  white-space: nowrap;
}
.bg-red { background: rgba(255,77,109,0.15); color: var(--red); }
.bg-green { background: rgba(61,220,132,0.15); color: var(--green); }
.bg-neutral { background: rgba(255,255,255,0.05); color: var(--muted); }
.bg-accent { background: var(--accent-dim); color: var(--accent); }

/* Raw toggle */
.raw-toggle {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--muted);
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 5px;
  padding: 8px 0;
  border-top: 1px solid var(--border);
  margin-top: 10px;
  transition: color 0.15s;
}
.raw-toggle:hover { color: var(--accent); }
.raw-box {
  background: rgba(0,0,0,0.5);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  color: var(--muted);
  max-height: 300px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
  margin-top: 6px;
  display: none;
}

/* Explorer */
.explorer-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  margin-bottom: 16px;
}
.explorer-card label { font-size: 9px; font-weight: 600; text-transform: uppercase; color: var(--muted); letter-spacing: 0.08em; display: block; margin-bottom: 4px; }
.explorer-card input, .explorer-card textarea {
  width: 100%;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 8px 12px;
  color: var(--text-bright);
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  outline: none;
  transition: border-color 0.15s;
  margin-bottom: 12px;
}
.explorer-card input:focus, .explorer-card textarea:focus { border-color: var(--accent); }
.explorer-card textarea { min-height: 60px; resize: vertical; }
.explorer-btn {
  padding: 8px 20px;
  background: var(--accent);
  color: #000;
  font-weight: 600;
  font-size: 12px;
  border-radius: 8px;
  border: none;
  cursor: pointer;
  transition: opacity 0.15s;
}
.explorer-btn:hover { opacity: 0.85; }
.chip-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.chip {
  padding: 4px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 9px;
  color: var(--muted);
  cursor: pointer;
  transition: all 0.15s;
}
.chip:hover { border-color: var(--accent); color: var(--accent); background: var(--accent-dim); }

/* Skeleton */
.skeleton {
  background: linear-gradient(90deg, rgba(255,255,255,0.02) 25%, rgba(255,255,255,0.06) 50%, rgba(255,255,255,0.02) 75%);
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
  border-radius: 8px;
}
@keyframes shimmer { 0% { background-position: -200% 0 } 100% { background-position: 200% 0 } }

/* Misc */
.error-box { background: rgba(255,77,109,0.08); border: 1px solid rgba(255,77,109,0.2); border-radius: 10px; padding: 14px 16px; color: var(--red); font-family: 'JetBrains Mono', monospace; font-size: 12px; margin-bottom: 14px; }
.error-box strong { display: block; font-weight: 600; margin-bottom: 4px; }
.empty-state { text-align: center; padding: 40px 20px; color: var(--muted); }
.empty-state .icon { font-size: 28px; margin-bottom: 8px; }

/* Responsive */
@media (max-width: 768px) {
  .sidebar { width: 48px; }
  .sb-logo-text, .sb-cat, .sb-item span { display: none; }
  .sb-item { padding: 10px; justify-content: center; }
  .stats-grid { grid-template-columns: 1fr 1fr; }
}
</style>
</head>
<body>
<div class="shell">
  <nav class="sidebar" id="sidebar"></nav>
  <div class="main">
    <div class="topbar">
      <div class="tb-status"><span class="tb-dot"></span>LIVE</div>
      <div class="tb-chip" id="tbCount"></div>
      <div class="tb-chip" id="tbPanel">Select endpoint</div>
      <div class="tb-time" id="tbTime">--:--:--</div>
      <button class="tb-refresh" onclick="refresh()">↻ Refresh</button>
    </div>
    <div class="content" id="content"></div>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
let currentId = null;
let registry = [];
let charts = {};

// ── Fetch registry ────────────────────────────────────────────
async function loadRegistry() {
  const r = await fetch('/api/registry');
  const j = await r.json();
  registry = j.endpoints;
  buildSidebar();
}

function buildSidebar() {
  const cats = {};
  registry.forEach(e => {
    if (!cats[e.cat]) cats[e.cat] = [];
    cats[e.cat].push(e);
  });
  const sidebar = document.getElementById('sidebar');
  let html = `
    <div class="sb-logo">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <rect width="24" height="24" rx="6" fill="#f0b429"/>
        <path d="M12 3L4 13h6v8l8-10h-6V3z" fill="#070b14"/>
      </svg>
      <div class="sb-logo-text"><span>CoinGlass</span><small>Terminal</small></div>
    </div>
  `;
  for (const [cat, items] of Object.entries(cats)) {
    html += `<div class="sb-cat">${cat}</div>`;
    items.forEach(e => {
      html += `<div class="sb-item" data-id="${e.id}" onclick="loadEndpoint('${e.id}')">
        <span class="dot"></span>
        <span>${e.label}</span>
        <span class="badge">${Object.keys(e.params || {}).length}</span>
      </div>`;
    });
  }
  // Explorer
  html += `<div class="sb-cat">Tools</div>
    <div class="sb-item" data-id="explorer" onclick="showExplorer()">
      <span class="dot" style="background:var(--accent)"></span>
      <span>API Explorer</span>
    </div>`;
  sidebar.innerHTML = html;
}

// ── Navigation ────────────────────────────────────────────────
function setActive(id) {
  document.querySelectorAll('.sb-item').forEach(el => el.classList.remove('active'));
  const active = document.querySelector(`.sb-item[data-id="${id}"]`);
  if (active) active.classList.add('active');
}

function loadEndpoint(id) {
  currentId = id;
  setActive(id);
  const ep = registry.find(e => e.id === id);
  if (!ep) return;
  document.getElementById('tbPanel').textContent = ep.label;
  fetchData(id);
}

function refresh() {
  if (currentId && currentId !== 'explorer') loadEndpoint(currentId);
}

async function fetchData(id) {
  const content = document.getElementById('content');
  content.innerHTML = skeletonHTML();
  try {
    const r = await fetch('/api/' + id);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    document.getElementById('tbTime').textContent = new Date().toLocaleTimeString();
    if (!j.success) throw new Error(j.error || 'Unknown error');
    renderData(j.data, j.extracted || []);
  } catch (e) {
    content.innerHTML = `<div class="error-box"><strong>Error</strong>${e.message}</div>`;
  }
}

function skeletonHTML() {
  return `
    <div class="stats-grid">
      ${Array(3).fill('<div class="stat-box skeleton" style="height:60px"></div>').join('')}
    </div>
    <div class="card skeleton" style="height:200px;margin-bottom:16px"></div>
    <div class="table-wrap skeleton" style="height:260px"></div>
  `;
}

function renderData(data, extracted) {
  const list = extracted.length ? extracted : (Array.isArray(data) ? data : []);
  // Build stats
  let stats = [];
  if (list.length) {
    const keys = Object.keys(list[0] || {});
    keys.slice(0, 4).forEach(k => {
      const values = list.map(item => parseFloat(item[k])).filter(v => !isNaN(v));
      if (values.length) {
        const avg = values.reduce((a,b) => a+b, 0) / values.length;
        const max = Math.max(...values);
        stats.push({ label: k, value: max.toFixed(2), sub: `avg ${avg.toFixed(2)}` });
      }
    });
  }
  if (!stats.length) {
    stats = [{ label: 'Rows', value: list.length, sub: '' }];
  }

  let html = `<div class="stats-grid">`;
  stats.forEach(s => {
    html += `<div class="stat-box">
      <div class="label">${s.label}</div>
      <div class="value">${s.value}</div>
      <div class="sub">${s.sub}</div>
    </div>`;
  });
  html += `</div>`;

  // Chart – if numeric fields exist
  if (list.length > 1) {
    const first = list[0];
    const numericKeys = Object.keys(first).filter(k => !isNaN(parseFloat(first[k])));
    if (numericKeys.length) {
      const chartKey = numericKeys[0];
      html += `<div class="card" style="margin-bottom:16px">
        <div class="card-title">${chartKey} trend</div>
        <div class="chart-container"><canvas id="chartCanvas"></canvas></div>
      </div>`;
    }
  }

  // Table
  if (list.length) {
    const cols = Object.keys(list[0]).slice(0, 8);
    html += `<div class="table-wrap">
      <div class="table-head">
        <span class="title">Data</span>
        <span class="meta">${list.length} rows</span>
      </div>
      <div class="table-scroll">
        <table id="dataTable">
          <thead><tr>${cols.map(c => `<th data-col="${c}">${c}</th>`).join('')}</tr></thead>
          <tbody>
            ${list.slice(0, 200).map(row => `
              <tr>${cols.map(c => {
                let val = row[c];
                if (val === undefined || val === null) val = '—';
                if (typeof val === 'number') {
                  if (Math.abs(val) > 1000) val = '$' + formatNum(val);
                  else if (Math.abs(val) < 0.01) val = val.toFixed(6);
                  else val = val.toFixed(2);
                } else if (typeof val === 'object') {
                  val = JSON.stringify(val).slice(0, 40);
                }
                return `<td>${String(val)}</td>`;
              }).join('')}</tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>`;
  } else {
    html += `<div class="empty-state"><div class="icon">📭</div><div>No data extracted</div></div>`;
  }

  // Raw toggle
  html += `<div class="raw-toggle" onclick="toggleRaw()">▶ Raw JSON</div>
    <div class="raw-box" id="rawBox">${JSON.stringify(data, null, 2)}</div>`;

  document.getElementById('content').innerHTML = html;

  // Draw chart
  if (list.length > 1) {
    const canvas = document.getElementById('chartCanvas');
    if (canvas) {
      const ctx = canvas.getContext('2d');
      const numericKey = Object.keys(list[0]).find(k => !isNaN(parseFloat(list[0][k])));
      if (numericKey) {
        const labels = list.map((_, i) => i+1);
        const values = list.map(row => parseFloat(row[numericKey]) || 0);
        if (charts.main) charts.main.destroy();
        charts.main = new Chart(ctx, {
          type: 'line',
          data: { labels, datasets: [{ data: values, borderColor: '#f0b429', backgroundColor: 'rgba(240,180,41,0.08)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2 }] },
          options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { grid: { color: 'rgba(255,255,255,0.04)' } }, x: { grid: { display: false } } } }
        });
      }
    }
  }

  // Sortable table
  const table = document.getElementById('dataTable');
  if (table) {
    table.querySelectorAll('thead th').forEach(th => {
      th.addEventListener('click', () => {
        const col = th.dataset.col;
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const dir = th.classList.contains('sorted-asc') ? -1 : 1;
        rows.sort((a, b) => {
          const va = a.cells[Array.from(th.parentElement.children).indexOf(th)]?.textContent || '';
          const vb = b.cells[Array.from(th.parentElement.children).indexOf(th)]?.textContent || '';
          const na = parseFloat(va), nb = parseFloat(vb);
          return (!isNaN(na) && !isNaN(nb)) ? (na - nb) * dir : va.localeCompare(vb) * dir;
        });
        rows.forEach(r => tbody.appendChild(r));
        table.querySelectorAll('thead th').forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));
        th.classList.add(dir === 1 ? 'sorted-asc' : 'sorted-desc');
      });
    });
  }
}

function toggleRaw() {
  const box = document.getElementById('rawBox');
  box.style.display = box.style.display === 'none' ? 'block' : 'none';
}

function formatNum(n) {
  if (n >= 1e9) return (n/1e9).toFixed(2) + 'B';
  if (n >= 1e6) return (n/1e6).toFixed(2) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
  return n.toFixed(2);
}

// ── Explorer ──────────────────────────────────────────────────
function showExplorer() {
  setActive('explorer');
  document.getElementById('tbPanel').textContent = 'API Explorer';
  const content = document.getElementById('content');
  content.innerHTML = `
    <div class="explorer-card">
      <label>Endpoint Path</label>
      <input id="exPath" placeholder="/api/coin/liq/heatmap" value="/api/coin/liq/heatmap">
      <label>Params (JSON)</label>
      <textarea id="exParams">{"time":"h1","type":"coin"}</textarea>
      <button class="explorer-btn" onclick="runExplorer()">Fetch & Decrypt</button>
      <div class="chip-list">
        ${registry.slice(0, 12).map(e => `<span class="chip" onclick="setExplorer('${e.path}', '${JSON.stringify(e.params)}')">${e.path}</span>`).join('')}
      </div>
    </div>
    <div id="exResult"></div>
  `;
}

function setExplorer(path, params) {
  document.getElementById('exPath').value = path;
  document.getElementById('exParams').value = params;
}

async function runExplorer() {
  const path = document.getElementById('exPath').value.trim();
  let params = {};
  try { params = JSON.parse(document.getElementById('exParams').value || '{}'); } catch(e) { alert('Invalid JSON params'); return; }
  const result = document.getElementById('exResult');
  result.innerHTML = '<div class="skeleton" style="height:200px;border-radius:12px"></div>';
  try {
    const r = await fetch('/api/explore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, params })
    });
    const j = await r.json();
    if (!j.success) throw new Error(j.error);
    result.innerHTML = `
      <div class="table-wrap">
        <div class="table-head"><span class="title">${j.url}</span><span class="badge bg-green">✅ Decrypted</span></div>
        <div class="table-scroll"><pre style="padding:12px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--muted);max-height:300px;overflow:auto">${JSON.stringify(j.data, null, 2)}</pre></div>
      </div>
    `;
  } catch(e) {
    result.innerHTML = `<div class="error-box"><strong>Error</strong>${e.message}</div>`;
  }
}

// ── Clock ──────────────────────────────────────────────────────
setInterval(() => {
  const el = document.getElementById('tbTime');
  if (el && el.textContent !== '--:--:--') el.textContent = new Date().toLocaleTimeString();
}, 1000);

// ── Init ──────────────────────────────────────────────────────
loadRegistry().then(() => {
  // Load first endpoint
  const first = registry[0];
  if (first) loadEndpoint(first.id);
});
</script>
</body>
</html>
HTMLEOF

EXPOSE 10000
CMD ["python", "/app/main.py"]