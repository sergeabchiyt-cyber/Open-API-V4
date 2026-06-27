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
# dashboard.html – Complete UI overhaul (UI/UX PRO Institutional Terminal)
# ============================================================
RUN cat <<'HTMLEOF' > /app/templates/dashboard.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CoinGlass Terminal PRO</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://unpkg.com/lightweight-charts@5.2.0/dist/lightweight-charts.standalone.production.js"></script>
<style>
:root {
  --bg-main: #060913;
  --bg-surface: #0b1120;
  --bg-surface-elevated: #131b2e;
  --border-primary: rgba(255, 255, 255, 0.05);
  --border-focus: #3b82f6;
  --brand-accent: #f0b429;
  --brand-accent-dim: rgba(240, 180, 41, 0.08);
  
  --text-primary: #f1f5f9;
  --text-secondary: #94a3b8;
  --text-muted: #475569;
  
  --bull-green: #22c55e;
  --bear-red: #ef4444;
  --bull-dim: rgba(34, 197, 94, 0.1);
  --bear-dim: rgba(239, 68, 68, 0.1);
  
  --font-sans: 'Plus Jakarta Sans', sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
  --sidebar-width: 260px;
  --sidebar-collapsed-width: 60px;
  --topbar-height: 48px;
}

* { margin: 0; padding: 0; box-sizing: border-box; -webkit-font-smoothing: antialiased; }
body {
  background: var(--bg-main);
  color: var(--text-primary);
  font-family: var(--font-sans);
  font-size: 12px;
  height: 100vh;
  overflow: hidden;
}

/* Custom Scrollbars */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-thumb { background: var(--text-muted); border-radius: 2px; }
::-webkit-scrollbar-track { background: transparent; }

.app-container { display: flex; height: 100vh; width: 100vw; }

/* Sidebar Navigation */
.sidebar {
  width: var(--sidebar-width);
  background: var(--bg-surface);
  border-right: 1px solid var(--border-primary);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  transition: width 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  z-index: 20;
}
.sidebar.collapsed { width: var(--sidebar-collapsed-width); }

.sidebar-header {
  height: var(--topbar-height);
  display: flex;
  align-items: center;
  padding: 0 16px;
  border-bottom: 1px solid var(--border-primary);
  gap: 12px;
  overflow: hidden;
}
.brand-icon {
  width: 26px; height: 26px; background: var(--brand-accent); border-radius: 6px;
  display: flex; align-items: center; justify-content: center; flex-shrink: 0;
}
.brand-icon svg { width: 14px; height: 14px; fill: var(--bg-main); }
.brand-meta { transition: opacity 0.15s ease; white-space: nowrap; }
.brand-meta h1 { font-size: 14px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.3px; line-height: 1.2; }
.brand-meta span { font-family: var(--font-mono); font-size: 9px; color: var(--brand-accent); font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
.sidebar.collapsed .brand-meta { opacity: 0; pointer-events: none; }

.search-container { padding: 10px 12px; border-bottom: 1px solid var(--border-primary); }
.sidebar.collapsed .search-container { display: none; }
.search-wrapper { position: relative; }
.search-wrapper input {
  width: 100%; background: var(--bg-main); border: 1px solid var(--border-primary);
  border-radius: 6px; padding: 6px 10px; color: var(--text-primary);
  font-family: var(--font-sans); font-size: 11px; outline: none; transition: all 0.15s;
}
.search-wrapper input:focus { border-color: var(--border-focus); background: var(--bg-surface-elevated); }

.nav-scroll { flex: 1; overflow-y: auto; padding: 8px 0; }
.nav-group { margin-bottom: 12px; }
.nav-group-header {
  padding: 6px 16px; font-size: 9px; font-weight: 700; color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 1.5px; display: flex; align-items: center;
  justify-content: space-between; cursor: pointer; user-select: none;
}
.nav-group-header:hover { color: var(--text-secondary); }
.nav-group-header .chevron { font-family: var(--font-mono); font-size: 8px; transition: transform 0.2s; }
.nav-group.collapsed .chevron { transform: rotate(-90deg); }
.nav-group.collapsed .nav-items { display: none; }

.sidebar.collapsed .nav-group-header { display: none; }

.nav-item {
  display: flex; align-items: center; padding: 7px 16px; font-size: 12px; font-weight: 500;
  color: var(--text-secondary); cursor: pointer; border-left: 2px solid transparent;
  transition: all 0.15s ease; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.nav-item:hover { background: rgba(255,255,255,0.02); color: var(--text-primary); }
.nav-item.active { background: var(--brand-accent-dim); color: var(--brand-accent); border-left-color: var(--brand-accent); font-weight: 600; }
.nav-item .node-dot { width: 4px; height: 4px; border-radius: 50%; background: var(--text-muted); margin-right: 10px; flex-shrink: 0; }
.nav-item.active .node-dot { background: var(--brand-accent); }
.nav-item .param-count { margin-left: auto; font-family: var(--font-mono); font-size: 9px; background: rgba(255,255,255,0.04); padding: 1px 5px; border-radius: 4px; color: var(--text-muted); }
.sidebar.collapsed .nav-item { padding: 12px 0; justify-content: center; }
.sidebar.collapsed .nav-item span:not(.node-dot) { display: none; }
.sidebar.collapsed .nav-item .node-dot { margin-right: 0; width: 6px; height: 6px; }

/* Main Workspace Floor */
.workspace { flex: 1; display: flex; flex-direction: column; overflow: hidden; background: var(--bg-main); }

/* Control Topbar */
.topbar {
  height: var(--topbar-height); background: var(--bg-surface);
  border-bottom: 1px solid var(--border-primary); display: flex;
  align-items: center; padding: 0 20px; gap: 16px; flex-shrink: 0;
}
.sidebar-toggle { background: transparent; border: none; color: var(--text-secondary); cursor: pointer; padding: 4px; display: flex; align-items: center; justify-content: center; font-size: 14px; }
.sidebar-toggle:hover { color: var(--text-primary); }
.endpoint-badge { font-family: var(--font-mono); background: var(--bg-surface-elevated); border: 1px solid var(--border-primary); padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; color: var(--text-primary); }
.sys-status { display: flex; align-items: center; gap: 6px; font-family: var(--font-mono); font-size: 10px; font-weight: 600; color: var(--bull-green); margin-left: auto; }
.status-pulse { width: 6px; height: 6px; background: var(--bull-green); border-radius: 50%; box-shadow: 0 0 8px var(--bull-green); animation: pulse 2s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
.timestamp-clock { font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary); border-left: 1px solid var(--border-primary); padding-left: 16px; }
.btn-refresh { background: var(--bg-surface-elevated); border: 1px solid var(--border-primary); color: var(--text-primary); padding: 4px 10px; border-radius: 4px; font-family: var(--font-sans); font-size: 11px; font-weight: 500; cursor: pointer; transition: all 0.15s; display: flex; align-items: center; gap: 4px; }
.btn-refresh:hover { border-color: var(--text-secondary); }

/* Main Dynamic Viewport */
.viewport-content { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 16px; }

/* Metric Strips */
.ticker-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
.ticker-card { background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: 8px; padding: 12px 16px; position: relative; overflow: hidden; }
.ticker-card .label { font-size: 10px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
.ticker-card .value { font-family: var(--font-mono); font-size: 20px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.5px; }
.ticker-card .subtext { font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); margin-top: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* Grid Dashboard Layer */
.pane-layout { display: grid; grid-template-columns: 1fr; gap: 16px; }
@media(min-width: 1200px) { .pane-layout { grid-template-columns: 3fr 2fr; } }

.panel-node { background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: 8px; display: flex; flex-direction: column; overflow: hidden; }
.panel-header { padding: 10px 16px; border-bottom: 1px solid var(--border-primary); display: flex; align-items: center; justify-content: space-between; background: rgba(255,255,255,0.01); }
.panel-header h3 { font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.5px; }

/* TradingView Chart Customizations */
.chart-viewport { height: 380px; width: 100%; position: relative; background: var(--bg-surface); }
.chart-overlay-legend { position: absolute; top: 12px; left: 16px; z-index: 10; font-family: var(--font-mono); font-size: 11px; pointer-events: none; display: flex; flex-direction: column; gap: 2px; }
.legend-row-main { display: flex; align-items: center; gap: 8px; font-weight: 600; color: var(--text-primary); }
.legend-ohlc { display: flex; gap: 8px; font-size: 10px; color: var(--text-secondary); margin-top: 2px; }
.legend-val { color: var(--brand-accent); }

/* High Performance Data Table */
.table-container { overflow: hidden; width: 100%; }
.table-scroll { overflow: auto; max-height: 380px; position: relative; }
table.crypto-grid { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 11px; font-family: var(--font-sans); text-align: left; }
table.crypto-grid th {
  position: sticky; top: 0; background: var(--bg-surface-elevated); padding: 8px 12px;
  font-family: var(--font-sans); font-size: 10px; font-weight: 600; color: var(--text-secondary);
  text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border-primary);
  cursor: pointer; user-select: none; z-index: 2; white-space: nowrap;
}
table.crypto-grid th:hover { color: var(--text-primary); background: rgba(255,255,255,0.04); }
table.crypto-grid th.sort-asc::after { content: " ⬆"; font-size: 8px; color: var(--brand-accent); }
table.crypto-grid th.sort-desc::after { content: " ⬇"; font-size: 8px; color: var(--brand-accent); }
table.crypto-grid td { padding: 7px 12px; border-bottom: 1px solid var(--border-primary); color: var(--text-primary); white-space: nowrap; font-family: var(--font-mono); font-size: 11px; }
table.crypto-grid tr:hover td { background: rgba(255,255,255,0.02); }

/* UI Component Utilities */
.trend-up { color: var(--bull-green) !important; }
.trend-down { color: var(--bear-red) !important; }
.badge-ui { display: inline-block; padding: 2px 6px; border-radius: 4px; font-family: var(--font-mono); font-size: 10px; font-weight: 600; }
.badge-up { background: var(--bull-dim); color: var(--bull-green); }
.badge-down { background: var(--bear-dim); color: var(--bear-red); }

/* JSON Inspect Element */
.inspector-toggle { display: flex; align-items: center; gap: 6px; font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary); cursor: pointer; padding: 8px 0; border-top: 1px solid var(--border-primary); margin-top: 8px; user-select: none; }
.inspector-toggle:hover { color: var(--text-primary); }
.inspector-pre { background: #04060b; border: 1px solid var(--border-primary); border-radius: 6px; padding: 12px; font-family: var(--font-mono); font-size: 11px; color: #64748b; max-height: 250px; overflow: auto; display: none; margin-top: 4px; }

/* Advanced API Custom Tool Explorer */
.explorer-panel { background: var(--bg-surface); border: 1px solid var(--border-primary); border-radius: 8px; padding: 16px; display: flex; flex-direction: column; gap: 12px; }
.form-row { display: grid; grid-template-columns: 1fr; gap: 12px; }
@media(min-width: 768px) { .form-row { grid-template-columns: 2fr 3fr; } }
.field-group { display: flex; flex-direction: column; gap: 4px; }
.field-group label { font-size: 10px; font-weight: 600; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.5px; }
.field-group input, .field-group textarea { background: var(--bg-main); border: 1px solid var(--border-primary); border-radius: 6px; padding: 8px 12px; color: var(--text-primary); font-family: var(--font-mono); font-size: 12px; outline: none; transition: border-color 0.15s; }
.field-group input:focus, .field-group textarea:focus { border-color: var(--border-focus); }
.field-group textarea { min-height: 54px; resize: vertical; }
.btn-submit { background: var(--brand-accent); color: var(--bg-main); font-family: var(--font-sans); font-size: 12px; font-weight: 600; padding: 8px 20px; border: none; border-radius: 6px; cursor: pointer; align-self: flex-start; transition: opacity 0.15s; }
.btn-submit:hover { opacity: 0.9; }

/* Skeletons & States */
.shimmer-state { background: linear-gradient(90deg, rgba(255,255,255,0.01) 25%, rgba(255,255,255,0.04) 50%, rgba(255,255,255,0.01) 75%); background-size: 200% 100%; animation: logic-shimmer 1.5s infinite; border-radius: 6px; }
@keyframes logic-shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
.error-fallback { background: var(--bear-dim); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 8px; padding: 16px; color: var(--bear-red); font-family: var(--font-mono); font-size: 12px; }
.state-empty { text-align: center; padding: 48px; color: var(--text-secondary); font-size: 13px; }
.chart-fallback { text-align: center; padding: 48px; color: var(--text-muted); font-family: var(--font-mono); font-size: 12px; }
</style>
</head>
<body>

<div class="app-container">
  <aside class="sidebar" id="sidebarNode">
    <div class="sidebar-header">
      <div class="brand-icon">
        <svg viewBox="0 0 24 24">
          <path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2v7zm4 0h-2V7h2v10zm4 0h-2v-4h2v4z"/>
        </svg>
      </div>
      <div class="brand-meta">
        <h1>CoinGlass</h1>
        <span>Terminal.PRO</span>
      </div>
    </div>
    <div class="search-container">
      <div class="search-wrapper">
        <input type="text" placeholder="Search structures..." id="searchRoute" oninput="executeRouteFilter()">
      </div>
    </div>
    <div class="nav-scroll" id="sidebarNavFloor"></div>
  </aside>

  <main class="workspace">
    <div class="topbar">
      <button class="sidebar-toggle" onclick="toggleSidebarLayout()">☰</button>
      <div class="endpoint-badge" id="currentPanelLabel">Initialize</div>
      
      <div class="sys-status">
        <span class="status-pulse"></span>
        <span>ENGINE ONLINE</span>
      </div>
      <div class="timestamp-clock" id="clockFloor">--:--:--</div>
      <button class="btn-refresh" onclick="triggerManualReconstruct()">↻ Execution Refresh</button>
    </div>

    <div class="viewport-content" id="viewportMainFloor">
      <div class="state-empty">Select endpoint array to map and evaluate matrix context.</div>
    </div>
  </main>
</div>

<script>
const parseDom = id => document.getElementById(id);
let activeId = null;
let dataRegistry = [];
let tvChartInstance = null;
let tvCandleSeries = null;
let tvLineSeries = null;
let sortingConfig = { column: null, direction: 1 };

// Core Router Init
async function instantiateTerminalInfrastructure() {
  try {
    const res = await fetch('/api/registry');
    const json = await res.json();
    dataRegistry = json.endpoints;
    constructNavigationTree();
    
    // Auto-load prime data node if registration holds array structure
    if (dataRegistry.length > 0) {
      evaluateDataNode(dataRegistry[0].id);
    }
  } catch (err) {
    parseDom('viewportMainFloor').innerHTML = `<div class="error-fallback">System Fault Instantiating Registry Mapping Matrix: ${err.message}</div>`;
  }
}

function constructNavigationTree() {
  const dictionary = {};
  dataRegistry.forEach(node => {
    if (!dictionary[node.cat]) dictionary[node.cat] = [];
    dictionary[node.cat].push(node);
  });
  
  let structuralHtml = '';
  for (const [category, routes] of Object.entries(dictionary)) {
    structuralHtml += `
      <div class="nav-group" data-group-cat="${category}">
        <div class="nav-group-header" onclick="toggleCategoryGroup(this)">
          <span>${category}</span>
          <span class="chevron">▼</span>
        </div>
        <div class="nav-items">
    `;
    routes.forEach(route => {
      structuralHtml += `
        <div class="nav-item" data-route-id="${route.id}" onclick="evaluateDataNode('${route.id}')">
          <span class="node-dot"></span>
          <span>${route.label}</span>
          <span class="param-count">${Object.keys(route.params || {}).length}</span>
        </div>
      `;
    });
    structuralHtml += `</div></div>`;
  }
  
  // Custom Execution Layer Injection
  structuralHtml += `
    <div class="nav-group" data-group-cat="Tools">
      <div class="nav-group-header" onclick="toggleCategoryGroup(this)">
        <span>Core Engine Tools</span>
        <span class="chevron">▼</span>
      </div>
      <div class="nav-items">
        <div class="nav-item" data-route-id="api_explorer" onclick="renderDynamicExplorer()">
          <span class="node-dot" style="background:var(--brand-accent)"></span>
          <span>API Matrix Explorer</span>
        </div>
      </div>
    </div>
  `;
  
  parseDom('sidebarNavFloor').innerHTML = structuralHtml;
}

function toggleCategoryGroup(element) {
  element.parentElement.classList.toggle('collapsed');
}

function executeRouteFilter() {
  const query = parseDom('searchRoute').value.toLowerCase();
  document.querySelectorAll('.nav-item').forEach(item => {
    const stringContext = item.textContent.toLowerCase();
    item.style.display = stringContext.includes(query) ? 'flex' : 'none';
  });
}

function toggleSidebarLayout() {
  parseDom('sidebarNode').classList.toggle('collapsed');
  if(tvChartInstance) {
    // autoSize handles resize automatically in v5
    setTimeout(() => tvChartInstance.applyOptions({}), 220);
  }
}

function evaluateDataNode(id) {
  activeId = id;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const activeTarget = document.querySelector(`.nav-item[data-route-id="${id}"]`);
  if (activeTarget) activeTarget.classList.add('active');
  
  const entity = dataRegistry.find(item => item.id === id);
  parseDom('currentPanelLabel').textContent = entity ? entity.label : "API Matrix Explorer";
  
  executeNodeFetch(id);
}

function triggerManualReconstruct() {
  if (activeId && activeId !== 'api_explorer') evaluateDataNode(activeId);
}

async function executeNodeFetch(id) {
  const targetFloor = parseDom('viewportMainFloor');
  targetFloor.innerHTML = renderSystemSkeletons();
  
  try {
    const response = await fetch(`/api/${id}`);
    if (!response.ok) throw new Error(`Network Stream Fault Status: ${response.status}`);
    const networkPayload = await response.json();
    
    if (!networkPayload.success) throw new Error(networkPayload.error || 'System Fault Evaluated Matrix Payload Exception');
    
    renderMatrixInterface(networkPayload.data, networkPayload.extracted || []);
  } catch (err) {
    targetFloor.innerHTML = `<div class="error-fallback"><strong>Execution Engine Exception</strong>${err.message}</div>`;
  }
}

function renderSystemSkeletons() {
  return `
    <div class="ticker-grid">
      ${Array(4).fill('<div class="ticker-card shimmer-state" style="height:64px"></div>').join('')}
    </div>
    <div class="pane-layout">
      <div class="panel-node shimmer-state" style="height:420px"></div>
      <div class="panel-node shimmer-state" style="height:420px"></div>
    </div>
  `;
}

function renderMatrixInterface(rawMatrix, arrayContext) {
  const normalizedDataset = arrayContext.length ? arrayContext : (Array.isArray(rawMatrix) ? rawMatrix : []);
  
  // Statistical Calculations Optimization Engine
  let statisticsProfile = [];
  if (normalizedDataset.length > 0) {
    const objectArchetype = normalizedDataset[0] || {};
    const quantifiableKeys = Object.keys(objectArchetype).filter(k => typeof objectArchetype[k] === 'number' || !isNaN(parseFloat(objectArchetype[k])));
    
    quantifiableKeys.slice(0, 4).forEach(field => {
      const sampleArray = normalizedDataset.map(row => parseFloat(row[field])).filter(v => !isNaN(v));
      if (sampleArray.length > 0) {
        const peak = Math.max(...sampleArray);
        const trough = Math.min(...sampleArray);
        const mean = sampleArray.reduce((acc, curr) => acc + curr, 0) / sampleArray.length;
        statisticsProfile.push({
          keyName: field,
          peakValue: formatMetricDecimal(peak),
          metadataStr: `MIN: ${formatMetricDecimal(trough)} | AVG: ${formatMetricDecimal(mean)}`
        });
      }
    });
  }
  
  if (!statisticsProfile.length) {
    statisticsProfile = [{ keyName: 'Data Arrays Evaluated', peakValue: normalizedDataset.length, metadataStr: 'Matrix Dimension Array Bounds' }];
  }

  // Construct High Fidelity Blueprint
  let structuralDomString = `<div class="ticker-grid">`;
  statisticsProfile.forEach(stat => {
    structuralDomString += `
      <div class="ticker-card">
        <div class="label">${stat.keyName}</div>
        <div class="value">${stat.peakValue}</div>
        <div class="subtext">${stat.metadataStr}</div>
      </div>
    `;
  });
  structuralDomString += `</div>`;

  // Main Dashboard Grid
  structuralDomString += `
    <div class="pane-layout">
      <div class="panel-node">
        <div class="panel-header">
          <h3>TradingView Realtime Structural Vector</h3>
        </div>
        <div class="chart-viewport" id="tvChartMountNode">
          <div class="chart-overlay-legend" id="chartOverlayLegendFloor">
            <div class="legend-row-main" id="legendMainTitle">Tracking Stream Array Vector</div>
            <div class="legend-ohlc" id="legendOhlcDataMetrics"></div>
          </div>
        </div>
      </div>
      
      <div class="panel-node">
        <div class="panel-header">
          <h3>High Fidelity Linear Matrix Datagrid</h3>
        </div>
        <div class="table-container">
          <div class="table-scroll" id="tableScrollContainerFloor">
            ${generateDataGridMarkup(normalizedDataset)}
          </div>
        </div>
      </div>
    </div>
  `;

  // Raw JSON Diagnostic Section
  structuralDomString += `
    <div class="inspector-toggle" onclick="toggleMatrixInspector()">▼ Toggle Engine Matrix Context (JSON Payload Inspect)</div>
    <pre class="inspector-pre" id="rawPayloadInspectorFloor">${escapeHtmlMarkup(JSON.stringify(rawMatrix, null, 2))}</pre>
  `;

  parseDom('viewportMainFloor').innerHTML = structuralDomString;

  // Mount TradingView Candlestick Engine
  if (normalizedDataset.length > 0) {
    mountTradingViewChartEngine(parseDom('tvChartMountNode'), normalizedDataset);
  }
}

function generateDataGridMarkup(records) {
  if (!records.length) {
    return `<div class="state-empty">Execution matrix returned null set schema array dimensions.</div>`;
  }
  
  const headers = Object.keys(records[0]).slice(0, 10);
  let markup = `
    <table class="crypto-grid" id="executableDataGridFloor">
      <thead>
        <tr>
          ${headers.map(head => `<th data-matrix-column="${head}" onclick="sortGridColumn('${head}')">${head}</th>`).join('')}
        </tr>
      </thead>
      <tbody>
  `;
  
  records.slice(0, 250).forEach(row => {
    markup += `<tr>`;
    headers.forEach(head => {
      let variant = row[head];
      if (variant === undefined || variant === null) {
        variant = '—';
      }
      
      let applicationClass = '';
      if (typeof variant === 'number') {
        if (variant > 0 && head.toLowerCase().includes('change')) applicationClass = 'trend-up';
        if (variant < 0 && head.toLowerCase().includes('change')) applicationClass = 'trend-down';
        
        if (Math.abs(variant) >= 1000) variant = formatMetricDecimal(variant);
        else if (Math.abs(variant) < 0.01 && variant !== 0) variant = variant.toFixed(6);
        else variant = variant.toFixed(2);
      } else if (typeof variant === 'object') {
        variant = JSON.stringify(variant).slice(0, 30) + '...';
      }
      
      markup += `<td class="${applicationClass}">${escapeHtmlMarkup(String(variant))}</td>`;
    });
    markup += `</tr>`;
  });
  
  markup += `</tbody></table>`;
  return markup;
}

function sortGridColumn(column) {
  const table = parseDom('executableDataGridFloor');
  if (!table) return;
  
  const tbody = table.querySelector('tbody');
  const rowElements = Array.from(tbody.querySelectorAll('tr'));
  const headerElements = Array.from(table.querySelectorAll('thead th'));
  const targetHeader = headerElements.find(th => th.dataset.matrixColumn === column);
  
  if (sortingConfig.column === column) {
    sortingConfig.direction *= -1;
  } else {
    sortingConfig.column = column;
    sortingConfig.direction = 1;
  }
  
  const targetIndex = headerElements.indexOf(targetHeader);
  
  rowElements.sort((x, y) => {
    const rawX = x.cells[targetIndex]?.textContent || '';
    const rawY = y.cells[targetIndex]?.textContent || '';
    
    const parsedX = parseFloat(rawX.replace(/,/g, ''));
    const parsedY = parseFloat(rawY.replace(/,/g, ''));
    
    if (!isNaN(parsedX) && !isNaN(parsedY)) {
      return (parsedX - parsedY) * sortingConfig.direction;
    }
    return rawX.localeCompare(rawY) * sortingConfig.direction;
  });
  
  rowElements.forEach(r => tbody.appendChild(r));
  
  headerElements.forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
  targetHeader.classList.add(sortingConfig.direction === 1 ? 'sort-asc' : 'sort-desc');
}

// Flexible OHLC field detection — works with whatever the API gives us
function detectOhlcFields(rowKeys) {
  const map = {};
  for (const key of rowKeys) {
    const lower = key.toLowerCase();
    if (lower === 'open'  || lower === 'o') map.open = key;
    if (lower === 'high'  || lower === 'h') map.high = key;
    if (lower === 'low'   || lower === 'l') map.low = key;
    if (lower === 'close' || lower === 'c') map.close = key;
  }
  return map.open && map.high && map.low && map.close ? map : null;
}

function mountTradingViewChartEngine(container, sourceData) {
  const rowKeys = Object.keys(sourceData[0] || {});
  
  // Try flexible OHLC detection first
  const ohlcMap = detectOhlcFields(rowKeys);
  const detectedTimeToken = rowKeys.find(k => /time|date|timestamp|^t$/i.test(k)) || '';

  // Parse, standardise and isolate timestamps to secure ascending linearity order requirement
  let timelineSequence = [];
  
  if (ohlcMap) {
    timelineSequence = sourceData.map((record, index) => ({
      time: extractTimelineInteger(record[detectedTimeToken], index, sourceData.length),
      open: parseFloat(record[ohlcMap.open] ?? 0),
      high: parseFloat(record[ohlcMap.high] ?? 0),
      low: parseFloat(record[ohlcMap.low] ?? 0),
      close: parseFloat(record[ohlcMap.close] ?? 0),
    })).filter(item => item.time !== null);
    
    // Enforce Ascending Time Matrix Ordering
    timelineSequence.sort((a, b) => a.time - b.time);
    
    // Instantiating High Performance Chart
    tvChartInstance = LightweightCharts.createChart(container, {
      layout: {
        background: { type: 'solid', color: '#0b1120' },
        textColor: '#94a3b8',
        fontFamily: varStyle('--font-mono'),
      },
      grid: {
        vertLines: { color: 'rgba(255, 255, 255, 0.02)' },
        horzLines: { color: 'rgba(255, 255, 255, 0.02)' },
      },
      crosshair: {
        mode: LightweightCharts.CrosshairMode.Normal,
        vertLine: { color: 'rgba(240, 180, 41, 0.4)', style: 3, labelBackgroundColor: '#131b2e' },
        horzLine: { color: 'rgba(240, 180, 41, 0.4)', style: 3, labelBackgroundColor: '#131b2e' },
      },
      rightPriceScale: { borderColor: 'rgba(255, 255, 255, 0.05)' },
      timeScale: { borderColor: 'rgba(255, 255, 255, 0.05)', timeVisible: true, secondsVisible: false },
      autoSize: true,
    });

    tvCandleSeries = tvChartInstance.addSeries(LightweightCharts.CandlestickSeries, {
      upColor: '#22c55e',
      downColor: '#ef4444',
      borderVisible: false,
      wickUpColor: '#22c55e',
      wickDownColor: '#ef4444',
    });
    tvCandleSeries.setData(timelineSequence);
    updateLegendOverlayDisplay(timelineSequence[timelineSequence.length - 1], true);
    
    // Crosshair Interaction
    tvChartInstance.subscribeCrosshairMove(param => {
      if (param.time) {
        const structuralRow = param.seriesData.get(tvCandleSeries);
        if (structuralRow) updateLegendOverlayDisplay(structuralRow, true);
      } else {
        updateLegendOverlayDisplay(timelineSequence[timelineSequence.length - 1], true);
      }
    });
    
  } else {
    // Fallback: Dynamic Linear Vector for non-OHLC data
    const numericTargetKey = rowKeys.find(k => typeof sourceData[0][k] === 'number' || !isNaN(parseFloat(sourceData[0][k])));
    if (numericTargetKey) {
      timelineSequence = sourceData.map((record, index) => ({
        time: extractTimelineInteger(record[detectedTimeToken], index, sourceData.length),
        value: parseFloat(record[numericTargetKey] ?? 0),
      })).filter(item => item.time !== null);
      
      timelineSequence.sort((a, b) => a.time - b.time);
      
      tvChartInstance = LightweightCharts.createChart(container, {
        layout: {
          background: { type: 'solid', color: '#0b1120' },
          textColor: '#94a3b8',
          fontFamily: varStyle('--font-mono'),
        },
        grid: {
          vertLines: { color: 'rgba(255, 255, 255, 0.02)' },
          horzLines: { color: 'rgba(255, 255, 255, 0.02)' },
        },
        crosshair: {
          mode: LightweightCharts.CrosshairMode.Normal,
          vertLine: { color: 'rgba(240, 180, 41, 0.4)', style: 3, labelBackgroundColor: '#131b2e' },
          horzLine: { color: 'rgba(240, 180, 41, 0.4)', style: 3, labelBackgroundColor: '#131b2e' },
        },
        rightPriceScale: { borderColor: 'rgba(255, 255, 255, 0.05)' },
        timeScale: { borderColor: 'rgba(255, 255, 255, 0.05)', timeVisible: true, secondsVisible: false },
        autoSize: true,
      });

      tvLineSeries = tvChartInstance.addSeries(LightweightCharts.AreaSeries, {
        topColor: 'rgba(240, 180, 41, 0.2)',
        bottomColor: 'rgba(240, 180, 41, 0.0)',
        lineColor: '#f0b429',
        lineWidth: 2,
      });
      tvLineSeries.setData(timelineSequence);
      updateLegendOverlayDisplay({ label: numericTargetKey, value: timelineSequence[timelineSequence.length - 1]?.value }, false);
      
      tvChartInstance.subscribeCrosshairMove(param => {
        if (param.time) {
          const structuralRow = param.seriesData.get(tvLineSeries);
          if (structuralRow) updateLegendOverlayDisplay({ label: numericTargetKey, value: structuralRow.value }, false);
        } else {
          updateLegendOverlayDisplay({ label: numericTargetKey, value: timelineSequence[timelineSequence.length - 1]?.value }, false);
        }
      });
    } else {
      // No chartable numeric data
      container.innerHTML = `<div class="chart-fallback">No chartable time-series data for this endpoint.<br>The datagrid below contains the full payload.</div>`;
      return;
    }
  }

  tvChartInstance.timeScale().fitContent();
}

function updateLegendOverlayDisplay(datasetObject, isOhlcFormat) {
  const frameMount = parseDom('legendOhlcDataMetrics');
  if (!datasetObject) return;
  
  if (isOhlcFormat) {
    const priceDelta = datasetObject.close - datasetObject.open;
    const performanceIndicatorClass = priceDelta >= 0 ? 'trend-up' : 'trend-down';
    frameMount.innerHTML = `
      O <span class="legend-val">${formatMetricDecimal(datasetObject.open)}</span>
      H <span class="legend-val">${formatMetricDecimal(datasetObject.high)}</span>
      L <span class="legend-val">${formatMetricDecimal(datasetObject.low)}</span>
      C <span class="legend-val ${performanceIndicatorClass}">${formatMetricDecimal(datasetObject.close)}</span>
      Δ <span class="legend-val ${performanceIndicatorClass}">${priceDelta >= 0 ? '+' : ''}${formatMetricDecimal(priceDelta)}</span>
    `;
  } else {
    frameMount.innerHTML = `
      ${escapeHtmlMarkup(datasetObject.label)}: <span class="legend-val" style="color:var(--brand-accent)">${formatMetricDecimal(datasetObject.value)}</span>
    `;
  }
}

function extractTimelineInteger(rawToken, elementIndex, structuralLength) {
  if (!rawToken) {
    return Math.floor(Date.now() / 1000) - (structuralLength - elementIndex) * 60;
  }
  if (typeof rawToken === 'number') {
    if (rawToken > 5e11) return Math.floor(rawToken / 1000);
    return rawToken;
  }
  if (typeof rawToken === 'string') {
    const convertedDateObject = new Date(rawToken);
    if (!isNaN(convertedDateObject.getTime())) return Math.floor(convertedDateObject.getTime() / 1000);
  }
  return Math.floor(Date.now() / 1000) - (structuralLength - elementIndex) * 60;
}

function formatMetricDecimal(numValue) {
  if (numValue === undefined || numValue === null || isNaN(numValue)) return '0.00';
  const numericAbsolute = Math.abs(numValue);
  if (numericAbsolute >= 1e9) return (numValue / 1e9).toFixed(2) + 'B';
  if (numericAbsolute >= 1e6) return (numValue / 1e6).toFixed(2) + 'M';
  if (numericAbsolute >= 1e3) return (numValue / 1e3).toFixed(1) + 'K';
  return numValue.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 4 });
}

function varStyle(propertyString) {
  return getComputedStyle(document.documentElement).getPropertyValue(propertyString).trim();
}

function toggleMatrixInspector() {
  const panel = parseDom('rawPayloadInspectorFloor');
  panel.style.display = panel.style.display === 'block' ? 'none' : 'block';
}

function escapeHtmlMarkup(unsafeTextStr) {
  return unsafeTextStr
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Custom Endpoint Explorer Pipeline Block Layer
function renderDynamicExplorer() {
  activeId = 'api_explorer';
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  parseDom('currentPanelLabel').textContent = 'API Engine Matrix Explorer';
  
  parseDom('viewportMainFloor').innerHTML = `
    <div class="explorer-panel">
      <div class="form-row">
        <div class="field-group">
          <label>Target Entry Path Router</label>
          <input id="expRouterPath" placeholder="/api/coin/liq/heatmap" value="/api/coin/liq/heatmap">
        </div>
        <div class="field-group">
          <label>Payload Parameter Construct (Strict JSON Map Structural Layout)</label>
          <textarea id="expRouterParams">{"time":"h1","type":"coin"}</textarea>
        </div>
      </div>
      <button class="btn-submit" onclick="executeCustomPipelineDiscovery()">Query Decentralized Matrix Vector</button>
    </div>
    <div id="explorerEngineResponseFloor"></div>
  `;
}

async function executeCustomPipelineDiscovery() {
  const path = parseDom('expRouterPath').value.trim();
  let argumentsPayload = {};
  
  try {
    argumentsPayload = JSON.parse(parseDom('expRouterParams').value || '{}');
  } catch (ex) {
    alert('Strict Parser Exception Validation Error: Invalid Structural Parameter JSON Mapping Format Passed.');
    return;
  }
  
  const responseFrame = parseDom('explorerEngineResponseFloor');
  responseFrame.innerHTML = '<div class="panel-node shimmer-state" style="height:220px"></div>';
  
  try {
    const rawResStream = await fetch('/api/explore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, params: argumentsPayload })
    });
    const networkResponseData = await rawResStream.json();
    if (!networkResponseData.success) throw new Error(networkResponseData.error);
    
    responseFrame.innerHTML = `
      <div class="panel-node" style="margin-top:16px;">
        <div class="panel-header">
          <h3>Decrypted Memory Context Engine Vector Stream Output: ${escapeHtmlMarkup(networkResponseData.url)}</h3>
        </div>
        <pre style="padding:16px; background:#04060b; color:#22c55e; font-family:var(--font-mono); font-size:11px; max-height:400px; overflow:auto;">${escapeHtmlMarkup(JSON.stringify(networkResponseData.data, null, 2))}</pre>
      </div>
    `;
  } catch (err) {
    responseFrame.innerHTML = `<div class="error-fallback" style="margin-top:16px;"><strong>Discovery Exception Pipeline Halt</strong>${err.message}</div>`;
  }
}

// Clock Loop Synchronization
setInterval(() => {
  parseDom('clockFloor').textContent = new Date().toLocaleTimeString();
}, 1000);

// Global Boot Event Binding Hook
window.addEventListener('DOMContentLoaded', instantiateTerminalInfrastructure);
</script>
</body>
</html>
HTMLEOF

EXPOSE 10000
CMD ["python", "/app/main.py"]
