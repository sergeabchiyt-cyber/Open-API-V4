FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] httpx pycryptodome jinja2
RUN mkdir -p /app/templates

# ============================================================
# decrypt.py
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
            except Exception:
                return {"raw": r.text}
        return decrypt(r.text, user, v, url)
PYEOF

# ============================================================
# main.py — updated extract() with parallel-array handling
# ============================================================
RUN cat <<'PYEOF' > /app/main.py
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
            except Exception:
                return {"raw": r.text}
        return decrypt(r.text, user, v, url)

# ============================================================
# main.py — 200 status on API errors so client can read JSON
# ============================================================
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import traceback

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app  = FastAPI(title="CoinGlass Terminal")
T    = Jinja2Templates(directory="/app/templates")
BASE = "https://capi.coinglass.com"

REGISTRY = [
    {"id":"mkt_all",        "cat":"Market",  "label":"All Markets",         "path":"/api/home/v2/coinMarkets","params":{"sort":"","order":"","keyword":"","pageNum":1,"pageSize":50,"ex":"all"}},
    {"id":"mkt_rsi",        "cat":"Market",  "label":"Top RSI",             "path":"/api/home/v2/coinMarkets","params":{"sort":"rsi4h","order":"desc","pageNum":1,"pageSize":20,"ex":"all"}},
    {"id":"mkt_price_chg",  "cat":"Market",  "label":"Top Price Change",    "path":"/api/home/v2/coinMarkets","params":{"sort":"h4PriceChangePercent","order":"desc","pageNum":1,"pageSize":20,"ex":"all"}},
    {"id":"mkt_oi_chg",     "cat":"Market",  "label":"Top OI Change",       "path":"/api/home/v2/coinMarkets","params":{"sort":"h4OiChangePercent","order":"desc","pageNum":1,"pageSize":20,"ex":"all"}},
    {"id":"mkt_liq",        "cat":"Market",  "label":"Top Liquidations",    "path":"/api/home/v2/coinMarkets","params":{"sort":"h1LiquidationUsd","order":"desc","pageNum":1,"pageSize":20,"ex":"all"}},
    {"id":"hot_exs",        "cat":"Market",  "label":"Hot Exchanges",       "path":"/api/coin/hot/exs","params":{}},
    {"id":"symbols",        "cat":"Market",  "label":"Support Symbols",     "path":"/api/support/symbol","params":{}},
    {"id":"symbols_v2",     "cat":"Market",  "label":"Symbols V2",          "path":"/api/v2/support/symbol","params":{}},
    {"id":"etf_flow_all",   "cat":"ETF",     "label":"ETF Overall Flow",    "path":"/api/etf/flow","params":{}},
    {"id":"etf_flow_eth",   "cat":"ETF",     "label":"ETF ETH Flow",        "path":"/api/etf/eth/flow","params":{}},
    {"id":"etf_flow_sol",   "cat":"ETF",     "label":"ETF SOL Flow",        "path":"/api/etf/sol/flow","params":{}},
    {"id":"fr_avg",         "cat":"Funding", "label":"Funding Avg",         "path":"/api/fundingRate/avg","params":{}},
    {"id":"fr_rank",        "cat":"Funding", "label":"Funding Rank",        "path":"/api/fundingRate/rank","params":{}},
    {"id":"fr_home",        "cat":"Funding", "label":"Funding Home",        "path":"/api/fundingRate/v2/home","params":{}},
    {"id":"fr_btc",         "cat":"Funding", "label":"Funding BTC 8h",      "path":"/api/fundingRate/v2/history/chart","params":{"symbol":"BTC","type":"U","interval":"h8"}},
    {"id":"fr_eth",         "cat":"Funding", "label":"Funding ETH 8h",      "path":"/api/fundingRate/v2/history/chart","params":{"symbol":"ETH","type":"U","interval":"h8"}},
    {"id":"fr_sol",         "cat":"Funding", "label":"Funding SOL 8h",      "path":"/api/fundingRate/v2/history/chart","params":{"symbol":"SOL","type":"U","interval":"h8"}},
    {"id":"oi_gains",       "cat":"OI",      "label":"OI Gainers 1h",       "path":"/api/openInterest/change","params":{"time":"h1","gains":"gains"}},
    {"id":"oi_losers",      "cat":"OI",      "label":"OI Losers 1h",        "path":"/api/openInterest/change","params":{"time":"h1","gains":"loser"}},
    {"id":"oi_ex_btc",      "cat":"OI",      "label":"OI Exchange BTC",     "path":"/api/openInterest/ex/info","params":{"symbol":"BTC"}},
    {"id":"oi_ex_eth",      "cat":"OI",      "label":"OI Exchange ETH",     "path":"/api/openInterest/ex/info","params":{"symbol":"ETH"}},
    {"id":"oi_ex_sol",      "cat":"OI",      "label":"OI Exchange SOL",     "path":"/api/openInterest/ex/info","params":{"symbol":"SOL"}},
    {"id":"oi_history",     "cat":"OI",      "label":"OI History",          "path":"/api/openInterest/history/all","params":{}},
    {"id":"oi_vol_ratio",   "cat":"OI",      "label":"OI/Vol Ratio",        "path":"/api/openInterest/oiVolRadio","params":{}},
    {"id":"oi_chart_btc",   "cat":"OI",      "label":"OI Chart BTC",        "path":"/api/openInterest/v3/chart","params":{"symbol":"BTC","timeType":0,"exchangeName":"","currency":"USD","type":0}},
    {"id":"oi_chart_eth",   "cat":"OI",      "label":"OI Chart ETH",        "path":"/api/openInterest/v3/chart","params":{"symbol":"ETH","timeType":0,"exchangeName":"","currency":"USD","type":0}},
    {"id":"fut_price_change","cat":"Futures","label":"Price Change All",    "path":"/api/futures/coins/priceChange","params":{"ex":"all"}},
    {"id":"fut_home_stats", "cat":"Futures", "label":"Futures Stats",       "path":"/api/futures/home/statistics","params":{}},
    {"id":"fut_liq_chart",  "cat":"Futures", "label":"Liquidation Chart",   "path":"/api/futures/liquidation/chart","params":{"symbol":"","timeType":"4","range":"90d"}},
    {"id":"fut_liq_ex",     "cat":"Futures", "label":"Liq by Exchange",     "path":"/api/futures/liquidation/ex/info","params":{"time":"h4","symbol":""}},
    {"id":"fut_liq_max",    "cat":"Futures", "label":"Largest Liq Orders",  "path":"/api/futures/liquidation/maxOrder","params":{}},
    {"id":"fut_liq_orders", "cat":"Futures", "label":"Liquidation Orders",  "path":"/api/futures/liquidation/order","params":{"volUsd":"","symbol":"","exName":"","pageNum":1,"pageSize":1000}},
    {"id":"fut_markets",    "cat":"Futures", "label":"Futures Markets",     "path":"/api/futures/v2/coins/markets","params":{}},
    {"id":"coin_liq",       "cat":"Futures", "label":"Coin Liquidations",   "path":"/api/coin/liquidation","params":{}},
    {"id":"liq_heatmap",    "cat":"Futures", "label":"Liquidation Heatmap", "path":"/api/coin/liq/heatmap","params":{"time":"h1","type":"coin"}},
    {"id":"cgdi",           "cat":"Index",   "label":"CGDI",                "path":"/api/index/cgdi","params":{}},
    {"id":"rsi_map",        "cat":"Index",   "label":"RSI Map",             "path":"/api/index/rsiMap","params":{}},
]

def extract(d):
    """Extract tabular rows from CoinGlass API responses.

    Handles:
    - Standard nested lists (list, topInflowList, rankList, etc.)
    - Parallel-array time-series (dateList + dataMap/frDataMap + priceList)
    - Simple parallel arrays (dates + prices)
    - Flat list of objects (ETF flow, liquidation orders)
    - Nested exchange breakdowns (fut_liq_chart with createTime + list)
    """
    if isinstance(d, list):
        if len(d) > 0 and isinstance(d[0], dict):
            # ETF-like: {date, change, changeUsd, list: [...]} — already good
            if 'date' in d[0] and 'list' in d[0]:
                return d
            # Liquidation-like: {createTime, list: [{exchangeName, ...}, ...]}
            if 'createTime' in d[0] and 'list' in d[0]:
                result = []
                for item in d:
                    row = {k: v for k, v in item.items() if k != 'list'}
                    for ex in item.get('list', []):
                        ex_name = ex.get('exchangeName', 'Unknown')
                        for k, v in ex.items():
                            if k not in ('exchangeName', 'exchangeLogo'):
                                row[f"{ex_name}_{k}"] = v
                    result.append(row)
                return result
        return d

    if isinstance(d, dict):
        # CoinGlass parallel-array time-series: dateList + dataMap/frDataMap + priceList
        if 'dateList' in d and isinstance(d.get('dateList'), list):
            date_list = d['dateList']
            result = []
            for i, ts in enumerate(date_list):
                row = {'time': ts}
                # Price series (BTC/ETH price alongside funding/OI)
                if 'priceList' in d and i < len(d['priceList']):
                    row['price'] = d['priceList'][i]
                # Prefer frDataMap (funding rates) over dataMap to avoid duplicates
                if 'frDataMap' in d:
                    for key, values in d['frDataMap'].items():
                        if i < len(values):
                            row[key] = values[i]
                elif 'dataMap' in d:
                    for key, values in d['dataMap'].items():
                        if i < len(values):
                            row[key] = values[i]
                result.append(row)
            return result

        # Simple parallel arrays: dates + prices (CGDI index)
        if 'dates' in d and 'prices' in d and isinstance(d.get('dates'), list) and isinstance(d.get('prices'), list):
            return [{'time': t, 'value': v} for t, v in zip(d['dates'], d['prices'])]

        # Standard nested list extraction
        for k in ["list", "topInflowList", "inflowList", "rankList", "coins", "data", "rows"]:
            if k not in d:
                continue
            v = d[k]
            if isinstance(v, list):
                return v
            if isinstance(v, dict):
                for kk in ["list", "topInflowList", "rankList"]:
                    if kk in v and isinstance(v[kk], list):
                        return v[kk]
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
    if not ep:
        raise HTTPException(404, f"Unknown endpoint: {eid}")
    try:
        d = await fetch_and_decrypt(f"{BASE}{ep['path']}", ep["params"])
        return {"success": True, "data": d, "extracted": extract(d)}
    except Exception as e:
        logger.error(traceback.format_exc())
        return JSONResponse(status_code=200, content={"success": False, "error": str(e)})

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
        return JSONResponse(status_code=200, content={"success": False, "url": url, "error": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)

PYEOF

# ============================================================
# dashboard.html — updated smartExtract, chart rendering, multi-series
# ============================================================
RUN cat <<'HTMLEOF' > /app/templates/dashboard.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CoinGlass Terminal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<script src="https://unpkg.com/lightweight-charts@4.1.7/dist/lightweight-charts.standalone.production.js"></script>
<style>
:root {
  --bg:       #04080E;
  --surface:  #07101C;
  --elevated: #0C1828;
  --border:   rgba(255,255,255,0.07);
  --border2:  rgba(255,255,255,0.13);
  --accent:   #F0A416;
  --accent-bg:rgba(240,164,22,0.07);
  --accent-br:rgba(240,164,22,0.25);
  --green:    #0EBA88;
  --red:      #F4455A;
  --green-bg: rgba(14,186,136,0.08);
  --red-bg:   rgba(244,69,90,0.08);
  --t1: #DCE4EF;
  --t2: #5E7285;
  --t3: #2A3848;
  --font: 'IBM Plex Mono', monospace;
  --sidebar: 224px;
  --topbar:  44px;
}
* { margin:0; padding:0; box-sizing:border-box; -webkit-font-smoothing:antialiased; }
body { background:var(--bg); color:var(--t1); font-family:var(--font); font-size:12px; height:100vh; overflow:hidden; }
::-webkit-scrollbar { width:3px; height:3px; }
::-webkit-scrollbar-thumb { background:var(--t3); }
::-webkit-scrollbar-track { background:transparent; }

/* ── App shell ── */
.app { display:flex; height:100vh; }

/* ── Sidebar ── */
.sidebar {
  width:var(--sidebar); flex-shrink:0;
  background:var(--surface);
  border-right:1px solid var(--border);
  display:flex; flex-direction:column;
}
.logo {
  height:var(--topbar); padding:0 14px;
  display:flex; align-items:center; gap:9px;
  border-bottom:1px solid var(--border);
  flex-shrink:0;
}
.logo-mark {
  width:22px; height:22px;
  background:var(--accent);
  display:grid; place-items:center;
  font-size:10px; font-weight:700; color:var(--bg);
  letter-spacing:-0.5px; flex-shrink:0;
}
.logo-name { font-size:13px; font-weight:700; letter-spacing:-0.5px; }
.logo-tag  { font-size:9px; color:var(--t2); margin-left:auto; }
.nav-search {
  padding:8px 10px;
  border-bottom:1px solid var(--border);
  flex-shrink:0;
}
.nav-search input {
  width:100%; background:var(--bg);
  border:1px solid var(--border);
  padding:5px 8px; color:var(--t1);
  font-family:var(--font); font-size:11px; outline:none;
}
.nav-search input:focus { border-color:var(--accent-br); }
.nav { flex:1; overflow-y:auto; padding-bottom:8px; }
.nav-cat {
  font-size:9px; font-weight:700; color:var(--t3);
  text-transform:uppercase; letter-spacing:1.5px;
  padding:10px 12px 4px;
}
.nav-item {
  display:flex; align-items:center; gap:6px;
  padding:6px 12px; cursor:pointer;
  font-size:11px; color:var(--t2);
  border-left:2px solid transparent;
  transition:color 0.1s, background 0.1s;
}
.nav-item:hover { color:var(--t1); background:rgba(255,255,255,0.02); }
.nav-item.active {
  color:var(--accent); border-left-color:var(--accent);
  background:var(--accent-bg);
}
.nav-dot { width:3px; height:3px; border-radius:50%; background:var(--t3); flex-shrink:0; }
.nav-item.active .nav-dot { background:var(--accent); }
.nav-count {
  margin-left:auto; font-size:9px; color:var(--t3);
  background:var(--elevated); padding:1px 4px;
}

/* ── Main ── */
.main { flex:1; display:flex; flex-direction:column; overflow:hidden; }
.topbar {
  height:var(--topbar); flex-shrink:0;
  background:var(--surface);
  border-bottom:1px solid var(--border);
  display:flex; align-items:center; padding:0 16px; gap:10px;
}
.topbar-title { font-size:12px; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:260px; }
.topbar-path  { font-size:10px; color:var(--t2); background:var(--elevated); border:1px solid var(--border); padding:2px 7px; white-space:nowrap; }
.spacer { flex:1; }
.live-dot { width:5px; height:5px; border-radius:50%; background:var(--green); box-shadow:0 0 6px var(--green); animation:blink 2s infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.25} }
.live-label { font-size:10px; color:var(--green); }
.topbar-clock { font-size:11px; color:var(--t2); border-left:1px solid var(--border); padding-left:10px; }
.btn {
  font-family:var(--font); font-size:11px;
  background:var(--elevated); border:1px solid var(--border);
  color:var(--t1); padding:4px 10px; cursor:pointer; white-space:nowrap;
}
.btn:hover { border-color:var(--border2); }
.btn-accent { background:var(--accent); color:var(--bg); border:none; font-weight:700; }
.btn-accent:hover { opacity:0.88; }

/* ── Content ── */
.content { flex:1; overflow-y:auto; padding:12px; display:flex; flex-direction:column; gap:12px; }

/* ── KPI strip ── */
.kpi-row { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:8px; }
.kpi {
  background:var(--surface); border:1px solid var(--border);
  padding:11px 13px; position:relative;
}
.kpi::before {
  content:''; position:absolute; left:0; top:0; bottom:0;
  width:2px; background:var(--accent);
}
.kpi-label { font-size:9px; font-weight:600; color:var(--t2); text-transform:uppercase; letter-spacing:0.8px; margin-bottom:5px; }
.kpi-value { font-size:17px; font-weight:700; letter-spacing:-0.5px; }
.kpi-sub   { font-size:10px; color:var(--t2); margin-top:3px; }

/* ── Split panel ── */
.split { display:grid; grid-template-columns:3fr 2fr; gap:12px; }
@media(max-width:1080px) { .split { grid-template-columns:1fr; } }

/* ── Panel ── */
.panel { background:var(--surface); border:1px solid var(--border); display:flex; flex-direction:column; }
.panel-head {
  padding:7px 12px; border-bottom:1px solid var(--border);
  display:flex; align-items:center; gap:8px;
  background:rgba(255,255,255,0.01); flex-shrink:0;
}
.panel-head h3 { font-size:9px; font-weight:700; text-transform:uppercase; color:var(--t2); letter-spacing:0.6px; }
.panel-head .pill { font-size:9px; color:var(--t3); background:var(--elevated); padding:1px 5px; margin-left:auto; }

/* ── Chart ── */
.chart-host { position:relative; height:340px; overflow:hidden; }
/* signature: subtle CRT scanline grid */
.chart-host::after {
  content:''; position:absolute; inset:0; pointer-events:none; z-index:5;
  background:repeating-linear-gradient(
    0deg,
    transparent,
    transparent 3px,
    rgba(0,0,0,0.04) 3px,
    rgba(0,0,0,0.04) 4px
  );
}
#lwcMount { position:absolute; inset:0; }
.chart-legend {
  position:absolute; top:10px; left:12px; z-index:10;
  pointer-events:none; font-size:11px; line-height:1.6;
}
.lg-name { font-weight:600; color:var(--t1); }
.lg-ohlc { font-size:10px; color:var(--t2); display:flex; flex-wrap:wrap; gap:6px; }
.lg-ohlc .v { color:var(--accent); }
.lg-ohlc .up { color:var(--green); }
.lg-ohlc .dn { color:var(--red); }
.chart-empty {
  height:340px; display:flex; flex-direction:column;
  align-items:center; justify-content:center; gap:8px;
  color:var(--t2); font-size:11px;
}
.chart-empty-icon { font-size:28px; color:var(--t3); }

/* ── Bar chart ── */
.bar-chart { padding:10px 14px; display:flex; flex-direction:column; gap:5px; max-height:340px; overflow-y:auto; }
.bar-row   { display:flex; align-items:center; gap:8px; }
.bar-label { font-size:10px; color:var(--t2); width:72px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; text-align:right; flex-shrink:0; }
.bar-track { flex:1; height:16px; background:var(--elevated); position:relative; overflow:hidden; }
.bar-fill  { height:100%; background:var(--accent-bg); border-right:2px solid var(--accent); transition:width 0.35s cubic-bezier(0.4,0,0.2,1); }
.bar-fill.pos { background:var(--green-bg); border-right-color:var(--green); }
.bar-fill.neg { background:var(--red-bg);   border-right-color:var(--red); }
.bar-val { font-size:10px; color:var(--t1); width:68px; text-align:right; flex-shrink:0; }

/* ── Table ── */
.table-wrap { overflow:auto; max-height:340px; }
table { width:100%; border-collapse:collapse; font-size:11px; font-family:var(--font); }
th {
  position:sticky; top:0; z-index:2;
  background:var(--elevated); border-bottom:1px solid var(--border);
  padding:6px 10px; font-size:9px; font-weight:700;
  text-transform:uppercase; letter-spacing:0.5px; color:var(--t2);
  text-align:left; cursor:pointer; user-select:none; white-space:nowrap;
}
th:hover { color:var(--t1); }
th.asc::after  { content:' ↑'; color:var(--accent); font-size:8px; }
th.desc::after { content:' ↓'; color:var(--accent); font-size:8px; }
td {
  padding:5px 10px; border-bottom:1px solid rgba(255,255,255,0.025);
  color:var(--t1); white-space:nowrap;
}
tr:hover td { background:rgba(255,255,255,0.015); }
.up { color:var(--green) !important; }
.dn { color:var(--red) !important; }

/* ── Inspector ── */
.inspector-toggle {
  padding:8px 12px; font-size:10px; color:var(--t2);
  cursor:pointer; display:flex; align-items:center; gap:6px;
}
.inspector-toggle:hover { color:var(--t1); }
.inspector-body {
  display:none; padding:12px;
  background:#030508; color:#3D5A72;
  font-size:10px; max-height:220px; overflow:auto;
  border-top:1px solid var(--border); font-family:var(--font); white-space:pre;
}

/* ── Explorer ── */
.explorer { background:var(--surface); border:1px solid var(--border); padding:14px; display:flex; flex-direction:column; gap:10px; }
.form-row  { display:grid; grid-template-columns:2fr 3fr; gap:10px; }
.field     { display:flex; flex-direction:column; gap:4px; }
.field label { font-size:9px; font-weight:700; text-transform:uppercase; color:var(--t2); letter-spacing:0.5px; }
.field input, .field textarea {
  background:var(--bg); border:1px solid var(--border);
  padding:6px 9px; color:var(--t1);
  font-family:var(--font); font-size:11px; outline:none;
}
.field input:focus, .field textarea:focus { border-color:var(--accent-br); }
.field textarea { min-height:48px; resize:vertical; }

/* ── States ── */
.skeleton {
  background:linear-gradient(90deg, var(--surface) 25%, var(--elevated) 50%, var(--surface) 75%);
  background-size:200%; animation:shimmer 1.4s infinite;
}
@keyframes shimmer { 0%{background-position:-200%0} 100%{background-position:200%0} }
.error {
  background:var(--red-bg); border:1px solid rgba(244,69,90,0.2);
  padding:14px; color:var(--red);
}
.error strong { display:block; margin-bottom:6px; font-size:13px; }
.error small  { color:var(--t2); font-size:10px; }
.empty { padding:40px; text-align:center; color:var(--t2); font-size:11px; }
</style>
</head>
<body>
<div class="app">

  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="logo">
      <div class="logo-mark">CG</div>
      <span class="logo-name">TERMINAL</span>
      <span class="logo-tag">PRO</span>
    </div>
    <div class="nav-search">
      <input type="text" id="navSearch" placeholder="filter endpoints..." oninput="filterNav()">
    </div>
    <nav class="nav" id="nav"></nav>
  </aside>

  <!-- Main workspace -->
  <div class="main">
    <div class="topbar">
      <span class="topbar-title" id="topTitle">Loading...</span>
      <span class="topbar-path" id="topPath">—</span>
      <div class="spacer"></div>
      <div class="live-dot"></div>
      <span class="live-label">LIVE</span>
      <span class="topbar-clock" id="clock">--:--:--</span>
      <button class="btn" onclick="reload()">↻ Refresh</button>
    </div>
    <div class="content" id="content">
      <div class="empty">Initializing...</div>
    </div>
  </div>

</div>
<script>
/* ── State ── */
const S = { id:null, reg:[], chart:null, series:null, sort:{col:null,dir:1} };

/* ── Boot ── */
async function boot() {
  try {
    const r = await fetch('/api/registry');
    const j = await r.json();
    S.reg = j.endpoints;
    buildNav();
    const def = S.reg.find(e => e.id === 'mkt_all') || S.reg[0];
    if (def) loadEndpoint(def.id);
  } catch(err) {
    $('content').innerHTML = errBox('Boot failed', err.message);
  }
}

/* ── Nav ── */
function buildNav() {
  const cats = {};
  S.reg.forEach(e => { (cats[e.cat] = cats[e.cat]||[]).push(e); });
  let h = '';
  for (const [cat, items] of Object.entries(cats)) {
    h += `<div class="nav-cat">${cat}</div>`;
    items.forEach(e => {
      h += `<div class="nav-item" id="ni-${e.id}" onclick="loadEndpoint('${e.id}')">
        <span class="nav-dot"></span><span>${e.label}</span>
        <span class="nav-count">${Object.keys(e.params||{}).length}</span>
      </div>`;
    });
  }
  h += `<div class="nav-cat">Tools</div>
    <div class="nav-item" id="ni-explorer" onclick="showExplorer()">
      <span class="nav-dot" style="background:var(--accent)"></span><span>API Explorer</span>
    </div>`;
  $('nav').innerHTML = h;
}

function filterNav() {
  const q = $('navSearch').value.toLowerCase();
  document.querySelectorAll('.nav-item').forEach(el => {
    el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

function setActive(id) {
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const el = $('ni-'+id);
  if (el) { el.classList.add('active'); el.scrollIntoView({block:'nearest'}); }
}

function reload() { if (S.id && S.id !== 'explorer') loadEndpoint(S.id); }

/* ── Load endpoint ── */
async function loadEndpoint(id) {
  S.id = id;
  setActive(id);
  const ep = S.reg.find(e => e.id === id);
  $('topTitle').textContent = ep?.label || id;
  $('topPath').textContent  = ep?.path  || id;
  showSkeleton();
  try {
    const res  = await fetch('/api/'+id);
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'API returned an error');
    render(json.data, json.extracted || []);
  } catch(err) {
    $('content').innerHTML = errBox('Fetch failed', err.message);
  }
}

/* ── Skeleton ── */
function showSkeleton() {
  destroyChart();
  $('content').innerHTML =
    '<div class="kpi-row">' + Array(4).fill('<div class="skeleton" style="height:62px"></div>').join('') + '</div>' +
    '<div class="split"><div class="skeleton" style="height:360px"></div><div class="skeleton" style="height:360px"></div></div>';
}

/* ── Render ── */
function render(raw, rows) {
  destroyChart();
  if (!rows.length) rows = normalize(smartExtract(raw));
  const IS_TIME = k => /^(time|t|date|timestamp|ts|createTime)$/i.test(k) || /time|date/i.test(k);
  const allKeys = rows.length ? Object.keys(rows[0]) : [];
  const numKeys = allKeys.filter(k => {
    const v = rows[0][k];
    return typeof v === 'number' || (!isNaN(parseFloat(v)) && v !== null && v !== '' && typeof v !== 'object');
  });

  /* KPI cards — top 4 numeric columns, skip pure time fields */
  const kpiCols = numKeys.filter(k => !IS_TIME(k)).slice(0, 4);
  let kpiHtml = '';
  if (kpiCols.length) {
    kpiCols.forEach(col => {
      const vals = rows.map(r => parseFloat(r[col])).filter(v => !isNaN(v));
      if (!vals.length) return;
      const mx = Math.max(...vals), mn = Math.min(...vals);
      const avg = vals.reduce((a,b)=>a+b,0)/vals.length;
      kpiHtml += `<div class="kpi">
        <div class="kpi-label">${esc(col)}</div>
        <div class="kpi-value">${fmt(mx)}</div>
        <div class="kpi-sub">min ${fmt(mn)} · avg ${fmt(avg)}</div>
      </div>`;
    });
  }
  if (!kpiHtml) {
    kpiHtml = `<div class="kpi">
      <div class="kpi-label">Records</div>
      <div class="kpi-value">${rows.length}</div>
      <div class="kpi-sub">rows in response</div>
    </div>`;
  }

  $('content').innerHTML = `
    <div class="kpi-row">${kpiHtml}</div>
    <div class="split">
      <div class="panel">
        <div class="panel-head"><h3>Chart</h3><span class="pill" id="chartPill">—</span></div>
        <div class="chart-host" id="chartHost"></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Data</h3><span class="pill">${rows.length} rows</span></div>
        <div class="table-wrap">${buildTable(rows)}</div>
      </div>
    </div>
    <div class="panel">
      <div class="inspector-toggle" onclick="toggleInspector()">
        <span id="iArrow">▶</span> Raw JSON
      </div>
      <div class="inspector-body" id="iBody">${esc(JSON.stringify(raw,null,2))}</div>
    </div>`;

  mountChart(rows, numKeys, allKeys);
}

/* ── Chart ── */
function mountChart(rows, numKeys, allKeys) {
  const host = $('chartHost');
  if (!host || !rows.length || !numKeys.length) {
    if (host) host.innerHTML = '<div class="chart-empty"><div class="chart-empty-icon">∅</div>No chartable data</div>';
    return;
  }

  const keys    = allKeys || Object.keys(rows[0]);
  const timeKey = keys.find(k => /^(time|t|date|timestamp|ts|createTime)$/i.test(k) || /time|date/i.test(k)) || null;

  /* OHLC detection */
  const ohlc = (() => {
    const m = {};
    keys.forEach(k => {
      const l = k.toLowerCase();
      if (l==='open'||l==='o')  m.o=k;
      if (l==='high'||l==='h')  m.h=k;
      if (l==='low' ||l==='l')  m.l=k;
      if (l==='close'||l==='c') m.c=k;
    });
    return (m.o&&m.h&&m.l&&m.c) ? m : null;
  })();

  if (timeKey || ohlc) {
    // Prefer price/value/close as primary series, then first numeric non-time
    const preferred = numKeys.find(k => (k==='price'||k==='value'||k==='close') && k!==timeKey);
    const valCol = preferred || numKeys.find(k => k !== timeKey) || numKeys[0];
    mountLWC(host, rows, timeKey, ohlc, valCol, numKeys);
  } else {
    // No time axis — render horizontal bar chart
    const preferredLabels = ['symbol','name','exchangeName','ticker','coin'];
    const lblKey = preferredLabels.find(k => keys.includes(k) && typeof rows[0][k]==='string')
                || keys.find(k => typeof rows[0][k]==='string' && rows[0][k].length<30) || null;
    // Prefer endpoint-relevant numeric columns for bar values
    const preferredBarVals = ['rsi4h','rsi1h','rsi24h','rsi1w','h4PriceChangePercent','h1PriceChangePercent',
                               'h4OiChangePercent','h1OiChangePercent','h1LiquidationUsd','h24LiquidationUsd',
                               'change','changeUsd','avgFundingRateByOi','avgFundingRateBySymbol'];
    const barVal = preferredBarVals.find(k => numKeys.includes(k)) || numKeys[0];
    mountBarChart(host, rows, barVal, lblKey);
  }
}

function toUnix(v, i, n) {
  if (v == null) return Math.floor(Date.now()/1000)-(n-i)*3600;
  if (typeof v==='number') return v>1e11 ? Math.floor(v/1000) : v;
  const d = new Date(v);
  return isNaN(d) ? Math.floor(Date.now()/1000)-(n-i)*3600 : Math.floor(d.getTime()/1000);
}

function dedup(data) {
  const seen = new Set();
  return data.filter(d=>{ if(seen.has(d.time)) return false; seen.add(d.time); return true; });
}

function mountLWC(host, rows, timeKey, ohlc, numCol, allNumKeys) {
  host.innerHTML = `
    <div id="lwcMount"></div>
    <div class="chart-legend">
      <div class="lg-name" id="lgName">${ohlc ? 'OHLC' : esc(numCol)}</div>
      <div class="lg-ohlc" id="lgOhlc"></div>
    </div>`;

  requestAnimationFrame(() => {
  const mount = $('lwcMount');
  if (!mount) return;
  const w = Math.max(mount.clientWidth || 0, host.clientWidth || 0, 300);

  S.chart = LightweightCharts.createChart(mount, {
    layout: {
      background:{color:'#07101C'},
      textColor:'#5E7285',
      fontFamily:"'IBM Plex Mono',monospace",
      fontSize:11,
    },
    grid: {
      vertLines:{color:'rgba(255,255,255,0.025)'},
      horzLines:{color:'rgba(255,255,255,0.025)'},
    },
    crosshair: {
      mode: LightweightCharts.CrosshairMode.Normal,
      vertLine:{color:'rgba(240,164,22,0.3)', labelBackgroundColor:'#0C1828'},
      horzLine:{color:'rgba(240,164,22,0.3)', labelBackgroundColor:'#0C1828'},
    },
    rightPriceScale:{borderColor:'rgba(255,255,255,0.06)'},
    timeScale:{borderColor:'rgba(255,255,255,0.06)', timeVisible:true, secondsVisible:false},
    width:w,
    height:340,
  });

  if (ohlc) {
    S.series = S.chart.addCandlestickSeries({
      upColor:'#0EBA88', downColor:'#F4455A',
      borderUpColor:'#0EBA88', borderDownColor:'#F4455A',
      wickUpColor:'#0EBA88', wickDownColor:'#F4455A',
    });
    const data = dedup(
      rows.map((r,i)=>({
        time:  toUnix(timeKey ? r[timeKey] : null, i, rows.length),
        open:  parseFloat(r[ohlc.o])||0,
        high:  parseFloat(r[ohlc.h])||0,
        low:   parseFloat(r[ohlc.l])||0,
        close: parseFloat(r[ohlc.c])||0,
      })).sort((a,b)=>a.time-b.time)
    );
    S.series.setData(data);
    if (data.length) setLegendOHLC(data[data.length-1]);
    S.chart.subscribeCrosshairMove(p => {
      const bar = p.seriesData && p.seriesData.get(S.series);
      setLegendOHLC(bar || data[data.length-1]);
    });
    $('chartPill') && ($('chartPill').textContent = data.length+' bars');

  } else {
    // Primary area series
    S.series = S.chart.addAreaSeries({
      topColor:'rgba(240,164,22,0.14)',
      bottomColor:'rgba(240,164,22,0)',
      lineColor:'#F0A416',
      lineWidth:2,
    });
    const data = dedup(
      rows.map((r,i)=>({
        time:  toUnix(timeKey ? r[timeKey] : null, i, rows.length),
        value: parseFloat(r[numCol])||0,
      })).sort((a,b)=>a.time-b.time)
    );
    S.series.setData(data);
    if (data.length) $('lgOhlc').innerHTML = `<span class="v">${fmt(data[data.length-1].value)}</span>`;
    S.chart.subscribeCrosshairMove(p => {
      const bar = p.seriesData && p.seriesData.get(S.series);
      if (bar) $('lgOhlc').innerHTML = `<span class="v">${fmt(bar.value)}</span>`;
    });
    $('chartPill') && ($('chartPill').textContent = data.length+' pts');

    // Add secondary line series for other numeric columns (up to 3 extras)
    const extraCols = (allNumKeys || []).filter(k => k !== numCol && k !== timeKey && k !== 'time').slice(0, 3);
    const colors = ['#0EBA88', '#F4455A', '#5E7285'];
    extraCols.forEach((col, idx) => {
      const s = S.chart.addLineSeries({
        color: colors[idx % colors.length],
        lineWidth: 1,
        priceScaleId: 'left',
      });
      const d = dedup(
        rows.map((r,i)=>({
          time:  toUnix(timeKey ? r[timeKey] : null, i, rows.length),
          value: parseFloat(r[col])||0,
        })).sort((a,b)=>a.time-b.time)
      );
      s.setData(d);
    });
    if (extraCols.length) {
      S.chart.priceScale('left').applyOptions({ visible: true, borderColor: 'rgba(255,255,255,0.06)' });
    }
  }

  S.chart.timeScale().fitContent();

  new ResizeObserver(()=>{
    if (S.chart && mount.clientWidth>0) S.chart.applyOptions({width:mount.clientWidth});
  }).observe(mount);
  }); // end requestAnimationFrame
}

function setLegendOHLC(bar) {
  if (!bar || bar.close == null) return;
  const d = bar.close - bar.open;
  const dc = d>=0 ? 'up' : 'dn';
  $('lgOhlc').innerHTML =
    `O <span class="v">${fmt(bar.open)}</span> ` +
    `H <span class="v">${fmt(bar.high)}</span> ` +
    `L <span class="v">${fmt(bar.low)}</span> ` +
    `C <span class="v ${dc}">${fmt(bar.close)}</span> ` +
    `<span class="${dc}">${d>=0?'+':''}${fmt(d)}</span>`;
}

function mountBarChart(host, rows, numCol, lblCol) {
  const top = rows.slice(0,30);
  const vals = top.map(r=>parseFloat(r[numCol])||0);
  const maxAbs = Math.max(...vals.map(Math.abs),1);
  let h = '<div class="bar-chart">';
  top.forEach(r => {
    const v   = parseFloat(r[numCol])||0;
    const pct = Math.abs(v)/maxAbs*100;
    const lbl = lblCol ? String(r[lblCol]).slice(0,12) : numCol;
    const cls = v>0?'pos':v<0?'neg':'';
    h += `<div class="bar-row">
      <div class="bar-label">${esc(lbl)}</div>
      <div class="bar-track"><div class="bar-fill ${cls}" style="width:${pct.toFixed(1)}%"></div></div>
      <div class="bar-val">${fmt(v)}</div>
    </div>`;
  });
  h += '</div>';
  host.innerHTML = h;
  $('chartPill') && ($('chartPill').textContent = 'bar chart');
}

/* ── Table ── */
function buildTable(rows) {
  if (!rows.length) return '<div class="empty">No data returned</div>';
  const cols = Object.keys(rows[0]).slice(0,12);
  let h = '<table><thead><tr>';
  cols.forEach(c => { h += `<th id="th-${esc(c)}" onclick="sortBy('${esc(c)}')">${esc(c)}</th>`; });
  h += '</tr></thead><tbody>';
  rows.slice(0,300).forEach(r => {
    h += '<tr>';
    cols.forEach(c => {
      let v = r[c], cls = '';
      if (v===null||v===undefined) { v='—'; }
      else if (typeof v==='object') { v=JSON.stringify(v).slice(0,40)+'…'; }
      else if (typeof v==='number') {
        if (/change|pct|rate|percent|diff/i.test(c)) cls = v>0?'up':'dn';
        v = Math.abs(v)>=1000 ? fmt(v) : (v%1===0 ? v.toString() : v.toFixed(4).replace(/\.?0+$/,''));
      }
      h += `<td class="${cls}">${esc(String(v))}</td>`;
    });
    h += '</tr>';
  });
  return h+'</tbody></table>';
}

function sortBy(col) {
  const th = $('th-'+col);
  if (!th) return;
  if (S.sort.col===col) S.sort.dir*=-1; else { S.sort.col=col; S.sort.dir=1; }
  document.querySelectorAll('th').forEach(el=>el.classList.remove('asc','desc'));
  th.classList.add(S.sort.dir===1?'asc':'desc');
  const tbody = th.closest('table')?.querySelector('tbody');
  if (!tbody) return;
  const idx = Array.from(th.parentElement.children).indexOf(th);
  const trs = Array.from(tbody.querySelectorAll('tr'));
  trs.sort((a,b)=>{
    const ta=a.cells[idx]?.textContent||'', tb=b.cells[idx]?.textContent||'';
    const na=parseFloat(ta.replace(/[^0-9.-]/g,'')), nb=parseFloat(tb.replace(/[^0-9.-]/g,''));
    return (!isNaN(na)&&!isNaN(nb)) ? (na-nb)*S.sort.dir : ta.localeCompare(tb)*S.sort.dir;
  });
  trs.forEach(r=>tbody.appendChild(r));
}

/* ── Inspector ── */
function toggleInspector() {
  const b=$('iBody'), a=$('iArrow');
  b.style.display = b.style.display==='block' ? 'none' : 'block';
  a.textContent   = b.style.display==='block'  ? '▼'    : '▶';
}

/* ── Explorer ── */
function showExplorer() {
  S.id='explorer'; setActive('explorer');
  $('topTitle').textContent='API Explorer';
  $('topPath').textContent='POST /api/explore';
  destroyChart();
  $('content').innerHTML = `
    <div class="explorer">
      <div class="form-row">
        <div class="field">
          <label>Path</label>
          <input id="expPath" value="/api/fundingRate/avg">
        </div>
        <div class="field">
          <label>Params (JSON)</label>
          <textarea id="expParams">{}</textarea>
        </div>
      </div>
      <button class="btn btn-accent" onclick="runExplorer()">Execute</button>
    </div>
    <div id="explorerOut"></div>`;
}

async function runExplorer() {
  let params={};
  try { params=JSON.parse($('expParams').value||'{}'); } catch { alert('Invalid JSON'); return; }
  const path = $('expPath').value.trim();
  const out  = $('explorerOut');
  out.innerHTML = '<div class="skeleton" style="height:200px;margin-top:12px"></div>';
  try {
    const res  = await fetch('/api/explore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path,params})});
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    out.innerHTML = `<div class="panel" style="margin-top:12px">
      <div class="panel-head"><h3>${esc(json.url)}</h3></div>
      <div class="inspector-body" style="display:block">${esc(JSON.stringify(json.data,null,2))}</div>
    </div>`;
  } catch(err) {
    out.innerHTML = `<div style="margin-top:12px">${errBox('Explorer error',err.message)}</div>`;
  }
}

/* ── Helpers ── */
function destroyChart() {
  if (S.chart) { try{S.chart.remove();}catch(e){} S.chart=null; S.series=null; }
}

function fmt(n) {
  if (n===undefined||n===null||isNaN(n)) return '—';
  const a=Math.abs(n);
  if (a>=1e12) return (n/1e12).toFixed(2)+'T';
  if (a>=1e9)  return (n/1e9).toFixed(2)+'B';
  if (a>=1e6)  return (n/1e6).toFixed(2)+'M';
  if (a>=1e3)  return (n/1e3).toFixed(1)+'K';
  if (a<0.0001&&a>0) return n.toExponential(3);
  return n.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:4});
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function errBox(title, msg) {
  return `<div class="error"><strong>${esc(title)}</strong>${esc(msg)}<br><br><small>Check the CoinGlass API connection and endpoint parameters.</small></div>`;
}

function $(id) { return document.getElementById(id); }

/* ── Smart extraction: handles nested CoinGlass data shapes ── */
function smartExtract(raw) {
  if (Array.isArray(raw)) {
    if (raw.length > 0 && typeof raw[0] === 'object' && !Array.isArray(raw[0])) {
      // ETF-like: {date, change, changeUsd, list: [...]} — already good
      if ('date' in raw[0] && 'list' in raw[0]) return raw;
      // Liquidation-like: {createTime, list: [{exchangeName, ...}, ...]}
      if ('createTime' in raw[0] && 'list' in raw[0]) {
        return raw.map(item => {
          const row = {...item};
          delete row.list;
          (item.list || []).forEach(ex => {
            const name = ex.exchangeName || 'Unknown';
            Object.entries(ex).forEach(([k, v]) => {
              if (k !== 'exchangeName' && k !== 'exchangeLogo') row[`${name}_${k}`] = v;
            });
          });
          return row;
        });
      }
    }
    return raw;
  }
  if (!raw || typeof raw !== 'object') return [];

  // CoinGlass parallel-array time-series: dateList + dataMap/frDataMap + priceList
  if (raw.dateList && Array.isArray(raw.dateList)) {
    const result = [];
    for (let i = 0; i < raw.dateList.length; i++) {
      const row = {time: raw.dateList[i]};
      if (raw.priceList && i < raw.priceList.length) row.price = raw.priceList[i];
      // Prefer frDataMap over dataMap to avoid duplicate columns
      if (raw.frDataMap) {
        Object.entries(raw.frDataMap).forEach(([key, values]) => {
          if (i < values.length) row[key] = values[i];
        });
      } else if (raw.dataMap) {
        Object.entries(raw.dataMap).forEach(([key, values]) => {
          if (i < values.length) row[key] = values[i];
        });
      }
      result.push(row);
    }
    return result;
  }

  // Simple parallel arrays: dates + prices (CGDI index)
  if (raw.dates && raw.prices && Array.isArray(raw.dates) && Array.isArray(raw.prices)) {
    return raw.dates.map((t, i) => ({time: t, value: raw.prices[i]}));
  }

  if (Array.isArray(raw.data)) return raw.data;

  // dig up to depth 3 for the largest array of objects or 2-tuples
  const found = [];
  function dig(obj, d) {
    if (d > 3) return;
    for (const v of Object.values(obj)) {
      if (Array.isArray(v) && v.length > 1) found.push(v);
      else if (v && typeof v === 'object' && !Array.isArray(v)) dig(v, d+1);
    }
  }
  dig(raw, 0);
  found.sort((a,b) => b.length - a.length);
  return found[0] || [];
}

/* ── Normalize: convert [[ts,val],...] 2D arrays into objects ── */
function normalize(rows) {
  if (!rows.length) return rows;
  if (Array.isArray(rows[0])) {
    return rows.map(r => r.length === 2
      ? {time: r[0], value: r[1]}
      : Object.fromEntries(r.map((v,i) => ['v'+i, v]))
    );
  }
  return rows;
}

/* ── Clock ── */
setInterval(()=>{ const c=$('clock'); if(c) c.textContent=new Date().toLocaleTimeString(); }, 1000);

/* ── Go ── */
boot();
</script>
</body>
</html>

HTMLEOF

EXPOSE 10000
CMD ["python", "/app/main.py"]
