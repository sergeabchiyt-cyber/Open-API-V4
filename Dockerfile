FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] httpx pycryptodome jinja2
RUN mkdir -p /app/templates

# ============================================================
# decrypt.py – handles CoinGlass encryption (v=0,1,2,55,66,77)
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

# Inject extra keys via env: CAPI_EXTRA_KEYS="88=abc...,99=xyz..."
for _pair in os.environ.get("CAPI_EXTRA_KEYS", "").split(","):
    if "=" in _pair:
        _k, _v = _pair.strip().split("=", 1)
        _KEY_TABLE[_k.strip()] = _v.strip()

def _derive_key0(v, url="", outer=None):
    if v == "0":
        # Use the full request URL (including query) as constant
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
# main.py – FastAPI app with full endpoint registry + Explorer
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

# Verified endpoints (based on official V4 docs + common usage)
REGISTRY = [
    # SPOT
    {"id":"rsi",       "cat":"spot",        "label":"RSI Matrix",
     "path":"/api/spot/rsi/list",                "params":{"pageSize":500,"pageNum":1}},
    {"id":"gainers",   "cat":"spot",        "label":"Gainers / Losers",
     "path":"/api/spot/gainLossList",            "params":{"pageSize":100}},
    # DERIVATIVES
    {"id":"funding",   "cat":"derivatives", "label":"Funding Rates",
     "path":"/api/fundingRate/list",             "params":{"pageSize":100,"pageNum":1}},
    {"id":"oi",        "cat":"derivatives", "label":"Open Interest",
     "path":"/api/openInterest/statistics",      "params":{}},
    {"id":"oi_ex",     "cat":"derivatives", "label":"OI by Exchange",
     "path":"/api/openInterest/exchange/list",   "params":{"symbol":"BTC"}},
    {"id":"longshort", "cat":"derivatives", "label":"Long / Short",
     "path":"/api/futures/longShortRatio/list",  "params":{"pageSize":100}},
    {"id":"liq",       "cat":"derivatives", "label":"Liquidations BTC",
     "path":"/api/futures/liquidation/today",    "params":{"symbol":"BTC"}},
    {"id":"liq_list",  "cat":"derivatives", "label":"Liq All Coins",
     "path":"/api/liquidation/v2/info/list",     "params":{"pageSize":100,"pageNum":1}},
    # MARKET
    {"id":"mcap",      "cat":"market",      "label":"Market Cap",
     "path":"/api/marketCapRank",                "params":{"pageSize":100}},
    {"id":"feargreed", "cat":"market",      "label":"Fear & Greed",
     "path":"/api/index/fearGreed/list",         "params":{}},
    {"id":"altseason", "cat":"market",      "label":"Altcoin Season",
     "path":"/api/index/altcoinSeason",          "params":{}},
    {"id":"global",    "cat":"market",      "label":"Global Overview",
     "path":"/api/global/homeOverview",          "params":{}},
    # ETF
    {"id":"etf",       "cat":"etf",         "label":"ETF Overview",
     "path":"/api/etf/overview",                 "params":{}},
    {"id":"etf_flow",  "cat":"etf",         "label":"Daily Flows",
     "path":"/api/etf/flowList",                 "params":{}},
    {"id":"etf_btc",   "cat":"etf",         "label":"BTC Net Inflow",
     "path":"/api/etf/bitcoin/flowList",         "params":{}},
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
# dashboard.html – Modern responsive UI with charts & explorer
# ============================================================
RUN cat <<'HTMLEOF' > /app/templates/dashboard.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CoinGlass Terminal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
:root{
  --bg:#04060c;--panel:#080c18;--card:rgba(10,14,28,0.85);
  --bdr:rgba(255,255,255,0.06);--bdr-hi:rgba(245,166,35,0.35);
  --acc:#f5a623;--acc-d:rgba(245,166,35,0.1);
  --blue:#4d9de0;--pos:#3dba6e;--neg:#e84545;
  --txt:#c8d0e0;--txt-hi:#e8edf8;--muted:#3d4a5c;
  --flash:rgba(245,166,35,0.18);
  --s:'Space Grotesk',sans-serif;--m:'IBM Plex Mono',monospace;
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden;background:var(--bg);color:var(--txt);
  font-family:var(--s);font-size:14px;-webkit-font-smoothing:antialiased}
button{cursor:pointer;border:none;background:none;font-family:var(--s)}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-thumb{background:var(--muted);border-radius:10px}
::-webkit-scrollbar-track{background:transparent}

/* layout */
.shell{display:flex;height:100vh}
.sidebar{width:220px;flex-shrink:0;display:flex;flex-direction:column;
  border-right:1px solid var(--bdr);background:var(--panel);overflow-y:auto}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.topbar{height:40px;flex-shrink:0;border-bottom:1px solid var(--bdr);
  display:flex;align-items:center;gap:14px;padding:0 20px;
  background:rgba(4,6,12,0.95);backdrop-filter:blur(10px)}
.content{flex:1;overflow-y:auto;padding:20px}

/* sidebar */
.sb-logo{display:flex;align-items:center;gap:10px;padding:16px 14px 12px;
  border-bottom:1px solid var(--bdr);flex-shrink:0}
.sb-logo-txt span{display:block;font-weight:700;font-size:14px;color:var(--txt-hi);letter-spacing:-.3px}
.sb-logo-txt small{font-family:var(--m);font-size:9px;color:var(--acc);letter-spacing:.12em;text-transform:uppercase}
.nav-cat{padding:14px 14px 4px;font-size:9px;font-weight:700;color:var(--muted);
  letter-spacing:.14em;text-transform:uppercase}
.nav-item{display:flex;align-items:center;gap:8px;padding:7px 14px;font-size:12px;
  font-weight:500;color:var(--txt);border-left:2px solid transparent;
  cursor:pointer;transition:all .15s;user-select:none}
.nav-item:hover{background:rgba(255,255,255,0.025);color:var(--txt-hi)}
.nav-item.active{color:var(--acc);border-left-color:var(--acc);background:rgba(245,166,35,0.05)}
.nav-dot{width:5px;height:5px;border-radius:50%;background:var(--muted);
  flex-shrink:0;transition:background .15s}
.nav-item.active .nav-dot{background:var(--acc)}
.nav-div{height:1px;background:var(--bdr);margin:8px 14px}

/* topbar */
.tb-live{display:flex;align-items:center;gap:5px;font-family:var(--m);font-size:11px;color:var(--pos)}
.tb-dot{width:7px;height:7px;border-radius:50%;background:var(--pos);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.tb-sep{width:1px;height:16px;background:var(--bdr)}
.tb-chip{font-family:var(--m);font-size:11px;color:var(--muted)}
.tb-chip b{color:var(--txt);font-weight:500}
.tb-time{font-family:var(--m);font-size:11px;color:var(--muted);margin-left:auto}
.tb-refresh{padding:4px 12px;border:1px solid var(--bdr);border-radius:6px;
  font-size:11px;color:var(--muted);font-family:var(--m);transition:all .15s}
.tb-refresh:hover{border-color:var(--acc);color:var(--acc)}

/* cards */
.card{background:var(--card);border:1px solid var(--bdr);border-radius:12px;padding:18px}
.card:hover{border-color:rgba(255,255,255,0.09)}
.card-lbl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;
  color:var(--muted);margin-bottom:8px}
.card-val{font-family:var(--m);font-size:22px;font-weight:600;color:var(--txt-hi);line-height:1}
.card-sub{font-family:var(--m);font-size:11px;color:var(--muted);margin-top:5px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.ch200{height:200px;position:relative}
.ch260{height:260px;position:relative}
.ch300{height:300px;position:relative}

/* stat strip */
.stats{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.stat{flex:1;min-width:110px;background:var(--card);border:1px solid var(--bdr);
  border-radius:10px;padding:12px 14px}
.stat-lbl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;
  color:var(--muted);margin-bottom:5px}
.stat-val{font-family:var(--m);font-size:18px;font-weight:600;color:var(--txt-hi)}

/* panel header */
.ph{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.ph-title{font-size:17px;font-weight:700;color:var(--txt-hi);letter-spacing:-.3px}
.ph-meta{font-family:var(--m);font-size:11px;color:var(--muted)}

/* tables */
.tw{background:var(--card);border:1px solid var(--bdr);border-radius:12px;
  overflow:hidden;margin-bottom:16px}
.tw-head{display:flex;align-items:center;justify-content:space-between;
  padding:11px 14px;border-bottom:1px solid var(--bdr)}
.tw-title{font-size:12px;font-weight:600;color:var(--txt-hi)}
.tw-meta{font-family:var(--m);font-size:11px;color:var(--muted)}
.ts{overflow-x:auto;max-height:420px;overflow-y:auto}
table{width:100%;border-collapse:collapse}
thead th{position:sticky;top:0;background:rgba(6,10,20,0.97);
  backdrop-filter:blur(8px);padding:9px 13px;font-size:9px;font-weight:700;
  text-transform:uppercase;letter-spacing:.09em;color:var(--muted);text-align:left;
  white-space:nowrap;cursor:pointer;user-select:none;transition:color .15s}
thead th:hover{color:var(--txt)}
thead th.sa::after{content:" ↑";color:var(--acc)}
thead th.sd::after{content:" ↓";color:var(--acc)}
tbody td{padding:8px 13px;font-size:12px;border-bottom:1px solid rgba(255,255,255,0.025);
  transition:background .15s}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:rgba(255,255,255,0.02)!important}

/* badges */
.b{display:inline-block;padding:2px 7px;border-radius:4px;font-family:var(--m);
  font-size:11px;font-weight:600;white-space:nowrap}
.br{background:rgba(232,69,69,.12);color:var(--neg)}
.bg{background:rgba(61,186,110,.12);color:var(--pos)}
.bn{background:rgba(255,255,255,.05);color:var(--muted)}
.ba{background:var(--acc-d);color:var(--acc)}

/* search / filter */
.sr{display:flex;gap:8px;margin-bottom:14px;align-items:center}
.si{flex:1;background:var(--panel);border:1px solid var(--bdr);border-radius:8px;
  padding:7px 11px;color:var(--txt);font-family:var(--m);font-size:12px;outline:none;
  transition:border-color .15s}
.si:focus{border-color:var(--acc)}
.si::placeholder{color:var(--muted)}
.fb{padding:6px 12px;border:1px solid var(--bdr);border-radius:7px;font-size:11px;
  color:var(--muted);font-family:var(--m);transition:all .15s}
.fb:hover,.fb.on{border-color:var(--acc);color:var(--acc);background:var(--acc-d)}

/* flash on update */
@keyframes flash{0%{background:var(--flash)}100%{background:transparent}}
.flash{animation:flash .7s ease-out}

/* raw / toggle */
.rt{font-family:var(--m);font-size:11px;color:var(--muted);cursor:pointer;
  display:flex;align-items:center;gap:5px;padding:8px 0;
  border-top:1px solid var(--bdr);margin-top:10px;transition:color .15s}
.rt:hover{color:var(--acc)}
.rb{background:rgba(4,6,12,.95);border:1px solid var(--bdr);border-radius:8px;
  padding:12px;font-family:var(--m);font-size:11px;color:var(--muted);
  max-height:380px;overflow:auto;line-height:1.65;margin-top:8px;
  white-space:pre-wrap;word-break:break-all}

/* explorer */
.ex-form{background:var(--card);border:1px solid var(--bdr);border-radius:12px;
  padding:20px;margin-bottom:16px}
.ex-lbl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;
  color:var(--muted);margin-bottom:6px}
.ex-path{width:100%;background:var(--panel);border:1px solid var(--bdr);border-radius:8px;
  padding:9px 12px;color:var(--txt-hi);font-family:var(--m);font-size:13px;outline:none;
  transition:border-color .15s;margin-bottom:12px}
.ex-path:focus{border-color:var(--acc)}
.ex-params{width:100%;background:var(--panel);border:1px solid var(--bdr);border-radius:8px;
  padding:9px 12px;color:var(--txt-hi);font-family:var(--m);font-size:12px;outline:none;
  resize:vertical;min-height:66px;transition:border-color .15s;margin-bottom:12px}
.ex-params:focus{border-color:var(--acc)}
.ex-btn{padding:9px 22px;background:var(--acc);color:#000;font-weight:700;font-size:13px;
  border-radius:8px;font-family:var(--s);transition:opacity .15s}
.ex-btn:hover{opacity:.85}
.ex-hint{font-family:var(--m);font-size:11px;color:var(--muted);margin-left:12px}
.chip-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.path-chip{padding:4px 10px;border:1px solid var(--bdr);border-radius:6px;
  font-family:var(--m);font-size:10px;color:var(--muted);cursor:pointer;
  transition:all .15s;white-space:nowrap}
.path-chip:hover{border-color:var(--acc);color:var(--acc);background:var(--acc-d)}

/* skeleton */
.sk{background:linear-gradient(90deg,rgba(255,255,255,.02) 25%,rgba(255,255,255,.05) 50%,rgba(255,255,255,.02) 75%);
  background-size:200% 100%;animation:shimmer 1.6s infinite;border-radius:8px}
@keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}

/* error / empty */
.err{background:rgba(232,69,69,.06);border:1px solid rgba(232,69,69,.2);border-radius:10px;
  padding:14px 16px;font-family:var(--m);font-size:12px;color:var(--neg);margin-bottom:14px}
.err b{display:block;margin-bottom:3px;font-weight:600}
.empty{text-align:center;padding:48px 24px;color:var(--muted)}
.empty-icon{font-size:28px;margin-bottom:8px}

@media(max-width:768px){
  .sidebar{width:44px}
  .sb-logo-txt,.nav-cat,.nav-item span{display:none}
  .nav-item{padding:11px;justify-content:center}
  .g2,.g3,.g4{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="shell">

<!-- SIDEBAR -->
<nav class="sidebar">
  <div class="sb-logo">
    <svg width="26" height="26" viewBox="0 0 26 26" fill="none" flex-shrink="0">
      <rect width="26" height="26" rx="7" fill="#f5a623"/>
      <path d="M13 4L5 14h6v8l8-10h-6V4z" fill="#04060c"/>
    </svg>
    <div class="sb-logo-txt">
      <span>CoinGlass</span>
      <small>Terminal</small>
    </div>
  </div>

  <div class="nav-cat">Spot</div>
  <div class="nav-item active" data-p="rsi" onclick="nav('rsi',this)"><span class="nav-dot"></span><span>RSI Matrix</span></div>
  <div class="nav-item" data-p="gainers" onclick="nav('gainers',this)"><span class="nav-dot"></span><span>Gainers / Losers</span></div>

  <div class="nav-cat">Derivatives</div>
  <div class="nav-item" data-p="funding" onclick="nav('funding',this)"><span class="nav-dot"></span><span>Funding Rates</span></div>
  <div class="nav-item" data-p="oi" onclick="nav('oi',this)"><span class="nav-dot"></span><span>Open Interest</span></div>
  <div class="nav-item" data-p="oi_ex" onclick="nav('oi_ex',this)"><span class="nav-dot"></span><span>OI by Exchange</span></div>
  <div class="nav-item" data-p="longshort" onclick="nav('longshort',this)"><span class="nav-dot"></span><span>Long / Short</span></div>
  <div class="nav-item" data-p="liq" onclick="nav('liq',this)"><span class="nav-dot"></span><span>Liquidations BTC</span></div>
  <div class="nav-item" data-p="liq_list" onclick="nav('liq_list',this)"><span class="nav-dot"></span><span>Liq All Coins</span></div>

  <div class="nav-cat">Market</div>
  <div class="nav-item" data-p="mcap" onclick="nav('mcap',this)"><span class="nav-dot"></span><span>Market Cap</span></div>
  <div class="nav-item" data-p="feargreed" onclick="nav('feargreed',this)"><span class="nav-dot"></span><span>Fear &amp; Greed</span></div>
  <div class="nav-item" data-p="altseason" onclick="nav('altseason',this)"><span class="nav-dot"></span><span>Altcoin Season</span></div>
  <div class="nav-item" data-p="global" onclick="nav('global',this)"><span class="nav-dot"></span><span>Global Overview</span></div>

  <div class="nav-cat">ETF</div>
  <div class="nav-item" data-p="etf" onclick="nav('etf',this)"><span class="nav-dot"></span><span>ETF Overview</span></div>
  <div class="nav-item" data-p="etf_flow" onclick="nav('etf_flow',this)"><span class="nav-dot"></span><span>Daily Flows</span></div>
  <div class="nav-item" data-p="etf_btc" onclick="nav('etf_btc',this)"><span class="nav-dot"></span><span>BTC Net Inflow</span></div>

  <div class="nav-div"></div>
  <div class="nav-item" data-p="explorer" onclick="nav('explorer',this)">
    <span class="nav-dot" style="background:var(--acc)"></span><span>API Explorer</span>
  </div>
</nav>

<!-- MAIN -->
<div class="main">
  <div class="topbar">
    <div class="tb-live"><span class="tb-dot"></span>LIVE</div>
    <div class="tb-sep"></div>
    <div class="tb-chip" id="tbCount"></div>
    <div class="tb-sep"></div>
    <div class="tb-chip" id="tbPanel">RSI Matrix</div>
    <div class="tb-time" id="tbTime">--:--:--</div>
    <button class="tb-refresh" onclick="refresh()">&#8635; Refresh</button>
  </div>
  <div class="content" id="content"></div>
</div>

</div>

<script>
const $ = id => document.getElementById(id);
let cur = 'rsi';
let charts = {};

// ── formatters ────────────────────────────────────────────────────
const fP = v => {
  v = +v; if (isNaN(v)) return '—';
  if (v >= 1000)  return '$' + v.toLocaleString('en',{maximumFractionDigits:2});
  if (v >= 1)     return '$' + v.toFixed(2);
  if (v >= 0.001) return '$' + v.toFixed(4);
  return '$' + v.toFixed(8);
};
const fN = v => {
  v = +v; if (isNaN(v)) return '—';
  const s = v < 0 ? '-' : ''; v = Math.abs(v);
  if (v >= 1e12) return s + (v/1e12).toFixed(2) + 'T';
  if (v >= 1e9)  return s + (v/1e9).toFixed(2)  + 'B';
  if (v >= 1e6)  return s + (v/1e6).toFixed(2)  + 'M';
  if (v >= 1e3)  return s + (v/1e3).toFixed(1)  + 'K';
  return s + v.toFixed(2);
};
const fPct = v => {
  v = +v; if (isNaN(v)) return '—';
  return (v > 0 ? '+' : '') + v.toFixed(3) + '%';
};
const gv = (o, keys, fb = '') => {
  for (const k of keys) if (o && o[k] !== undefined && o[k] !== null) return o[k];
  return fb;
};
const ts2date = t => {
  t = +t;
  const d = t > 1e12 ? new Date(t) : new Date(t * 1000);
  return d.toLocaleDateString('en', {month:'short', day:'numeric'});
};

// ── chart defaults ────────────────────────────────────────────────
Chart.defaults.color = '#3d4a5c';
Chart.defaults.borderColor = 'rgba(255,255,255,0.05)';
Chart.defaults.font.family = "'IBM Plex Mono', monospace";
Chart.defaults.font.size = 11;

function kc(id) { if (charts[id]) { charts[id].destroy(); delete charts[id]; } }
function ka() { Object.keys(charts).forEach(kc); }

// ── nav ───────────────────────────────────────────────────────────
function nav(id, el) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  if (el) el.classList.add('active');
  cur = id;
  $('tbPanel').textContent = el?.querySelector('span:last-child')?.textContent || id;
  ka();
  id === 'explorer' ? renderExplorer() : fetchPanel(id);
}

function refresh() { if (cur !== 'explorer') fetchPanel(cur); }

// ── fetch ─────────────────────────────────────────────────────────
async function fetchPanel(id) {
  $('content').innerHTML = skelHTML();
  try {
    const r = await fetch('/api/' + id);
    if (!r.ok) {
      const text = await r.text();
      throw new Error(`Server Error ${r.status}: ${text.substring(0, 100)}`);
    }
    const j = await r.json();
    $('tbTime').textContent = new Date().toLocaleTimeString();
    if (!j.success) { showErr(j.error); return; }
    renderPanel(id, j.data, j.extracted || []);
  } catch(e) { showErr(e.message); }
}

function skelHTML() {
  return '<div class="stats">'
    + Array(4).fill('<div class="stat sk" style="height:60px"></div>').join('')
    + '</div>'
    + '<div class="card sk" style="height:280px;margin-bottom:16px"></div>'
    + '<div class="tw sk" style="height:300px"></div>';
}
function showErr(msg) {
  $('content').innerHTML = '<div class="err"><b>Error</b>' + msg + '</div>';
}

// ── badges ────────────────────────────────────────────────────────
const bRsi = v => {
  v = +v; if (isNaN(v)) return '<span class="b bn">—</span>';
  if (v >= 70) return '<span class="b br">' + v.toFixed(1) + '</span>';
  if (v <= 30) return '<span class="b bg">' + v.toFixed(1) + '</span>';
  return '<span class="b bn">' + v.toFixed(1) + '</span>';
};
const bChg = v => {
  v = +v; if (isNaN(v)) return '<span class="b bn">—</span>';
  return v >= 0
    ? '<span class="b bg">+' + v.toFixed(2) + '%</span>'
    : '<span class="b br">' + v.toFixed(2) + '%</span>';
};
const bFr = v => {
  v = +v; if (isNaN(v)) return '<span class="b bn">—</span>';
  const d = (v * 100).toFixed(4) + '%';
  return v > 0 ? '<span class="b br">' + d + '</span>' : '<span class="b bg">' + d + '</span>';
};
const bLs = v => {
  v = +v; if (isNaN(v)) return '<span class="b bn">—</span>';
  return v > 1
    ? '<span class="b bg">' + v.toFixed(3) + '</span>'
    : '<span class="b br">' + v.toFixed(3) + '</span>';
};

// ── row heat (RSI) ────────────────────────────────────────────────
function rsiHeat(v) {
  v = +v || 50;
  if (v >= 70) return 'background:rgba(232,69,69,' + Math.min((v-70)/30*0.16, 0.16) + ')';
  if (v <= 30) return 'background:rgba(61,186,110,' + Math.min((30-v)/30*0.16, 0.16) + ')';
  return '';
}

// ── sortable tables ───────────────────────────────────────────────
function sortable(tbl) {
  tbl.querySelectorAll('thead th').forEach((th, i) => {
    th.addEventListener('click', () => {
      tbl.querySelectorAll('thead th').forEach(h => h.classList.remove('sa','sd'));
      const d = th.dataset.d === 'a' ? 'd' : 'a';
      th.dataset.d = d; th.classList.add(d === 'a' ? 'sa' : 'sd');
      const rows = Array.from(tbl.querySelector('tbody').querySelectorAll('tr'));
      rows.sort((a,b) => {
        const va = a.cells[i]?.dataset.v ?? a.cells[i]?.textContent ?? '';
        const vb = b.cells[i]?.dataset.v ?? b.cells[i]?.textContent ?? '';
        const na = +va, nb = +vb;
        const cmp = (!isNaN(na) && !isNaN(nb)) ? na - nb : va.localeCompare(vb);
        return d === 'a' ? cmp : -cmp;
      });
      rows.forEach(r => tbl.querySelector('tbody').appendChild(r));
    });
  });
}

// ── raw toggle ────────────────────────────────────────────────────
function raw(id) {
  const el = $(id); if (!el) return;
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
function rawBlock(id, data) {
  return '<div class="rt" onclick="raw(\'' + id + '\')">&#9656; Raw JSON response</div>'
       + '<div class="rb" id="' + id + '" style="display:none">' + JSON.stringify(data, null, 2) + '</div>';
}

// ── panel router ──────────────────────────────────────────────────
function renderPanel(id, data, ex) {
  switch(id) {
    case 'rsi':       return pRsi(data, ex);
    case 'gainers':   return pGeneric(data, ex, 'Gainers / Losers');
    case 'funding':   return pFunding(data, ex);
    case 'oi':        return pOI(data, ex);
    case 'oi_ex':     return pOIEx(data, ex);
    case 'longshort': return pLS(data, ex);
    case 'liq':       return pLiq(data, ex);
    case 'liq_list':  return pGeneric(data, ex, 'Liquidations — All Coins');
    case 'mcap':      return pMcap(data, ex);
    case 'feargreed': return pFG(data, ex);
    case 'altseason': return pAlt(data, ex);
    case 'global':    return pGlobal(data, ex);
    case 'etf':       return pEtf(data, ex);
    case 'etf_flow':  return pGeneric(data, ex, 'ETF Daily Flows');
    case 'etf_btc':   return pGeneric(data, ex, 'BTC ETF Net Inflow');
    default:          return pGeneric(data, ex, id);
  }
}

// ══════════════════════════════════════════════════════════════════
// RSI
// ══════════════════════════════════════════════════════════════════
let rsiAll = [], rsiQ = '';

function pRsi(data, ex) {
  rsiAll = ex.length ? ex : (Array.isArray(data) ? data : []);
  const ob = rsiAll.filter(c => +(gv(c,['rsi4h','rsi_4h'],50)) >= 70);
  const os = rsiAll.filter(c => +(gv(c,['rsi4h','rsi_4h'],50)) <= 30);
  $('tbCount').textContent = rsiAll.length + ' assets';
  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">RSI Matrix</div></div>'
    + '<div class="stats">'
    + stat('Total', rsiAll.length, '')
    + stat('Overbought &ge;70', ob.length, 'color:var(--neg)')
    + stat('Oversold &le;30',  os.length, 'color:var(--pos)')
    + stat('Neutral', rsiAll.length - ob.length - os.length, '')
    + '</div>'
    + '<div class="g2">'
    + '<div class="card"><div class="card-lbl">Top 15 Extremes (RSI 4h)</div>'
    + '<div class="ch200"><canvas id="cRsiEx"></canvas></div></div>'
    + '<div class="card"><div class="card-lbl">RSI Distribution</div>'
    + '<div class="ch200"><canvas id="cRsiDist"></canvas></div></div>'
    + '</div>'
    + '<div class="sr">'
    + '<input class="si" placeholder="Search symbol..." oninput="rsiSearch(this.value)">'
    + '<button class="fb on" onclick="rsiF(\'\',this)">All</button>'
    + '<button class="fb" onclick="rsiF(\'ob\',this)">Overbought</button>'
    + '<button class="fb" onclick="rsiF(\'os\',this)">Oversold</button>'
    + '</div>'
    + '<div class="tw"><div class="tw-head"><span class="tw-title">All Assets</span>'
    + '<span class="tw-meta" id="rsiCnt">' + rsiAll.length + ' assets</span></div>'
    + '<div class="ts"><table id="tRsi"><thead><tr>'
    + '<th>#</th><th>Symbol</th><th>Price</th><th>RSI 1h</th><th>RSI 4h</th><th>RSI 24h</th>'
    + '</tr></thead><tbody id="bRsi"></tbody></table></div></div>'
    + rawBlock('rawRsi', data);

  buildRsiCharts(ob, os);
  buildRsiDist();
  rsiRows();
  sortable($('tRsi'));
}

function buildRsiCharts(ob, os) {
  const top = [...ob.slice(0,8), ...os.slice(0,7)];
  kc('cRsiEx');
  charts.cRsiEx = new Chart($('cRsiEx'), {
    type:'bar',
    data:{
      labels: top.map(c => gv(c,['symbol','s'],'?')),
      datasets:[{
        data: top.map(c => +(gv(c,['rsi4h','rsi_4h'],0))),
        backgroundColor: top.map(c => +(gv(c,['rsi4h','rsi_4h'],0)) >= 70
          ? 'rgba(232,69,69,.65)' : 'rgba(61,186,110,.65)'),
        borderRadius: 3,
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        y:{min:0,max:100,grid:{color:'rgba(255,255,255,.04)'},ticks:{stepSize:25}},
        x:{grid:{display:false},ticks:{font:{size:9}}}
      }
    }
  });
}

function buildRsiDist() {
  const buckets = Array(10).fill(0);
  rsiAll.forEach(c => {
    const v = +(gv(c,['rsi4h','rsi_4h'],50));
    buckets[Math.min(Math.floor(v/10), 9)]++;
  });
  kc('cRsiDist');
  charts.cRsiDist = new Chart($('cRsiDist'), {
    type:'bar',
    data:{
      labels:['0','10','20','30','40','50','60','70','80','90'],
      datasets:[{
        data:buckets,
        backgroundColor: buckets.map((_,i) =>
          i<=2 ? 'rgba(61,186,110,.55)' : i>=7 ? 'rgba(232,69,69,.55)' : 'rgba(77,157,224,.35)'),
        borderRadius:3,
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        y:{grid:{color:'rgba(255,255,255,.04)'}},
        x:{grid:{display:false},ticks:{font:{size:9}}}
      }
    }
  });
}

function rsiSearch(q) { rsiQ = q.toLowerCase(); rsiRows(); }
function rsiF(type, btn) {
  document.querySelectorAll('.fb').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  rsiQ = type; rsiRows();
}

function rsiRows() {
  let list = rsiAll;
  if (rsiQ === 'ob') list = rsiAll.filter(c => +(gv(c,['rsi4h','rsi_4h'],50)) >= 70);
  else if (rsiQ === 'os') list = rsiAll.filter(c => +(gv(c,['rsi4h','rsi_4h'],50)) <= 30);
  else if (rsiQ) list = rsiAll.filter(c => gv(c,['symbol','s'],'').toLowerCase().includes(rsiQ));
  $('rsiCnt').textContent = list.length + ' assets';
  $('bRsi').innerHTML = list.slice(0,200).map((c,i) => {
    const r4 = +(gv(c,['rsi4h','rsi_4h'],50));
    return '<tr style="' + rsiHeat(r4) + '">'
      + '<td style="color:var(--muted);font-family:var(--m)">' + (i+1) + '</td>'
      + '<td style="font-weight:600;color:var(--txt-hi)">' + gv(c,['symbol','s'],'?') + '</td>'
      + '<td class="mono" data-v="' + gv(c,['price','p'],0) + '">' + fP(gv(c,['price','p'],0)) + '</td>'
      + '<td data-v="' + gv(c,['rsi1h','rsi_1h'],0) + '">' + bRsi(gv(c,['rsi1h','rsi_1h'],0)) + '</td>'
      + '<td data-v="' + r4 + '">' + bRsi(r4) + '</td>'
      + '<td data-v="' + gv(c,['rsi24h','rsi_24h'],0) + '">' + bRsi(gv(c,['rsi24h','rsi_24h'],0)) + '</td>'
      + '</tr>';
  }).join('');
}

// ══════════════════════════════════════════════════════════════════
// Funding Rates
// ══════════════════════════════════════════════════════════════════
function pFunding(data, ex) {
  let rows = [];
  const coins = ex.length ? ex : (Array.isArray(data) ? data : []);
  if (coins.length && typeof coins[0] === 'object') {
    coins.forEach(c => {
      const vals = Object.values(c);
      vals.forEach(v => {
        if (Array.isArray(v)) v.forEach(e => { if (e && 'fundingRate' in e) rows.push(e); });
      });
    });
  }
  if (!rows.length) rows = coins;
  const sorted = [...rows].sort((a,b) => Math.abs(+b.fundingRate) - Math.abs(+a.fundingRate));
  const top30 = sorted.slice(0,30);
  $('tbCount').textContent = rows.length + ' rates';

  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">Funding Rates</div></div>'
    + '<div class="card" style="margin-bottom:16px"><div class="card-lbl">Top 30 by Absolute Rate</div>'
    + '<div class="ch260"><canvas id="cFr"></canvas></div></div>'
    + '<div class="tw"><div class="tw-head"><span class="tw-title">All Rates</span>'
    + '<span class="tw-meta">' + rows.length + ' entries</span></div>'
    + '<div class="ts"><table id="tFr"><thead><tr>'
    + '<th>Exchange</th><th>Symbol</th><th>Rate</th><th>Next Funding</th>'
    + '</tr></thead><tbody>'
    + sorted.slice(0,200).map(e => {
        const fr = +e.fundingRate;
        const bg = fr > 0.001 ? 'background:rgba(232,69,69,.04)' : fr < -0.001 ? 'background:rgba(61,186,110,.04)' : '';
        return '<tr style="' + bg + '">'
          + '<td style="font-weight:600">' + gv(e,['exName','exchangeName'],'?') + '</td>'
          + '<td style="font-family:var(--m)">' + gv(e,['symbol'],'?') + '</td>'
          + '<td data-v="' + e.fundingRate + '">' + bFr(e.fundingRate) + '</td>'
          + '<td style="font-family:var(--m);font-size:11px;color:var(--muted)">'
          + (e.nextFundingTime ? new Date(e.nextFundingTime).toLocaleTimeString() : '—') + '</td>'
          + '</tr>';
      }).join('')
    + '</tbody></table></div></div>'
    + rawBlock('rawFr', data);

  kc('cFr');
  charts.cFr = new Chart($('cFr'), {
    type:'bar',
    data:{
      labels: top30.map(e => gv(e,['symbol'],'?')),
      datasets:[{
        data: top30.map(e => +(e.fundingRate) * 100),
        backgroundColor: top30.map(e => +(e.fundingRate) > 0 ? 'rgba(232,69,69,.65)' : 'rgba(61,186,110,.65)'),
        borderRadius:3,
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        y:{grid:{color:'rgba(255,255,255,.04)'},ticks:{callback:v => v + '%'}},
        x:{grid:{display:false},ticks:{font:{size:9}}}
      }
    }
  });
  sortable($('tFr'));
}

// ══════════════════════════════════════════════════════════════════
// Open Interest
// ══════════════════════════════════════════════════════════════════
function pOI(data, ex) {
  const d     = data?.data || data || {};
  const dates = (d.dateList || []).map(ts2date);
  const vals  = d.openInterestList || [];
  const cur   = vals[vals.length - 1] || 0;
  const peak  = Math.max(...vals.filter(Boolean), 0);
  $('tbCount').textContent = vals.length + ' data pts';

  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">Open Interest</div></div>'
    + '<div class="stats">'
    + stat('Current OI', '$' + fN(cur), 'color:var(--acc)')
    + stat('Peak OI', '$' + fN(peak), '')
    + stat('Data Points', vals.length, '')
    + '</div>'
    + '<div class="card" style="margin-bottom:16px"><div class="card-lbl">Open Interest History</div>'
    + '<div class="ch300"><canvas id="cOI"></canvas></div></div>'
    + rawBlock('rawOI', data);

  kc('cOI');
  charts.cOI = new Chart($('cOI'), {
    type:'line',
    data:{
      labels:dates,
      datasets:[{
        data:vals, borderColor:'#f5a623',
        backgroundColor:'rgba(245,166,35,.08)',
        fill:true, tension:.3, pointRadius:0, borderWidth:2,
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        y:{grid:{color:'rgba(255,255,255,.04)'},ticks:{callback:v=>'$'+fN(v)}},
        x:{grid:{display:false},ticks:{maxTicksLimit:8}}
      }
    }
  });
}

// ══════════════════════════════════════════════════════════════════
// OI by Exchange
// ══════════════════════════════════════════════════════════════════
function pOIEx(data, ex) {
  const list = ex.length ? ex : (Array.isArray(data) ? data : []);
  const sorted = [...list].sort((a,b) =>
    +(gv(b,['openInterest','oi','openInterestUsd'],0)) - +(gv(a,['openInterest','oi','openInterestUsd'],0))
  ).slice(0,15);
  $('tbCount').textContent = list.length + ' exchanges';

  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">Open Interest by Exchange (BTC)</div></div>'
    + '<div class="card" style="margin-bottom:16px"><div class="card-lbl">OI Distribution</div>'
    + '<div class="ch300"><canvas id="cOIEx"></canvas></div></div>'
    + rawBlock('rawOIEx', data);

  kc('cOIEx');
  charts.cOIEx = new Chart($('cOIEx'), {
    type:'bar',
    data:{
      labels: sorted.map(e => gv(e,['exchangeName','exchange','ex'],'?')),
      datasets:[{
        data: sorted.map(e => +(gv(e,['openInterest','oi','openInterestUsd','value'],0))),
        backgroundColor:'rgba(77,157,224,.6)',
        borderRadius:4,
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false, indexAxis:'y',
      plugins:{legend:{display:false}},
      scales:{
        x:{grid:{color:'rgba(255,255,255,.04)'},ticks:{callback:v=>'$'+fN(v)}},
        y:{grid:{display:false}}
      }
    }
  });
}

// ══════════════════════════════════════════════════════════════════
// Long / Short
// ══════════════════════════════════════════════════════════════════
function pLS(data, ex) {
  const list = ex.length ? ex : (Array.isArray(data) ? data : []);
  $('tbCount').textContent = list.length + ' assets';
  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">Long / Short Ratio</div></div>'
    + '<div class="tw"><div class="tw-head"><span class="tw-title">L/S Ratio</span></div>'
    + '<div class="ts"><table id="tLS"><thead><tr>'
    + '<th>Symbol</th><th>Exchange</th><th>Long %</th><th>Short %</th><th>L/S Ratio</th>'
    + '</tr></thead><tbody>'
    + list.slice(0,200).map(r => {
        const lp = +(gv(r,['longAccount','longRatio'],0)) * 100;
        const sp = +(gv(r,['shortAccount','shortRatio'],0)) * 100;
        const ratio = lp && sp ? lp/sp : +(gv(r,['longShortRatio','ratio'],0));
        return '<tr>'
          + '<td style="font-weight:600">' + gv(r,['symbol','s'],'?') + '</td>'
          + '<td>' + gv(r,['exchangeName','exchange'],'?') + '</td>'
          + '<td style="font-family:var(--m);color:var(--pos)">' + (lp ? lp.toFixed(1)+'%' : '—') + '</td>'
          + '<td style="font-family:var(--m);color:var(--neg)">' + (sp ? sp.toFixed(1)+'%' : '—') + '</td>'
          + '<td data-v="' + ratio + '">' + bLs(ratio) + '</td>'
          + '</tr>';
      }).join('')
    + '</tbody></table></div></div>'
    + rawBlock('rawLS', data);
  sortable($('tLS'));
}

// ══════════════════════════════════════════════════════════════════
// Liquidations BTC
// ══════════════════════════════════════════════════════════════════
function pLiq(data, ex) {
  const d     = data?.data || data || {};
  const longU = +(gv(d,['longLiquidationUsd','longAmount'],0));
  const shrU  = +(gv(d,['shortLiquidationUsd','shortAmount'],0));
  $('tbCount').textContent = '$' + fN(longU + shrU) + ' liquidated';

  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">Liquidations — BTC 24h</div></div>'
    + '<div class="stats">'
    + stat('Long Liquidated', '$' + fN(longU), 'color:var(--neg)')
    + stat('Short Liquidated', '$' + fN(shrU), 'color:var(--pos)')
    + stat('Total', '$' + fN(longU + shrU), 'color:var(--acc)')
    + '</div>'
    + '<div class="g2">'
    + '<div class="card"><div class="card-lbl">Long vs Short</div>'
    + '<div class="ch260"><canvas id="cLiq"></canvas></div></div>'
    + '<div class="card"><div class="card-lbl">Summary</div>'
    + '<pre class="rb" style="margin-top:0;max-height:260px;border:none;padding:0">'
    + JSON.stringify(d, null, 2) + '</pre></div>'
    + '</div>'
    + rawBlock('rawLiq', data);

  kc('cLiq');
  charts.cLiq = new Chart($('cLiq'), {
    type:'doughnut',
    data:{
      labels:['Long Liq','Short Liq'],
      datasets:[{
        data:[longU||1, shrU||1],
        backgroundColor:['rgba(232,69,69,.7)','rgba(61,186,110,.7)'],
        borderColor:'transparent', borderWidth:0,
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false, cutout:'70%',
      plugins:{legend:{position:'bottom',labels:{padding:14,font:{size:11}}}}
    }
  });
}

// ══════════════════════════════════════════════════════════════════
// Market Cap
// ══════════════════════════════════════════════════════════════════
function pMcap(data, ex) {
  const list = ex.length ? ex : (Array.isArray(data) ? data : []);
  const top20 = list.slice(0,20);
  $('tbCount').textContent = list.length + ' assets';

  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">Market Cap Rankings</div></div>'
    + '<div class="card" style="margin-bottom:16px"><div class="card-lbl">Top 20 by Market Cap</div>'
    + '<div class="ch260"><canvas id="cMc"></canvas></div></div>'
    + '<div class="tw"><div class="tw-head"><span class="tw-title">All Assets</span>'
    + '<span class="tw-meta">' + list.length + ' assets</span></div>'
    + '<div class="ts"><table id="tMc"><thead><tr>'
    + '<th>#</th><th>Asset</th><th>Price</th><th>Market Cap</th><th>24h Vol</th><th>24h %</th>'
    + '</tr></thead><tbody>'
    + list.map((c,i) => '<tr>'
        + '<td style="color:var(--muted);font-family:var(--m)">' + (i+1) + '</td>'
        + '<td style="font-weight:600;color:var(--txt-hi)">' + gv(c,['symbol','code','s'],'?') + '</td>'
        + '<td style="font-family:var(--m)" data-v="' + gv(c,['price','p'],0) + '">' + fP(gv(c,['price','p'],0)) + '</td>'
        + '<td style="font-family:var(--m)" data-v="' + gv(c,['marketCap','market_cap','mc'],0) + '">$' + fN(gv(c,['marketCap','market_cap','mc'],0)) + '</td>'
        + '<td style="font-family:var(--m);color:var(--muted)">$' + fN(gv(c,['volume24h','vol','v'],0)) + '</td>'
        + '<td data-v="' + gv(c,['priceChangePercent','change24h'],0) + '">' + bChg(gv(c,['priceChangePercent','change24h'],0)) + '</td>'
        + '</tr>').join('')
    + '</tbody></table></div></div>'
    + rawBlock('rawMc', data);

  kc('cMc');
  charts.cMc = new Chart($('cMc'), {
    type:'bar',
    data:{
      labels: top20.map(c => gv(c,['symbol','code','s'],'?')),
      datasets:[{
        data: top20.map(c => +(gv(c,['marketCap','market_cap','mc'],0))),
        backgroundColor:'rgba(245,166,35,.5)',
        borderRadius:4,
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        y:{grid:{color:'rgba(255,255,255,.04)'},ticks:{callback:v=>'$'+fN(v)}},
        x:{grid:{display:false},ticks:{font:{size:9}}}
      }
    }
  });
  sortable($('tMc'));
}

// ══════════════════════════════════════════════════════════════════
// Fear & Greed
// ══════════════════════════════════════════════════════════════════
function pFG(data, ex) {
  const list = ex.length ? ex : (Array.isArray(data) ? data : []);
  const cur  = list[0] || {};
  const val  = +(gv(cur,['value','index'],50));
  const lbl  = gv(cur,['valueClassification','label','classification'],'—');
  const col  = val>=75?'var(--neg)':val>=55?'var(--acc)':val>=30?'var(--blue)':'var(--pos)';
  const hist = list.slice(0,30).reverse();
  $('tbCount').textContent = 'Index: ' + val.toFixed(0);

  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">Fear &amp; Greed Index</div></div>'
    + '<div class="g2">'
    + '<div class="card" style="text-align:center;display:flex;flex-direction:column;justify-content:center;min-height:220px">'
    + '<div class="card-lbl">Current Index</div>'
    + '<div style="font-family:var(--m);font-size:80px;font-weight:600;line-height:1;margin:12px 0;color:' + col + '">'
    + val.toFixed(0) + '</div>'
    + '<div style="font-size:14px;font-weight:600;color:' + col + '">' + lbl + '</div>'
    + '</div>'
    + '<div class="card"><div class="card-lbl">30-Day History</div>'
    + '<div class="ch260"><canvas id="cFG"></canvas></div></div>'
    + '</div>'
    + rawBlock('rawFG', data);

  kc('cFG');
  charts.cFG = new Chart($('cFG'), {
    type:'line',
    data:{
      labels: hist.map(h => ts2date(gv(h,['timestamp','updateTime'],0))),
      datasets:[{
        data: hist.map(h => +(gv(h,['value','index'],0))),
        borderColor:'#f5a623', backgroundColor:'rgba(245,166,35,.08)',
        fill:true, tension:.3, pointRadius:0, borderWidth:2,
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        y:{min:0,max:100,grid:{color:'rgba(255,255,255,.04)'}},
        x:{grid:{display:false},ticks:{maxTicksLimit:6}}
      }
    }
  });
}

// ══════════════════════════════════════════════════════════════════
// Altcoin Season
// ══════════════════════════════════════════════════════════════════
function pAlt(data, ex) {
  const d   = data?.data || data || {};
  const val = +(gv(d,['altcoinIndex','value','altcoinSeasonIndex','index'],0));
  const isSeason = val >= 75;
  $('tbCount').textContent = 'Index: ' + (val||'—');
  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">Altcoin Season Index</div></div>'
    + '<div class="stats">'
    + stat('Current Index', isNaN(val)||!val ? '—' : val.toFixed(0), isSeason ? 'color:var(--acc)' : 'color:var(--blue)')
    + stat('Status', isSeason ? 'ALTCOIN SEASON' : 'Bitcoin Season', isSeason ? 'color:var(--acc);font-size:14px' : 'font-size:14px')
    + stat('Threshold', '≥ 75 = Altcoin Season', '')
    + '</div>'
    + '<div class="card"><div class="card-lbl">Full Response</div>'
    + '<pre class="rb" style="border:none;padding:0;max-height:300px">'
    + JSON.stringify(d, null, 2) + '</pre></div>'
    + rawBlock('rawAlt', data);
}

// ══════════════════════════════════════════════════════════════════
// Global Overview
// ══════════════════════════════════════════════════════════════════
function pGlobal(data, ex) {
  const d = data?.data || data || {};
  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">Global Market Overview</div></div>'
    + '<div class="tw"><div class="tw-head"><span class="tw-title">All Fields</span></div>'
    + '<div class="ts"><table><thead><tr><th>Field</th><th>Value</th></tr></thead>'
    + '<tbody>' + (typeof d === 'object' && d
        ? Object.entries(d).map(([k,v]) =>
            '<tr><td style="font-family:var(--m);color:var(--muted)">' + k + '</td>'
            + '<td style="font-family:var(--m);color:var(--txt-hi)">'
            + (typeof v === 'object' ? JSON.stringify(v) : String(v))
            + '</td></tr>').join('')
        : '<tr><td colspan="2" style="color:var(--muted)">No structured data</td></tr>')
    + '</tbody></table></div></div>'
    + rawBlock('rawGlb', data);
}

// ══════════════════════════════════════════════════════════════════
// ETF Overview
// ══════════════════════════════════════════════════════════════════
function pEtf(data, ex) {
  const list  = ex.length ? ex : (Array.isArray(data) ? data : []);
  const top10 = list.slice(0,10);
  $('tbCount').textContent = list.length + ' funds';

  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">Bitcoin ETF Overview</div></div>'
    + '<div class="g2">'
    + '<div class="card"><div class="card-lbl">Inflow / Outflow (Top 10)</div>'
    + '<div class="ch260"><canvas id="cEtf"></canvas></div></div>'
    + '<div class="card"><div class="card-lbl">Fund Summary</div>'
    + '<div style="overflow:auto;max-height:260px">'
    + list.map(e => '<div style="display:flex;justify-content:space-between;'
        + 'padding:6px 0;border-bottom:1px solid var(--bdr);font-size:12px">'
        + '<span style="font-family:var(--m);font-weight:600">' + gv(e,['ticker'],'?') + '</span>'
        + '<span style="font-family:var(--m);color:' + (+(gv(e,['changeUsd'],0))>=0?'var(--pos)':'var(--neg)') + '">'
        + fN(gv(e,['changeUsd'],0)) + '</span>'
        + '</div>').join('')
    + '</div></div>'
    + '</div>'
    + rawBlock('rawEtf', data);

  kc('cEtf');
  charts.cEtf = new Chart($('cEtf'), {
    type:'bar',
    data:{
      labels: top10.map(e => gv(e,['ticker'],'?')),
      datasets:[{
        data: top10.map(e => +(gv(e,['changeUsd'],0))),
        backgroundColor: top10.map(e => +(gv(e,['changeUsd'],0))>=0?'rgba(61,186,110,.65)':'rgba(232,69,69,.65)'),
        borderRadius:4,
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        y:{grid:{color:'rgba(255,255,255,.04)'},ticks:{callback:v=>fN(v)}},
        x:{grid:{display:false}}
      }
    }
  });
}

// ══════════════════════════════════════════════════════════════════
// Generic table
// ══════════════════════════════════════════════════════════════════
function pGeneric(data, ex, title) {
  const list = ex.length ? ex : (Array.isArray(data) ? data : []);
  $('tbCount').textContent = list.length ? list.length + ' rows' : '';

  if (!list.length) {
    $('content').innerHTML =
      '<div class="ph"><div class="ph-title">' + title + '</div></div>'
      + '<div class="empty"><div class="empty-icon">&#128269;</div>'
      + '<div>No list data. Check raw response below.</div></div>'
      + rawBlock('rawGen', data);
    return;
  }

  const cols = Object.keys(list[0] || {}).slice(0,10);
  $('content').innerHTML =
    '<div class="ph"><div class="ph-title">' + title + '</div></div>'
    + '<div class="tw"><div class="tw-head"><span class="tw-title">' + title + '</span>'
    + '<span class="tw-meta">' + list.length + ' rows</span></div>'
    + '<div class="ts"><table id="tGen"><thead><tr>'
    + cols.map(c => '<th>' + c + '</th>').join('')
    + '</tr></thead><tbody>'
    + list.slice(0,200).map(r =>
        '<tr>' + cols.map(c => {
          const v = r[c];
          const s = typeof v === 'object' ? JSON.stringify(v) : String(v ?? '—');
          return '<td style="font-family:var(--m);font-size:11px" data-v="' + s + '">'
            + (s.length > 60 ? s.slice(0,60) + '…' : s) + '</td>';
        }).join('') + '</tr>').join('')
    + '</tbody></table></div></div>'
    + rawBlock('rawGen', data);
  sortable($('tGen'));
}

// ══════════════════════════════════════════════════════════════════
// API Explorer
// ══════════════════════════════════════════════════════════════════
const PATHS = [
  '/api/spot/rsi/list',
  '/api/fundingRate/list',
  '/api/futures/liquidation/today',
  '/api/openInterest/statistics',
  '/api/openInterest/exchange/list',
  '/api/futures/longShortRatio/list',
  '/api/liquidation/v2/info/list',
  '/api/etf/overview',
  '/api/etf/flowList',
  '/api/etf/bitcoin/flowList',
  '/api/marketCapRank',
  '/api/index/fearGreed/list',
  '/api/index/altcoinSeason',
  '/api/global/homeOverview',
  '/api/spot/gainLossList',
  '/api/futures/globalLongShortAccountRatio',
  '/api/futures/topLongShortAccountRatio',
  '/api/futures/openInterest/list',
  '/api/exchange/volume/list',
  '/api/bitcoin/price/history',
  '/api/bitcoin/dominate',
  '/api/option/overview',
  '/api/option/maxPain',
  '/api/index/cgdi',
  '/api/spot/topList',
  '/api/exchange/info/list',
  '/api/futures/liquidation/aggregated/list',
];

const DEFAULT_PARAMS = {
  '/api/spot/rsi/list':               '{"pageSize":500,"pageNum":1}',
  '/api/fundingRate/list':            '{"pageSize":100,"pageNum":1}',
  '/api/futures/liquidation/today':   '{"symbol":"BTC"}',
  '/api/openInterest/exchange/list':  '{"symbol":"BTC"}',
  '/api/marketCapRank':               '{"pageSize":100}',
  '/api/spot/gainLossList':           '{"pageSize":100}',
  '/api/liquidation/v2/info/list':    '{"pageSize":100,"pageNum":1}',
  '/api/bitcoin/price/history':       '{"symbol":"BTC","type":"1","currency":"USD"}',
};

function renderExplorer() {
  $('tbCount').textContent = '280+ endpoints';
  $('content').innerHTML =
    '<div class="ph">'
    + '<div class="ph-title">API Explorer</div>'
    + '<div class="ph-meta">Direct access to all capi.coinglass.com encrypted endpoints</div>'
    + '</div>'
    + '<div class="ex-form">'
    + '<div class="ex-lbl">Endpoint Path</div>'
    + '<input class="ex-path" id="exPath" placeholder="/api/spot/rsi/list" value="/api/spot/rsi/list" list="pathList">'
    + '<datalist id="pathList">' + PATHS.map(p => '<option value="' + p + '">').join('') + '</datalist>'
    + '<div class="ex-lbl">Params (JSON)</div>'
    + '<textarea class="ex-params" id="exParams">{"pageSize":500,"pageNum":1}</textarea>'
    + '<div style="display:flex;align-items:center">'
    + '<button class="ex-btn" onclick="runExplore()">Fetch &amp; Decrypt</button>'
    + '<span class="ex-hint">Base: <code style="color:var(--acc)">capi.coinglass.com</code> — AES decrypted automatically</span>'
    + '</div>'
    + '</div>'
    + '<div id="exRes"></div>'
    + '<div style="margin-top:4px">'
    + '<div class="ex-lbl">Known Paths</div>'
    + '<div class="chip-list">' + PATHS.map(p =>
        '<span class="path-chip" onclick="exSet(\'' + p + '\')">' + p + '</span>').join('') + '</div>'
    + '</div>';
}

function exSet(p) {
  $('exPath').value = p;
  $('exParams').value = DEFAULT_PARAMS[p] || '{}';
}

async function runExplore() {
  const path = $('exPath').value.trim();
  let params = {};
  try { params = JSON.parse($('exParams').value || '{}'); }
  catch(e) {
    $('exRes').innerHTML = '<div class="err"><b>Invalid JSON params</b>' + e.message + '</div>';
    return;
  }
  $('exRes').innerHTML = '<div class="sk" style="height:200px;border-radius:12px"></div>';
  try {
    const r = await fetch('/api/explore', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({path, params})
    });
    if (!r.ok) {
      const text = await r.text();
      throw new Error(`Server Error ${r.status}: ${text.substring(0, 100)}`);
    }
    const j = await r.json();
    $('tbTime').textContent = new Date().toLocaleTimeString();
    if (!j.success) {
      $('exRes').innerHTML = '<div class="err"><b>Error — ' + j.url + '</b>' + j.error + '</div>';
      return;
    }
    const d   = j.data;
    const arr = Array.isArray(d) ? d : (d?.list || d?.data?.list || d?.data || []);
    const cols = Array.isArray(arr) && arr.length ? Object.keys(arr[0]||{}).slice(0,10) : [];

    $('exRes').innerHTML =
      '<div class="tw" style="margin-bottom:10px">'
      + '<div class="tw-head"><span class="tw-title" style="color:var(--acc)">' + j.url + '</span>'
      + '<span class="b bg">Decrypted &#10003;</span></div>'
      + (cols.length
          ? '<div class="ts"><table id="tEx"><thead><tr>'
            + cols.map(c => '<th>' + c + '</th>').join('')
            + '</tr></thead><tbody>'
            + arr.slice(0,100).map(row =>
                '<tr>' + cols.map(c => {
                  const v = row[c];
                  const s = typeof v==='object' ? JSON.stringify(v) : String(v??'—');
                  return '<td style="font-family:var(--m);font-size:11px" data-v="' + s + '">'
                    + (s.length>60?s.slice(0,60)+'…':s) + '</td>';
                }).join('') + '</tr>').join('')
            + '</tbody></table></div>'
          : '')
      + '</div>'
      + '<div class="rt" onclick="raw(\'exRaw\')">'
      + '&#9656; Full decrypted JSON (' + JSON.stringify(d).length.toLocaleString() + ' chars)'
      + '</div>'
      + '<div class="rb" id="exRaw" style="display:none">' + JSON.stringify(d, null, 2) + '</div>';

    if ($('tEx')) sortable($('tEx'));
  } catch(e) {
    $('exRes').innerHTML = '<div class="err"><b>Fetch Error</b>' + e.message + '</div>';
  }
}

// ── stat helper ───────────────────────────────────────────────────
function stat(label, value, style) {
  return '<div class="stat"><div class="stat-lbl">' + label + '</div>'
       + '<div class="stat-val" style="' + style + '">' + value + '</div></div>';
}

// ── clock ─────────────────────────────────────────────────────────
setInterval(() => {
  const el = $('tbTime');
  if (el && el.textContent === '--:--:--') el.textContent = new Date().toLocaleTimeString();
}, 1000);

// ── auto-refresh every 60s ────────────────────────────────────────
setInterval(() => { if (cur !== 'explorer') fetchPanel(cur); }, 60000);

// ── boot ─────────────────────────────────────────────────────────
nav('rsi', document.querySelector('[data-p="rsi"]'));
</script>
</body>
</html>
HTMLEOF

EXPOSE 10000
CMD ["python", "/app/main.py"]