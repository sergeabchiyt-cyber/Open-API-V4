FROM python:3.11-slim

# System deps: gcc for Crypto; playwright --with-deps installs browser system libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python packages
RUN pip install --no-cache-dir \
    fastapi uvicorn[standard] httpx pycryptodome jinja2 aiofiles playwright

# Chromium for browser key-discovery fallback (lazy-spawned, 1 page max, only used
# when static AES key derivation fails for an unknown v= value)
RUN playwright install --with-deps chromium

RUN mkdir -p /app/templates /app/static
RUN python -c "import urllib.request; urllib.request.urlretrieve('https://unpkg.com/lightweight-charts@4.1.7/dist/lightweight-charts.standalone.production.js', '/app/static/lwc.js')"

# ============================================================
# decrypt.py  — no hardcoded keys, browser fallback for unknown v
# ============================================================
RUN cat <<'PYEOF' > /app/decrypt.py
import os, json, gzip, base64, time, logging, asyncio
from urllib.parse import urlparse, urlencode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import httpx

logger = logging.getLogger(__name__)

# ── No hardcoded keys in source ────────────────────────────────────────────────
# Populate at deploy time: CAPI_EXTRA_KEYS="55=170b070da9654622,66=d6537d845a964081,77=863f08689c97435b"
_CONSTANTS: dict[str, str] = {}
for _pair in os.environ.get("CAPI_EXTRA_KEYS", "").split(","):
    if "=" in _pair:
        _k, _v = _pair.strip().split("=", 1)
        _CONSTANTS[_k.strip()] = _v.strip()

# Runtime key0 cache populated on first successful decrypt for each v value
_KEY0_CACHE: dict[str, str] = {}

# Single browser at a time
_BROWSER_SEM: asyncio.Semaphore | None = None


def _get_sem() -> asyncio.Semaphore:
    global _BROWSER_SEM
    if _BROWSER_SEM is None:
        _BROWSER_SEM = asyncio.Semaphore(1)
    return _BROWSER_SEM


def _b64k(s: str) -> str | None:
    """base64(s)[:16]  – returns None if result would not be 16 chars."""
    if not s:
        return None
    k = base64.b64encode(s.encode()).decode()[:16]
    return k if len(k) == 16 else None


def _candidates(v: str, url: str, outer: dict) -> list[str]:
    """Return ordered, deduplicated list of 16-char key0 strings to try."""
    seen: set[str] = set()
    out: list[str] = []

    def push(k0: str | None) -> None:
        if k0 and len(k0) == 16 and k0 not in seen:
            seen.add(k0)
            out.append(k0)

    # 1. Previously discovered key0 for this v (fastest path)
    push(_KEY0_CACHE.get(v))

    # 2. Env-configured constant for this v
    push(_b64k(_CONSTANTS.get(v, "")))

    # 3. Version-specific derivation
    if v == "0":
        push(_b64k(url))
    elif v == "1":
        push(_b64k(urlparse(url).path or url))
    else:
        # v=2 and unknown: CG derives key from a time field in the outer JSON.
        # Try every plausible field name and timestamp format.
        for fld in ("time", "ts", "timestamp", "t", "serverTime",
                    "server_time", "createTime", "requestTime", "stime"):
            val = outer.get(fld)
            if val is None:
                continue
            push(_b64k(str(val)))
            if isinstance(val, (int, float)):
                push(_b64k(str(int(val))))
                if val > 1_000_000_000_000:          # looks like milliseconds
                    push(_b64k(str(int(val) // 1000)))
                elif val > 1_000_000_000:             # seconds — try ms form too
                    push(_b64k(str(int(val) * 1000)))

    # 4. All env constants (brute-force over unknown v values)
    for c in _CONSTANTS.values():
        push(_b64k(c))

    # 5. URL-based fallbacks (v=0/1 equivalents)
    push(_b64k(urlparse(url).path))
    push(_b64k(url))

    return out


def _run(token: bytes, payload: bytes, key0: str) -> dict:
    step1 = unpad(AES.new(key0.encode(), AES.MODE_ECB).decrypt(token), 16)
    akey  = gzip.decompress(step1).decode()
    step2 = unpad(AES.new(akey.encode(), AES.MODE_ECB).decrypt(payload), 16)
    return json.loads(gzip.decompress(step2).decode())


def decrypt(body: str, user_b64: str, v: str, url: str = "") -> dict:
    outer = json.loads(body)
    if "data" not in outer:
        return outer

    payload = base64.b64decode(outer["data"])
    token   = base64.b64decode(user_b64)
    cands   = _candidates(v, url, outer)

    for i, k0 in enumerate(cands):
        try:
            result = _run(token, payload, k0)
            if i > 0:
                logger.info("v=%s: candidate #%d succeeded (key0=%.6s…)", v, i, k0)
            # Cache for fast path next time
            if v not in ("0", "1"):
                _KEY0_CACHE[v] = k0
            return result
        except Exception:
            continue

    raise ValueError(
        f"All {len(cands)} candidates failed for v={v}. "
        "Add key via CAPI_EXTRA_KEYS or enable browser discovery."
    )


# ── Browser fallback ───────────────────────────────────────────────────────────

async def _browser_fetch_decrypt(url: str, params: dict) -> dict:
    """
    Single headless Chromium page.  Visit coinglass.com to pick up session
    cookies, then fetch the target endpoint from that context.  The server
    may return a different (known) v when accessed from a real browser, or
    organic page-load calls for the same path are captured directly.
    Browser is opened and closed in one shot; max 1 concurrent.
    """
    sem = _get_sem()
    async with sem:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise RuntimeError(
                "playwright not installed.  "
                "Set CAPI_EXTRA_KEYS or run: pip install playwright && playwright install chromium"
            )

        qs   = urlencode(params) if params else ""
        full = f"{url}?{qs}" if qs else url
        logger.info("🌐 browser fallback → %s", full)

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
                    "--no-zygote", "--single-process",
                    "--disable-background-networking",
                    "--disable-extensions", "--disable-default-apps",
                    "--no-first-run", "--mute-audio", "--hide-scrollbars",
                    "--disable-background-timer-throttling",
                ],
            )
            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36"
                ),
            )
            page = await context.new_page()

            # ── Stage 1: capture organic API calls during homepage load ────
            organic: dict[str, dict] = {}

            async def _on_resp(response: object) -> None:
                try:
                    if "capi.coinglass.com" not in response.url:  # type: ignore[attr-defined]
                        return
                    u_h = response.headers.get("user")            # type: ignore[attr-defined]
                    v_h = response.headers.get("v")               # type: ignore[attr-defined]
                    if not u_h or not v_h:
                        return
                    body_txt = await response.text()              # type: ignore[attr-defined]
                    organic[response.url] = {"user": u_h, "v": v_h, "body": body_txt}  # type: ignore[attr-defined]
                except Exception:
                    pass

            page.on("response", _on_resp)

            try:
                await page.goto(
                    "https://www.coinglass.com/",
                    wait_until="domcontentloaded",
                    timeout=28_000,
                )
                await asyncio.sleep(4)          # wait for initial XHR burst
            except Exception as e:
                logger.warning("CG homepage: %s", e)

            # Check if the exact path was captured organically
            target_path = urlparse(full).path
            for cap_url, cap in organic.items():
                if urlparse(cap_url).path == target_path:
                    try:
                        result = decrypt(cap["body"], cap["user"], cap["v"], cap_url)
                        logger.info("🌐 organic capture succeeded (%s)", target_path)
                        await browser.close()
                        return result
                    except Exception:
                        pass

            # ── Stage 2: direct fetch from CG browser context ─────────────
            raw = await page.evaluate(
                """
                async ([targetUrl]) => {
                    try {
                        const r = await fetch(targetUrl, {
                            credentials: "include",
                            headers: {
                                "encryption":  "true",
                                "cache-ts-v2": String(Date.now()),
                                "language":    "en",
                                "Origin":      "https://www.coinglass.com",
                                "Referer":     "https://www.coinglass.com/"
                            }
                        });
                        return {
                            ok:   true,
                            user: r.headers.get("user"),
                            v:    r.headers.get("v"),
                            body: await r.text()
                        };
                    } catch(e) {
                        return { ok: false, error: String(e) };
                    }
                }
                """,
                [full],
            )
            await browser.close()

        if not raw.get("ok"):
            raise ValueError(f"browser fetch error: {raw.get('error')}")

        b = raw.get("body", "")
        u = raw.get("user", "")
        v2 = raw.get("v", "")

        if not all([b, u, v2]):
            raise ValueError(f"browser returned incomplete fields: v={v2!r}")

        return decrypt(b, u, v2, full)


# ── Public entry-point ─────────────────────────────────────────────────────────

async def fetch_and_decrypt(
    url: str, params: dict | None = None, timeout: int = 15
) -> dict:
    headers = {
        "Accept":        "application/json, text/plain, */*",
        "cache-ts-v2":   str(int(time.time() * 1000)),
        "encryption":    "true",
        "language":      "en",
        "Origin":        "https://www.coinglass.com",
        "Referer":       "https://www.coinglass.com",
        "User-Agent":    "Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0.0.0 Safari/537.36",
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

    try:
        return decrypt(r.text, user, v, url)
    except ValueError as e:
        logger.warning("static decrypt failed (%s) → browser fallback", e)
        return await _browser_fetch_decrypt(url, params or {})

PYEOF

# ============================================================
# main.py
# ============================================================
RUN cat <<'PYEOF2' > /app/main.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from decrypt import fetch_and_decrypt
import json, logging, traceback

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app  = FastAPI(title="CoinGlass Terminal")
app.mount("/static", StaticFiles(directory="/app/static"), name="static")
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
    if isinstance(d, list): return d
    if isinstance(d, dict):
        if "dateList" in d and "dataMap" in d:
            dates   = d["dateList"]
            datamap = d["dataMap"]
            if isinstance(dates, list) and isinstance(datamap, dict):
                for exch, vals in datamap.items():
                    if isinstance(vals, list) and len(vals) == len(dates):
                        return [{"time": dates[i], exch: vals[i]} for i in range(len(dates))]
        for k in ["list","topInflowList","inflowList","rankList","coins","data","rows"]:
            if k not in d: continue
            v = d[k]
            if isinstance(v, list): return v
            if isinstance(v, dict):
                nested = extract(v)
                if nested: return nested
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

PYEOF2

# ============================================================
# dashboard.html
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
<script src="/static/lwc.js"></script>
<style>
:root {
  --bg:        #030709;
  --surface:   #070E18;
  --elevated:  #0B1624;
  --raised:    #0F1D2E;
  --border:    rgba(255,255,255,0.055);
  --border2:   rgba(255,255,255,0.11);
  --accent:    #F0A416;
  --accent-bg: rgba(240,164,22,0.08);
  --accent-br: rgba(240,164,22,0.30);
  --green:     #0DC989;
  --red:       #F4455A;
  --green-bg:  rgba(13,201,137,0.09);
  --red-bg:    rgba(244,69,90,0.09);
  --t1: #CDD8E5;
  --t2: #4E6478;
  --t3: #1E2E3E;
  --font: 'IBM Plex Mono', monospace;
  --sidebar: 220px;
  --topbar:  46px;
  --radius: 0;
}
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; -webkit-font-smoothing:antialiased; }
html, body { height:100%; }
body { background:var(--bg); color:var(--t1); font-family:var(--font); font-size:12px; overflow:hidden; }

::-webkit-scrollbar       { width:3px; height:3px; }
::-webkit-scrollbar-thumb { background:var(--t3); border-radius:2px; }
::-webkit-scrollbar-track { background:transparent; }

/* ── Layout ──────────────────────────────────────────────────────────────── */
.app   { display:flex; height:100vh; }

/* ── Sidebar ─────────────────────────────────────────────────────────────── */
.sidebar {
  width:var(--sidebar); flex-shrink:0;
  background:var(--surface);
  border-right:1px solid var(--border);
  display:flex; flex-direction:column;
  overflow:hidden;
}
.logo {
  height:var(--topbar);
  padding:0 14px;
  display:flex; align-items:center; gap:9px;
  border-bottom:1px solid var(--border);
  flex-shrink:0;
}
.logo-mark {
  width:24px; height:24px;
  background:var(--accent);
  display:grid; place-items:center;
  font-size:10px; font-weight:700; color:var(--bg);
  letter-spacing:-0.5px; flex-shrink:0; clip-path:polygon(0 0,100% 0,100% 75%,75% 100%,0 100%);
}
.logo-name { font-size:12px; font-weight:700; letter-spacing:0.5px; color:var(--t1); }
.logo-tag  { font-size:8px; color:var(--t2); margin-left:auto; letter-spacing:1px; }

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
.nav-search input::placeholder { color:var(--t3); }

.nav { flex:1; overflow-y:auto; padding-bottom:16px; }

.nav-cat {
  display:flex; align-items:center; justify-content:space-between;
  padding:11px 14px 4px;
  font-size:9px; font-weight:700; color:var(--t3);
  text-transform:uppercase; letter-spacing:1.8px;
}
.nav-cat-count { font-size:9px; color:var(--t3); letter-spacing:0; }

.nav-item {
  display:flex; align-items:center; gap:7px;
  padding:7px 14px; cursor:pointer;
  font-size:11px; color:var(--t2);
  border-left:2px solid transparent;
  letter-spacing:0.01em;
  transition:color 0.12s, background 0.12s, border-color 0.12s;
  position:relative;
}
.nav-item:hover { color:var(--t1); background:rgba(255,255,255,0.025); }
.nav-item.active {
  color:var(--accent);
  border-left-color:var(--accent);
  background:linear-gradient(90deg, var(--accent-bg) 0%, transparent 100%);
}
.nav-dot {
  width:4px; height:4px; border-radius:50%;
  background:var(--t3); flex-shrink:0;
  transition:background 0.12s;
}
.nav-item.active .nav-dot { background:var(--accent); box-shadow:0 0 5px var(--accent); }
.nav-badge {
  margin-left:auto; font-size:9px; color:var(--t3);
  background:var(--elevated); padding:1px 5px; letter-spacing:0;
}
.nav-item.active .nav-badge { color:var(--accent); background:var(--accent-bg); }

/* ── Main ────────────────────────────────────────────────────────────────── */
.main { flex:1; display:flex; flex-direction:column; overflow:hidden; min-width:0; }

.topbar {
  height:var(--topbar); flex-shrink:0;
  background:var(--surface);
  border-bottom:1px solid var(--border);
  display:flex; align-items:center; padding:0 16px; gap:10px;
}
.topbar-title {
  font-size:13px; font-weight:600; letter-spacing:-0.2px;
  white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:240px;
}
.topbar-path {
  font-size:10px; color:var(--t2);
  background:var(--elevated); border:1px solid var(--border);
  padding:2px 8px; white-space:nowrap; letter-spacing:0.01em;
}
.spacer { flex:1; }

.live-dot {
  width:6px; height:6px; border-radius:50%;
  background:var(--green); box-shadow:0 0 8px var(--green);
  animation:pulse 2.4s ease-in-out infinite;
}
@keyframes pulse { 0%,100%{opacity:1;box-shadow:0 0 8px var(--green)} 50%{opacity:0.35;box-shadow:0 0 3px var(--green)} }
.live-label { font-size:10px; color:var(--green); letter-spacing:1px; }
.topbar-clock { font-size:11px; color:var(--t2); border-left:1px solid var(--border); padding-left:12px; letter-spacing:0.05em; font-variant-numeric:tabular-nums; }

.btn {
  font-family:var(--font); font-size:11px;
  background:var(--elevated); border:1px solid var(--border);
  color:var(--t1); padding:5px 11px; cursor:pointer; white-space:nowrap;
  letter-spacing:0.02em;
  transition:border-color 0.12s, color 0.12s;
}
.btn:hover { border-color:var(--border2); color:#fff; }
.btn-accent { background:var(--accent); color:var(--bg); border:none; font-weight:700; }
.btn-accent:hover { opacity:0.88; }

/* ── Content ─────────────────────────────────────────────────────────────── */
.content { flex:1; overflow-y:auto; padding:12px; display:flex; flex-direction:column; gap:10px; }

/* ── KPI row ─────────────────────────────────────────────────────────────── */
.kpi-row { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:8px; }
.kpi {
  background:var(--surface);
  border:1px solid var(--border);
  border-top:2px solid var(--accent);
  padding:13px 14px 11px;
}
.kpi-label {
  font-size:9px; font-weight:700; color:var(--t2);
  text-transform:uppercase; letter-spacing:1.2px;
  margin-bottom:6px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
}
.kpi-value { font-size:17px; font-weight:700; letter-spacing:-0.5px; line-height:1.1; }
.kpi-sub   { font-size:10px; color:var(--t2); margin-top:4px; letter-spacing:0.01em; }

/* ── Split ───────────────────────────────────────────────────────────────── */
.split { display:grid; grid-template-columns:3fr 2fr; gap:10px; min-height:0; }
@media(max-width:1080px) { .split { grid-template-columns:1fr; } }

/* ── Panel ───────────────────────────────────────────────────────────────── */
.panel {
  background:var(--surface); border:1px solid var(--border);
  display:flex; flex-direction:column; min-height:0;
}
.panel-head {
  padding:8px 13px;
  border-bottom:1px solid var(--border);
  display:flex; align-items:center; gap:8px;
  flex-shrink:0;
}
.panel-head h3 {
  font-size:9px; font-weight:700;
  text-transform:uppercase; color:var(--t2);
  letter-spacing:1.2px;
}
.panel-pill {
  font-size:9px; color:var(--t3);
  background:var(--elevated); padding:2px 6px;
  margin-left:auto; letter-spacing:0;
}

/* ── Chart ───────────────────────────────────────────────────────────────── */
.chart-host {
  position:relative;
  height:clamp(360px, 44vh, 540px);
  overflow:hidden; flex-shrink:0;
}
.chart-host::after {
  content:''; position:absolute; inset:0; pointer-events:none; z-index:5;
  background:repeating-linear-gradient(
    0deg, transparent 0px, transparent 3px,
    rgba(0,0,0,0.035) 3px, rgba(0,0,0,0.035) 4px
  );
}
#lwcMount { position:absolute; inset:0; }
.chart-legend {
  position:absolute; top:10px; left:12px; z-index:10;
  pointer-events:none; font-size:11px; line-height:1.7;
}
.lg-name  { font-weight:600; color:var(--t1); letter-spacing:0.03em; }
.lg-ohlc  { font-size:10px; color:var(--t2); display:flex; flex-wrap:wrap; gap:7px; }
.lg-ohlc .v  { color:var(--accent); }
.lg-ohlc .up { color:var(--green); }
.lg-ohlc .dn { color:var(--red); }

.chart-empty {
  height:100%; display:flex; flex-direction:column;
  align-items:center; justify-content:center; gap:10px;
  color:var(--t2); font-size:11px; letter-spacing:0.03em;
}
.chart-empty-icon { font-size:26px; color:var(--t3); }

/* ── Bar chart ───────────────────────────────────────────────────────────── */
.bar-chart { padding:10px 14px; display:flex; flex-direction:column; gap:6px; overflow-y:auto; height:100%; }
.bar-row   { display:flex; align-items:center; gap:8px; }
.bar-label {
  font-size:10px; color:var(--t2); width:74px;
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  text-align:right; flex-shrink:0; letter-spacing:0.01em;
}
.bar-track { flex:1; height:18px; background:var(--bg); position:relative; overflow:hidden; }
.bar-fill  {
  height:100%; min-width:2px;
  background:var(--accent-bg); border-right:2px solid var(--accent);
  transition:width 0.38s cubic-bezier(.4,0,.2,1);
}
.bar-fill.pos { background:var(--green-bg); border-right-color:var(--green); }
.bar-fill.neg { background:var(--red-bg);   border-right-color:var(--red); }
.bar-val { font-size:10px; color:var(--t1); width:72px; text-align:right; flex-shrink:0; letter-spacing:0; font-variant-numeric:tabular-nums; }

/* ── Table ───────────────────────────────────────────────────────────────── */
.table-wrap { overflow:auto; max-height:clamp(360px, 44vh, 540px); }
table { width:100%; border-collapse:collapse; font-size:11px; }
thead tr { position:sticky; top:0; z-index:2; }
th {
  background:var(--elevated); border-bottom:1px solid var(--border);
  padding:7px 11px;
  font-size:9px; font-weight:700;
  text-transform:uppercase; letter-spacing:0.9px; color:var(--t2);
  text-align:left; cursor:pointer; user-select:none; white-space:nowrap;
  transition:color 0.1s;
}
th:hover { color:var(--t1); }
th.asc::after  { content:' ↑'; color:var(--accent); font-size:8px; }
th.desc::after { content:' ↓'; color:var(--accent); font-size:8px; }
td {
  padding:7px 11px;
  border-bottom:1px solid rgba(255,255,255,0.022);
  color:var(--t1); white-space:nowrap;
  letter-spacing:0.01em;
}
tr:nth-child(even) td { background:rgba(255,255,255,0.008); }
tr:hover td { background:rgba(255,255,255,0.018); }
.up { color:var(--green) !important; }
.dn { color:var(--red)   !important; }
td.num { font-variant-numeric:tabular-nums; text-align:right; }

/* ── Raw JSON inspector ──────────────────────────────────────────────────── */
.inspector-toggle {
  padding:8px 13px; font-size:10px; color:var(--t2);
  cursor:pointer; display:flex; align-items:center; gap:7px;
  letter-spacing:0.03em; border-top:1px solid var(--border);
  transition:color 0.1s;
}
.inspector-toggle:hover { color:var(--t1); }
.inspector-body {
  display:none; padding:12px;
  background:#020406; color:#3B5368;
  font-size:10px; max-height:200px; overflow:auto;
  font-family:var(--font); white-space:pre; line-height:1.6;
}

/* ── Explorer ────────────────────────────────────────────────────────────── */
.explorer { background:var(--surface); border:1px solid var(--border); padding:14px; display:flex; flex-direction:column; gap:10px; }
.form-row  { display:grid; grid-template-columns:2fr 3fr; gap:10px; }
.field     { display:flex; flex-direction:column; gap:4px; }
.field label { font-size:9px; font-weight:700; text-transform:uppercase; color:var(--t2); letter-spacing:0.9px; }
.field input, .field textarea {
  background:var(--bg); border:1px solid var(--border);
  padding:6px 9px; color:var(--t1);
  font-family:var(--font); font-size:11px; outline:none; letter-spacing:0.01em;
}
.field input:focus, .field textarea:focus { border-color:var(--accent-br); }
.field textarea { min-height:48px; resize:vertical; }

/* ── Skeleton / error / empty ────────────────────────────────────────────── */
.skeleton {
  background:linear-gradient(90deg, var(--surface) 25%, var(--elevated) 50%, var(--surface) 75%);
  background-size:200% 100%;
  animation:shimmer 1.5s ease-in-out infinite;
}
@keyframes shimmer { 0%{background-position:-200% 0} 100%{background-position:200% 0} }

.error {
  background:var(--red-bg); border:1px solid rgba(244,69,90,0.18);
  padding:16px; color:var(--red); letter-spacing:0.02em;
}
.error strong { display:block; margin-bottom:6px; font-size:13px; }
.error small  { color:var(--t2); font-size:10px; }
.empty { padding:48px; text-align:center; color:var(--t2); font-size:11px; letter-spacing:0.03em; }
</style>
</head>
<body>
<div class="app">

  <aside class="sidebar">
    <div class="logo">
      <div class="logo-mark">CG</div>
      <span class="logo-name">TERMINAL</span>
      <span class="logo-tag">v2</span>
    </div>
    <div class="nav-search">
      <input type="text" id="navSearch" placeholder="filter endpoints…" oninput="filterNav()">
    </div>
    <nav class="nav" id="nav"></nav>
  </aside>

  <div class="main">
    <div class="topbar">
      <span class="topbar-title" id="topTitle">Loading…</span>
      <span class="topbar-path"  id="topPath">—</span>
      <div class="spacer"></div>
      <div class="live-dot"></div>
      <span class="live-label">LIVE</span>
      <span class="topbar-clock" id="clock">--:--:--</span>
      <button class="btn" onclick="reload()">↻ Refresh</button>
    </div>
    <div class="content" id="content">
      <div class="empty">Initializing…</div>
    </div>
  </div>

</div>
<script>
/* ─── State ──────────────────────────────────────────────────────────────── */
const S = {
  id: null, reg: [], chart: null, series: null,
  sort: { col: null, dir: 1 }
};

/* ─── Bootstrap ──────────────────────────────────────────────────────────── */
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

/* ─── Nav ────────────────────────────────────────────────────────────────── */
function buildNav() {
  const cats = {};
  S.reg.forEach(e => { (cats[e.cat] = cats[e.cat] || []).push(e); });
  let h = '';
  for (const [cat, items] of Object.entries(cats)) {
    h += `<div class="nav-cat"><span>${cat}</span><span class="nav-cat-count">${items.length}</span></div>`;
    items.forEach(e => {
      const pc = Object.keys(e.params || {}).length;
      h += `<div class="nav-item" id="ni-${e.id}" onclick="loadEndpoint('${e.id}')">
        <span class="nav-dot"></span>
        <span>${e.label}</span>
        ${pc > 0 ? `<span class="nav-badge">${pc}</span>` : ''}
      </div>`;
    });
  }
  h += `<div class="nav-cat"><span>Tools</span></div>
    <div class="nav-item" id="ni-explorer" onclick="showExplorer()">
      <span class="nav-dot" style="background:var(--accent)"></span>
      <span>API Explorer</span>
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
  const el = $('ni-' + id);
  if (el) { el.classList.add('active'); el.scrollIntoView({ block: 'nearest' }); }
}

function reload() { if (S.id && S.id !== 'explorer') loadEndpoint(S.id); }

/* ─── Load endpoint ──────────────────────────────────────────────────────── */
async function loadEndpoint(id) {
  S.id = id;
  setActive(id);
  const ep = S.reg.find(e => e.id === id);
  $('topTitle').textContent = ep?.label || id;
  $('topPath').textContent  = ep?.path  || id;
  showSkeleton();
  try {
    const res  = await fetch('/api/' + id);
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'API error');
    render(json.data, json.extracted || []);
  } catch(err) {
    $('content').innerHTML = errBox('Fetch failed', err.message);
  }
}

function showSkeleton() {
  destroyChart();
  $('content').innerHTML =
    '<div class="kpi-row">' +
      Array(4).fill('<div class="skeleton" style="height:70px"></div>').join('') +
    '</div>' +
    '<div class="split">' +
      '<div class="skeleton" style="height:380px"></div>' +
      '<div class="skeleton" style="height:380px"></div>' +
    '</div>';
}

/* ─── Render ─────────────────────────────────────────────────────────────── */
function render(raw, rows) {
  destroyChart();
  if (!rows.length) rows = normalize(smartExtract(raw));

  const allKeys = rows.length ? Object.keys(rows[0]) : [];
  const numKeys = allKeys.filter(k => {
    const v = rows[0]?.[k];
    return typeof v === 'number' ||
      (v !== null && v !== '' && typeof v !== 'object' && !isNaN(parseFloat(v)));
  });

  /* KPI cards */
  const kpiCols = numKeys.filter(k => !isTimeKey(k)).slice(0, 4);
  let kpiHtml = '';
  if (kpiCols.length) {
    kpiCols.forEach(col => {
      const vals = rows.map(r => parseFloat(r[col])).filter(v => !isNaN(v));
      if (!vals.length) return;
      const mx = Math.max(...vals), mn = Math.min(...vals);
      const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
      kpiHtml += `<div class="kpi">
        <div class="kpi-label">${fmtCol(col)}</div>
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
        <div class="panel-head"><h3>Chart</h3><span class="panel-pill" id="chartPill">—</span></div>
        <div class="chart-host" id="chartHost"></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Data</h3><span class="panel-pill">${rows.length} rows</span></div>
        <div class="table-wrap">${buildTable(rows)}</div>
      </div>
    </div>
    <div class="panel" style="margin-top:0">
      <div class="inspector-toggle" onclick="toggleInspector()">
        <span id="iArrow">▶</span><span>Raw JSON</span>
      </div>
      <div class="inspector-body" id="iBody">${esc(JSON.stringify(raw, null, 2))}</div>
    </div>`;

  mountChart(rows, numKeys);
}

/* ─── Chart ──────────────────────────────────────────────────────────────── */
function isTimeKey(k) {
  return /^(time|t|date|timestamp|ts)$/i.test(k) || /time|date/i.test(k);
}

function mountChart(rows, numKeys) {
  const host = $('chartHost');
  if (!host || !rows.length || !numKeys.length) {
    if (host) host.innerHTML = '<div class="chart-empty"><div class="chart-empty-icon">∅</div>No chartable data</div>';
    return;
  }

  const keys    = Object.keys(rows[0]);
  const timeKey = keys.find(isTimeKey) || null;

  const ohlc = (() => {
    const m = {};
    keys.forEach(k => {
      const l = k.toLowerCase();
      if (l === 'open'  || l === 'o') m.o = k;
      if (l === 'high'  || l === 'h') m.h = k;
      if (l === 'low'   || l === 'l') m.l = k;
      if (l === 'close' || l === 'c') m.c = k;
    });
    return (m.o && m.h && m.l && m.c) ? m : null;
  })();

  if (timeKey || ohlc) {
    const valCol = numKeys.find(k => k !== timeKey) || numKeys[0];
    mountLWC(host, rows, timeKey, ohlc, valCol);
  } else {
    /* Horizontal bar chart */
    const ep      = S.reg.find(e => e.id === S.id);
    const sortCol = ep?.params?.sort;
    const spread  = k => Math.max(...rows.slice(0, 30).map(r => Math.abs(parseFloat(r[k]) || 0)));
    let valCol;
    if (sortCol && numKeys.includes(sortCol)) {
      valCol = sortCol;
    } else {
      const rateCols = numKeys.filter(k => /rate|apr|rsi|percent|change|pct|ratio/i.test(k) && spread(k) > 0);
      valCol = rateCols.length
        ? rateCols.reduce((best, k) => spread(k) > spread(best) ? k : best, rateCols[0])
        : numKeys.slice(0, 10).reduce((best, k) => spread(k) > spread(best) ? k : best, numKeys[0]);
    }
    const lblKey =
      keys.find(k => /^(symbol|coin|baseCoin|baseSym|name|ticker)$/i.test(k)) ||
      keys.find(k => typeof rows[0][k] === 'string' && rows[0][k].length < 24) ||
      null;
    mountBarChart(host, rows, valCol, lblKey);
  }
}

function toUnix(v, i, n) {
  if (v == null) return Math.floor(Date.now() / 1000) - (n - i) * 3600;
  if (typeof v === 'number') return v > 1e11 ? Math.floor(v / 1000) : v;
  const d = new Date(v);
  return isNaN(d) ? Math.floor(Date.now() / 1000) - (n - i) * 3600 : Math.floor(d / 1000);
}

function dedup(data) {
  const seen = new Set();
  return data.filter(d => { if (seen.has(d.time)) return false; seen.add(d.time); return true; });
}

function mountLWC(host, rows, timeKey, ohlc, numCol) {
  host.innerHTML = `
    <div id="lwcMount"></div>
    <div class="chart-legend">
      <div class="lg-name" id="lgName">${ohlc ? 'OHLC' : fmtCol(numCol)}</div>
      <div class="lg-ohlc" id="lgOhlc"></div>
    </div>`;

  requestAnimationFrame(() => {
    const mount = $('lwcMount');
    if (!mount) return;
    const w = Math.max(mount.clientWidth || 0, host.clientWidth || 0, 300);
    const h = Math.max(host.clientHeight || 0, 360);

    S.chart = LightweightCharts.createChart(mount, {
      width: w,
      height: h,
      layout: {
        background:  { color: '#070E18' },
        textColor:   '#4E6478',
        fontFamily:  "'IBM Plex Mono', monospace",
        fontSize:    11,
      },
      grid: {
        vertLines: { color: 'rgba(255,255,255,0.022)' },
        horzLines: { color: 'rgba(255,255,255,0.022)' },
      },
      crosshair: {
        mode: LightweightCharts.CrosshairMode.Normal,
        vertLine: { color: 'rgba(240,164,22,0.35)', labelBackgroundColor: '#0B1624' },
        horzLine: { color: 'rgba(240,164,22,0.35)', labelBackgroundColor: '#0B1624' },
      },
      rightPriceScale: { borderColor: 'rgba(255,255,255,0.05)' },
      timeScale:       { borderColor: 'rgba(255,255,255,0.05)', timeVisible: true, secondsVisible: false },
    });

    if (ohlc) {
      S.series = S.chart.addCandlestickSeries({
        upColor:        '#0DC989', downColor:        '#F4455A',
        borderUpColor:  '#0DC989', borderDownColor:  '#F4455A',
        wickUpColor:    '#0DC989', wickDownColor:    '#F4455A',
      });
      const data = dedup(
        rows.map((r, i) => ({
          time:  toUnix(timeKey ? r[timeKey] : null, i, rows.length),
          open:  parseFloat(r[ohlc.o]) || 0,
          high:  parseFloat(r[ohlc.h]) || 0,
          low:   parseFloat(r[ohlc.l]) || 0,
          close: parseFloat(r[ohlc.c]) || 0,
        })).sort((a, b) => a.time - b.time)
      );
      S.series.setData(data);
      if (data.length) setLegendOHLC(data[data.length - 1]);
      S.chart.subscribeCrosshairMove(p => {
        const bar = p.seriesData?.get(S.series);
        setLegendOHLC(bar || data[data.length - 1]);
      });
      $('chartPill') && ($('chartPill').textContent = data.length + ' bars');

    } else {
      S.series = S.chart.addAreaSeries({
        topColor:    'rgba(240,164,22,0.30)',
        bottomColor: 'rgba(240,164,22,0.02)',
        lineColor:   '#F0A416',
        lineWidth:   2,
        priceLineVisible: true,
        priceLineColor:   'rgba(240,164,22,0.4)',
      });
      const data = dedup(
        rows.map((r, i) => ({
          time:  toUnix(timeKey ? r[timeKey] : null, i, rows.length),
          value: parseFloat(r[numCol]) || 0,
        })).sort((a, b) => a.time - b.time)
      );
      S.series.setData(data);
      if (data.length) $('lgOhlc').innerHTML = `<span class="v">${fmt(data[data.length - 1].value)}</span>`;
      S.chart.subscribeCrosshairMove(p => {
        const bar = p.seriesData?.get(S.series);
        if (bar) $('lgOhlc').innerHTML = `<span class="v">${fmt(bar.value)}</span>`;
      });
      $('chartPill') && ($('chartPill').textContent = data.length + ' pts');
    }

    S.chart.timeScale().fitContent();

    new ResizeObserver(() => {
      if (S.chart && mount.clientWidth > 0) {
        S.chart.applyOptions({ width: mount.clientWidth, height: host.clientHeight });
      }
    }).observe(mount);
  });
}

function setLegendOHLC(bar) {
  if (!bar || bar.close == null) return;
  const d = bar.close - bar.open;
  const cls = d >= 0 ? 'up' : 'dn';
  $('lgOhlc').innerHTML =
    `O <span class="v">${fmt(bar.open)}</span> ` +
    `H <span class="v">${fmt(bar.high)}</span> ` +
    `L <span class="v">${fmt(bar.low)}</span> ` +
    `C <span class="v ${cls}">${fmt(bar.close)}</span> ` +
    `<span class="${cls}">${d >= 0 ? '+' : ''}${fmt(d)}</span>`;
}

function mountBarChart(host, rows, numCol, lblCol) {
  const top    = rows.slice(0, 30);
  const vals   = top.map(r => parseFloat(r[numCol]) || 0);
  const maxAbs = Math.max(...vals.map(Math.abs), 1e-9);

  let h = `<div class="bar-chart"><div style="font-size:9px;color:var(--t2);letter-spacing:.8px;text-transform:uppercase;padding:2px 0 6px;flex-shrink:0">${fmtCol(numCol)}</div>`;
  top.forEach(r => {
    const v   = parseFloat(r[numCol]) || 0;
    const pct = (Math.abs(v) / maxAbs * 100).toFixed(1);
    const lbl = lblCol ? String(r[lblCol]).slice(0, 10) : '';
    const cls = v > 0 ? 'pos' : v < 0 ? 'neg' : '';
    h += `<div class="bar-row">
      <div class="bar-label">${esc(lbl)}</div>
      <div class="bar-track"><div class="bar-fill ${cls}" style="width:${pct}%"></div></div>
      <div class="bar-val">${fmtNum(v)}</div>
    </div>`;
  });
  h += '</div>';
  host.innerHTML = h;
  $('chartPill') && ($('chartPill').textContent = 'bar · ' + fmtCol(numCol));
}

/* ─── Table ──────────────────────────────────────────────────────────────── */
function buildTable(rows) {
  if (!rows.length) return '<div class="empty">No data</div>';
  const cols = Object.keys(rows[0]).slice(0, 14);
  let h = '<table><thead><tr>';
  cols.forEach(c => {
    h += `<th id="th-${esc(c)}" onclick="sortBy('${esc(c)}')">${fmtCol(c)}</th>`;
  });
  h += '</tr></thead><tbody>';
  rows.slice(0, 300).forEach(r => {
    h += '<tr>';
    cols.forEach(c => {
      let v = r[c], cls = '', extra = '';
      if (v === null || v === undefined) { v = '—'; }
      else if (typeof v === 'object') { v = JSON.stringify(v).slice(0, 36) + '…'; }
      else if (typeof v === 'number' && isTimeKey(c)) {
        extra = ' num';
        v = fmtTime(v);
      }
      else if (typeof v === 'number') {
        if (/change|pct|rate|percent|diff/i.test(c)) cls = v > 0 ? 'up' : 'dn';
        extra = ' num';
        v = Math.abs(v) >= 1000 ? fmt(v) : (v % 1 === 0 ? v.toString() : v.toFixed(4).replace(/\.?0+$/, ''));
      }
      h += `<td class="${cls}${extra}">${esc(String(v))}</td>`;
    });
    h += '</tr>';
  });
  return h + '</tbody></table>';
}

function sortBy(col) {
  const th = $('th-' + col);
  if (!th) return;
  if (S.sort.col === col) S.sort.dir *= -1;
  else { S.sort.col = col; S.sort.dir = 1; }
  document.querySelectorAll('th').forEach(el => el.classList.remove('asc', 'desc'));
  th.classList.add(S.sort.dir === 1 ? 'asc' : 'desc');
  const tbody = th.closest('table')?.querySelector('tbody');
  if (!tbody) return;
  const idx = Array.from(th.parentElement.children).indexOf(th);
  const trs = Array.from(tbody.querySelectorAll('tr'));
  trs.sort((a, b) => {
    const ta = a.cells[idx]?.textContent || '', tb = b.cells[idx]?.textContent || '';
    const na = parseFloat(ta.replace(/[^0-9.\-]/g, '')), nb = parseFloat(tb.replace(/[^0-9.\-]/g, ''));
    return (!isNaN(na) && !isNaN(nb)) ? (na - nb) * S.sort.dir : ta.localeCompare(tb) * S.sort.dir;
  });
  trs.forEach(r => tbody.appendChild(r));
}

/* ─── Inspector ──────────────────────────────────────────────────────────── */
function toggleInspector() {
  const b = $('iBody'), a = $('iArrow');
  b.style.display = b.style.display === 'block' ? 'none' : 'block';
  a.textContent   = b.style.display === 'block'  ? '▼'    : '▶';
}

/* ─── Explorer ───────────────────────────────────────────────────────────── */
function showExplorer() {
  S.id = 'explorer'; setActive('explorer');
  $('topTitle').textContent = 'API Explorer';
  $('topPath').textContent  = 'POST /api/explore';
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
  let params = {};
  try { params = JSON.parse($('expParams').value || '{}'); } catch { alert('Invalid JSON'); return; }
  const path = $('expPath').value.trim();
  const out  = $('explorerOut');
  out.innerHTML = '<div class="skeleton" style="height:200px;margin-top:12px"></div>';
  try {
    const res  = await fetch('/api/explore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, params })
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    out.innerHTML = `<div class="panel" style="margin-top:12px">
      <div class="panel-head"><h3>${esc(json.url)}</h3></div>
      <div class="inspector-body" style="display:block">${esc(JSON.stringify(json.data, null, 2))}</div>
    </div>`;
  } catch(err) {
    out.innerHTML = `<div style="margin-top:12px">${errBox('Explorer error', err.message)}</div>`;
  }
}

/* ─── Utilities ──────────────────────────────────────────────────────────── */
function destroyChart() {
  if (S.chart) { try { S.chart.remove(); } catch(e) {} S.chart = null; S.series = null; }
}

function smartExtract(raw) {
  if (Array.isArray(raw)) return raw;
  if (!raw || typeof raw !== 'object') return [];
  if (Array.isArray(raw.data)) return raw.data;
  const found = [];
  function dig(obj, d) {
    if (d > 3) return;
    for (const v of Object.values(obj)) {
      if (Array.isArray(v) && v.length > 1) found.push(v);
      else if (v && typeof v === 'object' && !Array.isArray(v)) dig(v, d + 1);
    }
  }
  dig(raw, 0);
  found.sort((a, b) => b.length - a.length);
  return found[0] || [];
}

function normalize(rows) {
  if (!rows.length) return rows;
  if (Array.isArray(rows[0])) {
    return rows.map(r => r.length === 2
      ? { time: r[0], value: r[1] }
      : Object.fromEntries(r.map((v, i) => ['v' + i, v]))
    );
  }
  return rows;
}

/**
 * Convert CamelCase/ALLCAPS column names to readable title case.
 * e.g. "avgFundingRateByOiApr" → "Avg Funding Rate By OI Apr"
 *      "h24TurnoverUsd"         → "H24 Turnover USD"
 */
function fmtCol(s) {
  if (!s) return String(s);
  s = String(s);
  // ALL_CAPS with no lowercase: just title-case it, easier to read than shouting
  if (s === s.toUpperCase() && s.length > 3) {
    const lc = s.toLowerCase();
    return (lc[0].toUpperCase() + lc.slice(1)).substring(0, 22);
  }
  // camelCase / PascalCase
  s = s.replace(/([a-z\d])([A-Z])/g, '$1 $2')
       .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
       .replace(/_/g, ' ');
  // Acronym normalisation
  const fixes = {Usd:'USD', Oi:'OI', Rsi:'RSI', Apr:'APR', Btc:'BTC', Eth:'ETH', Sol:'SOL'};
  s = s.replace(/\b(Usd|Oi|Rsi|Apr|Btc|Eth|Sol)\b/g, m => fixes[m] || m);
  // Title-case remaining words
  s = s.replace(/\b([a-z])/g, l => l.toUpperCase());
  return s.substring(0, 22);
}

/* Render unix timestamps (seconds or ms) as readable local date/time for table cells */
function fmtTime(v) {
  const ms = v > 1e11 ? v : v * 1000;
  const d  = new Date(ms);
  if (isNaN(d)) return String(v);
  const sameDay = d.toDateString() === new Date().toDateString();
  return sameDay
    ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' +
      d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

function fmt(n) {
  if (n === undefined || n === null || isNaN(n)) return '—';
  const a = Math.abs(n);
  if (a >= 1e12) return (n / 1e12).toFixed(2) + ' T';
  if (a >= 1e9)  return (n / 1e9).toFixed(2)  + ' B';
  if (a >= 1e6)  return (n / 1e6).toFixed(2)  + ' M';
  if (a >= 1e3)  return (n / 1e3).toFixed(1)  + ' K';
  if (a < 0.0001 && a > 0) return n.toExponential(3);
  return n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 4 });
}

/* compact fmt for bar chart values */
function fmtNum(n) {
  if (isNaN(n)) return '—';
  const a = Math.abs(n);
  if (a >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (a >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (a >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return n.toFixed(Math.abs(n) < 0.01 ? 5 : 2);
}

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function errBox(title, msg) {
  return `<div class="error"><strong>${esc(title)}</strong>${esc(msg)}<br><br>
    <small>Check the API connection and endpoint parameters. If encryption fails, set CAPI_EXTRA_KEYS.</small></div>`;
}

function $(id) { return document.getElementById(id); }

/* ─── Clock ──────────────────────────────────────────────────────────────── */
setInterval(() => { const c = $('clock'); if (c) c.textContent = new Date().toLocaleTimeString(); }, 1000);

boot();
</script>
</body>
</html>

HTMLEOF

EXPOSE 10000
CMD ["python", "/app/main.py"]