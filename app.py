import os, re, time, requests
from flask import Flask, request, jsonify
from urllib.parse import urlparse
from html import unescape
import tldextract, idna

app = Flask(__name__)

# === Reputation service (env var) ===
GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()
GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# === Heuristic config ===
SUSPICIOUS_TLDS = {"zip","xyz","ru","tk","top","work","click","fit","cf","gq","ml"}
SAFE_TLDS       = {"com","org","net","co","uk","edu","gov"}
SHORTENERS      = {"bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","is.gd"}

# Tolerant URL regex (avoids < > " ), captures domains-with-paths too
URL_RE = re.compile(
    r'(https?://[^\s<>"\)]+|[a-z0-9.-]+\.[a-z]{2,}(/[^\s<>"\)]*)?)',
    re.I
)

# ---------------------------
# Utilities
# ---------------------------

def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw
    p = urlparse(raw)
    host = p.hostname or ""
    try:
        host_ascii = idna.encode(host).decode("ascii")
    except Exception:
        host_ascii = host
    query = re.sub(r"(utm_[^=&]+|fbclid|gclid)=[^&]+&?", "", p.query, flags=re.I)
    port = f":{p.port}" if p.port else ""
    path = p.path or "/"
    norm = f"{p.scheme.lower()}://{host_ascii}{port}{path}"
    if query:
        norm += f"?{query}"
    return norm

def extract_first_url(text: str):
    """Extract URL from HTML/Markdown/plain text."""
    if not text:
        return None
    t = unescape(text).replace("\u200b","").replace("\u2060","").strip()

    # 1) HTML <a href="...">
    m = re.search(r'href=["\']([^"\']+)["\']', t, flags=re.I)
    if m:
        return m.group(1).strip()

    # 2) Markdown [label](https://url)
    m = re.search(r'\]\((https?://[^\s)]+)\)', t, flags=re.I)
    if m:
        return m.group(1).strip()

    # 3) Angle style <https://url>
    m = re.search(r'<(https?://[^>\s]+)>', t, flags=re.I)
    if m:
        return m.group(1).strip()

    # 4) Fallback plain text/domain
    m = URL_RE.search(t)
    return m.group(0).strip() if m else None

def heuristic_score(url: str):
    score, signals = 0.0, []
    p = urlparse(url)
    host = (p.hostname or "").lower()
    ext = tldextract.extract(host)
    domain = ".".join([x for x in [ext.domain, ext.suffix] if x])

    if p.scheme != "https":
        score += 2; signals.append("no_https")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 3; signals.append("ip_host")
    if len(url) > 120:
        score += 1; signals.append("long_url")
    if ext.subdomain and len(ext.subdomain.split(".")) >= 3:
        score += 1; signals.append("many_subdomains")

    tld = (ext.suffix or "").lower()
    if tld in SUSPICIOUS_TLDS:
        score += 2; signals.append("suspicious_tld")
    elif tld and tld not in SAFE_TLDS:
        score += 0.5; signals.append("uncommon_tld")

    if any(ch in host for ch in ["0","1","5"]) and any(ch in host for ch in ["o","l","i","s"]):
        score += 1; signals.append("lookalike_hint")

    path = (p.path or "").lower()
    for b in ["bank","paypal","amazon","microsoft","royalmail","dhl","hmrc","gov"]:
        if f"/{b}" in path and b not in domain:
            score += 1.5; signals.append("brand_mismatch"); break

    if host in SHORTENERS:
        score += 0.5; signals.append("shortener")

    return score, signals, domain

# ---------------------------
# Reputation lookup
# ---------------------------

def gsb_lookup(url: str):
    """Google Safe Browsing v4. Returns 'malicious', 'clean', 'error', or None if not configured."""
    if not GSB_API_KEY:
        return None
    payload = {
        "client": {"clientId": "cyber-helper", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        r = requests.post(f"{GSB_URL}?key={GSB_API_KEY}", json=payload, timeout=5)
        data = r.json()
        return "malicious" if data.get("matches") else "clean"
    except Exception as e:
        print("GSB lookup error:", e)
        return "error"

def decide(score, rep):
    if rep == "malicious":
        return "danger", "Reported as malicious by a reputation service."
    if score >= 3:
        return "caution", "Unusual patterns (HTTPS/TLD/subdomain). Check carefully."
    return "safe", "No obvious risks found in quick checks."

# ---------------------------
# Routes
# ---------------------------

@app.post("/check_url")
def check_url():
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or body.get("url") or "").strip()
    url_raw = extract_first_url(text)
    if not url_raw:
        return jsonify({
            "risk": "caution",
            "rationale": "I couldn’t find a link in your message.",
            "tips": [
                "Share the message to the chatbot.",
                "Or read the link aloud slowly."
            ]
        }), 200

    t0 = time.time()
    url = normalize_url(url_raw)
    score, signals, domain = heuristic_score(url)

    rep = gsb_lookup(url)  # may be None if no key
    risk, rationale = decide(score, rep)

    tips = {
        "safe": [
            "Open only if you expected it.",
            "Avoid entering passwords unless you trust the site."
        ],
        "caution": [
            "Don’t click directly; verify via the official app.",
            "Check sender and domain spelling carefully."
        ],
        "danger": [
            "Do not open this link.",
            "Delete the message and block the sender."
        ]
    }[risk]

    # Decorated fields for Tiledesk (no conditionals in template)
    banner_map = {
        "safe": "✅ SAFE",
        "caution": "⚠️ CAUTION",
        "danger": "⛔ DANGER"
    }
    pet_map = {
        "safe": "🙂 Great job checking first!",
        "caution": "😟 Be careful — verify sender details.",
        "danger": "😣 Don’t click this link!"
    }
    banner = banner_map[risk]
    pet = pet_map[risk]

    return jsonify({
        "risk": risk,
        "rationale": rationale,
        "tips": tips,
        "banner": banner,
        "pet": pet,
        "evidence": {
            "url": url,
            "score": score,
            "signals": signals,
            "rep": rep
        },
        "elapsed_ms": int((time.time() - t0) * 1000)
    }), 200

@app.get("/health")
def health():
    return {"ok": True}, 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)