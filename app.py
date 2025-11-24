import os
import re
import time
import requests
from flask import Flask, request, jsonify
from urllib.parse import urlparse
from html import unescape
import tldextract
import idna

from openai import OpenAI   # NEW SDK

app = Flask(__name__)

# ================================
# API KEYS (ENV)
# ================================
GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

# DEBUG: print whether GSB key is loaded
print("DEBUG — GSB KEY LOADED:", bool(GSB_API_KEY))

client = OpenAI(api_key=OPENAI_API_KEY)

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# ================================
# Heuristic Settings
# ================================
SUSPICIOUS_TLDS = {"zip", "xyz", "ru", "tk", "top", "work", "click", "fit", "cf", "gq", "ml"}
SAFE_TLDS = {"com", "org", "net", "co", "uk", "edu", "gov"}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd"}

URL_RE = re.compile(
    r'(https?://[^\s<>"\)]+|[a-z0-9.-]+\.[a-z]{2,}(/[^\s<>"\)]*)?)',
    re.I
)

# ================================
# URL Normalisation
# ================================
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

    url = f"{p.scheme.lower()}://{host_ascii}{port}{path}"
    if query:
        url += "?" + query
    return url

# ================================
# Extract URL from message
# ================================
def extract_first_url(text: str):
    if not text:
        return None

    t = unescape(text).replace("\u200b", "").replace("\u2060", "").strip()

    m = re.search(r'href=["\']([^"\']+)["\']', t, flags=re.I)
    if m: return m.group(1).strip()

    m = re.search(r'\]\((https?://[^\s)]+)\)', t, flags=re.I)
    if m: return m.group(1).strip()

    m = re.search(r'<(https?://[^>\s]+)>', t, flags=re.I)
    if m: return m.group(1).strip()

    m = URL_RE.search(t)
    return m.group(0).strip() if m else None

# ================================
# Heuristic Scoring
# ================================
def heuristic_score(url: str):
    score, signals = 0.0, []

    p = urlparse(url)
    host = (p.hostname or "").lower()
    ext = tldextract.extract(host)
    domain = ".".join([x for x in [ext.domain, ext.suffix] if x])

    # HTTPS check
    if p.scheme != "https":
        score += 2
        signals.append("no_https")

    # IP address domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 3
        signals.append("ip_host")

    # Long URL
    if len(url) > 120:
        score += 1
        signals.append("long_url")

    # Too many subdomains
    if ext.subdomain and len(ext.subdomain.split(".")) >= 3:
        score += 1
        signals.append("many_subdomains")

    # Suspicious TLD
    tld = (ext.suffix or "").lower()
    if tld in SUSPICIOUS_TLDS:
        score += 2
        signals.append("suspicious_tld")

    elif tld and tld not in SAFE_TLDS:
        score += 0.5
        signals.append("uncommon_tld")

    # Lookalike domains
    if any(ch in host for ch in ["0", "1", "5"]) and any(ch in host for ch in ["o", "l", "i", "s"]):
        score += 1
        signals.append("lookalike_hint")

    # Brand mismatch in path
    path = (p.path or "").lower()
    for brand in ["bank", "paypal", "amazon", "microsoft", "royalmail", "dhl", "hmrc", "gov"]:
        if f"/{brand}" in path and brand not in domain:
            score += 1.5
            signals.append("brand_mismatch")
            break

    # URL shorteners
    if host in SHORTENERS:
        score += 0.5
        signals.append("shortener")

    return score, signals, domain

# ================================
# Google Safe Browsing API
# ================================
def gsb_lookup(url: str):
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

# ================================
# Decide Final Risk
# ================================
def decide(score, rep):
    if rep == "malicious":
        return "danger", "Reported as malicious by Google Safe Browsing."

    if score >= 3:
        return "caution", "Unusual patterns found — check carefully."

    return "safe", "No obvious risks found in initial checks."

# ================================
# URL CHECK ENDPOINT
# ================================
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
        })

    t0 = time.time()
    url = normalize_url(url_raw)

    score, signals, domain = heuristic_score(url)
    rep = gsb_lookup(url)

    risk, rationale = decide(score, rep)

    tips = {
        "safe": [
            "Open only if you expected it.",
            "Never enter passwords unless sure."
        ],
        "caution": [
            "Be careful — verify sender details.",
            "Check the domain spelling closely."
        ],
        "danger": [
            "Do not open this link.",
            "Delete the message and block the sender."
        ]
    }[risk]

    banner = {
        "safe": "✅ SAFE",
        "caution": "⚠️ CAUTION",
        "danger": "⛔ DANGER"
    }[risk]

    pet = {
        "safe": "🙂 Cyber Hint: Looks safe.",
        "caution": "😟 Cyber Hint: Be careful.",
        "danger": "😣 Cyber Hint: Don’t click this link!"
    }[risk]

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
    })

# ================================
# AI ANSWER ENDPOINT
# ================================
@app.post("/ai_answer")
def ai_answer():
    try:
        data = request.get_json() or {}
        user_message = data.get("message", "").strip()

        if not user_message:
            return jsonify({"reply": "Please type your question again."})

        if not OPENAI_API_KEY:
            return jsonify({"reply": "AI replies not configured."})

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are Cyber Helper, a friendly AI for senior citizens. "
                        "Use very simple language and step-by-step instructions."
                    )
                },
                {"role": "user", "content": user_message}
            ],
            max_tokens=350,
            temperature=0.4
        )

        return jsonify({"reply": completion.choices[0].message.content})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ================================
# Health Check
# ================================
@app.get("/health")
def health():
    return {"ok": True}, 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)