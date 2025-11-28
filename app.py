import os
import re
import time
import requests
from flask import Flask, request, jsonify
from urllib.parse import urlparse
from html import unescape
import tldextract
import idna

from openai import OpenAI  # NEW SDK

app = Flask(__name__)

# ================================
# API KEYS
# ================================
GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

print("DEBUG — GSB KEY LOADED:", bool(GSB_API_KEY))
print("DEBUG — OPENAI KEY LOADED:", bool(OPENAI_API_KEY))

client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# ================================
# Heuristic settings
# ================================
SUSPICIOUS_TLDS = {
    "zip", "xyz", "ru", "tk", "top", "work", "click", "fit", "cf", "gq", "ml"
}
SAFE_TLDS = {"com", "org", "net", "co", "uk", "edu", "gov"}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd"}

HIGH_TRUST_DOMAINS = {
    "wikipedia.org",
    "en.wikipedia.org",
    "nhs.uk",
    "gov.uk",
    "service.gov.uk",
    "europa.eu",
}

URL_RE = re.compile(
    r'(https?://[^\s<>"\)]+|[a-z0-9.-]+\.[a-z]{2,}(/[^\s<>"\)]*)?)',
    re.I,
)

# ================================
# URL Normalisation
# ================================
def normalize_url(raw: str) -> str:
    if not raw:
        return ""

    raw = raw.strip()

    # add scheme if missing
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw

    p = urlparse(raw)
    host = p.hostname or ""

    # punycode normalisation
    try:
        host_ascii = idna.encode(host).decode("ascii")
    except Exception:
        host_ascii = host

    # strip tracking params
    query = re.sub(
        r"(utm_[^=&]+|fbclid|gclid)=[^&]+&?",
        "",
        p.query,
        flags=re.I,
    ).strip("&")

    port = f":{p.port}" if p.port else ""
    path = p.path or "/"

    url = f"{p.scheme.lower()}://{host_ascii}{port}{path}"
    if query:
        url += f"?{query}"

    return url

# ================================
# Extract URL (raw + OCR)
# ================================
def extract_first_url(text: str):
    if not text:
        return None

    t = (
        unescape(text)
        .replace("\u200b", "")
        .replace("\u2060", "")
        .strip()
    )

    m = re.search(r'href=["\']([^"\']+)["\']', t, flags=re.I)
    if m: return m.group(1).strip()

    m = re.search(r"\]\((https?://[^\s)]+)\)", t, flags=re.I)
    if m: return m.group(1).strip()

    m = re.search(r"<(https?://[^>\s]+)>", t, flags=re.I)
    if (m): return m.group(1).strip()

    m = URL_RE.search(t)
    return m.group(0).strip() if m else None

# ================================
# Heuristic scoring
# ================================
def heuristic_score(url: str):
    score = 0.0
    signals = []

    p = urlparse(url)
    host = (p.hostname or "").lower()

    ext = tldextract.extract(host)
    domain = ".".join([x for x in [ext.domain, ext.suffix] if x])
    full_host = ".".join([x for x in [ext.subdomain, ext.domain, ext.suffix] if x])

    # highly trusted domains
    if full_host in HIGH_TRUST_DOMAINS or domain in HIGH_TRUST_DOMAINS:
        score -= 1.5
        signals.append("high_trust_domain")

    if p.scheme != "https":
        score += 2; signals.append("no_https")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 3; signals.append("ip_address_domain")

    if len(url) > 120:
        score += 1; signals.append("long_url")

    if ext.subdomain and len(ext.subdomain.split(".")) >= 3:
        score += 1; signals.append("many_subdomains")

    tld = (ext.suffix or "").lower()
    if tld in SUSPICIOUS_TLDS:
        score += 2; signals.append("suspicious_tld")
    elif tld and tld not in SAFE_TLDS:
        score += 0.5; signals.append("uncommon_tld")

    if any(c in host for c in "015") and any(c in host for c in "olis"):
        score += 1; signals.append("lookalike_domain")

    path = (p.path or "").lower()
    for brand in ["paypal","amazon","microsoft","bank","hsbc","dhl","royalmail","hmrc","gov"]:
        if f"/{brand}" in path and brand not in domain:
            score += 1.5; signals.append("brand_mismatch")
            break

    if host in SHORTENERS:
        score += 0.5; signals.append("url_shortener")

    return score, signals, domain or full_host or host

# ================================
# Google Safe Browsing
# ================================
def gsb_lookup(url: str):
    if not GSB_API_KEY:
        return None

    payload = {
        "client": {"clientId": "cyber-helper", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE","SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        r = requests.post(
            f"{GSB_URL}?key={GSB_API_KEY}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        data = r.json()
        if data.get("matches"):
            return "malicious"
        return "clean"
    except Exception as e:
        print("GSB ERROR:", e)
        return "error"

# ================================
# AI review of URLs
# ================================
def ai_url_review(url: str, surrounding_text: str = None):
    if not client:
        return None, None

    try:
        prompt = (
            "Analyse the URL and classify its risk as SAFE, CAUTION, or DANGER.\n"
            "Return JSON only: {\"risk\": \"...\",
             \"reason\": \"...\"}\n"
            f"URL: {url}\nContext: {surrounding_text}"
        )

        out = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Return JSON only."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=150,
            temperature=0.1,
        )

        raw = out.choices[0].message.content or ""

        import json
        m = re.search(r"\{.*\}", raw, re.S)
        if not m: return None, None

        data = json.loads(m.group(0))
        risk_map = {"SAFE": "safe", "CAUTION": "caution", "DANGER": "danger"}
        risk = risk_map.get(str(data.get("risk","")).upper())
        return risk, data.get("reason")
    except:
        return None, None

# ================================
# NEW: AI extract URL from screenshot OCR text
# ================================
@app.post("/ai_extract_url")
def ai_extract_url():
    try:
        data = request.get_json(silent=True) or {}
        text = (data.get("text") or "").strip()

        if not text:
            return jsonify({"url": None, "reason": "No text provided."})

        if not client:
            return jsonify({"url": None, "reason": "AI unavailable."})

        prompt = (
            "Extract a URL from the text. Fix broken formats like:\n"
            "hxxp → http, example dot com → example.com, scam[.]site → scam.site.\n"
            "Return JSON: {\"url\": \"...\", \"reason\": \"...\"}\n\n"
            f"TEXT:\n{text}"
        )

        out = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "JSON only."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=200,
            temperature=0.2,
        )

        raw = out.choices[0].message.content or ""
        import json
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            return jsonify({"url": None, "reason": "Invalid AI response."})

        return jsonify(json.loads(m.group(0)))
    except Exception as e:
        return jsonify({"url": None, "reason": str(e)})

# ================================
# Decide risk
# ================================
def decide(score, rep, ai_risk=None, ai_reason=None):
    if rep == "malicious":
        return "danger", "Reported malicious by Google Safe Browsing."

    if ai_risk in {"danger","caution"}:
        return ai_risk, ai_reason

    if score >= 3:
        return "caution", "Unusual patterns detected."

    return "safe", "No strong danger signals detected."

# ================================
# URL CHECK ENDPOINT
# ================================
@app.post("/check_url")
def check_url():
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()

    url_raw = extract_first_url(text)
    if not url_raw:
        return jsonify({
            "risk": "caution",
            "rationale": "I couldn’t find a link in the message.",
            "tips": ["Try typing it manually.", "Ask someone you trust."],
        })

    t0 = time.time()

    url = normalize_url(url_raw)
    score, signals, domain = heuristic_score(url)
    rep = gsb_lookup(url)
    ai_risk, ai_reason = (None, None)

    if rep != "malicious":
        ai_risk, ai_reason = ai_url_review(url, text)

    risk, rationale = decide(score, rep, ai_risk, ai_reason)

    tips_map = {
        "safe": [
            "Open only if you expected it.",
            "Never enter passwords unless sure."
        ],
        "caution": [
            "Double-check sender.",
            "Don’t log in if unsure."
        ],
        "danger": [
            "DO NOT open this link.",
            "Delete the message immediately."
        ]
    }

    banner = {
        "safe": "✅ SAFE",
        "caution": "⚠️ CAUTION",
        "danger": "⛔ DANGER",
    }[risk]

    return jsonify({
        "risk": risk,
        "rationale": rationale,
        "tips": tips_map[risk],
        "banner": banner,
        "evidence": {
            "url": url,
            "score": score,
            "signals": signals,
            "rep": rep,
            "ai_risk": ai_risk,
        },
        "elapsed_ms": int((time.time() - t0) * 1000),
    })

# ================================
# AI ANSWER ENDPOINT
# ================================
@app.post("/ai_answer")
def ai_answer():
    try:
        data = request.get_json(silent=True) or {}
        msg = (data.get("message") or "").strip()

        if not msg:
            return jsonify({"reply": "Please type your question again."})

        if not client:
            return jsonify({"reply": "AI unavailable at the moment."})

        out = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system",
                 "content": (
                     "You are Cyber Helper for senior citizens. "
                     "Use simple language and short steps."
                 )},
                {"role": "user", "content": msg},
            ],
            max_tokens=350,
            temperature=0.4,
        )

        return jsonify({"reply": out.choices[0].message.content})

    except:
        return jsonify({"reply": "Something went wrong. Try again later."})

# ================================
# HEALTH CHECK
# ================================
@app.get("/health")
def health():
    return {"ok": True}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)