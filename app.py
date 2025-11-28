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
SUSPICIOUS_TLDS = {"zip","xyz","ru","tk","top","work","click","fit","cf","gq","ml"}
SAFE_TLDS = {"com","org","net","co","uk","edu","gov"}
SHORTENERS = {"bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","is.gd"}

HIGH_TRUST_DOMAINS = {
    "wikipedia.org","en.wikipedia.org","nhs.uk","gov.uk",
    "service.gov.uk","europa.eu"
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

    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw

    p = urlparse(raw)
    host = p.hostname or ""

    try:
        host_ascii = idna.encode(host).decode("ascii")
    except Exception:
        host_ascii = host

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
# Extract URL (from manual text OR OCR)
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

    # HTML href
    m = re.search(r'href=["\']([^"\']+)["\']', t, flags=re.I)
    if m:
        return m.group(1).strip()

    # Markdown
    m = re.search(r"\]\((https?://[^\s)]+)\)", t, flags=re.I)
    if m:
        return m.group(1).strip()

    # <https://...>
    m = re.search(r"<(https?://[^>\s]+)>", t, flags=re.I)
    if m:
        return m.group(1).strip()

    # Plain URL
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
    full_host = ".".join(part for part in [ext.subdomain, ext.domain, ext.suffix] if part)

    if full_host in HIGH_TRUST_DOMAINS or domain in HIGH_TRUST_DOMAINS:
        score -= 1.5
        signals.append("high_trust_domain")

    if p.scheme != "https":
        score += 2
        signals.append("no_https")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 3
        signals.append("ip_address_domain")

    if len(url) > 120:
        score += 1
        signals.append("long_url")

    if ext.subdomain and len(ext.subdomain.split(".")) >= 3:
        score += 1
        signals.append("many_subdomains")

    tld = (ext.suffix or "").lower()
    if tld in SUSPICIOUS_TLDS:
        score += 2
        signals.append("suspicious_tld")
    elif tld not in SAFE_TLDS:
        score += 0.5
        signals.append("uncommon_tld")

    if any(c in host for c in "015") and any(c in host for c in "olis"):
        score += 1
        signals.append("lookalike_domain")

    path = (p.path or "").lower()
    for brand in ["paypal","amazon","microsoft","bank","hsbc","dhl","royalmail","hmrc","gov"]:
        if f"/{brand}" in path and brand not in domain:
            score += 1.5
            signals.append("brand_mismatch")
            break

    if host in SHORTENERS:
        score += 0.5
        signals.append("url_shortener")

    return score, signals, domain or full_host or host

# ================================
# Google Safe Browsing Lookup
# ================================
def gsb_lookup(url: str):
    if not GSB_API_KEY:
        return None

    payload = {
        "client": {"clientId": "cyber-helper", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
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
        r.raise_for_status()
        data = r.json()

        if data.get("matches"):
            return "malicious"
        return "clean"

    except Exception:
        return "error"

# ================================
# AI URL review
# ================================
def ai_url_review(url: str, surrounding_text: str | None = None):
    if not client:
        return None, None

    try:
        prompt = (
            "You are Cyber Helper, a cautious online safety assistant.\n"
            "Analyse the URL and classify the risk as SAFE, CAUTION, or DANGER.\n"
            "Focus on phishing and scams.\n\n"
            f"URL: {url}\n"
            f"Surrounding text:\n{surrounding_text or '(none)'}\n\n"
            "Return ONLY JSON in this format:\n"
            '{"risk": "SAFE|CAUTION|DANGER", "reason": "..."}'
        )

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Reply only in JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=150,
        )

        raw = completion.choices[0].message.content.strip()

        m = re.search(r"\{.*\}", raw, flags=re.S)
        if not m:
            return None, None

        import json
        data = json.loads(m.group(0))

        risk_map = {"SAFE": "safe", "CAUTION": "caution", "DANGER": "danger"}
        risk = risk_map.get(data.get("risk", "").upper())

        return risk, data.get("reason")

    except Exception:
        return None, None

# ================================
# FINAL DECISION
# ================================
def decide(score, rep, ai_risk=None, ai_reason=None):
    if rep == "malicious":
        return "danger", "Reported as malicious by Google Safe Browsing."

    if ai_risk in {"danger", "caution"}:
        return ai_risk, ai_reason or "Extra checks found issues."

    if score >= 3:
        return "caution", "Unusual patterns found — please be careful."

    return "safe", "No obvious risks found."

# ================================
# URL CHECK ENDPOINT
# ================================
@app.post("/check_url")
def check_url_route():
    body = request.get_json(silent=True) or {}

    text = (body.get("text") or body.get("url") or "").strip()
    url_raw = extract_first_url(text)

    if not url_raw:
        return jsonify({
            "risk": "caution",
            "rationale": "I couldn’t find a link in your message.",
            "tips": [
                "Try to read the link aloud or type what you see.",
                "Or share a clearer screenshot."
            ]
        })

    t0 = time.time()
    url = normalize_url(url_raw)

    score, signals, domain = heuristic_score(url)
    rep = gsb_lookup(url)
    ai_risk, ai_reason = (None, None)

    if rep != "malicious":
        ai_risk, ai_reason = ai_url_review(url, text)

    risk, rationale = decide(score, rep, ai_risk, ai_reason)

    tips = {
        "safe": [
            "Open only if you expected this message.",
            "Never enter passwords unless sure the site is real."
        ],
        "caution": [
            "Check spelling carefully.",
            "If unsure, avoid entering personal details."
        ],
        "danger": [
            "Do NOT open this link.",
            "Delete the message and block the sender."
        ]
    }

    return jsonify({
        "risk": risk,
        "rationale": rationale,
        "tips": tips[risk],
        "evidence": {
            "url": url,
            "score": score,
            "signals": signals,
            "rep": rep,
            "ai_risk": ai_risk
        },
        "elapsed_ms": int((time.time() - t0) * 1000)
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
            return jsonify({"reply": "Please type something."})

        if not client:
            return jsonify({"reply": "I cannot reach the helper service."})

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system",
                 "content": (
                     "You are Cyber Helper. Speak simply. Use short steps. "
                     "Help seniors stay safe online."
                 )},
                {"role": "user", "content": msg},
            ],
            max_tokens=300,
            temperature=0.4
        )

        reply = completion.choices[0].message.content
        return jsonify({"reply": reply})

    except Exception:
        return jsonify({
            "reply": "Something went wrong. Please try again later."
        })

# ================================
# HEALTH
# ================================
@app.get("/health")
def health():
    return {"ok": True}, 200


# ================================
# RUN
# ================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)