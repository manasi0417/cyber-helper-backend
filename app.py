import os
import re
import time
import requests
from flask import Flask, request, jsonify
from urllib.parse import urlparse
from html import unescape
import tldextract
import idna

from openai import OpenAI

app = Flask(__name__)

# -----------------------------------------
# ENVIRONMENT KEYS
# -----------------------------------------
GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

print("GSB KEY LOADED:", bool(GSB_API_KEY))
print("OPENAI KEY LOADED:", bool(OPENAI_API_KEY))

client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# -----------------------------------------
# URL REGEX
# -----------------------------------------
URL_RE = re.compile(
    r"(https?://[^\s<>()]+|www\.[^\s<>()]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
    re.I,
)

# -----------------------------------------
# URL NORMALIZER
# -----------------------------------------
def normalize_url(raw):
    if not raw:
        return ""

    raw = raw.strip()

    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw

    p = urlparse(raw)
    host = p.hostname or ""

    # Punycode conversion
    try:
        host_ascii = idna.encode(host).decode("ascii")
    except Exception:
        host_ascii = host

    query = p.query
    query = re.sub(r"(utm_[^=&]+|fbclid|gclid)=[^&]+&?", "", query).strip("&")

    port = f":{p.port}" if p.port else ""
    path = p.path or "/"

    final = f"{p.scheme.lower()}://{host_ascii}{port}{path}"
    if query:
        final += f"?{query}"

    return final


# -----------------------------------------
# AI URL EXTRACTION FROM TEXT
# -----------------------------------------
def ai_extract_url_from_text(text):
    if not client:
        return None, None

    prompt = (
        "Extract ONLY the usable website link from this text. "
        "If no real link exists, return null.\n\n"
        f"{text}\n\n"
        "Respond only in JSON: {\"url\": \"...\", \"reason\": \"...\"}"
    )

    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Respond only in JSON."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=80,
            temperature=0.1,
        )

        raw = completion.choices[0].message.content.strip()
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            return None, None

        import json

        js = json.loads(m.group(0))
        return js.get("url"), js.get("reason")

    except Exception as e:
        print("AI extraction error:", e)
        return None, None


# -----------------------------------------
# HARD-CORE MALICIOUS HEURISTICS
# -----------------------------------------
def heuristic_score(url):
    score = 0
    signals = []

    p = urlparse(url)
    host = (p.hostname or "").lower()
    ext = tldextract.extract(host)
    domain = ".".join([ext.domain, ext.suffix]) if ext.domain and ext.suffix else ""
    full_host = ".".join(x for x in [ext.subdomain, ext.domain, ext.suffix] if x)
    tld = (ext.suffix or "").lower()

    # 1) Trusted domains → safe weight
    SAFE_BRANDS = {
        "paypal.com", "amazon.com", "google.com", "apple.com", "facebook.com",
        "instagram.com", "bbc.co.uk", "wikipedia.org", "gov.uk", "nhs.uk",
        "outlook.com", "microsoft.com"
    }

    if full_host in SAFE_BRANDS:
        score -= 3
        signals.append("trusted_brand")

    # 2) Brand impersonation
    BRANDS = [
        "paypal", "amazon", "google", "apple", "bank", "hsbc", "barclays",
        "facebook", "instagram", "microsoft", "gov"
    ]
    for b in BRANDS:
        if b in url.lower() and b not in full_host:
            score += 5
            signals.append("brand_impersonation")
            break

    # 3) Dangerous TLDs
    BAD_TLDS = {"ru", "zip", "tk", "ml", "cf", "gq", "xyz", "click", "buzz", "rest", "fit"}
    if tld in BAD_TLDS:
        score += 4
        signals.append("dangerous_tld")

    # 4) Phishing keywords
    PHISH_WORDS = ["verify", "secure", "update", "login", "account", "confirm", "unlock", "reset"]
    if any(w in url.lower() for w in PHISH_WORDS):
        score += 4
        signals.append("phishing_keyword")

    # 5) HTTP instead of HTTPS
    if p.scheme != "https":
        score += 3
        signals.append("no_https")

    # 6) Raw IP Address
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 5
        signals.append("ip_domain")

    # 7) Too long URL
    if len(url) > 140:
        score += 1
        signals.append("long_url")

    # 8) Shorteners
    SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
    if host in SHORTENERS:
        score += 3
        signals.append("shortener")

    return score, signals, domain or full_host or host


# -----------------------------------------
# Google Safe Browsing Check
# -----------------------------------------
def gsb_lookup(url):
    if not GSB_API_KEY:
        return None

    payload = {
        "client": {"clientId": "cyber-helper", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        r = requests.post(f"{GSB_URL}?key={GSB_API_KEY}", json=payload, timeout=5)
        data = r.json()
        return "malicious" if data.get("matches") else "clean"
    except:
        return "error"


# -----------------------------------------
# AI SECONDARY ANALYSIS
# -----------------------------------------
def ai_url_review(url, text=None):
    if not client:
        return None, None

    prompt = (
        "Classify this link as SAFE, CAUTION or DANGER. "
        "Use simple logic focusing on phishing, scams, fake logins.\n\n"
        f"URL: {url}\n"
        f"Text: {text or '(none)'}\n\n"
        "Respond only in JSON: {\"risk\":\"...\", \"reason\":\"...\"}"
    )

    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "Respond only in JSON."},
                      {"role": "user", "content": prompt}],
            max_tokens=120,
            temperature=0.2,
        )
        raw = completion.choices[0].message.content
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            return None, None
        import json
        js = json.loads(m.group(0))
        risk = js.get("risk", "").lower()
        reason = js.get("reason", "")
        if risk in {"safe", "caution", "danger"}:
            return risk, reason
        return None, None
    except:
        return None, None


# -----------------------------------------
# FINAL DECISION ENGINE
# -----------------------------------------
def decide(score, rep, ai_risk=None, ai_reason=None):
    # 1. Google Safe Browsing wins instantly
    if rep == "malicious":
        return "danger", "Google Safe Browsing flagged this URL."

    # 2. Hard danger threshold
    if score >= 7:
        return "danger", "Multiple strong danger signals detected."

    # 3. Medium risk
    if 4 <= score < 7:
        return "caution", "Several suspicious signs found."

    # 4. AI review ONLY if heuristics are low
    if ai_risk in {"danger", "caution"}:
        return ai_risk, ai_reason

    # 5. Default safe
    return "safe", "No major warning signs detected."


# -----------------------------------------
# URL CHECK ENDPOINT
# -----------------------------------------
@app.post("/check_url")
def check_url():
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()

    raw = extract_first_url(text)
    if not raw:
        return jsonify({
            "risk": "caution",
            "rationale": "I couldn't find a link.",
            "tips": ["Type the website manually.", "Or upload a screenshot."],
        })

    url = normalize_url(raw)

    score, signals, _ = heuristic_score(url)
    rep = gsb_lookup(url)
    ai_risk, ai_reason = ai_url_review(url, text)

    risk, rationale = decide(score, rep, ai_risk, ai_reason)

    tips = {
        "safe": [
            "Open only if expected.",
            "Never enter passwords unless sure.",
        ],
        "caution": [
            "Be careful — double check the sender.",
            "Do not log in unless you’re certain.",
        ],
        "danger": [
            "Do NOT open this link.",
            "Delete the message and block the sender.",
        ],
    }

    return jsonify({
        "risk": risk,
        "rationale": rationale,
        "tips": tips[risk],
        "signals": signals,
        "gsb": rep,
        "ai_risk": ai_risk,
    })


# -----------------------------------------
# URL EXTRACT ENDPOINT
# -----------------------------------------
@app.post("/ai_extract_url")
def ai_extract_endpoint():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    url, reason = ai_extract_url_from_text(text)
    return jsonify({"url": url, "reason": reason})


# -----------------------------------------
# NORMAL CHAT AI
# -----------------------------------------
@app.post("/ai_answer")
def ai_answer():
    data = request.get_json(silent=True) or {}
    msg = (data.get("message") or "").strip()

    if not msg:
        return jsonify({"reply": "Please type again."})

    if not client:
        return jsonify({"reply": "AI is unavailable right now."})

    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system",
                 "content": "You are Cyber Helper. Answer simply for seniors."},
                {"role": "user", "content": msg},
            ],
            max_tokens=350,
            temperature=0.4,
        )
        return jsonify({"reply": completion.choices[0].message.content})

    except Exception as e:
        print("AI ERROR:", e)
        return jsonify({"reply": "Something went wrong."})


# -----------------------------------------
# HEALTH CHECK
# -----------------------------------------
@app.get("/health")
def health():
    return {"ok": True}, 200


# -----------------------------------------
# URL EXTRACTION HELP
# -----------------------------------------
def extract_first_url(text):
    if not text:
        return None
    m = URL_RE.search(text)
    return m.group(0) if m else None


# -----------------------------------------
# RUN LOCAL
# -----------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)