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
# Extract URL from text / OCR
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
    if m:
        return m.group(1).strip()

    m = re.search(r"\]\((https?://[^\s)]+)\)", t, flags=re.I)
    if m:
        return m.group(1).strip()

    m = re.search(r"<(https?://[^>\s]+)>", t, flags=re.I)
    if m:
        return m.group(1).strip()

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

    # highly trusted domains → subtract a bit of risk
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
    elif tld and tld not in SAFE_TLDS:
        score += 0.5
        signals.append("uncommon_tld")

    if any(c in host for c in "015") and any(c in host for c in "olis"):
        score += 1
        signals.append("lookalike_domain")

    path = (p.path or "").lower()
    for brand in ["paypal", "amazon", "microsoft", "bank", "hsbc", "dhl", "royalmail", "hmrc", "gov"]:
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
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    headers = {"Content-Type": "application/json"}

    try:
        r = requests.post(
            f"{GSB_URL}?key={GSB_API_KEY}",
            json=payload,
            headers=headers,
            timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        print("GSB RAW RESPONSE:", data)

        if data.get("matches"):
            return "malicious"
        return "clean"

    except Exception as e:
        print("GSB ERROR:", e)
        return "error"


# ================================
# AI URL EXTRACTION ENDPOINT
# ================================
@app.post("/ai_extract_url")
def ai_extract_url():
    try:
        data = request.get_json(silent=True) or {}
        text = (data.get("text") or "").strip()

        if not text:
            return jsonify({"url": None, "reason": "No text provided"})

        if not client:
            return jsonify({"url": None, "reason": "AI service unavailable"})

        prompt = (
            "Extract a URL from this text. "
            "Many scammers split URLs like 'h t t p' or 'w w w .'. "
            "Fix spacing and obfuscation. "
            "Respond ONLY in JSON: {\"url\":\"\", \"reason\":\"\"}.\n\n"
            f"TEXT:\n{text}"
        )

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Reply strictly in JSON."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=120,
            temperature=0.1,
        )

        import json
        raw = completion.choices[0].message.content
        m = re.search(r"\{.*\}", raw, flags=re.S)

        if not m:
            return jsonify({"url": None, "reason": "AI returned no JSON"})

        data = json.loads(m.group(0))

        return jsonify({
            "url": data.get("url"),
            "reason": data.get("reason", "")
        })

    except Exception as e:
        print("AI URL EXTRACT ERROR:", e)
        return jsonify({"url": None, "reason": "Server error"})
        import json
        parsed = json.loads(m.group(0))

        return jsonify({
            "url": parsed.get("url"),
            "reason": parsed.get("reason")
        })

    except Exception as e:
        print("AI_EXTRACT_URL ERROR:", e)
        return jsonify({"url": None, "reason": "Error processing text."})


# ================================
# Advanced AI URL assessment
# ================================
def ai_url_review(url: str, surrounding_text: str | None = None):
    if not client:
        return None, None

    try:
        prompt = (
            "You are Cyber Helper, a cautious security assistant for senior citizens.\n"
            "Classify this link as SAFE, CAUTION, or DANGER.\n\n"
            f"URL: {url}\n\nText around it:\n{surrounding_text}\n\n"
            "Return JSON: {\"risk\":\"SAFE|CAUTION|DANGER\",\"reason\":\"...\"}"
        )

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Return JSON only."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=150,
            temperature=0.1,
        )

        raw = completion.choices[0].message.content or ""

        m = re.search(r"\{.*\}", raw, flags=re.S)
        if not m:
            return None, None

        import json
        data = json.loads(m.group(0))
        risk_str = data.get("risk", "").upper()
        reason = data.get("reason", "")

        mapping = {"SAFE": "safe", "CAUTION": "caution", "DANGER": "danger"}
        return mapping.get(risk_str), reason

    except Exception as e:
        print("AI URL REVIEW ERROR:", e)
        return None, None

# ================================
# Decide final risk
# ================================
def decide(score, rep, ai_risk=None, ai_reason=None):
    if rep == "malicious":
        return "danger", "Reported malicious by Google Safe Browsing."

    if ai_risk in {"danger", "caution"}:
        return ai_risk, ai_reason or "AI suggests caution."

    if score >= 3:
        return "caution", "Unusual pattern detected."

    return "safe", "No obvious risks found."

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
            "rationale": "No link detected.",
            "tips": [
                "If it's a screenshot, type the website manually.",
                "Ask someone you trust if unsure.",
            ],
        })

    t0 = time.time()

    url = normalize_url(url_raw)
    score, signals, domain = heuristic_score(url)
    rep = gsb_lookup(url)

    ai_risk, ai_reason = (None, None)
    if rep != "malicious":
        ai_risk, ai_reason = ai_url_review(url, surrounding_text=text)

    risk, rationale = decide(score, rep, ai_risk=ai_risk, ai_reason=ai_reason)

    tips_map = {
        "safe": [
            "Open only if expected.",
            "Never type passwords unless sure the website is real.",
        ],
        "caution": [
            "Check the sender carefully.",
            "Avoid giving personal details.",
        ],
        "danger": [
            "Do NOT open this link.",
            "Delete the message and block the sender.",
        ],
    }

    banner_map = {
        "safe": "✅ SAFE",
        "caution": "⚠️ CAUTION",
        "danger": "⛔ DANGER",
    }

    pet_map = {
        "safe": "🙂 Cyber Hint: Looks okay.",
        "caution": "😟 Cyber Hint: Be careful.",
        "danger": "😣 Cyber Hint: Don’t click this!",
    }

    return jsonify({
        "risk": risk,
        "rationale": rationale,
        "tips": tips_map[risk],
        "banner": banner_map[risk],
        "pet": pet_map[risk],
        "evidence": {
            "url": url,
            "original_text": text,
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
        user_message = (data.get("message") or "").strip()

        if not user_message:
            return jsonify({"reply": "Please type your question again."})

        if not client:
            return jsonify({"reply": "AI service unavailable."})

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are Cyber Helper, a friendly AI for senior citizens. "
                        "Use simple language and step-by-step advice."
                    ),
                },
                {"role": "user", "content": user_message},
            ],
            max_tokens=350,
            temperature=0.4,
        )

        return jsonify({"reply": completion.choices[0].message.content})

    except Exception as e:
        print("AI_ANSWER ERROR:", e)
        return jsonify({"reply": "Something went wrong. Try again later."})

# ================================
# Health Endpoint
# ================================
@app.get("/health")
def health():
    return {"ok": True}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)