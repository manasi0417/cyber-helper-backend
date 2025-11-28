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
    """
    Tries multiple patterns:
    - HTML href=""
    - Markdown [text](url)
    - <https://...>
    - Bare URLs / domains (also from OCR text)
    """
    if not text:
        return None

    t = (
        unescape(text)
        .replace("\u200b", "")
        .replace("\u2060", "")
        .strip()
    )

    # href="…"
    m = re.search(r'href=["\']([^"\']+)["\']', t, flags=re.I)
    if m:
        return m.group(1).strip()

    # markdown
    m = re.search(r"\]\((https?://[^\s)]+)\)", t, flags=re.I)
    if m:
        return m.group(1).strip()

    # <https://…>
    m = re.search(r"<(https?://[^>\s]+)>", t, flags=re.I)
    if m:
        return m.group(1).strip()

    # plain URL / domain
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

    # 1) HTTPS vs HTTP
    if p.scheme != "https":
        score += 2
        signals.append("no_https")

    # 2) Raw IP
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 3
        signals.append("ip_address_domain")

    # 3) Very long URL
    if len(url) > 120:
        score += 1
        signals.append("long_url")

    # 4) Many subdomains
    if ext.subdomain and len(ext.subdomain.split(".")) >= 3:
        score += 1
        signals.append("many_subdomains")

    # 5) TLD reputation
    tld = (ext.suffix or "").lower()
    if tld in SUSPICIOUS_TLDS:
        score += 2
        signals.append("suspicious_tld")
    elif tld and tld not in SAFE_TLDS:
        score += 0.5
        signals.append("uncommon_tld")

    # 6) Lookalike domain (cheap heuristic)
    if any(c in host for c in "015") and any(c in host for c in "olis"):
        score += 1
        signals.append("lookalike_domain")

    # 7) Brand mismatch in path
    path = (p.path or "").lower()
    for brand in ["paypal", "amazon", "microsoft", "bank", "hsbc", "dhl", "royalmail", "hmrc", "gov"]:
        if f"/{brand}" in path and brand not in domain:
            score += 1.5
            signals.append("brand_mismatch")
            break

    # 8) URL shortener
    if host in SHORTENERS:
        score += 0.5
        signals.append("url_shortener")

    return score, signals, domain or full_host or host

# ================================
# Google Safe Browsing Lookup
# ================================
def gsb_lookup(url: str):
    """
    Returns:
      'malicious' | 'clean' | 'error' | None (if key missing)
    """
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
        print("GSB RAW RESPONSE:", data)  # DEBUG

        if data.get("matches"):
            return "malicious"
        return "clean"

    except Exception as e:
        print("GSB ERROR:", e)
        return "error"

# ================================
# Advanced AI URL assessment
# ================================
def ai_url_review(url: str, surrounding_text: str | None = None):
    """
    Use OpenAI as a second opinion.
    Returns: (risk, explanation) or (None, None) on failure.
    risk ∈ {'safe','caution','danger'}
    """
    if not client:
        return None, None

    try:
        prompt = (
            "You are Cyber Helper, a cautious security assistant for senior citizens.\n"
            "They sent you a link and maybe some surrounding text.\n"
            "Classify the RISK of visiting the link as one of: SAFE, CAUTION, DANGER.\n"
            "Focus on phishing, scams, fake login pages and malware.\n\n"
            f"URL: {url}\n\n"
            f"Surrounding text:\n{surrounding_text or '(none)'}\n\n"
            "Answer in JSON with keys: risk, reason.\n"
            "risk must be exactly one of: SAFE, CAUTION, DANGER."
        )

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You respond in strict JSON only."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=150,
            temperature=0.1,
        )

        raw = completion.choices[0].message.content or ""
        # crude JSON extraction
        m = re.search(r"\{.*\}", raw, flags=re.S)
        if not m:
            return None, None

        import json

        data = json.loads(m.group(0))
        risk_str = str(data.get("risk", "")).strip().upper()
        reason = str(data.get("reason", "")).strip()

        mapping = {"SAFE": "safe", "CAUTION": "caution", "DANGER": "danger"}
        risk = mapping.get(risk_str)
        if risk not in {"safe", "caution", "danger"}:
            return None, None

        return risk, reason or None

    except Exception as e:
        print("AI URL REVIEW ERROR:", e)
        return None, None

# ================================
# Decide final risk
# ================================
def decide(score, rep, ai_risk=None, ai_reason=None):
    """
    Combine:
      - Google Safe Browsing verdict
      - Heuristic score
      - AI risk label (if any)
    """
    # 1) Hard verdict from Google
    if rep == "malicious":
        return "danger", "Reported as malicious by Google Safe Browsing."

    # 2) AI second opinion if available
    if ai_risk in {"danger", "caution"}:
        reason = ai_reason or "Extra checks suggest this link may not be safe."
        return ai_risk, reason

    # 3) Heuristics
    if score >= 3:
        return "caution", "Unusual patterns found in the link — please check carefully."

    # Low score → treat as safe
    return "safe", "No obvious risks found in the quick checks."

# ================================
# URL CHECK ENDPOINT
# ================================
@app.post("/check_url")
def check_url():
    body = request.get_json(silent=True) or {}

    # text can be: manual input OR OCR-extracted block
    text = (body.get("text") or body.get("url") or "").strip()
    url_raw = extract_first_url(text)

    if not url_raw:
        return jsonify(
            {
                "risk": "caution",
                "rationale": "I couldn’t find a link in your message.",
                "tips": [
                    "If it’s a picture, try to type the website address you can see.",
                    "Or ask someone you trust to help you read the link.",
                ],
            }
        )

    t0 = time.time()

    url = normalize_url(url_raw)

    # 1) Heuristics
    score, signals, domain = heuristic_score(url)

    # 2) Google Safe Browsing
    rep = gsb_lookup(url)

    # 3) AI review (only if not already flagged malicious)
    ai_risk, ai_reason = (None, None)
    if rep != "malicious":
        ai_risk, ai_reason = ai_url_review(url, surrounding_text=text)

    # 4) Final decision
    risk, rationale = decide(score, rep, ai_risk=ai_risk, ai_reason=ai_reason)

    # Tips for UI
    tips_map = {
        "safe": [
            "Open only if you expected this message.",
            "Never enter passwords unless you are sure the site is real.",
        ],
        "caution": [
            "Be careful — double-check the sender and the website address.",
            "If unsure, do not log in or enter any personal details.",
        ],
        "danger": [
            "Do NOT open this link.",
            "Delete the message and block the sender if possible.",
        ],
    }

    banner_map = {
        "safe": "✅ SAFE",
        "caution": "⚠️ CAUTION",
        "danger": "⛔ DANGER",
    }

    pet_map = {
        "safe": "🙂 Cyber Hint: This looks okay. Good job checking before you click.",
        "caution": "😟 Cyber Hint: Something feels off. Only continue if you’re really sure.",
        "danger": "😣 Cyber Hint: This looks dangerous. Don’t click the link.",
    }

    return jsonify(
        {
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
        }
    )

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
            return jsonify(
                {
                    "reply": (
                        "I’m having trouble reaching the helper service just now. "
                        "Please try again later or speak to someone you trust."
                    )
                }
            )

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are Cyber Helper, a friendly AI designed for senior citizens. "
                        "Use very simple language, short sentences, and step-by-step instructions. "
                        "Focus on online safety, scams, passwords, and privacy."
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
        return (
            jsonify(
                {
                    "reply": (
                        "Something went wrong while preparing your answer. "
                        "Please try again in a few minutes."
                    )
                }
            ),
            200,
        )

# ================================
# Health Endpoint
# ================================
@app.get("/health")
def health():
    return {"ok": True}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)