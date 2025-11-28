import os
import re
import time
import json
import requests
from flask import Flask, request, jsonify
from urllib.parse import urlparse
from html import unescape
import tldextract
import idna

from openai import OpenAI   # NEW SDK

app = Flask(__name__)

# =======================================================
# ENV + KEYS
# =======================================================
GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

print("GSB Loaded:", bool(GSB_API_KEY))
print("OpenAI Loaded:", bool(OPENAI_API_KEY))

client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

SUSPICIOUS_TLDS = {"zip","xyz","ru","tk","top","work","click","fit","cf","gq","ml"}
SAFE_TLDS = {"com","org","net","co","uk","edu","gov"}

SHORTENERS = {"bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","is.gd"}

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

# =======================================================
# URL NORMALIZATION
# =======================================================
def normalize_url(raw):
    if not raw:
        return ""

    raw = raw.strip()

    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw

    p = urlparse(raw)

    host = p.hostname or ""
    try:
        host_ascii = idna.encode(host).decode()
    except:
        host_ascii = host

    query = re.sub(
        r"(utm_[^=&]+|fbclid|gclid)=[^&]+&?",
        "",
        p.query,
        flags=re.I,
    ).strip("&")

    url = f"{p.scheme.lower()}://{host_ascii}"
    if p.port:
        url += f":{p.port}"
    url += p.path or "/"
    if query:
        url += f"?{query}"

    return url

# =======================================================
# URL EXTRACTION
# =======================================================
def extract_first_url(text):
    if not text:
        return None

    t = (
        unescape(text)
        .replace("\u200b", "")
        .replace("\u2060", "")
        .strip()
    )

    m = re.search(r'href=["\']([^"\']+)["\']', t)
    if m: return m.group(1).strip()

    m = re.search(r'\]\((https?://[^\s)]+)\)', t)
    if m: return m.group(1).strip()

    m = re.search(r'<(https?://[^>\s]+)>', t)
    if m: return m.group(1).strip()

    m = URL_RE.search(t)
    return m.group(0).strip() if m else None

# =======================================================
# AI URL Extraction for screenshots
# =======================================================
@app.post("/ai_extract_url")
def ai_extract_url():
    if not client:
        return jsonify({"url": None, "reason": "No AI key available"}), 200

    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()

    if not text:
        return jsonify({"url": None, "reason": "No text received"}), 200

    try:
        prompt = (
            "You will receive text extracted from a screenshot. "
            "Your job is to identify if ANY URL or website address exists. "
            "You MUST return ONLY JSON like this:\n\n"
            "{ \"url\": \"the-url-if-found\", \"reason\": \"why you think so\" }\n\n"
            "If no link, return:\n"
            "{ \"url\": null, \"reason\": \"No link found\" }\n\n"
            f"TEXT:\n{text}"
        )

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Always reply only in JSON."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=150,
            temperature=0.1,
        )

        raw = completion.choices[0].message.content
        m = re.search(r"\{.*\}", raw, flags=re.S)

        if not m:
            return jsonify({"url": None, "reason": "Bad JSON"}), 200

        data = json.loads(m.group(0))
        return jsonify(data), 200

    except Exception as e:
        print("AI Extract Error:", e)
        return jsonify({"url": None, "reason": "AI error"}), 200

# =======================================================
# HEURISTIC SCORING
# =======================================================
def heuristic_score(url):
    score = 0
    signals = []

    p = urlparse(url)
    host = (p.hostname or "").lower()

    ext = tldextract.extract(host)
    domain = ".".join(filter(None, [ext.domain, ext.suffix]))
    full_host = ".".join(filter(None, [ext.subdomain, ext.domain, ext.suffix]))

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
        score += 1
        signals.append("uncommon_tld")

    if host in SHORTENERS:
        score += 1
        signals.append("url_shortener")

    return score, signals, domain

# =======================================================
# GSB
# =======================================================
def gsb_lookup(url):
    if not GSB_API_KEY:
        return None
    try:
        payload = {
            "client": {"clientId": "cyber-helper", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        r = requests.post(
            f"{GSB_URL}?key={GSB_API_KEY}",
            json=payload,
            timeout=4
        )
        d = r.json()
        return "malicious" if d.get("matches") else "clean"

    except:
        return "error"

# =======================================================
# AI URL RISK REVIEW
# =======================================================
def ai_url_review(url, text):
    if not client:
        return None, None

    try:
        prompt = (
            f"Evaluate this URL for safety:\n{url}\n\n"
            "Text around it:\n" + (text or "") + "\n\n"
            "Return STRICT JSON {\"risk\":\"SAFE|CAUTION|DANGER\",\"reason\":\"why\"}"
        )

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "JSON only."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=150,
            temperature=0.2,
        )

        raw = completion.choices[0].message.content
        m = re.search(r"\{.*\}", raw, flags=re.S)
        if not m: return None, None

        d = json.loads(m.group(0))
        mapping = {"SAFE":"safe","CAUTION":"caution","DANGER":"danger"}
        return mapping.get(d.get("risk")), d.get("reason")

    except:
        return None, None

# =======================================================
# DECISION
# =======================================================
def decide(score, rep, ai_risk, ai_reason):
    if rep == "malicious":
        return "danger", "Reported malicious by Google Safe Browsing."

    if ai_risk in {"danger","caution"}:
        return ai_risk, ai_reason or "Extra checks suggest caution."

    if score >= 3:
        return "caution", "Unusual patterns detected."

    return "safe", "No major problems seen."

# =======================================================
# CHECK URL ENDPOINT
# =======================================================
@app.post("/check_url")
def check_url():
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or body.get("url") or "").strip()

    url_raw = extract_first_url(text)
    if not url_raw:
        return jsonify({
            "risk": "caution",
            "rationale": "No link found.",
            "tips": ["Try typing the link manually.", "Or upload the screenshot again."]
        })

    url = normalize_url(url_raw)

    score, signals, domain = heuristic_score(url)

    rep = gsb_lookup(url)

    ai_risk, ai_reason = (None,None)
    if rep != "malicious":
        ai_risk, ai_reason = ai_url_review(url, text)

    risk, rationale = decide(score, rep, ai_risk, ai_reason)

    tips = {
        "safe": ["Open only if expected.","Never enter passwords unless sure."],
        "caution": ["Double-check sender.","Do not log in unless certain."],
        "danger": ["Do NOT open this link.","Delete the message immediately."],
    }

    return jsonify({
        "risk": risk,
        "rationale": rationale,
        "tips": tips[risk],
        "evidence": {
            "url": url,
            "score": score,
            "signals": signals,
            "ai_risk": ai_risk,
            "rep": rep
        }
    })

# =======================================================
# SIMPLE AI ANSWER
# =======================================================
@app.post("/ai_answer")
def ai_answer():
    data = request.get_json(silent=True) or {}
    msg = (data.get("message") or "").strip()

    if not msg:
        return jsonify({"reply":"Please type your question again."})

    if not client:
        return jsonify({"reply":"AI service unavailable."})

    try:
        comp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role":"system","content":"Simple language, step-by-step, for seniors."},
                {"role":"user","content":msg},
            ],
            max_tokens=350,
            temperature=0.4,
        )
        return jsonify({"reply": comp.choices[0].message.content})

    except:
        return jsonify({"reply":"Something went wrong. Try again."})

# =======================================================
@app.get("/health")
def health():
    return {"ok":True}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)