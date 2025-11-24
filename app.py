import os, re, time, requests
from flask import Flask, request, jsonify
from urllib.parse import urlparse
from html import unescape
import tldextract, idna

# === NEW OPENAI SDK ===
from openai import OpenAI

app = Flask(__name__)

# === API KEYS ===
GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

client = OpenAI(api_key=OPENAI_API_KEY)

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# === Heuristic config ===
SUSPICIOUS_TLDS = {"zip","xyz","ru","tk","top","work","click","fit","cf","gq","ml"}
SAFE_TLDS       = {"com","org","net","co","uk","edu","gov"}
SHORTENERS      = {"bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","is.gd"}

URL_RE = re.compile(
    r'(https?://[^\s<>"\)]+|[a-z0-9.-]+\.[a-z]{2,}(/[^\s<>"\)]*)?)',
    re.I
)

# ---------------------------
# UTILITIES
# ---------------------------

def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    p = urlparse(raw)
    host = p.hostname or ""

    try:
        host_ascii = idna.encode(host).decode("ascii")
    except Exception:
        host_ascii = host

    query = re.sub(r"(utm_[^=&]+|fbclid|gclid)=[^&]+&?", "", p.query)
    port = f":{p.port}" if p.port else ""
    path = p.path or "/"

    result = f"{p.scheme.lower()}://{host_ascii}{port}{path}"
    if query:
        result += f"?{query}"
    return result


def extract_first_url(text: str):
    if not text:
        return None
    text = unescape(text).replace("\u200b", "").replace("\u2060", "").strip()

    patterns = [
        r'href=["\']([^"\']+)["\']',
        r'\]\((https?://[^\s)]+)\)',
        r'<(https?://[^>\s]+)>'
    ]

    for pattern in patterns:
        m = re.search(pattern, text, flags=re.I)
        if m:
            return m.group(1).strip()

    m = URL_RE.search(text)
    return m.group(0).strip() if m else None


def heuristic_score(url: str):
    score, signals = 0.0, []
    p = urlparse(url)
    ext = tldextract.extract(p.hostname or "")
    domain = ".".join(filter(None, [ext.domain, ext.suffix]))

    if p.scheme != "https":
        score += 2; signals.append("no_https")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", (p.hostname or "")):
        score += 3; signals.append("ip_host")

    if len(url) > 120:
        score += 1; signals.append("long_url")

    if ext.subdomain and len(ext.subdomain.split(".")) >= 3:
        score += 1; signals.append("many_subdomains")

    if ext.suffix in SUSPICIOUS_TLDS:
        score += 2; signals.append("suspicious_tld")
    elif ext.suffix not in SAFE_TLDS:
        score += 0.5; signals.append("uncommon_tld")

    if any(c in p.hostname for c in "015") and any(c in p.hostname for c in "olis"):
        score += 1; signals.append("lookalike_hint")

    for brand in ["bank", "paypal", "amazon", "microsoft", "royalmail", "dhl", "hmrc", "gov"]:
        if f"/{brand}" in p.path.lower() and brand not in domain:
            score += 1.5; signals.append("brand_mismatch")
            break

    if (p.hostname or "") in SHORTENERS:
        score += 0.5; signals.append("shortener")

    return score, signals, domain


def gsb_lookup(url: str):
    if not GSB_API_KEY:
        return None

    payload = {
        "client": {"clientId": "cyber-helper", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        r = requests.post(f"{GSB_URL}?key={GSB_API_KEY}", json=payload, timeout=6)
        data = r.json()
        return "malicious" if data.get("matches") else "clean"
    except:
        return "error"


def decide(score, rep):
    if rep == "malicious":
        return "danger", "Reported unsafe by Google Safe Browsing."
    if score >= 3:
        return "caution", "This link looks unusual. Please be careful."
    return "safe", "No obvious risks detected."

# ---------------------------
# URL CHECK ROUTE
# ---------------------------

@app.post("/check_url")
def check_url():
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or body.get("url") or "").strip()
    url_raw = extract_first_url(text)

    if not url_raw:
        return jsonify({
            "risk": "caution",
            "rationale": "I couldn't find a link in this message.",
            "tips": [
                "Share the message with the chatbot.",
                "Or read the link aloud slowly."
            ]
        })

    t0 = time.time()
    url = normalize_url(url_raw)
    score, signals, domain = heuristic_score(url)
    rep = gsb_lookup(url)
    risk, rationale = decide(score, rep)

    tips_map = {
        "safe": ["Open only if expected.", "Never enter passwords unless sure."],
        "caution": ["Don't click immediately.", "Check spelling and sender carefully."],
        "danger": ["Do NOT open this link.", "Delete the message immediately."]
    }

    banner = {"safe": "✅ SAFE", "caution": "⚠️ CAUTION", "danger": "⛔ DANGER"}[risk]
    pet = {"safe": "🙂 Looks okay!", "caution": "😟 Be careful.", "danger": "😣 Very risky!"}[risk]

    return jsonify({
        "risk": risk,
        "rationale": rationale,
        "tips": tips_map[risk],
        "banner": banner,
        "pet": pet,
        "evidence": {"url": url, "score": score, "signals": signals, "rep": rep},
        "elapsed_ms": int((time.time() - t0) * 1000)
    })

# ---------------------------
# SMART AI ROUTE (FIXED)
# ---------------------------

@app.post("/ai_answer")
def ai_answer():
    try:
        data = request.get_json() or {}
        user_message = data.get("message", "").strip()

        if not user_message:
            return jsonify({"reply": "Please type your question again."})

        chat = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are Cyber Helper. Speak simply, use short sentences, "
                        "and give clear step-by-step safety instructions for seniors."
                    )
                },
                {"role": "user", "content": user_message}
            ],
            max_tokens=320,
            temperature=0.4
        )

        reply = chat.choices[0].message.content.strip()
        return jsonify({"reply": reply})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------
# HEALTH
# ---------------------------

@app.get("/health")
def health():
    return {"ok": True}

# ---------------------------
# RUN
# ---------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)