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
from openai import OpenAI

app = Flask(__name__)

# -------------------------------------------------------------------
# KEYS
# -------------------------------------------------------------------
GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

print("GSB KEY:", bool(GSB_API_KEY))
print("OPENAI KEY:", bool(OPENAI_API_KEY))

client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


# -------------------------------------------------------------------
# URL REGEX
# -------------------------------------------------------------------
URL_RE = re.compile(
    r'(https?://[^\s<>"\)]+|www\.[^\s<>"\)]+|[a-z0-9.-]+\.[a-z]{2,})',
    re.I
)


# -------------------------------------------------------------------
# NORMALISE URL
# -------------------------------------------------------------------
def normalize_url(raw):
    if not raw:
        return None

    raw = raw.strip()

    if not raw.startswith("http"):
        raw = "http://" + raw

    p = urlparse(raw)
    host = p.hostname or ""

    try:
        host_ascii = idna.encode(host).decode()
    except:
        host_ascii = host

    query = re.sub(r"(utm_[^=&]+|fbclid|gclid)=[^&]+&?", "", p.query).strip("&")
    path = p.path or "/"
    port = f":{p.port}" if p.port else ""

    url = f"{p.scheme}://{host_ascii}{port}{path}"
    if query:
        url += f"?{query}"

    return url


# -------------------------------------------------------------------
# BASIC URL EXTRACT
# -------------------------------------------------------------------
def extract_first_url(text):
    if not text:
        return None

    text = unescape(text)
    text = text.replace("\u2060", "").replace("\u200b", "")

    m = URL_RE.search(text)
    return m.group(0) if m else None


# -------------------------------------------------------------------
# AI EXTRACT URL
# -------------------------------------------------------------------
def ai_extract_url(text):
    if not client:
        return None

    try:
        prompt = f"""
You will extract the REAL clickable URL from this screenshot text.
If user pasted broken text like "hxxp", "dot", "www . example . com", fix it.
Return ONLY JSON:
{{
  "url": "<the url or null>",
  "reason": "<short reason>"
}}

Here is the OCR text:

{text}
        """

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Return ONLY JSON."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=120,
            temperature=0.1
        )

        raw = completion.choices[0].message.content or ""
        m = re.search(r"\{.*\}", raw, flags=re.S)
        if not m:
            return None

        data = json.loads(m.group(0))
        url = data.get("url")
        reason = data.get("reason", "")

        return url, reason

    except Exception as e:
        print("AI EXTRACT ERROR:", e)
        return None


# -------------------------------------------------------------------
# GOOGLE SAFE BROWSING CHECK
# -------------------------------------------------------------------
def gsb_lookup(url):
    if not GSB_API_KEY:
        return None

    body = {
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
        r = requests.post(
            f"{GSB_URL}?key={GSB_API_KEY}",
            json=body,
            timeout=5
        )
        data = r.json()
        return "malicious" if data.get("matches") else "clean"

    except Exception as e:
        print("GSB ERROR:", e)
        return "error"


# -------------------------------------------------------------------
# URL CHECK ENDPOINT
# -------------------------------------------------------------------
@app.post("/check_url")
def check_url():
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()

    url_raw = extract_first_url(text)
    if not url_raw:
        return jsonify({
            "risk": "caution",
            "rationale": "I couldn’t find any link.",
            "tips": ["Check again", "Try to type the link manually"]
        })

    url = normalize_url(url_raw)

    rep = gsb_lookup(url)

    if rep == "malicious":
        return jsonify({
            "risk": "danger",
            "rationale": "Google reports this link as dangerous.",
            "tips": ["Do NOT click", "Delete message immediately"]
        })

    return jsonify({
        "risk": "safe",
        "rationale": "No problems found.",
        "tips": ["Open only if expected", "Never enter passwords unless sure"]
    })


# -------------------------------------------------------------------
# AI GENERAL ANSWER
# -------------------------------------------------------------------
@app.post("/ai_answer")
def ai_answer():
    body = request.get_json(silent=True) or {}
    msg = (body.get("message") or "").strip()

    if not msg:
        return jsonify({"reply": "Please type something."})

    if not client:
        return jsonify({"reply": "AI service offline. Try later."})

    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system",
                 "content": "Use very simple English. Short sentences."},
                {"role": "user", "content": msg}
            ],
            max_tokens=200,
            temperature=0.3
        )

        reply = completion.choices[0].message.content
        return jsonify({"reply": reply})

    except Exception as e:
        print("AI ERROR:", e)
        return jsonify({"reply": "Something went wrong. Try again."})


# -------------------------------------------------------------------
# AI SCREENSHOT URL EXTRACT ENDPOINT
# -------------------------------------------------------------------
@app.post("/ai_extract_url")
def ai_extract_url_endpoint():
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()

    result = ai_extract_url(text)

    if not result:
        return jsonify({"url": None, "reason": "AI could not read any URL"})

    url, reason = result

    return jsonify({"url": url, "reason": reason})


# -------------------------------------------------------------------
@app.get("/health")
def health():
    return {"ok": True}


# -------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)