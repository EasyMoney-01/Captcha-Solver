import os
import time
import threading
import httpx
import base64
import logging
from flask import Flask, request, jsonify
from functools import wraps

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

API_KEY = os.environ.get("API_KEY", "")
RENDER_URL = os.environ.get("RENDER_URL", "")

_last_ping = {"time": time.time()}

def keep_alive():
    while True:
        time.sleep(600)
        if RENDER_URL:
            try:
                httpx.get(f"{RENDER_URL}/health", timeout=10)
                _last_ping["time"] = time.time()
                log.info("Keep-alive ping sent")
            except Exception as e:
                log.warning(f"Keep-alive ping failed: {e}")

threading.Thread(target=keep_alive, daemon=True).start()


def require_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_KEY:
            return f(*args, **kwargs)
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def _2captcha_submit(api_key, payload):
    r = httpx.post("http://2captcha.com/in.php", data={**payload, "key": api_key, "json": 1}, timeout=30)
    data = r.json()
    if data.get("status") != 1:
        return None, f"2captcha submit error: {data.get('request')}"
    return data["request"], None

def _2captcha_result(api_key, task_id, timeout=180):
    elapsed = 0
    while elapsed < timeout:
        time.sleep(5)
        elapsed += 5
        try:
            res = httpx.get(f"http://2captcha.com/res.php?key={api_key}&action=get&id={task_id}&json=1", timeout=15)
            d = res.json()
        except Exception:
            continue
        if d.get("status") == 1:
            return d["request"], None
        req = d.get("request", "")
        if req not in ("CAPCHA_NOT_READY", "CAPTCHA_NOT_READY"):
            return None, f"2captcha error: {req}"
    return None, "Timeout"

def solve_2captcha(api_key, site_key, page_url, captcha_type, invisible, min_score, timeout):
    if captcha_type == "recaptchav2":
        payload = {"method": "userrecaptcha", "googlekey": site_key, "pageurl": page_url, "invisible": 1 if invisible else 0}
    elif captcha_type == "recaptchav3":
        payload = {"method": "userrecaptcha", "googlekey": site_key, "pageurl": page_url, "version": "v3", "action": "verify", "min_score": min_score or 0.3}
    elif captcha_type == "hcaptcha":
        payload = {"method": "hcaptcha", "sitekey": site_key, "pageurl": page_url}
    elif captcha_type == "turnstile":
        payload = {"method": "turnstile", "sitekey": site_key, "pageurl": page_url}
    elif captcha_type == "funcaptcha":
        payload = {"method": "funcaptcha", "publickey": site_key, "pageurl": page_url}
    elif captcha_type == "geetest":
        payload = {"method": "geetest", "gt": site_key, "pageurl": page_url}
    elif captcha_type == "image":
        payload = {"method": "base64", "body": site_key}
    else:
        return None, f"Unsupported type: {captcha_type}"
    task_id, err = _2captcha_submit(api_key, payload)
    if err:
        return None, err
    return _2captcha_result(api_key, task_id, timeout)


def _ac_submit(api_key, task, base_url):
    r = httpx.post(f"{base_url}/createTask", json={"clientKey": api_key, "task": task}, timeout=30)
    d = r.json()
    if d.get("errorId") != 0:
        return None, f"Submit error: {d.get('errorDescription')}"
    return d["taskId"], None

def _ac_result(api_key, task_id, base_url, timeout=180):
    elapsed = 0
    while elapsed < timeout:
        time.sleep(5)
        elapsed += 5
        try:
            res = httpx.post(f"{base_url}/getTaskResult", json={"clientKey": api_key, "taskId": task_id}, timeout=15)
            d = res.json()
        except Exception:
            continue
        if d.get("status") == "ready":
            sol = d.get("solution", {})
            return sol.get("gRecaptchaResponse") or sol.get("token") or sol.get("text") or str(sol), None
        if d.get("errorId", 0) != 0:
            return None, f"Error: {d.get('errorDescription')}"
    return None, "Timeout"

def solve_anticaptcha(api_key, site_key, page_url, captcha_type, invisible, min_score, timeout):
    base = "https://api.anti-captcha.com"
    if captcha_type == "recaptchav2":
        task = {"type": "NoCaptchaTaskProxyless", "websiteURL": page_url, "websiteKey": site_key, "isInvisible": invisible}
    elif captcha_type == "recaptchav3":
        task = {"type": "RecaptchaV3TaskProxyless", "websiteURL": page_url, "websiteKey": site_key, "minScore": min_score or 0.3, "pageAction": "verify"}
    elif captcha_type == "hcaptcha":
        task = {"type": "HCaptchaTaskProxyless", "websiteURL": page_url, "websiteKey": site_key}
    elif captcha_type == "turnstile":
        task = {"type": "TurnstileTaskProxyless", "websiteURL": page_url, "websiteKey": site_key}
    elif captcha_type == "funcaptcha":
        task = {"type": "FunCaptchaTaskProxyless", "websiteURL": page_url, "websitePublicKey": site_key}
    elif captcha_type == "geetest":
        task = {"type": "GeeTestTaskProxyless", "websiteURL": page_url, "gt": site_key}
    elif captcha_type == "image":
        task = {"type": "ImageToTextTask", "body": site_key}
    else:
        return None, f"Unsupported type: {captcha_type}"
    task_id, err = _ac_submit(api_key, task, base)
    if err:
        return None, err
    return _ac_result(api_key, task_id, base, timeout)

def solve_capmonster(api_key, site_key, page_url, captcha_type, invisible, min_score, timeout):
    base = "https://api.capmonster.cloud"
    if captcha_type == "recaptchav2":
        task = {"type": "NoCaptchaTaskProxyless", "websiteURL": page_url, "websiteKey": site_key, "isInvisible": invisible}
    elif captcha_type == "recaptchav3":
        task = {"type": "RecaptchaV3TaskProxyless", "websiteURL": page_url, "websiteKey": site_key, "minScore": min_score or 0.3, "pageAction": "verify"}
    elif captcha_type == "hcaptcha":
        task = {"type": "HCaptchaTaskProxyless", "websiteURL": page_url, "websiteKey": site_key}
    elif captcha_type == "turnstile":
        task = {"type": "TurnstileTaskProxyless", "websiteURL": page_url, "websiteKey": site_key}
    elif captcha_type == "funcaptcha":
        task = {"type": "FunCaptchaTaskProxyless", "websiteURL": page_url, "websitePublicKey": site_key}
    elif captcha_type == "image":
        task = {"type": "ImageToTextTask", "body": site_key}
    else:
        return None, f"Unsupported type: {captcha_type}"
    task_id, err = _ac_submit(api_key, task, base)
    if err:
        return None, err
    return _ac_result(api_key, task_id, base, timeout)

def solve_capsolver(api_key, site_key, page_url, captcha_type, invisible, min_score, timeout):
    base = "https://api.capsolver.com"
    if captcha_type == "recaptchav2":
        task = {"type": "ReCaptchaV2TaskProxyless", "websiteURL": page_url, "websiteKey": site_key, "isInvisible": invisible}
    elif captcha_type == "recaptchav3":
        task = {"type": "ReCaptchaV3TaskProxyless", "websiteURL": page_url, "websiteKey": site_key, "minScore": min_score or 0.3, "pageAction": "verify"}
    elif captcha_type == "hcaptcha":
        task = {"type": "HCaptchaTaskProxyless", "websiteURL": page_url, "websiteKey": site_key}
    elif captcha_type == "turnstile":
        task = {"type": "AntiTurnstileTaskProxyless", "websiteURL": page_url, "websiteKey": site_key}
    elif captcha_type == "funcaptcha":
        task = {"type": "FunCaptchaTaskProxyless", "websiteURL": page_url, "websitePublicKey": site_key}
    elif captcha_type == "image":
        task = {"type": "ImageToTextTask", "body": site_key}
    else:
        return None, f"Unsupported type: {captcha_type}"
    task_id, err = _ac_submit(api_key, task, base)
    if err:
        return None, err
    return _ac_result(api_key, task_id, base, timeout)


SOLVERS = {
    "2captcha": solve_2captcha,
    "anticaptcha": solve_anticaptcha,
    "capmonster": solve_capmonster,
    "capsolver": solve_capsolver,
}

CAPTCHA_TYPES = ["recaptchav2", "recaptchav3", "hcaptcha", "turnstile", "funcaptcha", "geetest", "image"]


def solve_with_fallback(services, site_key, page_url, captcha_type, invisible, min_score, timeout):
    last_err = "No service provided"
    for svc in services:
        name = svc.get("service", "").lower()
        key = svc.get("service_key", "")
        if name not in SOLVERS or not key:
            continue
        log.info(f"Trying service: {name}")
        token, err = SOLVERS[name](key, site_key, page_url, captcha_type, invisible, min_score, timeout)
        if token:
            return token, name, None
        log.warning(f"{name} failed: {err}")
        last_err = err
    return None, None, last_err


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status": "online",
        "service": "Captcha Solver API",
        "uptime_seconds": round(time.time() - _last_ping["time"]),
        "supported_types": CAPTCHA_TYPES,
        "supported_services": list(SOLVERS.keys()),
        "endpoints": {
            "POST /solve": "Solve captcha (single or fallback chain)",
            "GET /balance": "Check balance",
            "GET /health": "Health check"
        },
        "examples": {
            "single_service": {
                "service": "2captcha",
                "service_key": "YOUR_KEY",
                "site_key": "SITE_KEY",
                "page_url": "https://example.com",
                "type": "recaptchav2"
            },
            "fallback_chain": {
                "services": [
                    {"service": "capsolver", "service_key": "KEY1"},
                    {"service": "2captcha", "service_key": "KEY2"},
                    {"service": "anticaptcha", "service_key": "KEY3"}
                ],
                "site_key": "SITE_KEY",
                "page_url": "https://example.com",
                "type": "recaptchav2"
            }
        }
    })


@app.route("/solve", methods=["POST"])
@require_key
def solve():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"success": False, "error": "Invalid JSON body"}), 400

    site_key = data.get("site_key", "")
    page_url = data.get("page_url", "")
    captcha_type = data.get("type", "recaptchav2").lower()
    invisible = bool(data.get("invisible", False))
    min_score = data.get("min_score", None)
    timeout = int(data.get("timeout", 180))

    if not site_key:
        return jsonify({"success": False, "error": "site_key is required"}), 400
    if not page_url:
        return jsonify({"success": False, "error": "page_url is required"}), 400
    if captcha_type not in CAPTCHA_TYPES:
        return jsonify({"success": False, "error": f"type must be one of: {CAPTCHA_TYPES}"}), 400

    services_list = data.get("services")
    if services_list:
        if not isinstance(services_list, list):
            return jsonify({"success": False, "error": "services must be a list"}), 400
    else:
        service = data.get("service", "").lower()
        service_key = data.get("service_key", "")
        if not service:
            return jsonify({"success": False, "error": "service or services list is required"}), 400
        if not service_key:
            return jsonify({"success": False, "error": "service_key is required"}), 400
        services_list = [{"service": service, "service_key": service_key}]

    start = time.time()
    token, used_service, err = solve_with_fallback(services_list, site_key, page_url, captcha_type, invisible, min_score, timeout)
    elapsed = round(time.time() - start, 2)

    if err:
        return jsonify({"success": False, "error": err, "time": elapsed}), 500

    return jsonify({"success": True, "token": token, "service_used": used_service, "type": captcha_type, "time": elapsed})


@app.route("/balance", methods=["GET", "POST"])
@require_key
def balance():
    data = request.get_json(force=True, silent=True) or {}
    service = (data.get("service") or request.args.get("service", "2captcha")).lower()
    service_key = data.get("service_key") or request.args.get("service_key", "")

    if not service_key:
        return jsonify({"error": "service_key is required"}), 400

    try:
        if service == "2captcha":
            r = httpx.get(f"http://2captcha.com/res.php?key={service_key}&action=getbalance&json=1", timeout=15)
            d = r.json()
            return jsonify({"service": "2captcha", "balance": d.get("request", "unknown")})
        elif service in ("anticaptcha", "capmonster", "capsolver"):
            url_map = {
                "anticaptcha": "https://api.anti-captcha.com/getBalance",
                "capmonster": "https://api.capmonster.cloud/getBalance",
                "capsolver": "https://api.capsolver.com/getBalance",
            }
            r = httpx.post(url_map[service], json={"clientKey": service_key}, timeout=15)
            d = r.json()
            if d.get("errorId") == 0:
                return jsonify({"service": service, "balance": d.get("balance")})
            return jsonify({"service": service, "error": d.get("errorDescription")}), 400
        else:
            return jsonify({"error": f"Unknown service. Supported: {list(SOLVERS.keys())}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": time.time()})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
