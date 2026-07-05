"""
Yeelight bulb control - single file with xiaomi QR login

SETUP (one time)
  python -m pip install flask python-miio requests pycryptodome qrcode pillow pywebview

RUN
  python bulb_control.py
  then open http://localhost:5000

LOGIN
  click "QR login" - scan the qr with your Mi Home app on your phone - approve
  every bulb with its token is fetched and you tap yours to save it
  or use the Manual tab to type ip and token directly

This PC must be on the same wifi as the bulb to actually control it
"""

from flask import Flask, request, jsonify
from miio import Yeelight
import os
import json
import base64
import hashlib
import hmac
import random
import time
import io

try:
    from Crypto.Cipher import ARC4
except ModuleNotFoundError:
    from Cryptodome.Cipher import ARC4

import requests
import qrcode

import sys

# Check if the app is running as a compiled EXE
if getattr(sys, 'frozen', False):
    HERE = os.path.dirname(sys.executable)
else:
    # Otherwise, it is running as a normal Python script
    HERE = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(HERE, "bulb_config.json")

app = Flask(__name__)

SERVERS = ["cn", "de", "us", "ru", "tw", "sg", "in", "i2"]

# holds the active qr login session between requests
QR_STATE = {"connector": None, "status": "idle", "devices": []}


def load_config():
    cfg = None
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                cfg = json.load(f)
        except Exception:
            cfg = None
    if not cfg:
        return {"devices": [], "selected": []}
    # migrate old single-bulb format
    if "ip" in cfg and "devices" not in cfg:
        if cfg.get("ip") and cfg.get("token"):
            return {"devices": [{"name": "My bulb", "ip": cfg["ip"], "token": cfg["token"]}], "selected": [0]}
        return {"devices": [], "selected": []}
    # migrate single active format to multi select
    if "active" in cfg and "selected" not in cfg:
        cfg["selected"] = [cfg["active"]] if cfg.get("active", -1) >= 0 else []
        cfg.pop("active", None)
    cfg.setdefault("devices", [])
    cfg.setdefault("selected", [])
    cfg["selected"] = [i for i in cfg["selected"] if 0 <= i < len(cfg["devices"])]
    return cfg


def save_full_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f)


# cache Yeelight objects per ip so we do not rebuild them every command
_BULB_CACHE = {}
_LAST_CMD_TS = 0.0


def _bulb_for(ip, token):
    b = _BULB_CACHE.get(ip)
    if b is None:
        # short timeout so a bad packet fails fast then retries instead of hanging
        try:
            b = Yeelight(ip, token)
        except TypeError:
            b = Yeelight(ip, token)
        # tune the underlying miio protocol if the attributes exist
        try:
            b._protocol._timeout = 0.5 # Changed from 2 to 0.5 seconds
        except Exception:
            pass
        try:
            b.retry_count = 1 # Changed from 3 to 1 retry
        except Exception:
            pass
        _BULB_CACHE[ip] = b
    return b

def get_bulbs():
    cfg = load_config()
    if not cfg["selected"]:
        raise RuntimeError("no bulb selected - add and select at least one")
    return [_bulb_for(cfg["devices"][i]["ip"], cfg["devices"][i]["token"]) for i in cfg["selected"]]


def for_all_bulbs(fn):
    # build the bulb list once then fire the command at each - no rebuild
    import time as _t
    global _LAST_CMD_TS
    _LAST_CMD_TS = _t.time()
    bulbs = get_bulbs()
    errs = []
    for b in bulbs:
        try:
            fn(b)
        except Exception as e:
            errs.append(str(e))
    if errs and len(errs) == len(bulbs):
        raise RuntimeError("; ".join(errs))
    return errs


# ---------- xiaomi cloud connector (qr flow) ----------

class XiaomiQR:
    def __init__(self):
        self._agent = self._gen_agent()
        self._device_id = "".join(chr(random.randint(97, 122)) for _ in range(6))
        self._session = requests.session()
        self._ssecurity = None
        self.userId = None
        self._serviceToken = None
        self._location = None
        self.qr_image_url = None
        self.login_url = None
        self.long_polling_url = None
        self.timeout = 120

    @staticmethod
    def _gen_agent():
        agent_id = "".join(chr(random.randint(65, 69)) for _ in range(13))
        rnd = "".join(chr(random.randint(97, 122)) for _ in range(18))
        return f"{rnd}-{agent_id} APP/com.xiaomi.mihome APPV/10.5.201"

    @staticmethod
    def _to_json(text):
        return json.loads(text.replace("&&&START&&&", ""))

    def get_login_url(self):
        url = "https://account.xiaomi.com/longPolling/loginUrl"
        data = {
            "_qrsize": "480",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "callback": "https://sts.api.io.mi.com/sts",
            "_hasLogo": "false",
            "sid": "xiaomiio",
            "serviceParam": "",
            "_locale": "en_GB",
            "_dc": str(int(time.time() * 1000)),
        }
        r = self._session.get(url, params=data, timeout=10)
        if r.status_code == 200:
            d = self._to_json(r.text)
            if "qr" in d:
                self.qr_image_url = d["qr"]
                self.login_url = d["loginUrl"]
                self.long_polling_url = d["lp"]
                self.timeout = d.get("timeout", 120)
                return True
        return False

    def poll_once(self):
        # one long poll attempt - returns "waiting" "done" or "error"
        try:
            r = self._session.get(self.long_polling_url, timeout=15)
        except requests.exceptions.Timeout:
            return "waiting"
        except requests.exceptions.RequestException:
            return "error"
        if r.status_code != 200:
            return "waiting"
        d = self._to_json(r.text)
        if "ssecurity" not in d:
            return "waiting"
        self.userId = d["userId"]
        self._ssecurity = d["ssecurity"]
        self._location = d["location"]
        # fetch service token
        rr = self._session.get(self._location, headers={"content-type": "application/x-www-form-urlencoded"}, timeout=10)
        if rr.status_code != 200:
            return "error"
        self._serviceToken = rr.cookies.get("serviceToken")
        return "done"

    # ---- encrypted api calls ----

    @staticmethod
    def _api_url(country):
        return "https://" + ("" if country == "cn" else (country + ".")) + "api.io.mi.com/app"

    def _signed_nonce(self, nonce):
        h = hashlib.sha256(base64.b64decode(self._ssecurity) + base64.b64decode(nonce))
        return base64.b64encode(h.digest()).decode()

    @staticmethod
    def _gen_nonce(millis):
        nb = os.urandom(8) + (int(millis / 60000)).to_bytes(4, byteorder="big")
        return base64.b64encode(nb).decode()

    @staticmethod
    def _enc_signature(url, method, signed_nonce, params):
        sp = [str(method).upper(), url.split("com")[1].replace("/app/", "/")]
        for k, v in params.items():
            sp.append(f"{k}={v}")
        sp.append(signed_nonce)
        return base64.b64encode(hashlib.sha1("&".join(sp).encode("utf-8")).digest()).decode()

    @staticmethod
    def _enc_rc4(password, payload):
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return base64.b64encode(r.encrypt(payload.encode())).decode()

    @staticmethod
    def _dec_rc4(password, payload):
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return r.encrypt(base64.b64decode(payload))

    def _enc_params(self, url, method, signed_nonce, nonce, params):
        params["rc4_hash__"] = self._enc_signature(url, method, signed_nonce, params)
        for k, v in params.items():
            params[k] = self._enc_rc4(signed_nonce, v)
        params.update({
            "signature": self._enc_signature(url, method, signed_nonce, params),
            "ssecurity": self._ssecurity,
            "_nonce": nonce,
        })
        return params

    def _api_call(self, url, params):
        headers = {
            "Accept-Encoding": "identity",
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
        }
        cookies = {
            "userId": str(self.userId),
            "yetAnotherServiceToken": str(self._serviceToken),
            "serviceToken": str(self._serviceToken),
            "locale": "en_GB",
            "timezone": "GMT+02:00",
            "is_daylight": "1",
            "dst_offset": "3600000",
            "channel": "MI_APP_STORE",
        }
        millis = round(time.time() * 1000)
        nonce = self._gen_nonce(millis)
        signed = self._signed_nonce(nonce)
        fields = self._enc_params(url, "POST", signed, nonce, dict(params))
        r = self._session.post(url, headers=headers, cookies=cookies, params=fields, timeout=10)
        if r.status_code == 200:
            dec = self._dec_rc4(self._signed_nonce(fields["_nonce"]), r.text)
            return json.loads(dec)
        return None

    def get_homes(self, country):
        url = self._api_url(country) + "/v2/homeroom/gethome"
        params = {"data": '{"fg": true, "fetch_share": true, "fetch_share_dev": true, "limit": 300, "app_ver": 7}'}
        return self._api_call(url, params)

    def get_dev_cnt(self, country):
        url = self._api_url(country) + "/v2/user/get_device_cnt"
        params = {"data": '{ "fetch_own": true, "fetch_share": true}'}
        return self._api_call(url, params)

    def get_devices(self, country, home_id, owner_id):
        url = self._api_url(country) + "/v2/home/home_device_list"
        params = {"data": '{"home_owner": ' + str(owner_id) + ',"home_id": ' + str(home_id) +
                  ', "limit": 200, "get_split_device": true, "support_smart_home": true}'}
        return self._api_call(url, params)

    def fetch_all_devices(self):
        out = []
        for country in SERVERS:
            homes = []
            h = self.get_homes(country)
            if h and h.get("result"):
                for x in h["result"].get("homelist", []):
                    homes.append({"home_id": x["id"], "owner": self.userId})
            dc = self.get_dev_cnt(country)
            if dc and dc.get("result"):
                for x in dc["result"].get("share", {}).get("share_family", []):
                    homes.append({"home_id": x["home_id"], "owner": x["home_owner"]})
            for home in homes:
                devs = self.get_devices(country, home["home_id"], home["owner"])
                if devs and devs.get("result") and devs["result"].get("device_info"):
                    for d in devs["result"]["device_info"]:
                        out.append({
                            "name": d.get("name", ""),
                            "model": d.get("model", ""),
                            "ip": d.get("localip", ""),
                            "token": d.get("token", ""),
                        })
        # dedupe - same bulb answers from several regions
        seen = set()
        deduped = []
        for d in out:
            key = d.get("token") or (d.get("ip") + d.get("model", ""))
            if key and key not in seen:
                seen.add(key)
                deduped.append(d)
        # bulbs first
        deduped.sort(key=lambda d: ("light" not in (d.get("model") or "")))
        return deduped


# ---------- routes ----------

@app.route("/")
def index():
    return PAGE

@app.route("/hide_popup", methods=["POST"])
def hide_popup():
    global _popup_window, _popup_visible
    try:
        if _popup_window is not None:
            _popup_window.hide()
        _popup_visible = False
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

@app.route("/devices", methods=["GET"])
def devices_list():
    cfg = load_config()
    # never send tokens to the page - only a hint
    devs = [{"name": d.get("name", ""), "ip": d.get("ip", ""), "token_tail": (d.get("token", "")[-4:] if d.get("token") else "")} for d in cfg["devices"]]
    return jsonify(devices=devs, selected=cfg["selected"])


@app.route("/devices/add", methods=["POST"])
def devices_add():
    try:
        name = (request.json.get("name") or "").strip() or "Bulb"
        ip = (request.json.get("ip") or "").strip()
        token = (request.json.get("token") or "").strip()
        if not ip or not token:
            return jsonify(ok=False, error="ip and token required"), 400
        cfg = load_config()
        # replace if same token already saved
        for i, d in enumerate(cfg["devices"]):
            if d.get("token") == token:
                cfg["devices"][i] = {"name": name, "ip": ip, "token": token}
                if i not in cfg["selected"]:
                    cfg["selected"].append(i)
                save_full_config(cfg)
                return _test_and_reply(ip, token)
        cfg["devices"].append({"name": name, "ip": ip, "token": token})
        cfg["selected"].append(len(cfg["devices"]) - 1)
        save_full_config(cfg)
        return _test_and_reply(ip, token)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


def _test_and_reply(ip, token):
    try:
        Yeelight(ip, token).info()
        return jsonify(ok=True, tested=True)
    except Exception as e:
        return jsonify(ok=True, tested=False, warn=str(e))


@app.route("/devices/select", methods=["POST"])
def devices_select():
    # toggles selection - multiple bulbs can be selected at once
    try:
        idx = int(request.json.get("index", -1))
        cfg = load_config()
        if idx < 0 or idx >= len(cfg["devices"]):
            return jsonify(ok=False, error="bad index"), 400
        if idx in cfg["selected"]:
            cfg["selected"].remove(idx)
        else:
            cfg["selected"].append(idx)
        save_full_config(cfg)
        return jsonify(ok=True, selected=cfg["selected"])
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@app.route("/devices/delete", methods=["POST"])
def devices_delete():
    try:
        idx = int(request.json.get("index", -1))
        cfg = load_config()
        if idx < 0 or idx >= len(cfg["devices"]):
            return jsonify(ok=False, error="bad index"), 400
        cfg["devices"].pop(idx)
        cfg["selected"] = [i if i < idx else i - 1 for i in cfg["selected"] if i != idx]
        save_full_config(cfg)
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@app.route("/qr_start", methods=["POST"])
def qr_start():
    try:
        c = XiaomiQR()
        if not c.get_login_url():
            return jsonify(ok=False, error="could not get login url from xiaomi"), 500
        QR_STATE["connector"] = c
        QR_STATE["status"] = "waiting"
        QR_STATE["devices"] = []
        # build qr png from the login url
        img = qrcode.make(c.login_url)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode()
        return jsonify(ok=True, qr="data:image/png;base64," + b64, login_url=c.login_url)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@app.route("/qr_poll", methods=["POST"])
def qr_poll():
    c = QR_STATE.get("connector")
    if not c:
        return jsonify(ok=False, error="no active login - start again"), 400
    try:
        res = c.poll_once()
        if res == "waiting":
            return jsonify(ok=True, status="waiting")
        if res == "error":
            return jsonify(ok=False, error="login polling failed"), 500
        # login approved - client will call /qr_fetch next while showing a spinner
        QR_STATE["status"] = "logged_in"
        return jsonify(ok=True, status="logged_in")
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@app.route("/qr_fetch", methods=["POST"])
def qr_fetch():
    c = QR_STATE.get("connector")
    if not c:
        return jsonify(ok=False, error="no active login - start again"), 400
    try:
        devices = c.fetch_all_devices()
        QR_STATE["devices"] = devices
        QR_STATE["status"] = "done"
        return jsonify(ok=True, devices=devices)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@app.route("/popup")
def popup():
    return POPUP_PAGE


@app.route("/hsv", methods=["POST"])
def hsv():
    # set hue+saturation as rgb and brightness together in one shot
    try:
        r = int(request.json.get("r", 255)); g = int(request.json.get("g", 255)); b = int(request.json.get("b", 255))
        bright = request.json.get("bright", None)
        def apply(bulb):
            bulb.set_rgb((r, g, b))
            if bright is not None:
                bv = max(1, min(100, int(bright)))
                bulb.set_brightness(bv)
        for_all_bulbs(apply)
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@app.route("/discover", methods=["POST"])
def discover():
    try:
        import socket
        found = []
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(4)
        hello = bytes.fromhex("21310020" + "ff" * 28)
        s.sendto(hello, ("255.255.255.255", 54321))
        seen = set()
        while True:
            try:
                data, addr = s.recvfrom(1024)
                ip = addr[0]
                if ip not in seen:
                    seen.add(ip)
                    found.append({"ip": ip, "id": data[8:12].hex() if len(data) >= 12 else ""})
            except socket.timeout:
                break
        s.close()
        return jsonify(ok=True, bulbs=found)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@app.route("/on", methods=["POST"])
def on():
    try:
        for_all_bulbs(lambda b: b.on()); return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@app.route("/off", methods=["POST"])
def off():
    try:
        for_all_bulbs(lambda b: b.off()); return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@app.route("/brightness", methods=["POST"])
def brightness():
    try:
        val = max(1, min(100, int(request.json.get("value", 100))))
        for_all_bulbs(lambda b: b.set_brightness(val)); return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@app.route("/color", methods=["POST"])
def color():
    try:
        r = int(request.json.get("r", 255)); g = int(request.json.get("g", 255)); b = int(request.json.get("b", 255))
        for_all_bulbs(lambda bb: bb.set_rgb((r, g, b))); return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@app.route("/temp", methods=["POST"])
def temp():
    try:
        val = max(1700, min(6500, int(request.json.get("value", 4000))))
        for_all_bulbs(lambda b: b.set_color_temp(val)); return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


POPUP_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bulb Popup</title>
<style>
  :root { --bg:#1a1a22; --panel:#242430; --panel-hi:#2e2e3c; --text:#e8e8f0;
    --muted:#9494a8; --accent:#a06bff; --border:#33334200; }
  * { box-sizing:border-box; margin:0; padding:0; }
  html,body { background:var(--bg); color:var(--text);
    font-family:-apple-system,system-ui,"Segoe UI",sans-serif; overflow:hidden; }
  .wrap { padding:12px; }
  .head { display:flex; gap:6px; align-items:flex-start; margin-bottom:10px; }
  .lamps { display:flex; gap:6px; flex-wrap:wrap; flex:1; max-height: 56px; overflow-y: auto; }
  .lamp { font-size:11px; padding:6px 9px; border-radius:8px; background:var(--panel-hi);
    border:1px solid #33334233; cursor:pointer; white-space:nowrap; }
  .lamp.sel { background:var(--accent); border-color:var(--accent); color:#fff; }
  button.close-btn { flex:none; width:24px; height:24px; padding:0; background:transparent; border:none; color:var(--muted); font-size:16px; cursor:pointer; margin-left:auto; }
  button.close-btn:hover { color:var(--text); }
  .sq-wrap { position:relative; width:100%; aspect-ratio:1.35; border-radius:12px; overflow:hidden;
    cursor:crosshair; touch-action:none; }
  #sq { width:100%; height:100%; display:block; }
  .knob { position:absolute; width:16px; height:16px; border-radius:50%; border:2px solid #fff;
    box-shadow:0 0 0 1px rgba(0,0,0,.4); transform:translate(-50%,-50%); pointer-events:none; }
  .huebar { width:100%; height:16px; margin-top:10px; border-radius:8px; cursor:pointer; touch-action:none;
    background:linear-gradient(to right,#f00,#ff0,#0f0,#0ff,#00f,#f0f,#f00); position:relative; }
  .huehandle { position:absolute; top:-2px; width:6px; height:20px; border-radius:3px; background:#fff;
    box-shadow:0 0 2px rgba(0,0,0,.6); transform:translateX(-50%); pointer-events:none; }
  .brow { display:flex; align-items:center; gap:8px; margin-top:12px; }
  .brow span { font-size:11px; color:var(--muted); width:16px; }
  input[type=range]{ flex:1; accent-color:var(--accent); }
  .btns { display:flex; gap:6px; margin-top:12px; }
  .btns button { flex:1; font:inherit; font-size:12px; color:var(--text); background:var(--panel-hi);
    border:1px solid #33334233; border-radius:8px; padding:9px; cursor:pointer; }
  .btns button.on { background:var(--accent); border-color:var(--accent); color:#fff; }
  .hint { font-size:10px; color:var(--muted); text-align:center; margin-top:8px; }
</style>
</head>
<body>
<div class="wrap">
  <!-- This is the new drag handle at the top -->
  <div class="pywebview-drag-region" style="height: 18px; margin: -12px -12px 10px -12px; background: var(--panel-hi); cursor: grab; display: flex; align-items: center; justify-content: center; border-bottom: 1px solid #33334233;">
    <div style="width: 32px; height: 4px; background: var(--muted); border-radius: 2px;"></div>
  </div>
  
  <div class="head">
    <div class="lamps" id="lamps"></div>
    <button class="close-btn" onclick="fetch('/hide_popup', {method:'POST'})">✕</button>
  </div>
  <div class="sq-wrap" id="sqWrap">
    <canvas id="sq" width="220" height="160"></canvas>
    <div class="knob" id="knob" style="left:100%;top:0%"></div>
  </div>
  <div class="huebar" id="hue"><div class="huehandle" id="hueHandle" style="left:78%"></div></div>
  <div class="brow"><span>dim</span><input type="range" id="bright" min="1" max="100" value="100"><span id="bval">100</span></div>
  <div class="btns">
    <button class="on" onclick="power(true)">On</button>
    <button onclick="power(false)">Off</button>
  </div>
  <div class="hint">drag square down toward black to dim - or use the slider</div>
</div>
<script>
  let hue = 270, sat = 1, val = 1, bright = 100;
  const canvas = document.getElementById("sq"), ctx = canvas.getContext("2d");

  function drawSquare(){
    const w = canvas.width, h = canvas.height;
    ctx.fillStyle = "hsl("+hue+",100%,50%)";
    ctx.fillRect(0,0,w,h);
    let wg = ctx.createLinearGradient(0,0,w,0);
    wg.addColorStop(0,"rgba(255,255,255,1)"); wg.addColorStop(1,"rgba(255,255,255,0)");
    ctx.fillStyle = wg; ctx.fillRect(0,0,w,h);
    let bg = ctx.createLinearGradient(0,0,0,h);
    bg.addColorStop(0,"rgba(0,0,0,0)"); bg.addColorStop(1,"rgba(0,0,0,1)");
    ctx.fillStyle = bg; ctx.fillRect(0,0,w,h);
  }

  function hsvToRgb(h,s,v){
    let c=v*s, x=c*(1-Math.abs((h/60)%2-1)), m=v-c, r=0,g=0,b=0;
    if(h<60){r=c;g=x;} else if(h<120){r=x;g=c;} else if(h<180){g=c;b=x;}
    else if(h<240){g=x;b=c;} else if(h<300){r=x;b=c;} else {r=c;b=x;}
    return {r:Math.round((r+m)*255),g:Math.round((g+m)*255),b:Math.round((b+m)*255)};
  }

  let sendTimer=null;
  function queueSend(){
    if(sendTimer) return;
    sendTimer=setTimeout(()=>{ sendTimer=null; sendColor(); }, 250);
  }
  async function sendColor(){
    const rgb=hsvToRgb(hue,sat,1);
    try{ await fetch("/hsv",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({r:rgb.r,g:rgb.g,b:rgb.b,bright:bright})}); }catch(e){}
  }
  async function power(on){
    try{ await fetch(on?"/on":"/off",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}); }catch(e){}
  }

  function pickSquare(e){
    const r=canvas.getBoundingClientRect();
    let x=(e.clientX-r.left)/r.width, y=(e.clientY-r.top)/r.height;
    x=Math.max(0,Math.min(1,x)); y=Math.max(0,Math.min(1,y));
    sat=x;                     
    bright=Math.max(1,Math.round((1-y)*100));
    document.getElementById("bright").value=bright;
    document.getElementById("bval").textContent=bright;
    const knob=document.getElementById("knob");
    knob.style.left=(x*100)+"%"; knob.style.top=(y*100)+"%";
    queueSend();
  }

  function pickHue(e){
    const r=document.getElementById("hue").getBoundingClientRect();
    let x=(e.clientX-r.left)/r.width; x=Math.max(0,Math.min(1,x));
    hue=x*360;
    document.getElementById("hueHandle").style.left=(x*100)+"%";
    drawSquare(); queueSend();
  }

  let sqDown=false, hueDown=false;
  const sqWrap=document.getElementById("sqWrap"), hueEl=document.getElementById("hue");
  sqWrap.addEventListener("pointerdown",e=>{sqDown=true; sqWrap.setPointerCapture(e.pointerId); pickSquare(e);});
  sqWrap.addEventListener("pointermove",e=>{ if(sqDown) pickSquare(e); });
  sqWrap.addEventListener("pointerup",()=>{sqDown=false; sendColor();});
  hueEl.addEventListener("pointerdown",e=>{hueDown=true; hueEl.setPointerCapture(e.pointerId); pickHue(e);});
  hueEl.addEventListener("pointermove",e=>{ if(hueDown) pickHue(e); });
  hueEl.addEventListener("pointerup",()=>{hueDown=false; sendColor();});

  const slider=document.getElementById("bright");
  slider.addEventListener("input",()=>{ bright=+slider.value; document.getElementById("bval").textContent=bright;
    const knob=document.getElementById("knob"); knob.style.top=((1-bright/100)*100)+"%"; queueSend(); });

  async function loadLamps(){
    try{
      const data=await(await fetch("/devices")).json();
      const box=document.getElementById("lamps"); box.innerHTML="";
      data.devices.forEach((d,i)=>{
        const el=document.createElement("div");
        el.className="lamp"+(data.selected.includes(i)?" sel":"");
        el.textContent=d.name||d.ip;
        el.onclick=async()=>{ await fetch("/devices/select",{method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify({index:i})}); loadLamps(); };
        box.appendChild(el);
      });
    }catch(e){}
  }

  let hideTimer;
  function resetHideTimer() {
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => {
      fetch('/hide_popup', {method:'POST'}).catch(e=>{});
    }, 5000);
  }

  document.addEventListener('pointermove', resetHideTimer);
  document.addEventListener('pointerdown', resetHideTimer);
  resetHideTimer();

  drawSquare(); 
  loadLamps();
</script>
</body>
</html>"""


PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bulb Control</title>
<style>
  :root { --bg:#14141a; --panel:#1e1e28; --panel-hi:#262633; --text:#e8e8f0;
    --muted:#9494a8; --accent:#a06bff; --accent-hi:#b585ff; --border:#2e2e3c; --radius:14px; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:-apple-system,system-ui,"Segoe UI",sans-serif;
    display:flex; justify-content:center; min-height:100vh; padding:24px; }
  .app { width:100%; max-width:420px; }
  h1 { font-size:15px; font-weight:600; letter-spacing:.04em; text-transform:uppercase; color:var(--muted); margin-bottom:18px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); padding:18px; margin-bottom:14px; }
  .row { display:flex; gap:10px; }
  button { font:inherit; color:var(--text); background:var(--panel-hi); border:1px solid var(--border); border-radius:10px;
    padding:13px 16px; cursor:pointer; flex:1; transition:background .15s,border-color .15s,transform .05s; }
  button:hover { background:#2f2f40; border-color:#3a3a4c; }
  button:active { transform:scale(.97); }
  button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
  button.primary:hover { background:var(--accent-hi); }
  .label { font-size:12px; color:var(--muted); margin-bottom:10px; display:block; }
  input[type="text"] { width:100%; font:inherit; color:var(--text); background:var(--panel-hi);
    border:1px solid var(--border); border-radius:10px; padding:12px 14px; margin-bottom:10px; }
  input[type="range"] { width:100%; accent-color:var(--accent); height:6px; }
  input[type="color"] { width:100%; height:52px; border:1px solid var(--border); border-radius:10px; background:var(--panel-hi); cursor:pointer; }
  .presets { display:grid; grid-template-columns:repeat(6,1fr); gap:8px; }
  .swatch { aspect-ratio:1; border-radius:8px; border:1px solid var(--border); cursor:pointer; transition:transform .05s; }
  .swatch:active { transform:scale(.9); }
  .status { font-size:12px; color:var(--muted); text-align:center; min-height:18px; margin-top:4px; transition:color .2s; }
  .status.err { color:#ff6b6b; } .status.ok { color:#6bd88f; }
  .config-toggle { background:none; border:none; color:var(--muted); font-size:12px; cursor:pointer; padding:4px; flex:none; }
  .config-toggle:hover { color:var(--text); background:none; }
  .config-body { margin-top:12px; display:none; } .config-body.open { display:block; }
  .found-list { margin-top:8px; }
  .found-item { padding:10px 12px; background:var(--panel-hi); border:1px solid var(--border); border-radius:8px;
    margin-bottom:6px; cursor:pointer; font-size:13px; }
  .found-item:hover { border-color:var(--accent); }
  .head-row { display:flex; justify-content:space-between; align-items:center; }
  .tabs { display:flex; gap:8px; margin-bottom:12px; }
  .tab { padding:8px 12px; font-size:12px; border-radius:8px; background:var(--panel-hi); border:1px solid var(--border); cursor:pointer; text-align:center; flex:1; }
  .tab.active { background:var(--accent); border-color:var(--accent); color:#fff; }
  .pane { display:none; } .pane.active { display:block; }
  .hint { font-size:11px; color:var(--muted); margin-bottom:10px; line-height:1.5; }
  .qrbox { text-align:center; }
  .spinner { width:34px; height:34px; margin:16px auto; border:3px solid var(--border);
    border-top-color:var(--accent); border-radius:50%; animation:spin .8s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .qrbox img { width:220px; height:220px; border-radius:12px; background:#fff; padding:8px; }
</style>
</head>
<body>
<div class="app">
  <h1>Bulb Control</h1>

  <div class="card">
    <div class="head-row">
      <span class="label" style="margin:0">Bulb setup</span>
      <button class="config-toggle" onclick="toggleConfig()">edit</button>
    </div>
    <div class="config-body" id="configBody">
      <div class="tabs">
        <div class="tab active" id="tabQr" onclick="showPane('qr')">QR login</div>
        <div class="tab" id="tabManual" onclick="showPane('manual')">Manual</div>
      </div>

      <div class="pane active" id="paneQr">
        <div class="hint">tap start - scan the qr with your Mi Home app on your phone - approve the login - your bulbs appear with tokens</div>
        <button class="primary" onclick="qrStart()">Start QR login</button>
        <div class="qrbox" id="qrBox" style="margin-top:12px"></div>
        <div class="found-list" id="qrList"></div>
      </div>

      <div class="pane" id="paneManual">
        <input type="text" id="nameField" placeholder="name - example bedroom">
        <input type="text" id="ipField" placeholder="bulb ip - example 192.168.100.6">
        <input type="text" id="tokenField" placeholder="token - 32 characters">
        <div class="row">
          <button class="primary" onclick="saveConfig()">Save</button>
          <button onclick="scan()">Scan network</button>
        </div>
        <div class="found-list" id="foundList"></div>
      </div>
    </div>
  </div>

  <div class="card">
    <span class="label">Saved bulbs</span>
    <div class="found-list" id="savedList"></div>
  </div>

  <div class="card">
    <div class="row">
      <button class="primary" onclick="call('/on')">On</button>
      <button onclick="call('/off')">Off</button>
    </div>
  </div>
  <div class="card">
    <span class="label">Brightness</span>
    <input type="range" min="1" max="100" value="80" id="bright"
           oninput="briteLabel.textContent=this.value+'%'" onchange="call('/brightness',{value:+this.value})">
    <div class="status" id="briteLabel">80%</div>
  </div>
  <div class="card">
    <span class="label">Color</span>
    <input type="color" id="picker" value="#a06bff" onchange="sendColor(this.value)">
  </div>
  <div class="card">
    <span class="label">Presets</span>
    <div class="presets" id="presets"></div>
  </div>
  <div class="card">
    <span class="label">Warm to cool white</span>
    <input type="range" min="1700" max="6500" value="4000" id="temp" onchange="call('/temp',{value:+this.value})">
  </div>
  <div class="status" id="status"></div>
</div>
<script>
  const status = document.getElementById("status");
  let polling = false;

  async function call(path, body) {
    setStatus("...","");
    try {
      const res = await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body||{})});
      const data = await res.json();
      if (data.ok) setStatus("done","ok"); else setStatus("error - "+(data.error||"unknown"),"err");
    } catch(e){ setStatus("server unreachable - is the app running","err"); }
  }
  function setStatus(msg,cls){ status.textContent=msg; status.className="status "+cls; if(cls==="ok") setTimeout(()=>{status.textContent="";},1400); }
  function toggleConfig(){ document.getElementById("configBody").classList.toggle("open"); }
  function showPane(which){
    document.getElementById("tabQr").classList.toggle("active", which==="qr");
    document.getElementById("tabManual").classList.toggle("active", which==="manual");
    document.getElementById("paneQr").classList.toggle("active", which==="qr");
    document.getElementById("paneManual").classList.toggle("active", which==="manual");
  }
  async function loadDevices(){
    try {
      const data = await (await fetch("/devices")).json();
      const list = document.getElementById("savedList"); list.innerHTML="";
      if (!data.devices.length){
        list.innerHTML = '<div class="hint">no bulbs saved yet - use QR login or Manual below - tap saved bulbs to select or deselect - commands hit every selected bulb</div>';
        document.getElementById("configBody").classList.add("open");
        return;
      }
      data.devices.forEach((d,i)=>{
        const sel = data.selected.includes(i);
        const el=document.createElement("div"); el.className="found-item";
        el.style.display="flex"; el.style.justifyContent="space-between"; el.style.alignItems="center";
        if (sel) el.style.borderColor="var(--accent)";
        const label=document.createElement("span");
        label.textContent=(sel?"● ":"○ ")+(d.name||"bulb")+"   "+d.ip;
        label.style.flex="1"; label.style.cursor="pointer";
        label.onclick=async ()=>{
          await fetch("/devices/select",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({index:i})});
          setStatus(sel?"deselected "+(d.name||d.ip):"selected "+(d.name||d.ip),"ok");
          loadDevices();
        };
        const del=document.createElement("span");
        del.textContent="✕"; del.style.cursor="pointer"; del.style.color="var(--muted)"; del.style.padding="0 4px";
        del.onclick=async (ev)=>{
          ev.stopPropagation();
          await fetch("/devices/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({index:i})});
          setStatus("deleted","ok");
          loadDevices();
        };
        el.appendChild(label); el.appendChild(del);
        list.appendChild(el);
      });
    } catch(e){}
  }
  async function qrStart(){
    setStatus("getting qr from xiaomi...","");
    document.getElementById("qrList").innerHTML="";
    document.getElementById("qrBox").innerHTML="";
    try {
      const data = await (await fetch("/qr_start",{method:"POST"})).json();
      if (!data.ok){ setStatus("qr start failed - "+data.error,"err"); return; }
      document.getElementById("qrBox").innerHTML = '<img src="'+data.qr+'"><div class="hint" style="margin-top:8px">scan with Mi Home app then approve</div>';
      setStatus("waiting for you to scan...","");
      polling = true;
      pollLoop();
    } catch(e){ setStatus("server unreachable","err"); }
  }
  async function pollLoop(){
    if (!polling) return;
    try {
      const data = await (await fetch("/qr_poll",{method:"POST"})).json();
      if (!data.ok){ setStatus("login failed - "+data.error,"err"); polling=false; return; }
      if (data.status==="waiting"){ setTimeout(pollLoop, 500); return; }
      if (data.status==="logged_in"){
        polling=false;
        document.getElementById("qrBox").innerHTML='<div class="spinner"></div><div class="hint">logged in - scanning for your devices...</div>';
        setStatus("scanning your xiaomi account...","");
        const fr = await (await fetch("/qr_fetch",{method:"POST"})).json();
        document.getElementById("qrBox").innerHTML="";
        if (!fr.ok){ setStatus("device fetch failed - "+fr.error,"err"); return; }
        showDevices(fr.devices);
      }
    } catch(e){ setTimeout(pollLoop, 1000); }
  }
  function showDevices(devices){
    const list = document.getElementById("qrList"); list.innerHTML="";
    if (!devices.length){ setStatus("logged in but no devices found","err"); return; }
    setStatus("found "+devices.length+" devices - tap your bulb","ok");
    devices.forEach(d=>{
      const el=document.createElement("div"); el.className="found-item";
      el.textContent=(d.name||d.model||"device")+"   "+(d.ip||"no ip");
      el.onclick=async ()=>{
        if(!d.ip||!d.token){ setStatus("this device has no local ip or token","err"); return; }
        const rd=await (await fetch("/devices/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:d.name||d.model||"Bulb",ip:d.ip,token:d.token})})).json();
        if(rd.ok&&rd.tested) setStatus("added "+(d.name||d.ip)+" - bulb responded","ok");
        else if(rd.ok) setStatus("added but bulb did not answer - check wifi","err");
        else setStatus("error - "+(rd.error||"unknown"),"err");
        loadDevices();
      };
      list.appendChild(el);
    });
  }
  async function saveConfig(){
    const name=document.getElementById("nameField").value.trim();
    const ip=document.getElementById("ipField").value.trim();
    const token=document.getElementById("tokenField").value.trim();
    if(!ip||!token){ setStatus("fill both ip and token","err"); return; }
    setStatus("saving...","");
    try {
      const data=await (await fetch("/devices/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name,ip,token})})).json();
      if(data.ok&&data.tested) setStatus("added and bulb responded","ok");
      else if(data.ok) setStatus("added but bulb did not answer - check wifi","err");
      else setStatus("error - "+(data.error||"unknown"),"err");
      loadDevices();
    } catch(e){ setStatus("server unreachable","err"); }
  }
  async function scan(){
    setStatus("scanning...","");
    const list=document.getElementById("foundList"); list.innerHTML="";
    try {
      const data=await (await fetch("/discover",{method:"POST"})).json();
      if(!data.ok){ setStatus("scan error - "+data.error,"err"); return; }
      if(!data.bulbs.length){ setStatus("no bulbs found - check wifi","err"); return; }
      setStatus("found "+data.bulbs.length+" - tap one to use its ip","ok");
      data.bulbs.forEach(b=>{
        const d=document.createElement("div"); d.className="found-item";
        d.textContent=b.ip+(b.id?"   id "+b.id:"");
        d.onclick=()=>{ document.getElementById("ipField").value=b.ip; setStatus("ip filled - now paste its token and save",""); };
        list.appendChild(d);
      });
    } catch(e){ setStatus("server unreachable","err"); }
  }
  function hexToRgb(hex){ const n=parseInt(hex.slice(1),16); return {r:(n>>16)&255,g:(n>>8)&255,b:n&255}; }
  function sendColor(hex){ call("/color",hexToRgb(hex)); }
  const presetColors=["#ff3b30","#ff9500","#ffcc00","#34c759","#00c7be","#30b0ff","#007aff","#5856d6","#af52de","#ff2d92","#ffffff","#ff6b9d"];
  const presetsEl=document.getElementById("presets");
  presetColors.forEach(c=>{ const d=document.createElement("div"); d.className="swatch"; d.style.background=c;
    d.onclick=()=>{ document.getElementById("picker").value=c; sendColor(c); }; presetsEl.appendChild(d); });
  loadDevices();
</script>
</body>
</html>"""


def _keepalive_loop():
    # quietly poke every selected bulb every 25s so their wifi radios never sleep
    import socket
    import time as _t
    hello = bytes.fromhex("21310020" + "ff" * 28)
    while True:
        try:
            # only keep the radios awake while a UI window is open - when both the
            # setup and popup windows are hidden there is nothing to control, so we
            # skip the ping instead of hammering the bulbs in the background
            if not (_setup_visible or _popup_visible):
                _t.sleep(12)
                continue
            cfg = load_config()
            for i in cfg["selected"]:
                ip = cfg["devices"][i].get("ip")
                if not ip:
                    continue
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                try:
                    s.sendto(hello, (ip, 54321))
                    s.recvfrom(1024)
                except Exception:
                    pass
                finally:
                    s.close()
        except Exception:
            pass
        _t.sleep(12)


def _run_server():
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


# ---------- tray ----------

TRAY_COLORS = [
    ("Red", (255, 59, 48)),
    ("Orange", (255, 149, 0)),
    ("Yellow", (255, 204, 0)),
    ("Green", (52, 199, 89)),
    ("Cyan", (0, 199, 190)),
    ("Blue", (0, 122, 255)),
    ("Purple", (160, 107, 255)),
    ("Pink", (255, 45, 146)),
    ("White", (255, 255, 255)),
]

_window = None
# tracks whether either UI window is currently shown - the keepalive ping only
# runs while at least one is visible so we don't hammer the bulbs in the background
_setup_visible = False
_popup_visible = False


def _tray_do(fn):
    # run a bulb command off the tray thread so the menu never freezes
    import threading
    threading.Thread(target=lambda: _safe(fn), daemon=True).start()


def _safe(fn):
    try:
        for_all_bulbs(fn)
    except Exception:
        pass


def _toggle_device(index):
    def handler(icon, item):
        cfg = load_config()
        if index in cfg["selected"]:
            cfg["selected"].remove(index)
        else:
            cfg["selected"].append(index)
        save_full_config(cfg)
    return handler


def _is_selected(index):
    def check(item):
        return index in load_config()["selected"]
    return check


def _show_window(icon=None, item=None):
    global _window, _setup_visible
    try:
        if _window is not None:
            _window.show()
            _window.restore()
            _setup_visible = True
    except Exception:
        pass


def _make_tray_image():
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse([12, 6, 52, 46], fill=(160, 107, 255, 255))
    d.rectangle([26, 44, 38, 56], fill=(148, 148, 168, 255))
    return img


def _build_menu():
    import pystray

    def device_items():
        cfg = load_config()
        items = []
        for i, d in enumerate(cfg["devices"]):
            items.append(pystray.MenuItem(
                d.get("name") or d.get("ip") or f"bulb {i+1}",
                _toggle_device(i),
                checked=_is_selected(i),
            ))
        if not items:
            items.append(pystray.MenuItem("no bulbs saved - open panel", _show_window, enabled=True))
        return items

    color_items = [
        pystray.MenuItem(name, (lambda rgb: (lambda icon, item: _tray_do(lambda b: b.set_rgb(rgb))))(rgb))
        for name, rgb in TRAY_COLORS
    ]

    bright_items = [
        pystray.MenuItem(f"{v}%", (lambda vv: (lambda icon, item: _tray_do(lambda b: b.set_brightness(vv))))(v))
        for v in (100, 75, 50, 25, 10)
    ]

    return pystray.Menu(
        pystray.MenuItem("Open panel", _show_window, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Lamps", pystray.Menu(lambda: device_items())),
        pystray.MenuItem("Color", pystray.Menu(*color_items)),
        pystray.MenuItem("Brightness", pystray.Menu(*bright_items)),
        pystray.MenuItem("On", lambda icon, item: _tray_do(lambda b: b.on())),
        pystray.MenuItem("Off", lambda icon, item: _tray_do(lambda b: b.off())),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit", lambda icon, item: _quit(icon)),
    )


def _quit(icon):
    try:
        icon.stop()
    except Exception:
        pass
    os._exit(0)


_popup_window = None


def _show_popup(icon=None, item=None):
    global _popup_window, _popup_visible
    try:
        if _popup_window is not None:
            try:
                # Move window to bottom-right corner
                screens = webview.screens
                if screens:
                    s = screens[0]
                    # x = screen width - popup width (260) - 20px padding
                    x = s.width - 260 - 20
                    # y = screen height - popup height (460) - taskbar padding
                    y = s.height - 460 - 150
                    _popup_window.move(x, y)
            except Exception:
                pass
            _popup_window.show()
            _popup_visible = True
    except Exception:
        pass


def _show_setup(icon=None, item=None):
    global _window, _setup_visible
    try:
        if _window is not None:
            _window.show()
            _window.restore()
            _setup_visible = True
    except Exception:
        pass


if __name__ == "__main__":
    import threading

    server = threading.Thread(target=_run_server, daemon=True)
    server.start()

    keepalive = threading.Thread(target=_keepalive_loop, daemon=True)
    keepalive.start()

    tray_icon = None
    try:
        import pystray
        menu = pystray.Menu(
            pystray.MenuItem("Quick controls", _show_popup, default=True),
            pystray.MenuItem("Setup window", _show_setup),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Color", pystray.Menu(*[
                pystray.MenuItem(name, (lambda rgb: (lambda i, it: _tray_do(lambda b: b.set_rgb(rgb))))(rgb))
                for name, rgb in TRAY_COLORS
            ])),
            pystray.MenuItem("On", lambda i, it: _tray_do(lambda b: b.on())),
            pystray.MenuItem("Off", lambda i, it: _tray_do(lambda b: b.off())),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", lambda i, it: _quit(i)),
        )
        tray_icon = pystray.Icon("bulb_control", _make_tray_image(), "Bulb Control", menu=menu)
        tray_icon.run_detached()
    except Exception:
        tray_icon = None

    try:
        import webview

        _window = webview.create_window(
            "Bulb Control - Setup",
            "http://127.0.0.1:5000",
            width=470, height=760, resizable=True, min_size=(420, 600),
            hidden=True,
        )

        _popup_window = webview.create_window(
            "Bulb Control",
            "http://127.0.0.1:5000/popup",
            width=260, height=460, resizable=False,
            frameless=True, easy_drag=False, on_top=True,
            hidden=True,
        )
        def _hide_setup():
            global _setup_visible
            if tray_icon is not None:
                _window.hide(); _setup_visible = False; return False
            return True

        def _hide_popup():
            global _popup_visible
            _popup_window.hide(); _popup_visible = False; return False

        _window.events.closing += _hide_setup
        _popup_window.events.closing += _hide_popup

        webview.start()
        if tray_icon is None:
            os._exit(0)
        import time as _t
        while True:
            _t.sleep(3600)
    except Exception:
        import webbrowser, time as _t
        webbrowser.open("http://localhost:5000")
        print("Bulb control running - open http://localhost:5000")
        while True:
            _t.sleep(3600)
