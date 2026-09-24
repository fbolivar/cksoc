#!/usr/bin/env python3
"""Watchdog SOLO-LECTURA de la VPN SSL de DG&A.
Verifica que 'ksolution' conserve su acceso VPN (rutas X0/X3 y membresia al grupo
SSLVPN Services). Si detecta una regresion, avisa por Telegram (con cooldown).
NO escribe nada en el firewall — solo lee y alerta. Cron cada 10 min.
"""
import os, json, time, urllib.request, urllib.error, ssl, base64

ENV = {}
for line in open("/opt/hexwatch/backend/.env"):
    if "=" in line and not line.strip().startswith("#"):
        k, v = line.strip().split("=", 1); ENV[k] = v
BASE = ENV.get("SONICWALL_API_URL", "https://192.168.20.1").rstrip("/")
if not BASE.endswith("/api/sonicos"): BASE += "/api/sonicos"
U = ENV.get("SONICWALL_USER", "admin"); P = ENV.get("SONICWALL_PASS", "")
TG_TOKEN = ENV.get("TELEGRAM_BOT_TOKEN", ""); TG_CHAT = ENV.get("TELEGRAM_CHAT_ID", "")
VPN_USER = "ksolution"; VPN_GROUP = "SSLVPN Services"; WANT = {"X0 Subnet", "X3 Subnet"}
STATE = "/opt/hexwatch/sonicwall/.vpn_watch_state"; COOLDOWN = 1800  # 30 min entre avisos del mismo problema
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
_ck = [None]

def call(m, path, auth=False):
    req = urllib.request.Request(BASE + path, method=m)
    if auth: req.add_header("Authorization", "Basic " + base64.b64encode(f"{U}:{P}".encode()).decode())
    if _ck[0] and not auth: req.add_header("Cookie", _ck[0])
    try:
        r = urllib.request.urlopen(req, context=CTX, timeout=20); sc = r.headers.get("Set-Cookie")
        if sc: _ck[0] = sc.split(";")[0]
        raw = r.read().decode(); return r.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
    except urllib.error.HTTPError as e: return e.code, e.read().decode()
    except Exception as e: return 0, str(e)

def telegram(text):
    if not (TG_TOKEN and TG_CHAT): return
    for chat in [c.strip() for c in TG_CHAT.split(",") if c.strip()]:
        try:
            data = json.dumps({"chat_id": chat, "text": text, "disable_web_page_preview": True}).encode()
            req = urllib.request.Request(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            urllib.request.urlopen(req, timeout=15)
        except Exception: pass

def nets(obj): return {x.get("name") for x in (obj.get("vpn_client_access") or [])}

def main():
    st, _ = call("POST", "/auth", auth=True)
    problems = []
    stu, du = call("GET", "/user/local/users/name/" + VPN_USER)
    if stu != 200 or not isinstance(du, dict):
        problems.append(f"No se pudo leer el usuario {VPN_USER} (HTTP {stu}).")
    else:
        u = du["user"]["local"]["user"][0]
        mo = {m.get("name") for m in u.get("member_of", [])}
        if VPN_GROUP not in mo: problems.append(f"{VPN_USER} YA NO es miembro de '{VPN_GROUP}'.")
        if not WANT.issubset(nets(u)): problems.append(f"{VPN_USER} perdio rutas VPN (tiene {sorted(nets(u))}, faltan {sorted(WANT - nets(u))}).")
    stg, dg = call("GET", "/user/local/groups")
    if stg == 200 and isinstance(dg, dict):
        grp = next((g for g in dg.get("user", {}).get("local", {}).get("group", []) if g.get("name") == VPN_GROUP), None)
        if not grp: problems.append(f"El grupo '{VPN_GROUP}' NO existe.")
        else:
            if not any(m.get("name") == VPN_USER for m in grp.get("member", [])):
                problems.append(f"El grupo '{VPN_GROUP}' ya no lista a {VPN_USER}.")
            if not WANT.issubset(nets(grp)):
                problems.append(f"El grupo '{VPN_GROUP}' perdio rutas VPN (faltan {sorted(WANT - nets(grp))}).")
    # cooldown para no spamear
    now = int(time.time()); prev = ""
    try: prev = open(STATE).read().strip()
    except Exception: pass
    sig = "|".join(sorted(problems))
    if problems:
        last_sig, last_ts = (prev.split("@@") + ["", "0"])[:2]
        if sig != last_sig or (now - int(last_ts or 0)) > COOLDOWN:
            telegram("Soy Agentico. Aviso operativo importante para DG&A:\n\n"
                     "Detecte una regresion en el acceso VPN de la cuenta '" + VPN_USER + "':\n- " + "\n- ".join(problems) +
                     "\n\nEsto NO lo causa el bloqueo de HexWatch (su codigo no toca la VPN). Puede venir de la gestion central (GMS) o de una edicion manual. "
                     "Recomiendo revisar y restaurar en Device > Users: agregar '" + VPN_USER + "' al grupo '" + VPN_GROUP + "' y las rutas X0/X3. Quedamos atentos.")
            open(STATE, "w").write(sig + "@@" + str(now))
        print("[vpn_watch] PROBLEMA:", sig)
    else:
        open(STATE, "w").write("@@" + str(now))
        print("[vpn_watch] OK: VPN de", VPN_USER, "correcta (X0/X3 + grupo).")

if __name__ == "__main__":
    main()
