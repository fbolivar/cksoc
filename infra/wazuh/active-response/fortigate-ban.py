#!/usr/bin/env python3
# HexWatch active-response: banea/des-banea una IP atacante en el FortiGate (FW-GVM)
# via API de cuarentena. location=server (corre en el manager).
import sys, json, ipaddress, time, ssl, urllib.request

FGT_BASE = "https://192.168.2.1:12443/api/v2/monitor/user/banned"
KEYFILE  = "/var/ossec/etc/fortigate.key"
LOG      = "/var/ossec/logs/active-responses.log"
BAN_SECONDS = 600  # auto-desbaneo en el Forti a los 10 min

WHITELIST = [ipaddress.ip_network(x) for x in
             ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]]

def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write("%s fortigate-ban: %s\n" % (time.strftime("%Y/%m/%d %H:%M:%S"), msg))
    except Exception:
        pass

def api(path, payload=None):
    key = open(KEYFILE).read().strip()
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(FGT_BASE + path, data=data,
                                 method=("POST" if payload is not None else "GET"))
    req.add_header("Authorization", "Bearer " + key)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=12, context=ctx) as r:
        return r.status, r.read().decode()

def whitelisted(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(a in n for n in WHITELIST)

def ban(ip):
    if whitelisted(ip):
        log("omitido (whitelist/invalida): %s" % ip); return
    try:
        st, body = api("/add_users", {"ip_addresses": [ip], "expiry": BAN_SECONDS})
        log("BAN %s -> HTTP %s %s" % (ip, st, body[:140]))
    except Exception as e:
        log("ERROR ban %s: %s" % (ip, e))

def unban(ip):
    if whitelisted(ip):
        return
    try:
        st, body = api("/clear_users", {"ip_addresses": [ip]})
        log("UNBAN %s -> HTTP %s %s" % (ip, st, body[:140]))
    except Exception as e:
        log("ERROR unban %s: %s" % (ip, e))

def extract_ip(alert):
    for path in [("data", "srcip"), ("data", "src_ip"), ("srcip",)]:
        d = alert; ok = True
        for k in path:
            if isinstance(d, dict) and k in d: d = d[k]
            else: ok = False; break
        if ok and isinstance(d, str) and d:
            return d
    return None

def main():
    if len(sys.argv) >= 3 and sys.argv[1] in ("--test-add", "--test-del"):
        (ban if sys.argv[1] == "--test-add" else unban)(sys.argv[2]); return
    raw = sys.stdin.read()
    try:
        msg = json.loads(raw)
    except Exception as e:
        log("stdin no-JSON: %s" % e); return
    command = msg.get("command")
    alert = msg.get("parameters", {}).get("alert", {})
    ip = extract_ip(alert)
    if not ip:
        log("sin srcip (rule %s)" % alert.get("rule", {}).get("id")); return
    if command == "add":
        ban(ip)
    elif command == "delete":
        unban(ip)
    else:
        log("comando desconocido: %s" % command)

if __name__ == "__main__":
    main()
