#!/usr/bin/env python3
"""HexWatch -> SonicWall: bloqueo/desbloqueo SEGURO de IPs.
Uso:  block_ip.py block <ip> [motivo] | unblock <ip> | list

Diseño seguro (2026-09-24):
- Solo toca su propio grupo 'HexWatch-Blocked-IPs' (endpoint POR-GRUPO) y objetos HXW-Block-*.
- DIFIERE la accion si hay configuracion pendiente de otro admin (evita pisar el trabajo del
  administrador por preempcion de config-mode). Nunca usa la coleccion /address-groups/ipv4.
"""
import sys, os, json, urllib.request, urllib.error, ssl, base64

_raw = os.environ.get("SONICWALL_API_URL", "https://192.168.20.1/api/sonicos").rstrip("/")
BASE = _raw if _raw.endswith("/api/sonicos") else _raw + "/api/sonicos"
USER = os.environ.get("SONICWALL_USER", "admin")
PASS = os.environ.get("SONICWALL_PASS", "R3dN3tw0rk2026")
GROUP = "HexWatch-Blocked-IPs"
CTX = ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE
_cookie = None

def call(method, path, body=None, auth=False):
    global _cookie
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode())
    if _cookie:
        req.add_header("Cookie", _cookie)
    try:
        r = urllib.request.urlopen(req, context=CTX, timeout=20)
        sc = r.headers.get("Set-Cookie")
        if sc: _cookie = sc.split(";")[0]
        raw = r.read().decode()
        return r.status, (json.loads(raw) if raw.strip().startswith(("{","[")) else raw)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def login(): call("POST", "/auth", auth=True)
def cfg():   call("POST", "/config-mode")
def commit(): return call("POST", "/config/pending")

def pending_dirty():
    """True si hay cambios de configuracion pendientes (de otro admin) sin confirmar."""
    st, d = call("GET", "/config/pending")
    return isinstance(d, (dict, list)) and bool(d)

def get_group_members():
    st, d = call("GET", "/address-groups/ipv4/name/" + GROUP)
    try:
        return [m["name"] for m in d["address_groups"][0]["ipv4"].get("address_object", {}).get("ipv4", [])]
    except Exception:
        return []

def set_group(names):
    payload = {"address_groups":[{"ipv4":{"name":GROUP,"address_object":{"ipv4":[{"name":n} for n in sorted(set(names))]}}}]}
    return call("PUT", "/address-groups/ipv4/name/" + GROUP, payload)

def block(ip, reason=""):
    login()
    if pending_dirty():
        print(json.dumps({"action":"block","ip":ip,"ok":False,"deferred":True,"reason":"config pendiente de otro admin; bloqueo diferido para no pisar cambios"})); return
    cfg()
    name = f"HXW-Block-{ip}"
    call("POST", "/address-objects/ipv4", {"address_objects":[{"ipv4":{"name":name,"zone":"WAN","host":{"ip":ip},"comment":reason[:120]}}]})
    members = get_group_members(); members.append(name)
    set_group(members)
    st, r = commit()
    print(json.dumps({"action":"block","ip":ip,"ok":isinstance(r,dict) and r.get("status",{}).get("success",False),"detail":r}))

def unblock(ip):
    login()
    if pending_dirty():
        print(json.dumps({"action":"unblock","ip":ip,"ok":False,"deferred":True,"reason":"config pendiente de otro admin; desbloqueo diferido"})); return
    cfg()
    name = f"HXW-Block-{ip}"
    members = [m for m in get_group_members() if m != name]
    if not members: members = ["HexWatch-Block-Seed"]
    set_group(members)
    call("DELETE", "/address-objects/ipv4", {"address_objects":[{"ipv4":{"name":name}}]})
    st, r = commit()
    print(json.dumps({"action":"unblock","ip":ip,"ok":isinstance(r,dict) and r.get("status",{}).get("success",False),"detail":r}))

def lst():
    login()
    print(json.dumps({"blocked": [m for m in get_group_members() if m != "HexWatch-Block-Seed"]}))

if __name__ == "__main__":
    if len(sys.argv) < 2: print(__doc__); sys.exit(1)
    a = sys.argv[1]
    if a == "block" and len(sys.argv) >= 3: block(sys.argv[2], sys.argv[3] if len(sys.argv)>3 else "")
    elif a == "unblock" and len(sys.argv) >= 3: unblock(sys.argv[2])
    elif a == "list": lst()
    else: print(__doc__); sys.exit(1)
