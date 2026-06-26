#!/usr/bin/env python3
"""
SOC PNNC - Watchdog externo ("el vigilante del vigilante").

Seguro de ULTIMO RECURSO, totalmente INDEPENDIENTE de la app y de Wazuh.
Pensado para correr por cron en una maquina que vigila a OTRA (vigilancia cruzada):
  - En el servidor Wazuh (.5): vigila la app  ->  http://192.168.50.4/health
  - En el servidor de la app (.4): vigila Wazuh ->  https://192.168.50.5:55000  y  :9200

Cada ejecucion hace un chequeo HTTP a cada objetivo. Si un objetivo NO responde
(o responde con un codigo de error), envia un correo de alerta DIRECTO por SMTP,
sin pasar por la aplicacion. Mantiene un archivo de estado para no repetir el aviso
mientras el fallo persista, y avisa tambien la recuperacion.

Solo usa la libreria estandar de Python 3 (urllib, smtplib). Sin dependencias.

Config: archivo KEY=VALUE (por defecto /etc/soc-watchdog/watchdog.conf). Ver
watchdog.conf.example. El archivo de config guarda la clave SMTP -> chmod 600.
"""
import os
import ssl
import sys
import json
import time
import smtplib
import urllib.request
from email.message import EmailMessage
from urllib.error import HTTPError, URLError

DEFAULT_CONF = "/etc/soc-watchdog/watchdog.conf"
DEFAULT_EXPECT = {200, 301, 302, 401, 403}  # "responde" = liveness OK


def load_conf(path):
    conf = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            conf[k.strip()] = v.strip()
    return conf


def parse_targets(raw):
    """TARGETS = nombre|url|codigos ; nombre|url ; ...   (codigos opcionales, coma-sep)"""
    targets = []
    for item in raw.split(";"):
        item = item.strip()
        if not item:
            continue
        parts = [p.strip() for p in item.split("|")]
        name, url = parts[0], parts[1]
        expect = {int(c) for c in parts[2].split(",")} if len(parts) > 2 and parts[2] else set(DEFAULT_EXPECT)
        targets.append({"name": name, "url": url, "expect": expect})
    return targets


def check(url, expect, timeout=8, retries=2, pause=5):
    """Devuelve (ok, detalle). Reintenta para evitar falsos positivos por blips."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # certificados internos self-signed
    last = ""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "SOC-Watchdog/1.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                code = r.status
                if code in expect:
                    return True, f"HTTP {code}"
                last = f"HTTP {code} (inesperado)"
        except HTTPError as e:
            if e.code in expect:
                return True, f"HTTP {e.code}"
            last = f"HTTP {e.code}"
        except URLError as e:
            last = f"sin respuesta: {e.reason}"
        except Exception as e:  # noqa: BLE001
            last = f"error: {e}"
        if attempt < retries:
            time.sleep(pause)
    return False, last


def send_email(conf, subject, body):
    msg = EmailMessage()
    msg["From"] = conf.get("SMTP_FROM", conf.get("SMTP_USER", ""))
    msg["To"] = conf["ALERT_TO"]
    msg["Subject"] = subject
    msg.set_content(body)
    host = conf.get("SMTP_HOST", "smtp.gmail.com")
    port = int(conf.get("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=20) as s:
        s.starttls(context=ssl.create_default_context())
        if conf.get("SMTP_USER"):
            s.login(conf["SMTP_USER"], conf["SMTP_PASS"])
        s.send_message(msg)


def load_state(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


def save_state(path, state):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f)


def main():
    conf_path = os.environ.get("WATCHDOG_CONF", DEFAULT_CONF)
    if len(sys.argv) > 1:
        conf_path = sys.argv[1]
    if not os.path.exists(conf_path):
        print(f"Config no encontrada: {conf_path}", file=sys.stderr)
        sys.exit(2)

    conf = load_conf(conf_path)
    origen = conf.get("WATCHDOG_NAME", os.uname().nodename)
    state_path = conf.get("STATE_FILE", "/var/lib/soc-watchdog/state.json")
    targets = parse_targets(conf.get("TARGETS", ""))
    state = load_state(state_path)
    ts = time.strftime("%Y-%m-%d %H:%M:%S %Z")

    for t in targets:
        ok, detalle = check(t["url"], t["expect"])
        prev = state.get(t["name"], "up")  # se asume sano la primera vez
        now = "up" if ok else "down"

        if now != prev:
            if now == "down":
                send_email(
                    conf,
                    f"[SOC PNNC] WATCHDOG: {t['name']} NO RESPONDE",
                    f"El watchdog externo en '{origen}' detecto un fallo.\n\n"
                    f"Objetivo : {t['name']}\nURL      : {t['url']}\n"
                    f"Resultado: {detalle}\nHora     : {ts}\n\n"
                    f"Este aviso NO depende de la aplicacion SOC. Revisar el servicio cuanto antes.",
                )
                print(f"[ALERTA] {t['name']} DOWN ({detalle})")
            else:
                send_email(
                    conf,
                    f"[SOC PNNC] WATCHDOG: {t['name']} recuperado",
                    f"El objetivo '{t['name']}' ({t['url']}) volvio a responder ({detalle}).\n"
                    f"Detectado por el watchdog en '{origen}' a las {ts}.",
                )
                print(f"[OK] {t['name']} recuperado")
            state[t["name"]] = now
        else:
            print(f"[{now.upper()}] {t['name']} ({detalle})")

    save_state(state_path, state)


if __name__ == "__main__":
    main()
