#!/usr/bin/env python3
"""Loopback-only classroom portal with predefined fictional accounts."""

import argparse
from datetime import datetime, timezone
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import threading
from urllib.parse import parse_qs


ROOT = Path(__file__).resolve().parents[1]
DEMO_ACCOUNTS = {
    "participante-01": "DEMO-01",
    "participante-02": "DEMO-02",
    "participante-03": "DEMO-03",
}
MAX_BODY = 2048


class DemoJournal:
    """Store only allowlisted synthetic values; never arbitrary form input."""

    def __init__(self, directory):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / ("simulacion_" + secrets.token_hex(12) + ".txt")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        self.stream = os.fdopen(os.open(self.path, flags, 0o600), "w", encoding="utf-8")
        self.lock = threading.Lock()
        self.stream.write("SIMULACION EDUCATIVA - SOLO DATOS FICTICIOS\n")
        self.stream.flush()

    def record(self, account, demo_key):
        if not isinstance(account, str) or DEMO_ACCOUNTS.get(account) != demo_key:
            raise ValueError("Only predefined demo accounts are accepted")
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.lock:
            if self.stream.closed:
                raise OSError("Demo journal is closed")
            self.stream.write(f"{timestamp}\t{account}\t{DEMO_ACCOUNTS[account]}\n")
            self.stream.flush()
            os.fsync(self.stream.fileno())

    def close(self):
        with self.lock:
            self.stream.close()


def page(nonce, complete=False):
    accounts = ''.join(f'<option value="{name}">{name}</option>' for name in DEMO_ACCOUNTS)
    keys = ''.join(f'<option value="{key}">{key}</option>' for key in DEMO_ACCOUNTS.values())
    form = f"""
      <form action="/submit" method="post">
        <input type="hidden" name="nonce" value="{html.escape(nonce, quote=True)}">
        <label for="account">Alias ficticio</label>
        <select id="account" name="account" required>{accounts}</select>
        <label for="demo_key">Clave ficticia de la misma cuenta</label>
        <select id="demo_key" name="demo_key" required>{keys}</select>
        <label class="consent"><input type="checkbox" name="consent" value="yes" required>
          Entiendo que estoy participando en una simulación educativa.</label>
        <button type="submit">Registrar participación de prueba</button>
      </form>"""
    if complete:
        form = """<div class="success" role="status">Participación de prueba registrada.</div>
        <p>El TXT contiene únicamente el alias y la clave ficticios seleccionados.</p>
        <a href="/">Volver a la simulación</a>"""
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pocket Interceptor · Laboratorio</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#101827;color:#ecf2ff;font:16px/1.6 system-ui,sans-serif;
min-height:100vh;display:grid;place-items:center;padding:24px}}main{{width:100%;max-width:540px;
padding:32px;border:1px solid #35445e;border-radius:18px;background:#192438}}
.badge{{display:inline-block;color:#87ead1;font-size:12px;letter-spacing:.12em;font-weight:700}}
h1{{font-size:28px;line-height:1.2;margin:14px 0}}p{{color:#becbe1}}label{{display:block;margin:18px 0 6px}}
select,button{{width:100%;font:inherit;padding:12px;border-radius:8px}}select{{background:#101827;
color:#fff;border:1px solid #637590}}button{{background:#87ead1;color:#10251f;border:0;
font-weight:700;cursor:pointer;margin-top:18px}}.consent{{display:flex;align-items:flex-start;
gap:10px;font-size:14px}}.consent input{{margin-top:6px}}.success{{padding:14px;background:#143e35;
border:1px solid #87ead1;border-radius:8px}}a{{color:#87ead1}}footer{{margin-top:24px;
font-size:12px;color:#a7b5ca}}:focus-visible{{outline:3px solid #87ead1;outline-offset:3px}}
</style></head><body><main>
<span class="badge">SIMULACIÓN EDUCATIVA · LOCAL</span>
<h1>Portal de laboratorio</h1>
<p>Esta página demuestra cómo un formulario puede registrar datos. Utiliza solo
las cuentas de prueba disponibles. No introduzcas información personal.</p>
{form}<footer>Pocket Interceptor · No proporciona acceso a Internet ni cambia tu conexión.</footer>
</main></body></html>""".encode("utf-8")


def make_handler(journal, nonce):
    class DemoHandler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *args):
            # Do not retain arbitrary request paths, headers, IPs or user agents.
            pass

        def reply(self, status, body=b"", content_type="text/plain; charset=utf-8", location=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            if location:
                self.send_header("Location", location)
            self.end_headers()
            self.wfile.write(body)

        def valid_host(self):
            expected = f"127.0.0.1:{self.server.server_port}"
            return self.headers.get_all("Host", []) == [expected]

        def do_GET(self):
            if not self.valid_host():
                self.reply(400, b"Host no permitido.")
            elif self.path in ("/", "/done"):
                self.reply(200, page(nonce, complete=self.path == "/done"), "text/html; charset=utf-8")
            elif self.path == "/health":
                self.reply(200, json.dumps({"status": "ok", "mode": "simulation"}).encode(), "application/json")
            else:
                self.reply(404, b"Ruta no encontrada.")

        def do_POST(self):
            if not self.valid_host():
                self.reply(400, b"Host no permitido.")
                return
            if self.path != "/submit":
                self.reply(404, b"Ruta no encontrada.")
                return
            origin = f"http://127.0.0.1:{self.server.server_port}"
            if self.headers.get_all("Origin", []) != [origin]:
                self.reply(403, b"Origen no permitido.")
                return
            if self.headers.get("Transfer-Encoding") or self.headers.get_all("Content-Length") is None:
                self.reply(400, b"Longitud requerida.")
                return
            if self.headers.get_content_type() != "application/x-www-form-urlencoded":
                self.reply(415, b"Formato no permitido.")
                return
            try:
                lengths = self.headers.get_all("Content-Length")
                if len(lengths) != 1:
                    raise ValueError
                length = int(lengths[0])
                if not 0 < length <= MAX_BODY:
                    self.reply(413, b"Formulario demasiado grande o vacio.")
                    return
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError
                fields = parse_qs(raw.decode("utf-8"), keep_blank_values=True,
                                  strict_parsing=True, max_num_fields=4)
                expected = {"account", "demo_key", "consent", "nonce"}
                if set(fields) != expected or any(len(values) != 1 for values in fields.values()):
                    raise ValueError
                values = {name: data[0] for name, data in fields.items()}
                if not secrets.compare_digest(values["nonce"].encode("utf-8"), nonce.encode("utf-8")):
                    self.reply(403, b"Formulario de otra sesion.")
                    return
                if values["consent"] != "yes":
                    raise ValueError
                journal.record(values["account"], values["demo_key"])
            except (ValueError, UnicodeError):
                self.reply(400, "Solo se aceptan las cuentas ficticias predefinidas y el consentimiento.".encode())
                return
            except OSError:
                self.reply(503, b"No se pudo guardar la participacion de prueba.")
                return
            self.reply(303, location="/done")

    return DemoHandler


def create_server(journal, port=8765, nonce=None):
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(journal, nonce or secrets.token_hex(32)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765, help="Local port (default: 8765; 0 selects an available port)")
    args = parser.parse_args(argv)
    if args.port != 0 and not 1024 <= args.port <= 65535:
        parser.error("El puerto debe estar entre 1024 y 65535, o ser 0.")
    journal = None
    server = None
    try:
        journal = DemoJournal(ROOT / "data_collected" / "lab_portal")
        server = create_server(journal, args.port)
        print("\nPortal educativo: únicamente cuentas ficticias.", flush=True)
        print(f"Abre http://127.0.0.1:{server.server_port}/ en el navegador de Kali.", flush=True)
        print(f"TXT de esta sesión: {journal.path}", flush=True)
        print("Ctrl+C para detener el servidor. No se modifica la red.\n", flush=True)
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\nPortal de laboratorio detenido. El TXT se conserva.")
    except OSError:
        print("[ERROR] No se pudo iniciar el portal o preparar su TXT. Comprueba permisos y puerto; prueba --port 0.")
        return 1
    finally:
        if server:
            server.server_close()
        if journal:
            journal.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
