import os
from datetime import datetime, timezone
from functools import wraps
from hmac import compare_digest

from flask import Flask, Response, abort, render_template_string, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
# Render sits behind one trusted reverse proxy.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

ADMIN_PASSWORD = os.environ.get("WEBGUARD_ADMIN_PASSWORD", "")
entries = []  # Demo only: cleared whenever the server restarts.

HOME = """
<!doctype html><html lang="de"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebGuard</title>
<style>
body{background:#080d18;color:#eef4ff;font:16px Arial;padding:22px}
main{max-width:650px;margin:35px auto;background:#121c2d;border:1px solid #29405f;border-radius:16px;padding:24px}
h1{color:#55adff}.notice{background:#1c2b40;padding:14px;border-radius:10px}
p{line-height:1.5;color:#c6d3e5}label{display:flex;gap:10px;margin:20px 0}
button{background:#1686e8;color:white;border:0;border-radius:9px;padding:13px 18px}
.small{font-size:13px;color:#9aabc1}
</style><main>
<h1>🛡️ WebGuard</h1><h2>Freiwilliger Verbindungstest</h2>
<p>Wenn du den Test startest, wird die öffentliche IP-Adresse erfasst, von der aus du die Anfrage sendest.</p>
<div class="notice"><b>Erfasste Daten</b>
<p>IP-Adresse und Zeitpunkt des Tests. Keine Discord-Daten, kein genauer Standort und kein Geräte-Fingerabdruck.</p>
<p>Diese Demo speichert Einträge nur im Arbeitsspeicher. Sie werden beim Neustart gelöscht.</p></div>
<form method="post" action="/consent">
<label><input type="checkbox" name="consent" value="yes" required>
<span>Ich habe den Hinweis gelesen und willige freiwillig ein, dass WebGuard meine IP-Adresse für diesen Test erfasst.</span></label>
<button type="submit">Verbindungstest starten</button></form>
<p class="small">Du kannst die Seite schließen, ohne den Test zu starten. Ohne Häkchen wird nichts erfasst.</p>
</main>"""

RESULT = """<!doctype html><html lang="de"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{background:#080d18;color:#eef4ff;font:16px Arial;padding:24px}
main{max-width:600px;margin:45px auto;background:#121c2d;padding:24px;border-radius:16px}
h1{color:#55adff}.ok{color:#55d69e}</style>
<main><h1>🛡️ WebGuard</h1><h2 class="ok">Test abgeschlossen</h2>
<p>Deine Einwilligung wurde übermittelt und der Verbindungstest wurde durchgeführt.</p>
<p>Du kannst dieses Fenster jetzt schließen.</p></main>"""

ADMIN = """<!doctype html><html lang="de"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{background:#080d18;color:#eef4ff;font:15px Arial;padding:20px}
main{max-width:850px;margin:30px auto;background:#121c2d;padding:22px;border-radius:16px}
h1{color:#55adff}table{width:100%;border-collapse:collapse}
td,th{text-align:left;padding:12px;border-bottom:1px solid #29405f}
.note{color:#a9bad0;font-size:13px}</style>
<main><h1>🛡️ WebGuard – Admin</h1>
<p>Nur Tests mit ausdrücklicher Einwilligung.</p>
<table><tr><th>IP-Adresse</th><th>Zeitpunkt (UTC)</th></tr>
{% for x in rows %}<tr><td>{{ x.ip }}</td><td>{{ x.time }}</td></tr>
{% else %}<tr><td colspan="2">Noch keine Tests vorhanden.</td></tr>{% endfor %}
</table><p class="note">Demo-Speicher: Einträge werden beim Neustart gelöscht. Nutze die Daten nur für den angegebenen Zweck.</p></main>"""

def admin_only(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not ADMIN_PASSWORD:
            return Response("Admin-Zugang nicht eingerichtet. Setze WEBGUARD_ADMIN_PASSWORD.", 503)
        auth = request.authorization
        if not auth or auth.username != "admin" or not compare_digest(auth.password or "", ADMIN_PASSWORD):
            return Response("Admin-Anmeldung erforderlich.", 401,
                            {"WWW-Authenticate": 'Basic realm="WebGuard Admin"'})
        return fn(*args, **kwargs)
    return wrapped

@app.get("/")
def home():
    return render_template_string(HOME)

@app.post("/consent")
def consent():
    if request.form.get("consent") != "yes":
        abort(400, "Ohne Einwilligung wird nichts erfasst.")
    entries.insert(0, {
        "ip": request.remote_addr or "unbekannt",
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    })
    del entries[100:]
    return render_template_string(RESULT)

@app.get("/admin")
@admin_only
def admin():
    return render_template_string(ADMIN, rows=entries)

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
