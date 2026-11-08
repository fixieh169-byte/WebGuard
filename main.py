
import os
import secrets
from datetime import datetime, timezone
from functools import wraps
from hmac import compare_digest

from flask import (
    Flask, Response, abort, redirect,
    render_template_string, request, url_for
)
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# Render Reverse Proxy
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1
)

ADMIN_PASSWORD = os.environ.get("WEBGUARD_ADMIN_PASSWORD", "")
CSRF_TOKEN = secrets.token_urlsafe(32)

# Demo-Speicher (wird beim Neustart geleert)
entries = []

HOME = """
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebGuard</title>
<style>
body{background:#080d18;color:#eef4ff;font:16px Arial;padding:22px}
main{max-width:650px;margin:35px auto;background:#121c2d;
border:1px solid #29405f;border-radius:16px;padding:24px}
h1{color:#55adff}
.notice{background:#1c2b40;padding:14px;border-radius:10px}
p{line-height:1.5;color:#c6d3e5}
label{display:flex;gap:10px;margin:20px 0}
button{background:#1686e8;color:white;border:0;
border-radius:9px;padding:13px 18px;cursor:pointer}
.small{font-size:13px;color:#9aabc1}
</style>
</head>
<body>
<main>
<h1>🛡️ WebGuard</h1>
<h2>Freiwilliger Verbindungstest</h2>

<p>Starte den Test freiwillig, um deine öffentliche IP-Adresse
an WebGuard zu übermitteln.</p>

<div class="notice">
<b>Erfasste Daten</b>
<p>Öffentliche IP-Adresse und Zeitpunkt des Tests.</p>
<p>Die IP-Adresse wird ausschließlich im geschützten
Admin-Dashboard angezeigt.</p>
<p>Keine Discord-Daten und kein Geräte-Fingerabdruck.</p>
<p>Die Demo speichert Einträge nur bis zum Serverneustart.</p>
</div>

<form method="post" action="/consent">
<label>
<input type="checkbox" name="consent" value="yes" required>
<span>Ich habe den Hinweis gelesen und willige freiwillig
in die Erfassung meiner IP-Adresse für diesen Test ein.</span>
</label>
<button type="submit">Verbindungstest starten</button>
</form>

<p class="small">
Ohne Einwilligung werden keine Testdaten durch WebGuard erfasst.
</p>
</main>
</body>
</html>
"""

RESULT = """
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{background:#080d18;color:#eef4ff;font:16px Arial;padding:24px}
main{max-width:600px;margin:45px auto;background:#121c2d;
padding:24px;border-radius:16px}
h1{color:#55adff}
.ok{color:#55d69e}
</style>
</head>
<body>
<main>
<h1>🛡️ WebGuard</h1>
<h2 class="ok">Test abgeschlossen</h2>
<p>Deine Einwilligung wurde übermittelt.</p>
<p>Der Verbindungstest wurde durchgeführt.</p>
<p>Deine IP-Adresse wird nicht auf dieser Seite angezeigt.</p>
</main>
</body>
</html>
"""

ADMIN = """
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebGuard Admin</title>
<style>
*{box-sizing:border-box}
body{background:#080d18;color:#eef4ff;font:15px Arial;padding:20px}
main{max-width:950px;margin:25px auto}
h1{color:#55adff}
.cards{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}
.card{background:#121c2d;border:1px solid #29405f;
border-radius:14px;padding:20px}
.number{font-size:30px;font-weight:bold;color:#55adff}
table{width:100%;border-collapse:collapse;min-width:450px}
td,th{text-align:left;padding:13px;border-bottom:1px solid #29405f}
th{color:#55adff}
.panel{background:#121c2d;border:1px solid #29405f;
border-radius:15px;padding:20px;margin-top:20px;overflow-x:auto}
button{border:0;border-radius:8px;padding:10px 14px;
cursor:pointer;color:white}
.delete{background:#c03950}
.clear{background:#a52b3c}
.top{display:flex;justify-content:space-between;
align-items:center;gap:10px;flex-wrap:wrap}
.note{color:#9aabc1;font-size:13px}
.empty{color:#9aabc1;padding:20px}
@media(max-width:500px){
.cards{grid-template-columns:1fr}
body{padding:12px}
}
</style>
</head>
<body>
<main>

<div class="top">
<h1>🛡️ WebGuard Admin</h1>

<form method="post" action="/admin/clear"
onsubmit="return confirm('Wirklich alle Einträge löschen?')">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button class="clear" type="submit">Alle löschen</button>
</form>
</div>

<div class="cards">
<div class="card">
<p>Erfasste Tests</p>
<div class="number">{{ total }}</div>
</div>

<div class="card">
<p>Letzter Test</p>
<div class="number" style="font-size:17px">{{ latest }}</div>
</div>
</div>

<div class="panel">
<h2>Verbindungsprotokolle</h2>
<p class="note">
Nur freiwillig übermittelte Verbindungstests.
</p>

<table>
<tr>
<th>Öffentliche IP-Adresse</th>
<th>Zeitpunkt (UTC)</th>
<th>Aktion</th>
</tr>

{% for x in rows %}
<tr>
<td>{{ x.ip }}</td>
<td>{{ x.time }}</td>
<td>
<form method="post"
action="{{ url_for('delete_entry', entry_id=x.id) }}"
onsubmit="return confirm('Eintrag löschen?')">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button class="delete" type="submit">Löschen</button>
</form>
</td>
</tr>
{% else %}
<tr>
<td colspan="3" class="empty">
Noch keine Tests vorhanden.
</td>
</tr>
{% endfor %}
</table>
</div>

<p class="note">
WebGuard Demo · Speicherung im Arbeitsspeicher.
Einträge verschwinden beim Serverneustart.
</p>

</main>
</body>
</html>
"""


def admin_only(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):

        if not ADMIN_PASSWORD:
            return Response(
                "Admin-Zugang nicht eingerichtet. "
                "Setze WEBGUARD_ADMIN_PASSWORD.",
                503
            )

        auth = request.authorization

        if (
            not auth
            or auth.username != "admin"
            or not compare_digest(
                auth.password or "",
                ADMIN_PASSWORD
            )
        ):
            return Response(
                "Admin-Anmeldung erforderlich.",
                401,
                {
                    "WWW-Authenticate":
                    'Basic realm="WebGuard Admin"'
                }
            )

        response = fn(*args, **kwargs)
        return response

    return wrapped


def verify_csrf():
    token = request.form.get("csrf", "")

    if not compare_digest(token, CSRF_TOKEN):
        abort(403, "Ungültige Anfrage.")


@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/")
def home():
    return render_template_string(HOME)


@app.post("/consent")
def consent():

    if request.form.get("consent") != "yes":
        abort(400, "Ohne Einwilligung wird nichts erfasst.")

    # Client-IP über die konfigurierte Proxy-Kette
    public_ip = request.remote_addr or "unbekannt"

    entries.insert(0, {
        "id": secrets.token_urlsafe(12),
        "ip": public_ip,
        "time": datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    })

    # Maximal 100 Demo-Einträge
    del entries[100:]

    return render_template_string(RESULT)


@app.get("/admin")
@admin_only
def admin():

    latest = entries[0]["time"] if entries else "Noch keine Tests"

    return render_template_string(
        ADMIN,
        rows=entries,
        total=len(entries),
        latest=latest,
        csrf=CSRF_TOKEN
    )


@app.post("/admin/delete/<entry_id>")
@admin_only
def delete_entry(entry_id):

    verify_csrf()

    entries[:] = [
        x for x in entries
        if x["id"] != entry_id
    ]

    return redirect(url_for("admin"))


@app.post("/admin/clear")
@admin_only
def clear_entries():

    verify_csrf()
    entries.clear()

    return redirect(url_for("admin"))


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080"))
    )
