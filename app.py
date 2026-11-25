import logging
import sys
import threading
import webbrowser

from flask import Flask, jsonify, render_template, request

from scanner.engine import ScanEngine
from scanner.network import default_network

HOST = "127.0.0.1"
PORT = 5000

app = Flask(__name__)
engine = ScanEngine()
logging.getLogger("werkzeug").setLevel(logging.ERROR)


@app.get("/")
def index():
    return render_template("index.html", default_network=default_network())


@app.get("/api/status")
def status():
    return jsonify(engine.snapshot())


@app.post("/api/scan")
def scan():
    try:
        engine.start(request.get_json(silent=True) or {})
    except (ValueError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True})


@app.post("/api/stop")
def stop():
    engine.stop()
    return jsonify({"ok": True})


if __name__ == "__main__":
    url = f"http://{HOST}:{PORT}"
    print(f"NetProbe Wi-Fi rodando em {url}  (Ctrl+C para sair)")
    if "--no-browser" not in sys.argv:
        threading.Timer(1.0, webbrowser.open, args=[url]).start()
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
