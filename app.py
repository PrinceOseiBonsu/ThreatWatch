# app.py
# ThreatWatch - Threat Intelligence Dashboard

from flask import Flask, render_template, request
import os
from threat_intel import run_threat_scan

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "threatwatch-2026-prince")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    query = request.form.get("query", "").strip()
    if not query:
        return render_template("index.html", error="Please enter an IP, domain or file hash")

    results = run_threat_scan(query)
    return render_template("results.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)