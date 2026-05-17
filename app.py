from flask import Flask, render_template, request, jsonify
from backend.log_analyzer import analyze_logs
from backend.live_log_generator import generate_batch

app = Flask(__name__)

latest_results = []
latest_summary = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", live_mode=True)


@app.route("/analyze", methods=["POST"])
def analyze():
    global latest_results, latest_summary

    logs = request.form.get("logs", "")
    latest_results, latest_summary = analyze_logs(logs)

    return render_template("dashboard.html", live_mode=False)


@app.route("/api/live")
def api_live():
    global latest_results, latest_summary

    live_logs = generate_batch(10)
    latest_results, latest_summary = analyze_logs(live_logs)

    return jsonify({
        "results": latest_results,
        "summary": latest_summary
    })


@app.route("/api/latest")
def api_latest():
    return jsonify({
        "results": latest_results,
        "summary": latest_summary
    })


@app.route("/report")
def report():
    return render_template(
        "report.html",
        results=latest_results,
        summary=latest_summary
    )


if __name__ == "__main__":
    app.run(debug=True, port=5001)