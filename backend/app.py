import threading
import uuid
from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner.url_validator import is_valid_target
from scanner.scanner_engine import start_scan
from utils.helpers import print_banner


print_banner()

app = Flask(__name__)
CORS(app)

# In-memory scan store
scans = {}

@app.route("/scan", methods=["POST"])
def scan_target():
    data = request.get_json()
    target_url = data.get("url")

    if not target_url:
        return jsonify({"error": "URL is required"}), 400

    if not is_valid_target(target_url):
        return jsonify({"error": "Invalid or restricted URL"}), 400

    scan_id = str(uuid.uuid4())

    # Initialize the record
    scans[scan_id] = {
        "status": "in_progress",
        "target": target_url,
        "results": []
    }

    # Start the scan in a background thread
    # We pass the 'scans' dictionary so the thread can update it directly
    thread = threading.Thread(target=start_scan, args=(scan_id, target_url, scans))
    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "status": "started"
    }), 202

@app.route("/scan-status/<scan_id>", methods=["GET"])
def scan_status(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"scan_id": scan_id, "status": scan["status"]})

@app.route("/scan-result/<scan_id>", methods=["GET"])
def scan_result(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)

if __name__ == "__main__":
    print("[*] API is running on http://127.0.0.1:5000")
    
    # use_reloader=False ensures it only prints once and doesn't clear the screen
    app.run(debug=True, use_reloader=False)