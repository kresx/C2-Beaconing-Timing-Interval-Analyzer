import os
import uuid
import json
import logging
import secrets
from flask import Flask, render_template, request, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
from analyzer import extract_flow_metrics, sniff_live_traffic
from ai_agent import C2Agent

# Configure Logging (Syntax Error Fixed Here)
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Security & App Configuration
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
if not os.environ.get('SECRET_KEY'):
    logger.warning("SECRET_KEY is not set; generated an ephemeral key for this process.")
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB limit

ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}
MAX_AI_REQUEST_BYTES = 1 * 1024 * 1024
MAX_AI_FLOWS = 100

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def is_allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html', results=None)

@app.route('/analyze_pcap', methods=['POST'])
def analyze_pcap():
    if 'pcap_file' not in request.files:
        return render_template('index.html', error="No file part in the request.")
        
    file = request.files['pcap_file']
    
    if file.filename == '':
        return render_template('index.html', error="No file selected.")

    if not is_allowed_file(file.filename):
        return render_template('index.html', error="Invalid file format.")

    original_filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

    try:
        file.save(filepath)
        logger.info(f"Processing uploaded PCAP: {original_filename}")
        
        results = extract_flow_metrics(filepath)
        return render_template('index.html', results=results, filename=original_filename)
    except Exception as e:
        logger.exception("Error parsing PCAP")
        return render_template('index.html', error="Unable to parse the capture file.")
    finally:
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except OSError:
                pass

@app.route('/sniff_live', methods=['POST'])
def sniff_live():
    iface = request.form.get('interface', '').strip() or None
    raw_count = request.form.get('count', '100')
    raw_timeout = request.form.get('timeout', '30')

    try:
        count = int(raw_count)
        timeout = int(raw_timeout)
        if not 1 <= count <= 5000:
            raise ValueError("Packet count must be between 1 and 5,000.")
        if not 1 <= timeout <= 300:
            raise ValueError("Capture timeout must be between 1 and 300 seconds.")
    except ValueError as val_err:
        return render_template('index.html', error=f"Invalid capture setting: {val_err}")

    try:
        logger.info("Starting live packet sniff on interface '%s' for up to %s packets / %ss.", iface or 'default', count, timeout)
        results = sniff_live_traffic(interface=iface, packet_count=count, timeout=timeout)
        return render_template('index.html', results=results, interface=iface)
    except Exception:
        logger.exception("Live sniffing failed")
        return render_template('index.html', error="Live sniffing failed. Check the server logs and interface permissions.")

@app.route('/analyze_ai', methods=['POST'])
def analyze_ai():
    try:
        if request.form.get('ai_consent') != 'yes':
            return render_template('index.html', error="Confirm external AI processing before submitting flow data.")

        raw_profiles = request.form.get('flow_data', '[]')
        if len(raw_profiles.encode('utf-8')) > MAX_AI_REQUEST_BYTES:
            return render_template('index.html', error="AI analysis input exceeds the 1 MB limit.")

        profiles = json.loads(raw_profiles)
        if not isinstance(profiles, list) or not profiles:
            return render_template('index.html', error="No valid flows available for AI analysis.")
        if len(profiles) > MAX_AI_FLOWS or not all(isinstance(profile, dict) for profile in profiles):
            return render_template('index.html', error=f"Submit between 1 and {MAX_AI_FLOWS} flow profiles.")

        logger.info("Executing Claude AI Forensic Analysis for %d flows.", len(profiles))
        ai_response_raw = C2Agent().analyze_flows(profiles)

        try:
            ai_report = json.loads(ai_response_raw)
        except json.JSONDecodeError:
            ai_report = {"analysis_summary": ai_response_raw, "threats_detected": []}

        return render_template('index.html', results=profiles, ai_report=ai_report)
    except Exception:
        logger.exception("Claude API evaluation failed")
        return render_template('index.html', error="AI analysis failed. Check the server logs and API configuration.")

@app.route('/api/analyze_pcap', methods=['POST'])
def api_analyze_pcap():
    if 'pcap_file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'}), 400
        
    file = request.files['pcap_file']
    if file.filename == '' or not is_allowed_file(file.filename):
        return jsonify({'status': 'error', 'message': 'Invalid file format'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4().hex}_{filename}")

    try:
        file.save(filepath)
        results = extract_flow_metrics(filepath)
        return jsonify({'status': 'success', 'filename': filename, 'results': results})
    except Exception as e:
        logger.exception("API PCAP analysis failed")
        return jsonify({'status': 'error', 'message': 'Unable to parse the capture file.'}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template('index.html', error="File size exceeds the 32 MB limit."), 413

if __name__ == '__main__':
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    logger.info(f"[*] Launching C2 Analyzer Web App at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)