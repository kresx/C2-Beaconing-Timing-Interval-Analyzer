import os
import uuid
import json
import logging
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
app.secret_key = os.environ.get('SECRET_KEY', 'c2_analyzer_default_secret_key')
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB limit

ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}

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
        logger.error(f"Error parsing PCAP: {str(e)}", exc_info=True)
        return render_template('index.html', error=f"Error parsing PCAP: {str(e)}")
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
    
    try:
        count = int(raw_count)
        if count <= 0 or count > 5000:
            raise ValueError("Packet count must be between 1 and 5,000.")
    except ValueError as val_err:
        return render_template('index.html', error=f"Invalid packet count: {str(val_err)}")

    try:
        logger.info(f"Starting live packet sniff on interface '{iface or 'default'}' for {count} packets.")
        results = sniff_live_traffic(interface=iface, packet_count=count)
        return render_template('index.html', results=results, interface=iface)
    except Exception as e:
        return render_template('index.html', error=f"Live sniffing error: {str(e)}")

@app.route('/analyze_ai', methods=['POST'])
def analyze_ai():
    try:
        raw_profiles = request.form.get('flow_data', '[]')
        profiles = json.loads(raw_profiles)
        
        if not profiles:
            return render_template('index.html', error="No flows available for AI analysis.")
            
        logger.info("Executing Claude AI Forensic Analysis...")
        agent = C2Agent()
        ai_response_raw = agent.analyze_flows(profiles)
        
        try:
            ai_report = json.loads(ai_response_raw)
        except Exception:
            ai_report = {"analysis_summary": ai_response_raw, "threats_detected": []}
            
        return render_template('index.html', results=profiles, ai_report=ai_report)
    except Exception as e:
        logger.error(f"Claude API evaluation failed: {str(e)}", exc_info=True)
        return render_template('index.html', error=f"Claude API Error: {str(e)}")

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
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template('index.html', error="File size exceeds the 32 MB limit."), 413

if __name__ == '__main__':
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() in ('true', '1', 't')
    logger.info(f"[*] Launching C2 Analyzer Web App at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)