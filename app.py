"""
YARA AI Malware Analysis Platform - Flask Application
Integrates HTML/CSS/JS templates with YARA scanning and static analysis
"""

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_from_directory,
    send_file,
    redirect,
    url_for
)

import os
import json
import hashlib
import math
import uuid
import threading 
from datetime import datetime
from werkzeug.utils import secure_filename

# Import YARA scanner
from yara_scanner import YARAScanner

# Import AI service
from ai_service import generate_yara_report

# Import PDF report generator
from report_generator import generate_pdf_report

import logging


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(
    __name__,
    static_folder='static',
    static_url_path='/static',
    template_folder='templates'
)


# ============================================================
# CONFIGURATION
# ============================================================

UPLOAD_FOLDER = 'uploads'

ALLOWED_EXTENSIONS = {
    'exe',
    'dll',
    'pdf',
    'doc',
    'docx',
    'xls',
    'xlsx',
    'js',
    'vbs',
    'ps1',
    'zip',
    'txt',
    'bin'
}

MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB


# ============================================================
# DIRECTORIES
# ============================================================

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('scan_results', exist_ok=True)


# ============================================================
# YARA SCANNER
# ============================================================

yara_scanner = YARAScanner('yara_rules')


# ============================================================
# IN-MEMORY STORAGE
# ============================================================

scan_results = {}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def allowed_file(filename):
    """
    Check if file extension is allowed.
    """

    return (
        '.' in filename
        and filename.rsplit('.', 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def calculate_hashes(filepath):
    """
    Calculate SHA-256 and MD5 hashes.
    """

    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()

    with open(filepath, 'rb') as f:

        for byte_block in iter(
            lambda: f.read(4096),
            b""
        ):
            sha256_hash.update(byte_block)
            md5_hash.update(byte_block)

    return {
        'sha256': sha256_hash.hexdigest(),
        'md5': md5_hash.hexdigest()
    }


def calculate_entropy(filepath):
    """
    Calculate Shannon entropy of file.
    """

    try:

        with open(filepath, 'rb') as f:
            data = f.read()

        if not data:
            return 0.0

        frequencies = {}

        for byte in data:
            frequencies[byte] = (
                frequencies.get(byte, 0) + 1
            )

        entropy = 0.0

        for freq in frequencies.values():

            p = freq / len(data)

            entropy -= p * math.log2(p)

        return round(entropy, 2)

    except Exception:

        return 0.0


def format_file_size(size_bytes):
    """
    Format bytes to human-readable size.
    """

    for unit in ['B', 'KB', 'MB', 'GB']:

        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"

        size_bytes /= 1024

    return f"{size_bytes:.2f} TB"


def get_file_type(filename):
    """
    Determine file type from extension.
    """

    ext = (
        filename.rsplit('.', 1)[1].lower()
        if '.' in filename
        else 'unknown'
    )

    file_types = {

        'exe': 'Windows Executable',

        'dll': 'Dynamic Link Library',

        'pdf': 'PDF Document',

        'doc': 'Word Document',

        'docx': 'Word Document',

        'xls': 'Excel Spreadsheet',

        'xlsx': 'Excel Spreadsheet',

        'js': 'JavaScript',

        'vbs': 'VBScript',

        'ps1': 'PowerShell Script',

        'zip': 'ZIP Archive',

        'txt': 'Text File',

        'bin': 'Binary File'
    }

    return file_types.get(
        ext,
        'Unknown'
    )


def assess_risk(
    yara_matches,
    entropy,
    file_type
):
    """
    Calculate risk based on YARA matches,
    entropy and file type.
    """

    risk_score = 0

    indicators = []

    # ---------------------------------------------------------
    # YARA MATCHES
    # ---------------------------------------------------------

    match_count = len(yara_matches)

    if match_count > 0:

        # A YARA match must have significant weight
        risk_score += min(
            70,
            match_count * 30
        )

        indicators.append(
            f"YARA matched {match_count} rule(s)"
        )

    # ---------------------------------------------------------
    # ENTROPY
    # ---------------------------------------------------------

    if entropy > 7.0:

        risk_score += 20

        indicators.append(
            "High entropy detected "
            "(possible obfuscation or compression)"
        )

    elif entropy > 6.5:

        risk_score += 10

        indicators.append(
            "Moderate entropy detected"
        )

    # ---------------------------------------------------------
    # EXECUTABLE
    # ---------------------------------------------------------

    if file_type in [
        "Windows Executable",
        "Dynamic Link Library"
    ]:

        risk_score += 10

        indicators.append(
            "Executable file type"
        )

    # ---------------------------------------------------------
    # SCRIPT
    # ---------------------------------------------------------

    if file_type in [
        "PowerShell Script",
        "VBScript",
        "JavaScript"
    ]:

        risk_score += 10

        indicators.append(
            "Script file type"
        )

    # ---------------------------------------------------------
    # RISK LEVEL
    # ---------------------------------------------------------

    risk_score = min(
        100,
        risk_score
    )

    if risk_score >= 75:

        risk_level = "CRITICAL"

    elif risk_score >= 50:

        risk_level = "HIGH"

    elif risk_score >= 25:

        risk_level = "MEDIUM"

    elif risk_score > 0:

        risk_level = "LOW"

    else:

        risk_level = "SAFE"

    return {
        "level": risk_level,
        "score": risk_score,
        "indicators": indicators
    }


def get_threat_level(yara_matches):
    """
    Determine threat level based on YARA matches.
    Legacy compatibility.
    """

    match_count = (
        len(yara_matches)
        if yara_matches
        else 0
    )

    if match_count >= 5:

        return 'CRITICAL'

    elif match_count >= 3:

        return 'HIGH'

    elif match_count >= 1:

        return 'MEDIUM'

    else:

        return 'LOW'


# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    """
    Redirect to dashboard.
    """

    return redirect(
        url_for('dashboard')
    )


@app.route('/dashboard')
def dashboard():
    """
    Dashboard page.
    """

    stats = {

        'total_scans':
            len(scan_results),

        'threats_detected':
            sum(
                1
                for r in scan_results.values()
                if r.get('threat_level')
                in [
                    'MEDIUM',
                    'HIGH',
                    'CRITICAL'
                ]
            ),

        'clean_files':
            sum(
                1
                for r in scan_results.values()
                if r.get('threat_level') == 'SAFE'
            ),

        'detection_rate':
            0
    }

    if stats['total_scans'] > 0:

        stats['detection_rate'] = round(
            (
                stats['threats_detected']
                / stats['total_scans']
            ) * 100,
            1
        )

    return render_template(
        'dashboard.html',
        active_page='dashboard',
        stats=stats
    )

@app.route('/analysis')
def analysis():
    """
    File Analysis upload page.
    """

    return render_template(
        'analysis.html',
        active_page='analysis'
    )


@app.route(
    '/yara-analyzer',
    methods=['GET', 'POST']
)
def yara_analyzer():
    """
    YARA Rule Analyzer page.
    """

    return render_template(
        'yara_analyzer.html',
        active_page='yara'
    )


@app.route('/history')
def history():
    """
    Scan History page.
    """

    history_list = []

    for scan_id, result in scan_results.items():

        history_list.append({

            'id': scan_id,

            'filename':
                result.get(
                    'filename',
                    'Unknown'
                ),

            'file_size':
                result.get(
                    'file_size',
                    0
                ),

            'threat_level':
                result.get(
                    'threat_level',
                    'UNKNOWN'
                ),

            'yara_matches':
                result.get(
                    'yara_matches',
                    0
                ),

            'date':
                result.get(
                    'scan_date',
                    ''
                ),

            'scan_id':
                scan_id
        })

    history_list.sort(
        key=lambda x: x.get(
            'date',
            ''
        ),
        reverse=True
    )

    return render_template(
        'history.html',
        active_page='history',
        history=history_list
    )


@app.route('/reports')
def reports():
    """
    Reports page.
    """

    return render_template(
        'reports.html',
        active_page='reports'
    )




def run_ai_analysis_background(scan_id, yara_ai_input):
    """
    Run AI analysis in a background thread.

    The YARA result is already stored, so an AI problem
    cannot block the scan result.
    """

    try:
        logger.info(
            f"[AI] Starting background analysis for scan {scan_id}"
        )

        ai_report = generate_yara_report(yara_ai_input, scan_id=scan_id)

        if scan_id in scan_results:
            scan_results[scan_id]['ai'] = ai_report

        logger.info(
            f"[AI] Analysis completed for scan {scan_id}"
        )

    except Exception as e:

        logger.error(
            f"[AI] Background analysis failed for scan {scan_id}: {str(e)}",
            exc_info=True
        )

        if scan_id in scan_results:

            scan_results[scan_id]['ai'] = {
                'summary': 'AI analysis could not be generated.',
                'reasons': [],
                'evidence': [],
                'risk_assessment': 'AI risk assessment unavailable.',
                'recommendations': [],
                'error': str(e),
                'processing': False
            }    



# ============================================================
# FILE SCAN
# ============================================================

@app.route('/scan', methods=['POST'])
def scan():
    """
    Handle file upload, YARA scanning and AI analysis.

    YARA result is returned immediately.
    AI analysis runs in the background so it cannot block the scan.
    """

    try:

        # =====================================================
        # CHECK FILE
        # =====================================================

        if 'file' not in request.files:

            return jsonify({
                'error': 'No file uploaded'
            }), 400

        file = request.files['file']

        if file.filename == '':

            return jsonify({
                'error': 'No file selected'
            }), 400

        # =====================================================
        # CHECK FILE TYPE
        # =====================================================

        if not allowed_file(file.filename):

            return jsonify({
                'error': (
                    'File type not allowed. Allowed: '
                    + ', '.join(sorted(ALLOWED_EXTENSIONS))
                )
            }), 400

        # =====================================================
        # CHECK FILE SIZE
        # =====================================================

        file.seek(0, os.SEEK_END)

        file_size = file.tell()

        if file_size > MAX_FILE_SIZE:

            return jsonify({
                'error': (
                    f'File too large. Maximum size: '
                    f'{MAX_FILE_SIZE // 1024 // 1024}MB'
                )
            }), 413

        file.seek(0)

        # =====================================================
        # SAVE FILE
        # =====================================================

        secure_name = secure_filename(file.filename)

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S_"
        )

        filename = timestamp + secure_name

        filepath = os.path.join(
            UPLOAD_FOLDER,
            filename
        )

        file.save(filepath)

        logger.info(
            f"File uploaded: {filename} "
            f"({format_file_size(file_size)})"
        )

        # =====================================================
        # CREATE SCAN ID
        # =====================================================

        scan_id = str(uuid.uuid4())[:8]

        logger.info(
            f"Starting scan: {scan_id}"
        )

        # =====================================================
        # HASHES
        # =====================================================

        hashes = calculate_hashes(filepath)

        # =====================================================
        # ENTROPY
        # =====================================================

        entropy = calculate_entropy(filepath)

        # =====================================================
        # FILE TYPE
        # =====================================================

        file_type = get_file_type(
            file.filename
        )

        # =====================================================
        # YARA SCAN
        # =====================================================

        logger.info(
            f"Running YARA scan for {scan_id}"
        )

        yara_result = yara_scanner.scan_file(
            filepath
        )

        yara_matches = yara_result.get(
            'matches',
            []
        )

        logger.info(
            f"YARA scan finished for {scan_id}: "
            f"{len(yara_matches)} matches"
        )

        # =====================================================
        # RISK ASSESSMENT
        # =====================================================

        risk_assessment = assess_risk(
            yara_matches,
            entropy,
            file_type
        )

        logger.info(
            f"Risk calculated for {scan_id}: "
            f"{risk_assessment['level']} "
            f"(score={risk_assessment['score']})"
        )

        # =====================================================
        # BUILD YARA INFORMATION FOR AI
        # =====================================================

        yara_ai_input = {

            'match': len(yara_matches) > 0,

            'matches': yara_matches,

            'file_type': file_type,

            'entropy': entropy,

            'risk_level': risk_assessment['level'],

            'risk_score': risk_assessment['score'],

            'risk_indicators': risk_assessment['indicators']

        }

        # =====================================================
        # BUILD YARA RULE CARDS
        # =====================================================

        yara_rules = []

        for match in yara_matches:

            indicators = []

            for string_match in match.get(
                'strings',
                []
            ):

                value = string_match.get(
                    'data',
                    string_match.get(
                        'identifier',
                        ''
                    )
                )

                if value:
                    indicators.append(
                        value
                    )

            yara_rules.append({

                'name': match.get(
                    'rule',
                    'Unknown Rule'
                ),

                'namespace': match.get(
                    'namespace',
                    'default'
                ),

                'tags': match.get(
                    'tags',
                    []
                ),

                'severity': 'High',

                'description': (
                    f"Matched rule: "
                    f"{match.get('rule', 'Unknown Rule')}"
                ),

                'indicators': indicators[:10]

            })

        # =====================================================
        # INITIAL AI STATE
        # =====================================================

        ai_report = {

            'summary': (
                'AI analysis is being generated...'
            ),

            'reasons': [],

            'evidence': [],

            'risk_assessment': (
                'AI risk assessment is being generated...'
            ),

            'recommendations': [],

            'processing': True,

            'error': None

        }

        # =====================================================
        # BUILD COMPLETE RESULT
        # =====================================================

        result = {

            'scan_id': scan_id,

            'filename': file.filename,

            'file_size': format_file_size(
                file_size
            ),

            'file_type': file_type,

            'sha256': hashes['sha256'],

            'md5': hashes['md5'],

            'entropy': entropy,

            'scan_date': datetime.now().strftime(
                '%Y-%m-%d %H:%M:%S UTC'
            ),

            'yara_matches': len(
                yara_matches
            ),

            'yara_rules': yara_rules,

            'threat_level': risk_assessment[
                'level'
            ],

            'confidence': risk_assessment[
                'score'
            ],

            'status': (
                'Suspicious'
                if len(yara_matches) > 0
                else 'Clean'
            ),

            'risk_indicators': (
                risk_assessment[
                    'indicators'
                ]
            ),

            'report_id': (
                f"RPT-{scan_id.upper()}"
            ),

            'features': {

                'entropy': entropy,

                'pe_sections': (
                    'N/A'
                ),

                'imported_dlls': (
                    'N/A'
                ),

                'suspicious_apis': (
                    risk_assessment[
                        'indicators'
                    ]
                ),

                'strings': [],

                'metadata': {

                    'author': 'Unknown',

                    'created': 'Unknown',

                    'modified': 'Unknown'

                }

            },

            'ai': ai_report

        }

        # =====================================================
        # STORE RESULT IMMEDIATELY
        # =====================================================

        scan_results[scan_id] = result

        logger.info(
            f"Scan result stored: {scan_id}"
        )

        logger.info(
            f"Scan completed: {file.filename} - "
            f"Risk Level: {result['threat_level']} "
            f"(Score: {result['confidence']})"
        )

        # =====================================================
        # START AI IN BACKGROUND
        # =====================================================

        ai_thread = threading.Thread(

            target=run_ai_analysis_background,

            args=(
                scan_id,
                yara_ai_input
            ),

            daemon=True

        )

        ai_thread.start()

        logger.info(
            f"AI background thread started for {scan_id}"
        )

        # =====================================================
        # REDIRECT IMMEDIATELY
        # =====================================================

        return redirect(
            url_for(
                'result',
                scan_id=scan_id
            )
        )

    except Exception as e:

        logger.error(
            f"Scan error: {str(e)}",
            exc_info=True
        )

        return jsonify({
            'error': f'Scanning failed: {str(e)}'
        }), 500

# ============================================================
# RESULT PAGE
# ============================================================

@app.route('/result/<scan_id>')
def result(scan_id):
    """
    Display scan result.
    """

    if scan_id not in scan_results:

        return jsonify({
            'error':
                f'Scan ID "{scan_id}" not found.'
        }), 404

    result_data = scan_results[scan_id]

    return render_template(
        'result.html',
        scan_id=scan_id,
        result=result_data,
        current_year=datetime.now().year
    )


@app.route('/api/result/<scan_id>')
def api_result(scan_id):
    """
    Return scan result as JSON.
    Used by the result page to monitor AI processing.
    """

    if scan_id not in scan_results:

        return jsonify({
            'error': 'Scan not found'
        }), 404

    return jsonify(
        scan_results[scan_id]
    )

# ============================================================
# API STATS
# ============================================================

@app.route('/api/stats')
def get_stats():
    """
    Get dashboard statistics.
    """

    stats = {

        'total_scans':
            len(scan_results),

        'threats_detected':
            sum(
                1
                for r in scan_results.values()
                if r.get('threat_level')
                in [
                    'MEDIUM',
                    'HIGH',
                    'CRITICAL'
                ]
            ),

        'clean_files':
            sum(
                1
                for r in scan_results.values()
                if r.get('threat_level') == 'SAFE'
            ),

        'detection_rate':
            0,

        'threat_distribution': {

            'low':
                sum(
                    1
                    for r in scan_results.values()
                    if r.get('threat_level') == 'LOW'
                ),

            'medium':
                sum(
                    1
                    for r in scan_results.values()
                    if r.get('threat_level') == 'MEDIUM'
                ),

            'high':
                sum(
                    1
                    for r in scan_results.values()
                    if r.get('threat_level') == 'HIGH'
                ),

            'critical':
                sum(
                    1
                    for r in scan_results.values()
                    if r.get('threat_level') == 'CRITICAL'
                )
        },

        'top_rules':
            []
    }

    if stats['total_scans'] > 0:

        stats['detection_rate'] = round(
            (
                stats['threats_detected']
                / stats['total_scans']
            ) * 100,
            1
        )

    return jsonify(stats)


# ============================================================
# API HISTORY
# ============================================================

@app.route('/api/history')
def get_history():
    """
    Get scan history.
    """

    history_list = []

    for scan_id, result in scan_results.items():

        history_list.append({

            'id':
                scan_id,

            'filename':
                result.get(
                    'filename',
                    'Unknown'
                ),

            'file_size':
                result.get(
                    'file_size',
                    'Unknown'
                ),

            'threat_level':
                result.get(
                    'threat_level',
                    'UNKNOWN'
                ),

            'confidence_score':
                result.get(
                    'confidence',
                    0
                ),

            'yara_matches':
                result.get(
                    'yara_matches',
                    0
                ),

            'date':
                result.get(
                    'scan_date',
                    ''
                )
        })

    return jsonify(history_list)


# ============================================================
# STATIC FILES
# ============================================================

@app.route('/static/<path:path>')
def send_static(path):
    """
    Serve static files.
    """

    return send_from_directory(
        'static',
        path
    )


# ============================================================
# REPORT DOWNLOAD
# ============================================================

@app.route(
    '/report_download/<report_id>'
)
def report_download(report_id):
    """
    Generate and download a PDF report for the scan behind this
    report_id, using the real, already-stored scan result (the same
    data shown on its /result page). Nothing is invented here.
    """

    requested_id = report_id.strip()

    scan_id = None

    # report_id is generated as f"RPT-{scan_id.upper()}" (see /scan).
    # Reverse that first, then fall back to a direct lookup in case
    # the mapping ever changes.
    if requested_id.upper().startswith('RPT-'):

        candidate = requested_id[4:].lower()

        if candidate in scan_results:
            scan_id = candidate

    if scan_id is None:

        for candidate_id, candidate_result in scan_results.items():

            if candidate_result.get('report_id') == requested_id:
                scan_id = candidate_id
                break

    if scan_id is None or scan_id not in scan_results:

        return jsonify({
            'error': f'Report "{report_id}" not found.'
        }), 404

    result_data = scan_results[scan_id]

    try:

        pdf_buffer = generate_pdf_report(
            result_data,
            scan_id
        )

    except Exception as e:

        logger.error(
            f"PDF report generation failed for scan {scan_id}: {e}",
            exc_info=True
        )

        return jsonify({
            'error': 'Failed to generate PDF report.'
        }), 500

    logger.info(
        f"PDF report generated for scan {scan_id}"
    )

    return send_file(
        pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'YARA_AI_Report_{scan_id}.pdf'
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route('/health')
def health():
    """
    Health check endpoint.
    """

    return jsonify({

        'status':
            'healthy',

        'yara_scanner':
            (
                'ready'
                if yara_scanner.rules
                else 'no_rules'
            ),

        'timestamp':
            datetime.now().isoformat()
    })

@app.route('/favicon.ico')
def favicon():
    return '', 204

# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):
    """
    Handle 404 errors.
    """

    return jsonify({
        "error": "Page not found"
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """
    Handle 500 errors.
    """

    logger.error(
        f"Internal server error: {str(error)}"
    )

    return jsonify({
        'error':
            'Internal server error'
    }), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    """
    Handle file too large.
    """

    return jsonify({

        'error':
            (
                'File too large. '
                f'Maximum size: '
                f'{MAX_FILE_SIZE // 1024 // 1024}MB'
            )

    }), 413


# ============================================================
# CONTEXT PROCESSOR
# ============================================================

@app.context_processor
def inject_year():
    """
    Inject current year into templates.
    """

    return {
        'current_year':
            datetime.now().year
    }


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == '__main__':

    print()
    print("[*] Starting YARA AI Platform...")
    print(
        f"[+] Upload folder: "
        f"{os.path.abspath(UPLOAD_FOLDER)}"
    )
    print(
        f"[+] YARA rules loaded: "
        f"{'Yes' if yara_scanner.rules else 'No rules found'}"
    )
    print(
        f"[+] Max file size: "
        f"{MAX_FILE_SIZE // 1024 // 1024}MB"
    )
    print(
        f"[+] Supported formats: "
        f"{', '.join(sorted(ALLOWED_EXTENSIONS))}"
    )

    print()
    print(
        "[+] Access the platform at: "
        "http://localhost:5000"
    )
    print("[*] Press CTRL+C to stop")
    print()

    app.run(
        host='127.0.0.1',
        port=5000,
        debug=False,
        threaded=True
    )