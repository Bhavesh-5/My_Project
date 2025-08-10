import os
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from custom_scanner import run_custom_scan
import subprocess
import logging

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

def run_bandit_scan(filepath):
    try:
        result = subprocess.run(
            ['bandit', '-r', filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.splitlines()
    except Exception as e:
        return [f"Bandit scan failed: {str(e)}"]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    code = request.form.get('code')
    file = request.files.get('file')

    if not code and not file:
        return "Please provide code or upload a file.", 400

    # Save code to file if provided directly
    if code:
        filename = "submitted_code.py"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'w') as f:
            f.write(code)
    else:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

    try:
        logging.info("Scanning code...")
        bandit_results = run_bandit_scan(filepath)
        custom_results = run_custom_scan(filepath)
        return render_template('results.html',
                               bandit_results=bandit_results,
                               custom_results=custom_results)
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        return f"An error occurred: {e}", 500

@app.errorhandler(413)
def too_large(e):
    return "File is too large", 413

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    app.run(debug=True)