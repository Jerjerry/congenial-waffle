from flask import Flask, render_template, request, jsonify, send_file
import os
import tempfile
from pathlib import Path
from werkzeug.utils import secure_filename
from tools.pysign import IPASigner

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max file size

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/sign', methods=['POST'])
def sign_ipa():
    try:
        # Get uploaded files
        ipa_file = request.files.get('ipa')
        cert_file = request.files.get('certificate')
        dylib_file = request.files.get('dylib')
        
        if not ipa_file or not cert_file:
            return jsonify({'error': 'Missing required files'}), 400
            
        # Save uploaded files
        ipa_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(ipa_file.filename))
        cert_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(cert_file.filename))
        ipa_file.save(ipa_path)
        cert_file.save(cert_path)
        
        # Get other parameters
        password = request.form.get('password')
        bundle_id = request.form.get('bundleId')
        weak_dylib = request.form.get('weakDylib') == 'true'
        
        # Handle dylib if provided
        dylib_path = None
        if dylib_file:
            dylib_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(dylib_file.filename))
            dylib_file.save(dylib_path)
            
        # Create output path
        output_path = os.path.join(
            app.config['UPLOAD_FOLDER'],
            'signed_' + secure_filename(ipa_file.filename)
        )
        
        # Sign the IPA
        signer = IPASigner()
        signer.sign(
            ipa_path,
            cert_path,
            output_path,
            password=password,
            bundle_id=bundle_id,
            dylib_path=dylib_path,
            weak_dylib=weak_dylib
        )
        
        # Clean up input files
        os.unlink(ipa_path)
        os.unlink(cert_path)
        if dylib_path:
            os.unlink(dylib_path)
            
        # Send signed IPA
        return send_file(
            output_path,
            as_attachment=True,
            download_name='signed_' + os.path.basename(ipa_file.filename)
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
        
    finally:
        # Clean up output file
        if 'output_path' in locals() and os.path.exists(output_path):
            os.unlink(output_path)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
