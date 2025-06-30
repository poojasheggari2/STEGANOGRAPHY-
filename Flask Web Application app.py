import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for, send_file
from werkzeug.utils import secure_filename
from steganography import AdvancedSteganography
import uuid
from PIL import Image


# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key_for_development")

# Configuration
UPLOAD_FOLDER = 'static/uploads'
PROCESSED_FOLDER = 'static/processed'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'tiff'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROCESSED_FOLDER'] = PROCESSED_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Ensure upload directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

# Initialize steganography tool
steg_tool = AdvancedSteganography()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(filepath):
    """Validate that the uploaded file is a valid image"""
    try:
        with Image.open(filepath) as img:
            img.verify()
        return True
    except Exception as e:
        logging.error(f"Image validation failed: {e}")
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/embed', methods=['POST'])
def embed_message():
    try:
        # Check if image file was uploaded
        if 'image' not in request.files:
            flash('No image file selected', 'error')
            return redirect(url_for('index'))
        
        file = request.files['image']
        if file.filename == '':
            flash('No image file selected', 'error')
            return redirect(url_for('index'))
        
        # Get form data
        secret_message = request.form.get('message', '').strip()
        encryption_key = request.form.get('key', '').strip()
        
        if not secret_message:
            flash('Please enter a message to hide', 'error')
            return redirect(url_for('index'))
        
        if not file or not allowed_file(file.filename):
            flash('Invalid file type. Please upload PNG, JPG, JPEG, BMP, or TIFF images.', 'error')
            return redirect(url_for('index'))
        
        # Generate unique filename
        file_id = str(uuid.uuid4())
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        input_filename = f"{file_id}_input.{file_extension}"
        output_filename = f"{file_id}_output.png"
        
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
        output_path = os.path.join(app.config['PROCESSED_FOLDER'], output_filename)
        
        # Save uploaded file
        file.save(input_path)
        
        # Validate image
        if not validate_image(input_path):
            os.remove(input_path)
            flash('Invalid or corrupted image file', 'error')
            return redirect(url_for('index'))
        
        # Prepare encryption key
        key = None
        if encryption_key:
            # Pad or truncate key to 32 bytes for AES-256
            key = encryption_key.encode('utf-8')
            if len(key) < 32:
                key = key.ljust(32, b'\0')
            elif len(key) > 32:
                key = key[:32]
        
        # Embed message
        success = steg_tool.embed_data(input_path, secret_message, output_path, key)
        
        if success:
            # Clean up input file
            os.remove(input_path)
            
            return render_template('result.html', 
                                 operation='embed',
                                 success=True,
                                 output_file=output_filename,
                                 message_length=len(secret_message),
                                 encrypted=bool(encryption_key))
        else:
            flash('Failed to embed message in image', 'error')
            return redirect(url_for('index'))
            
    except ValueError as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Embedding error: {e}")
        flash('An unexpected error occurred during embedding', 'error')
        return redirect(url_for('index'))

@app.route('/extract', methods=['POST'])
def extract_message():
    try:
        # Check if image file was uploaded
        if 'image' not in request.files:
            flash('No image file selected', 'error')
            return redirect(url_for('index'))
        
        file = request.files['image']
        if file.filename == '':
            flash('No image file selected', 'error')
            return redirect(url_for('index'))
        
        # Get encryption key
        decryption_key = request.form.get('key', '').strip()
        
        if not file or not allowed_file(file.filename):
            flash('Invalid file type. Please upload PNG, JPG, JPEG, BMP, or TIFF images.', 'error')
            return redirect(url_for('index'))
        
        # Generate unique filename
        file_id = str(uuid.uuid4())
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        input_filename = f"{file_id}_extract.{file_extension}"
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
        
        # Save uploaded file
        file.save(input_path)
        
        # Validate image
        if not validate_image(input_path):
            os.remove(input_path)
            flash('Invalid or corrupted image file', 'error')
            return redirect(url_for('index'))
        
        # Prepare decryption key
        key = None
        if decryption_key:
            # Pad or truncate key to 32 bytes for AES-256
            key = decryption_key.encode('utf-8')
            if len(key) < 32:
                key = key.ljust(32, b'\0')
            elif len(key) > 32:
                key = key[:32]
        
        # Extract message
        extracted_message = steg_tool.extract_data(input_path, key)
        
        # Clean up input file
        os.remove(input_path)
        
        return render_template('result.html',
                             operation='extract',
                             success=True,
                             extracted_message=extracted_message,
                             message_length=len(extracted_message))
        
    except ValueError as e:
        flash(f'Extraction failed: {str(e)}', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Extraction error: {e}")
        flash('Failed to extract message. The image may not contain hidden data or the key is incorrect.', 'error')
        return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    try:
        file_path = os.path.join(app.config['PROCESSED_FOLDER'], filename)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True, download_name=f"steganographic_{filename}")
        else:
            flash('File not found', 'error')
            return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Download error: {e}")
        flash('Error downloading file', 'error')
        return redirect(url_for('index'))

@app.errorhandler(413)
def too_large(e):
    flash('File is too large. Maximum size is 16MB.', 'error')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
