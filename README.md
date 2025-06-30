# STEGANOGRAPHY


A comprehensive steganography application that allows you to hide encrypted messages in images using LSB (Least Significant Bit) embedding with AES-256 encryption and CRC32 data integrity checks.

## Features

- **LSB Steganography**: Hide messages in image pixels using 2-bit LSB embedding
- **AES-256 Encryption**: Optional encryption for maximum security
- **Data Integrity**: CRC32 checksums to verify data hasn't been corrupted
- **Multiple Interfaces**: Both web application and desktop GUI
- **Support for Multiple Formats**: PNG, JPG, JPEG, BMP, TIFF
- **File Size Limit**: Up to 16MB for web uploads

## Project Structure

```
steganography-tool/
├── app.py                 # Flask web application
├── main.py               # Main entry point for web app
├── steganography.py      # Core steganography engine
├── steganography_gui.py  # Desktop GUI application
├── pyproject.toml        # Project dependencies
├── templates/
│   ├── index.html        # Web interface home page
│   └── result.html       # Results display page
├── static/
│   ├── uploads/          # Temporary upload folder
│   └── processed/        # Processed images folder
└── README.md            # This file
```

## Installation

1. **Install Python 3.11+**

2. **Install dependencies using uv (recommended) or pip:**
   ```bash
   # Using uv
   uv add pillow pycryptodome numpy flask gunicorn

   # Or using pip
   pip install pillow pycryptodome numpy flask gunicorn
   ```

## Usage

### Web Application

1. **Start the web server:**
   ```bash
   python main.py
  
   ```

2. **Open your browser and navigate to:**
 

3. **Use the interface to:**
   - **Hide Message**: Upload an image, enter your secret message, optionally set an encryption key
   - **Reveal Message**: Upload a steganographic image, enter decryption key if used

### Desktop GUI Application

1. **Run the GUI application:**
   ```bash
   python steganography_gui.py
   ```

2. **Use the tabbed interface:**
   - **Hide Message Tab**: Select cover image, enter message, set encryption key, choose output location
   - **Reveal Message Tab**: Select steganographic image, enter decryption key, view extracted message

## How It Works

### LSB Steganography
The tool uses Least Significant Bit embedding to hide data in image pixels. Each pixel channel (R, G, B) can store 2 bits of data in its least significant bits without causing visible changes to the image.

### Encryption Process
1. Message is encrypted using AES-256 in CBC mode (if key provided)
2. A header containing message size and CRC32 checksum is created
3. Data is converted to binary and embedded in image pixels using LSB
4. Modified image is saved as PNG to preserve data integrity

### Extraction Process
1. LSB data is extracted from image pixels
2. Header is parsed to get message size and expected checksum
3. Data integrity is verified using CRC32
4. Message is decrypted if encryption key is provided

## Security Features

- **AES-256 Encryption**: Industry-standard encryption for message protection
- **CRC32 Checksums**: Detects data corruption or tampering
- **Key Padding**: Automatic key padding/truncation to 32 bytes for AES-256
- **File Validation**: Ensures uploaded files are valid images

## API Endpoints (Web App)

- `GET /` - Main interface
- `POST /embed` - Hide message in image
- `POST /extract` - Extract message from image
- `GET /download/<filename>` - Download steganographic image

## Dependencies

- **PIL (Pillow)**: Image processing
- **numpy**: Array operations for pixel manipulation
- **pycryptodome**: AES encryption and cryptographic functions
- **Flask**: Web framework (for web app)
- **tkinter**: GUI framework (for desktop app, included with Python)
- **gunicorn**: WSGI server for production deployment

## Supported Image Formats

- PNG (recommended for steganographic images)
- JPEG/JPG
- BMP
- TIFF

**Note**: PNG is recommended for output as it preserves data without compression artifacts.

## Limitations

- Image must be large enough to hold the message data
- Compressed formats (JPEG) may cause data loss
- Maximum file size: 16MB (web interface)

## Security Considerations

- Use strong encryption keys for sensitive messages
- Keep decryption keys secure and separate from steganographic images
- Avoid editing or compressing steganographic images
- Use PNG format to prevent compression artifacts

## Error Handling

The application includes comprehensive error handling for:
- Invalid file formats
- Corrupted images
- Insufficient image capacity
- Wrong decryption keys
- Data corruption detection

## Example Usage

### Hiding a Message
1. Select a cover image (preferably high resolution)
2. Enter your secret message
3. Optionally set an encryption key for security
4. Generate steganographic image
5. Download and share the steganographic image

### Revealing a Message
1. Upload the steganographic image
2. Enter the decryption key (if message was encrypted)
3. Extract and view the hidden message

## License
This project is open source and available under the MIT License.
