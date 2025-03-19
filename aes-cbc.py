from flask import Flask, request, render_template_string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)

# Static key (16 bytes of ASCII 'A'). Not secure in production!
STATIC_KEY = b'A' * 16
ZERO_IV = b'\x00' * 16  # IV set to all zeros (insecure)

# HTML template embedded directly into the script
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>AES Encryption & Decryption</title>
</head>
<body>
    <h2>AES-CBC Encryption & Decryption</h2>

    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}

    <form method="get" action="/">
        <label>Enter plaintext to encrypt:</label><br>
        <input type="text" name="plaintext">
        <input type="hidden" name="mode" value="encrypt">
        <button type="submit">Encrypt</button>
    </form>

    {% if encrypted %}
        <p><strong>Encrypted (Base64):</strong> {{ encrypted }}</p>
    {% endif %}

    <hr>

    <form method="get" action="/">
        <label>Enter ciphertext (Base64) to decrypt:</label><br>
        <input type="text" name="ciphertext">
        <input type="hidden" name="mode" value="decrypt">
        <button type="submit">Decrypt</button>
    </form>

    {% if decrypted %}
        <p><strong>Decrypted plaintext:</strong> {{ decrypted }}</p>
    {% endif %}

    <hr>

    <form method="post" enctype="multipart/form-data" action="/upload">
        <label>Upload file with plaintext or ciphertext (multiple lines):</label><br>
        <input type="file" name="file" required>
        <select name="mode">
            <option value="encrypt">Encrypt</option>
            <option value="decrypt">Decrypt</option>
        </select>
        <button type="submit">Process File</button>
    </form>

    {% if file_results %}
        <h3>File Processing Results:</h3>
        <pre>{{ file_results }}</pre>
    {% endif %}

</body>
</html>
"""

# Padding to ensure plaintext length is a multiple of 16 bytes
def pad(data):
    padding_length = 16 - (len(data) % 16)
    return data + (chr(padding_length) * padding_length).encode()

# Remove padding after decryption
def unpad(data):
    padding_length = data[-1]
    if padding_length > 16:
        raise ValueError("Invalid padding")
    return data[:-padding_length]

# AES encryption using AES-CBC with static key and zero IV
def aes_encrypt(plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(STATIC_KEY), modes.CBC(ZERO_IV), backend=backend)
    encryptor = cipher.encryptor()
    padded_data = pad(plaintext.encode())
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()

# AES decryption using AES-CBC with static key and zero IV
def aes_decrypt(ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(STATIC_KEY), modes.CBC(ZERO_IV), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
    return unpad(decrypted_padded).decode()

@app.route('/', methods=['GET'])
def index():
    encrypted_text, decrypted_text, error = None, None, None

    mode = request.args.get('mode')
    plaintext = request.args.get('plaintext')
    ciphertext = request.args.get('ciphertext')

    if mode == 'encrypt' and plaintext:
        try:
            encrypted_text = aes_encrypt(plaintext)
        except Exception as e:
            error = f'Encryption Error: {str(e)}'

    elif mode == 'decrypt' and ciphertext:
        try:
            decrypted_text = aes_decrypt(ciphertext)
        except Exception as e:
            error = f'Decryption Error: {str(e)}'

    return render_template_string(HTML_TEMPLATE, encrypted=encrypted_text, decrypted=decrypted_text, error=error)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    results = []
    error = None

    if request.method == 'POST':
        file = request.files.get('file')
        mode = request.form.get('mode')

        if not file:
            error = 'No file uploaded.'
        elif mode not in ['encrypt', 'decrypt']:
            error = 'Invalid mode selected.'
        else:
            try:
                lines = file.read().decode().splitlines()
                for line in lines:
                    if mode == 'encrypt':
                        results.append(f"Plaintext: {line} | Ciphertext: {aes_encrypt(line)}")
                    elif mode == 'decrypt':
                        results.append(f"Ciphertext: {line} | Plaintext: {aes_decrypt(line)}")
            except Exception as e:
                error = f'File Processing Error: {str(e)}'

    elif request.method == 'GET':
        mode = request.args.get('mode')
        plaintext = request.args.get('plaintext')
        ciphertext = request.args.get('ciphertext')

        try:
            if mode == 'encrypt' and plaintext:
                results.append(f"Plaintext: {plaintext} | Ciphertext: {aes_encrypt(plaintext)}")
            elif mode == 'decrypt' and ciphertext:
                results.append(f"Ciphertext: {ciphertext} | Plaintext: {aes_decrypt(ciphertext)}")
        except Exception as e:
            error = f'Error: {str(e)}'

    return render_template_string(HTML_TEMPLATE, file_results='\n'.join(results) if results else None, error=error)

if __name__ == '__main__':
    app.run(debug=True)
