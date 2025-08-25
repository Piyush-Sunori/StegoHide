import os
import io
import base64
from flask import Flask, request, render_template, send_file, flash, redirect, url_for
from PIL import Image # Pillow helps us work with images
from cryptography.fernet import Fernet # This is for strong encryption!
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Used to turn a password into a super-secure key
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
# We need a secret key for Flask to keep sessions secure and show little messages to the user.
app.config['SECRET_KEY'] = os.urandom(24)
# Let's set a limit so folks don't upload gigantic files and crash our app! (16MB max)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# --- Handy Functions for Turning Passwords into Super Secret Keys ---

def derive_key(password: str, salt: bytes) -> bytes:
    """
    This magical function takes your everyday password and a unique 'salt'
    to create a really strong encryption key. Think of the salt as a secret spice
    that makes each key unique, even if two people use the same password!
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # We want a 32-byte (256-bit) key for robust security
        salt=salt,
        iterations=100000, # A high number of these 'mixing' iterations makes it super hard for bad guys to guess your password!
        backend=default_backend()
    )
    # Fernet needs keys to be URL-safe base64, so we convert it for them.
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- Steganography Functions (LSB) ---

def text_to_binary(text: str) -> str:
    """
    Turns plain text into a long string of 0s and 1s (binary).
    Every letter becomes 8 bits. It's like converting letters into a secret code the computer understands.
    """
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary_string: str) -> str:
    """
    Reverses the trick! Takes that long string of 0s and 1s and brings it back to readable text.
    It groups the bits into 8s to form characters.
    """
    # Ensure the binary string length is a multiple of 8
    binary_string = binary_string[:len(binary_string) - (len(binary_string) % 8)]
    chars = []
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def hide_message(image: Image.Image, message_binary: str) -> Image.Image:
    """
    Hides a binary message in an image using LSB steganography.
    Modifies the least significant bit of each color channel.
    """
    print(f"\n--- HIDE MESSAGE DEBUG ---")
    print(f"Original message_binary length: {len(message_binary)}")

    if image.mode not in ('RGB', 'RGBA'):
        image = image.convert('RGBA')

    width, height = image.size
    pixels = image.load()

    # The length of the ENTIRE payload (message_binary) is stored first
    message_binary_length = len(message_binary)
    # We use 32 bits (4 bytes) to store the length of the message_binary
    length_binary = format(message_binary_length, '032b')

    # Combine length header and the actual message binary data
    full_binary_to_hide = length_binary + message_binary
    print(f"Length binary: {length_binary} (32 bits)")
    print(f"Full binary to hide length (header + payload): {len(full_binary_to_hide)}")

    # Calculate maximum capacity of the image (3 bits per pixel for RGB)
    max_capacity_bits = width * height * 3
    print(f"Image capacity (bits): {max_capacity_bits}")

    if len(full_binary_to_hide) > max_capacity_bits:
        raise ValueError("Message too large to hide in this image.")

    data_index = 0
    for y in range(height):
        for x in range(width):
            r, g, b, *a = pixels[x, y] # Get R, G, B, and optional A (alpha)
            
            # Modify LSB of R, G, B channels
            new_r, new_g, new_b = r, g, b

            if data_index < len(full_binary_to_hide):
                new_r = (r & 0xFE) | int(full_binary_to_hide[data_index])
                data_index += 1
            if data_index < len(full_binary_to_hide):
                new_g = (g & 0xFE) | int(full_binary_to_hide[data_index])
                data_index += 1
            if data_index < len(full_binary_to_hide):
                new_b = (b & 0xFE) | int(full_binary_to_hide[data_index])
                data_index += 1

            # Set the new pixel value
            if image.mode == 'RGBA':
                pixels[x, y] = (new_r, new_g, new_b, a[0] if a else 255)
            else:
                pixels[x, y] = (new_r, new_g, new_b)
            
            if data_index >= len(full_binary_to_hide):
                print(f"Total bits hidden: {data_index}")
                print(f"--- HIDE MESSAGE DEBUG END ---")
                return image # Message fully hidden

    print(f"Total bits hidden (end of image scan): {data_index}")
    print(f"--- HIDE MESSAGE DEBUG END ---")
    return image # Should only reach here if message fills entire image, but less than capacity

def reveal_message(image: Image.Image) -> str:
    """
    Extracts a binary message hidden in an image using LSB steganography.
    """
    print(f"\n--- REVEAL MESSAGE DEBUG ---")

    if image.mode not in ('RGB', 'RGBA'):
        image = image.convert('RGBA')

    width, height = image.size
    pixels = image.load()
    
    all_extracted_bits = []
    
    # Extract all possible bits, up to image capacity
    for y in range(height):
        for x in range(width):
            r, g, b, *a = pixels[x, y]
            all_extracted_bits.append(str(r & 1))
            all_extracted_bits.append(str(g & 1))
            all_extracted_bits.append(str(b & 1))
    
    full_extracted_binary_string = "".join(all_extracted_bits)
    print(f"Total extracted bits from image: {len(full_extracted_binary_string)}")

    # Extract the message length (first 32 bits)
    if len(full_extracted_binary_string) < 32:
        raise ValueError("Image too small or no length header found to reveal message.")
    
    length_binary_header = full_extracted_binary_string[:32]
    message_binary_length = int(length_binary_header, 2)
    print(f"Extracted length binary header: {length_binary_header}")
    print(f"Decoded message_binary_length: {message_binary_length} bits")

    # Extract the actual message binary data based on the decoded length
    # It starts AFTER the 32-bit length header
    start_of_message = 32
    end_of_message = start_of_message + message_binary_length

    if len(full_extracted_binary_string) < end_of_message:
        raise ValueError("Extracted data is shorter than indicated message length. Image might be corrupted or message truncated.")

    extracted_message_binary = full_extracted_binary_string[start_of_message:end_of_message]
    print(f"Extracted message_binary length: {len(extracted_message_binary)}")
    print(f"--- REVEAL MESSAGE DEBUG END ---")

    return extracted_message_binary

# --- Flask Routes ---

@app.route('/')
def index():
    """Renders the main index page."""
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    """
    Handles image and text upload, encrypts the text, hides it,
    and returns the stego-image for download.
    """
    if 'image' not in request.files:
        flash('No image file part')
        return redirect(url_for('index'))
    
    file = request.files['image']
    message = request.form.get('message')
    password = request.form.get('password')

    if file.filename == '':
        flash('No selected image file')
        return redirect(url_for('index'))
    if not message:
        flash('No message provided')
        return redirect(url_for('index'))
    if not password:
        flash('No password provided')
        return redirect(url_for('index'))

    try:
        # Load image
        img = Image.open(file.stream)
        
        # Generate a unique salt for this encryption operation
        salt = os.urandom(16) # Fernet uses 16-byte salts
        key = derive_key(password, salt)
        f = Fernet(key)

        # Encrypt the message. Prepend salt to the encrypted message.
        # This allows the receiver to use the same password and the embedded salt to derive the key.
        encrypted_message_bytes = f.encrypt(message.encode())
        full_payload_bytes = salt + encrypted_message_bytes
        
        print(f"\n--- ENCODE ROUTE DEBUG ---")
        print(f"Salt (bytes, length 16): {salt}")
        print(f"Encrypted message (bytes): {encrypted_message_bytes}")
        print(f"Full payload (salt + encrypted message, bytes) length: {len(full_payload_bytes)}")

        # Convert full_payload (bytes) to binary string for LSB embedding
        full_payload_binary = ''.join(format(byte, '08b') for byte in full_payload_bytes)
        print(f"Full payload binary string length: {len(full_payload_binary)} bits")

        stego_image = hide_message(img.copy(), full_payload_binary)

        # Save stego-image to a BytesIO object to send it back
        img_byte_arr = io.BytesIO()
        stego_image.save(img_byte_arr, format='PNG') # PNG is lossless, crucial for steganography
        img_byte_arr.seek(0)
        print(f"--- ENCODE ROUTE DEBUG END ---")

        # Using 'filename' for compatibility with older Flask versions if not updated
        return send_file(img_byte_arr, mimetype='image/png', as_attachment=True, download_name='stego_image.png')

    except ValueError as e:
        flash(f'Error during encoding: {e}', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        print(f"DEBUGGING ENCODE ERROR: {e}")
        import traceback
        traceback.print_exc()
        flash(f'An unexpected error occurred during encoding: {e}', 'error')
        return redirect(url_for('index'))

@app.route('/decode', methods=['POST'])
def decode():
    """
    Handles stego-image upload, extracts and decrypts the hidden message,
    and displays the original message.
    """
    if 'stego_image' not in request.files:
        flash('No stego image file part', 'error')
        return redirect(url_for('index'))
    
    file = request.files['stego_image']
    password = request.form.get('password_decode')

    if file.filename == '':
        flash('No selected stego image file', 'error')
        return redirect(url_for('index'))
    if not password:
        flash('No password provided for decoding', 'error')
        return redirect(url_for('index'))

    try:
        img = Image.open(file.stream)
        
        # Reveal the full binary payload (salt + encrypted message)
        full_payload_binary_extracted = reveal_message(img)
        print(f"\n--- DECODE ROUTE DEBUG ---")
        print(f"Full payload binary extracted length: {len(full_payload_binary_extracted)} bits")

        # Convert binary string back to bytes
        # Ensure it's a multiple of 8 bits before converting to bytes
        if len(full_payload_binary_extracted) % 8 != 0:
            # This should ideally not happen if hide/reveal logic is perfect,
            # but it's a safety net.
            print("WARNING: Extracted binary length not a multiple of 8. Truncating.")
            full_payload_binary_extracted = full_payload_binary_extracted[:-(len(full_payload_binary_extracted) % 8)]

        full_payload_bytes_extracted = bytes(int(full_payload_binary_extracted[i:i+8], 2) for i in range(0, len(full_payload_binary_extracted), 8))
        print(f"Full payload bytes extracted length: {len(full_payload_bytes_extracted)} bytes")
        
        # The first 16 bytes of the payload are the salt
        salt = full_payload_bytes_extracted[:16]
        encrypted_message_bytes_extracted = full_payload_bytes_extracted[16:]

        print(f"Extracted salt (bytes, length {len(salt)}): {salt}")
        print(f"Extracted encrypted message (bytes, length {len(encrypted_message_bytes_extracted)}): {encrypted_message_bytes_extracted}")

        if len(salt) != 16:
             raise ValueError("Extracted salt is not 16 bytes long. Data might be corrupted or not a valid stego-image.")
        if not encrypted_message_bytes_extracted:
            raise ValueError("No encrypted message extracted after salt. Data might be corrupted or not a valid stego-image.")


        key = derive_key(password, salt)
        f = Fernet(key)

        # Decrypt the message
        decrypted_message = f.decrypt(encrypted_message_bytes_extracted).decode()
        print(f"Decryption successful. Decrypted message length: {len(decrypted_message)}")
        print(f"--- DECODE ROUTE DEBUG END ---")
        
        # Store the decrypted message in the session to display on index.html
        flash(f'🎊 Your Secret Message: {decrypted_message}', 'decoded_message')
        return redirect(url_for('index'))

    except ValueError as e:
        print(f"DEBUGGING DECODE ERROR (ValueError): {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error during decoding: {e}. This might be due to an incorrect password, a corrupted image, or no hidden message.', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        print(f"DEBUGGING DECODE ERROR (General Exception): {e}")
        import traceback
        traceback.print_exc()
        flash(f'An unexpected problem popped up while decoding: {e}. Please double-check the password and image!', 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    app.run(debug=True)
