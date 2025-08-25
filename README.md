# StegoHide: Secure Image Steganography 🎨🔒
StegoHide is a simple, web-based tool that allows you to secretly hide text messages within images (steganography) and then extract them securely using a password. It's designed for private, covert data transfer, making your secret messages look like an ordinary image.

✨ Features
Hide Messages (Encode):

Upload any PNG or JPEG image as a "cover" for your secret message.

Enter your confidential text message.

Securely encrypt your message using a password (AES-256 equivalent via Fernet).

Embeds the encrypted message into the Least Significant Bits (LSB) of the image's pixel data.

Downloads the new "stego-image" (always as PNG to preserve hidden data).

Reveal Messages (Decode):

Upload a stego-image created by StegoHide.

Provide the correct decryption password.

Extracts and decrypts the hidden message, displaying it on the webpage.

Client-Side Enhancements:

Live image previews on upload.

Client-side form validation (image selected, message not empty, password length).

Loading indicators on buttons during processing.

Interactive button ripple effect.

💻 Technologies Used
Backend (Python Flask):

Python 3.x: The core programming language.

Flask: A micro web framework for handling routes, requests, and serving HTML templates.

Pillow (PIL Fork): For robust image manipulation (opening, accessing pixel data, saving).

cryptography Library (Fernet): Provides strong, symmetric encryption to secure your hidden messages using a password.

Frontend (HTML, CSS, JavaScript):

HTML5: Structures the web page content.

CSS3 (Tailwind CSS & Custom):

Tailwind CSS: A utility-first CSS framework for rapid and responsive styling.

Custom CSS (static/css/style.css): Adds unique visual enhancements like gradient backgrounds, frosted glass effects, hover animations, and decorative elements.

JavaScript: Enhances user experience with image previews, client-side validation, loading spinners, and button ripple effects.

📁 File Structure
StegoHide/
|-- app.py                  # Flask backend: server logic, steganography, encryption/decryption
|-- requirements.txt        # Python dependencies
|-- templates/
|   |-- index.html          # Main web page (HTML structure, forms, Jinja2 templating)
|-- static/
|   |-- css/
|   |   |-- style.css       # Custom CSS for visual flair
|   |-- js/
|       |-- main.js         # JavaScript for frontend interactivity

🚀 Setup and Installation
Follow these steps to get StegoHide running on your local machine:

Clone the Repository (or create the files):
If you're starting from scratch, create the StegoHide/ directory and all the files as described in the File Structure section.

Create a Python Virtual Environment (Recommended):
It's good practice to use a virtual environment to manage dependencies, keeping them separate from your global Python packages.

python -m venv venv

Activate the Virtual Environment:

Windows:

.\venv\Scripts\activate

macOS/Linux:

source venv/bin/activate

Install Python Dependencies:
Make sure your requirements.txt file is in the root directory and contains:

Flask
Pillow
cryptography

Then, install them:

pip install -r requirements.txt

▶️ How to Run the Application
Activate your virtual environment (if not already active).

Navigate to the StegoHide/ directory in your terminal.

Run the Flask application:

python app.py

You should see output indicating that the Flask server is running, typically on http://127.0.0.1:5000/.

Open your web browser and go to http://127.0.0.1:5000/.

📋 How to Use
Hiding a Message (Encode)
In the "Hide Message (Encode)" section:

Click "Choose File" and select an image (PNG is highly recommended; JPEG can lead to data loss due to compression).

Type your secret message into the "Your Secret Message" textarea.

Enter an "Encryption Password". Remember this password! You'll need it to decrypt the message later.

Click the "Encode Message & Download Image" button.

Your browser will download a file named stego_image.png. This is your image with the hidden, encrypted message.

Revealing a Message (Decode)
In the "Reveal Message (Decode)" section:

Click "Choose File" and upload the stego_image.png file you previously generated.

Enter the exact same password that was used during encoding into the "Decryption Password" field.

Click the "Decode Message" button.

If the image is valid and the password is correct, your secret message will appear in a green "flash message" alert at the top of the page!

⁉️ Troubleshooting
"Site not working" / Raw Jinja2 tags ({% ... %}):

Solution: Ensure your app.py Flask server is running in your terminal, and you are accessing the site via the URL provided by Flask (e.g., http://127.0.0.1:5000), not by directly opening index.html in your browser.

"Error during encoding: Message too large to hide...":

Solution: Your message is too long for the selected image. Try a larger image or a shorter message.

"Error during encoding/decoding: An unexpected error occurred / InvalidToken":

Solution: This is almost always due to an incorrect password or a corrupted image.

Password: Double-check that the encryption and decryption passwords are exactly the same (case-sensitive, no extra spaces).

Image Corruption: Always use PNG images for steganography. If the stego_image.png was saved in a lossy format (like JPEG) or re-processed by another tool after encoding, the hidden data will be destroyed. Use the exact PNG file downloaded from the encoding step.

For detailed errors: Check the terminal where app.py is running. Any specific Python tracebacks will give precise clues.

✨ Future Enhancements (Ideas!)
Support for other media types: Extend steganography to audio or video files.

Different Steganography Algorithms: Implement more advanced LSB variants or other techniques for increased robustness.

Key Sharing Mechanism: Develop a more secure way to share the decryption key with the recipient, perhaps via a one-time link or QR code.

User Accounts: Allow users to manage their encoded/decoded messages or images.

Interactive Messaging: Integrate a simple chat interface where messages are automatically steganographically hidden.

Error Reporting: A more user-friendly way to display detailed error messages without exposing sensitive backend information.
