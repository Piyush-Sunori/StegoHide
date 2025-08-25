document.addEventListener('DOMContentLoaded', () => {
    // This code runs once the entire web page (HTML) has loaded.
    // It's a good practice to put JavaScript that interacts with HTML
    // inside this listener to ensure all elements are available.

    // --- Getting References to Our HTML Elements ---
    const imageInput = document.getElementById('image');
    const imagePreview = document.getElementById('image-preview');
    const stegoImageInput = document.getElementById('stego_image');
    const stegoImagePreview = document.getElementById('stego-image-preview');

    const encodeForm = document.querySelector('form[action="/encode"]');
    const decodeForm = document.querySelector('form[action="/decode"]');
    const encodeButton = encodeForm ? encodeForm.querySelector('button[type="submit"]') : null;
    const decodeButton = decodeForm ? decodeForm.querySelector('button[type="submit"]') : null;

    // --- Helper Function for Image Previews ---
    const setupImagePreview = (inputElement, previewElement) => {
        if (!inputElement || !previewElement) return; // Guard against missing elements

        inputElement.addEventListener('change', (event) => {
            const file = event.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    previewElement.src = e.target.result;
                    previewElement.classList.remove('hidden');
                };
                reader.readAsDataURL(file);
            } else {
                previewElement.classList.add('hidden');
                previewElement.src = '#';
            }
        });
    };

    // --- Applying the Preview Function to Our Forms ---
    setupImagePreview(imageInput, imagePreview);
    setupImagePreview(stegoImageInput, stegoImagePreview);

    // --- Client-Side Validation and Loading Indicators ---

    // Function to show a loading state on buttons
    const showLoading = (button, originalText, loadingText) => {
        if (button) {
            button.innerHTML = `<svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>${loadingText}`;
            button.disabled = true;
            button.classList.add('cursor-not-allowed', 'opacity-70', 'flex', 'items-center', 'justify-center');
            button.dataset.originalText = originalText; // Store original text to restore later
        }
    };

    // Function to hide loading state
    const hideLoading = (button) => {
        if (button && button.dataset.originalText) {
            button.innerHTML = button.dataset.originalText;
            button.disabled = false;
            button.classList.remove('cursor-not-allowed', 'opacity-70', 'flex', 'items-center', 'justify-center');
            delete button.dataset.originalText;
        }
    };

    // Encode Form Validation and Loading
    if (encodeForm) {
        encodeForm.addEventListener('submit', (event) => {
            const messageInput = document.getElementById('message');
            const passwordInput = document.getElementById('password');

            if (!imageInput.files[0]) {
                alert('Please select an image file to hide your message!');
                event.preventDefault();
                return;
            }
            if (messageInput.value.trim() === '') {
                alert('Your secret message cannot be empty!');
                event.preventDefault();
                return;
            }
            if (passwordInput.value.length < 6) { // Minimum password length
                alert('The encryption password should be at least 6 characters long!');
                event.preventDefault();
                return;
            }

            // If validation passes, show loading
            showLoading(encodeButton, encodeButton.innerText, 'Hiding Message...');
        });
    }

    // Decode Form Validation and Loading
    if (decodeForm) {
        decodeForm.addEventListener('submit', (event) => {
            const passwordDecodeInput = document.getElementById('password_decode');

            if (!stegoImageInput.files[0]) {
                alert('Please upload the stego-image to reveal the message!');
                event.preventDefault();
                return;
            }
            if (passwordDecodeInput.value.length < 6) { // Minimum password length
                alert('The decryption password should be at least 6 characters long!');
                event.preventDefault();
                return;
            }

            // If validation passes, show loading
            showLoading(decodeButton, decodeButton.innerText, 'Revealing Message...');
        });
    }

    // --- Clearing Input Fields After Successful Operations ---
    // We check for the presence of a Flask flash message indicating success
    const decodedMessageFlash = document.querySelector('.flash-message.bg-green-100');
    if (decodedMessageFlash) {
        // If a decoded message is shown, it means decoding was successful.
        // Clear the decode form for the next operation.
        if (decodeForm) decodeForm.reset();
        if (stegoImagePreview) stegoImagePreview.classList.add('hidden');
        if (stegoImagePreview) stegoImagePreview.src = '#';
    }
    // You could also add logic here to clear the encode form if you had a success message
    // for encoding (e.g., if Flask flashed a message after download completes).
    // For now, after download, it's generally good to let the user see the form as-is.

    // --- Button Ripple Effect ---
    document.querySelectorAll('button[type="submit"]').forEach(button => {
        button.addEventListener('click', function(e) {
            const buttonRect = this.getBoundingClientRect();
            const x = e.clientX - buttonRect.left;
            const y = e.clientY - buttonRect.top;

            const ripple = document.createElement('span');
            ripple.classList.add('ripple'); // Using the CSS we defined for .ripple
            ripple.style.left = `${x}px`;
            ripple.style.top = `${y}px`;
            this.appendChild(ripple);

            // Remove the ripple element after the animation
            ripple.addEventListener('animationend', () => {
                ripple.remove();
            });
        });
    });

    // Add a custom CSS for the ripple effect in style.css, this will only style the element
    // when it's created by JS.
    const styleSheet = document.styleSheets[0];
    if (styleSheet) {
        styleSheet.insertRule(`
            .ripple {
                position: absolute;
                background: rgba(255, 255, 255, 0.5);
                border-radius: 50%;
                animation: ripple-effect 0.6s linear forwards;
                transform: translate(-50%, -50%);
                pointer-events: none;
                z-index: 10;
            }
        `, styleSheet.cssRules.length);

        styleSheet.insertRule(`
            @keyframes ripple-effect {
                0% {
                    width: 0;
                    height: 0;
                    opacity: 1;
                }
                100% {
                    width: 200%; /* Make it large enough to cover the button */
                    height: 200%;
                    opacity: 0;
                }
            }
        `, styleSheet.cssRules.length);
    }
});
