import io
import os
import sys
import base64
import logging
import PyPDF2
import speech_recognition as sr
from werkzeug.utils import secure_filename
from pydub import AudioSegment
from flask import current_app
import requests

logger = logging.getLogger(__name__)

def process_input(input_type, text_input, file_input):
    """
    Process user input based on the type.
    Returns (content, original_filename).
    """
    logger.debug(f"Processing input of type: {input_type}")
    
    if input_type == 'text':
        # Process text input
        if not text_input:
            raise ValueError("No text input provided")
        # Ensure text is UTF-8 encoded
        return text_input.encode('utf-8'), None
        
    elif input_type == 'txt':
        # Process text file
        if not file_input:
            raise ValueError("No file provided")
            
        filename = secure_filename(file_input.filename)
        file_content = file_input.read()
        
        # For text files, ensure the content is properly encoded as UTF-8
        try:
            # Try to decode to ensure it's valid text
            decoded_content = file_content.decode('utf-8', errors='replace')
            # Re-encode consistently with utf-8
            return decoded_content.encode('utf-8'), filename
        except Exception as e:
            logger.error(f"Error processing text file: {str(e)}")
            # Return the file content as is if decoding fails
            return file_content, filename
        
    elif input_type == 'pdf':
        # Process PDF file
        if not file_input:
            raise ValueError("No file provided")
            
        filename = secure_filename(file_input.filename)
        pdf_content = file_input.read()
        
        # Extract text from PDF
        try:
            text_content = extract_text_from_pdf(pdf_content)
            # Ensure consistent UTF-8 encoding
            return text_content.encode('utf-8'), filename
        except Exception as e:
            logger.error(f"Error processing PDF: {str(e)}")
            raise ValueError(f"Error processing PDF: {str(e)}")
        
    elif input_type == 'voice':
        # Process voice file
        if not file_input:
            raise ValueError("No file provided")
            
        filename = secure_filename(file_input.filename)
        voice_content = file_input.read()
        
        # Convert voice to text
        try:
            text_content = transcribe_audio(voice_content, filename)
            # Ensure consistent UTF-8 encoding
            return text_content.encode('utf-8'), filename
        except Exception as e:
            logger.error(f"Error processing voice file: {str(e)}")
            raise ValueError(f"Error processing voice file: {str(e)}")
        
    else:
        raise ValueError(f"Unsupported input type: {input_type}")

def extract_text_from_pdf(pdf_content):
    """Extract text from PDF binary content."""
    try:
        pdf_file = io.BytesIO(pdf_content)
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        
        text = ""
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            text += page.extract_text() or ""  # Handle pages with no text
            
        if not text.strip():
            return "[PDF contains no extractable text]"
            
        return text
    except Exception as e:
        logger.error(f"Error extracting text from PDF: {str(e)}")
        raise ValueError(f"Could not extract text from PDF: {str(e)}")

def transcribe_audio(audio_data, filename):
    """Transcribe audio content to text."""
    try:
        # Save audio data to a temporary file
        temp_path = f"temp_{secure_filename(filename)}"
        with open(temp_path, 'wb') as temp_file:
            temp_file.write(audio_data)
        
        # Determine file format from extension
        file_ext = filename.split('.')[-1].lower()
        
        # Convert to WAV if needed (as speech_recognition works best with WAV)
        if file_ext != 'wav':
            try:
                audio = AudioSegment.from_file(temp_path, format=file_ext)
                audio.export(temp_path + '.wav', format='wav')
                temp_path = temp_path + '.wav'
            except Exception as e:
                logger.error(f"Error converting audio to WAV: {str(e)}")
                return f"[Audio conversion failed: {str(e)}]"
        
        # Initialize recognizer
        r = sr.Recognizer()
        
        # Load audio file
        with sr.AudioFile(temp_path) as source:
            audio_data = r.record(source)
            
        # Transcribe
        try:
            text = r.recognize_google(audio_data)
            if not text:
                return "[No speech detected]"
            return text
        except sr.UnknownValueError:
            return "[Speech recognition could not understand audio]"
        except sr.RequestError as e:
            return f"[Speech recognition service error: {str(e)}]"
        
    except Exception as e:
        logger.error(f"Error transcribing audio: {str(e)}")
        return f"[Transcription failed: {str(e)}]"
    finally:
        # Clean up temporary files
        import os
        if os.path.exists(temp_path):
            os.remove(temp_path)

def format_key_for_display(binary_key):
    """Convert binary key to base64 for display."""
    return base64.b64encode(binary_key).decode('utf-8')

def parse_key_from_input(key_string):
    """Convert base64 key string back to binary."""
    try:
        # Clean up the key string - remove whitespace, newlines, etc.
        key_string = key_string.strip()
        
        # Check if already in binary format
        if isinstance(key_string, bytes):
            return key_string
            
        # Try to decode as base64
        return base64.b64decode(key_string)
    except Exception as e:
        logger.error(f"Key parsing error: {str(e)}")
        raise ValueError("Invalid key format. The master key must be the exact base64 string provided during encryption.")

def validate_email(email):
    """
    Validate an email address using Mailboxlayer API.
    
    Args:
        email (str): The email address to validate
        
    Returns:
        bool: True if the email is valid, False otherwise
    """
    try:
        # Mailboxlayer API key from environment
        api_key = os.environ.get('MAILBOXLAYER_API_KEY', '7c639742be0b2367c967904ba21b96dc')
        
        # API endpoint
        url = f"http://apilayer.net/api/check?access_key={api_key}&email={email}&smtp=1&format=1"
        
        # Make the request
        response = requests.get(url)
        data = response.json()
        
        # Log the response
        logger.debug(f"Mailboxlayer API response: {data}")
        
        # Check if the email is valid
        if data.get('format_valid') and data.get('smtp_check'):
            logger.info(f"Email {email} is valid according to Mailboxlayer")
            return True
        else:
            logger.warning(f"Email {email} is invalid according to Mailboxlayer: {data}")
            return False
    except Exception as e:
        logger.error(f"Error validating email with Mailboxlayer: {str(e)}")
        return False  # Default to True to prevent blocking registration if API fails

def send_encryption_key_email(user_email, master_key, data_info):
    """
    Send the encryption key to the user's email address using SparkPost.
    First validates the email using Mailboxlayer API.
    
    Args:
        user_email (str): The recipient's email address
        master_key (str): The base64-encoded master key
        data_info (dict): Information about the encrypted data
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    # Validate the email first
    if not validate_email(user_email):
        logger.warning(f"Email {user_email} is not valid. Skipping email sending.")
        return False
    
    try:
        import os
        from sparkpost import SparkPost

        # Get SparkPost API key from environment
        sparkpost_api_key = os.environ.get('SPARKPOST_API_KEY')
        if not sparkpost_api_key:
            logger.error("SparkPost API key not found in environment variables")
            return False
            
        # Create SparkPost client
        sp = SparkPost(sparkpost_api_key)
        
        # Prepare email subject and content
        subject = "Your DSSE Encryption Key"
        
        # Get encryption details
        input_type = data_info.get('input_type', 'unknown')
        filename = data_info.get('filename', 'Unnamed')
        created_at = data_info.get('created_at', 'N/A')
        
        # Create email content
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #4a6ee0; color: white; padding: 10px 20px; }}
                .content {{ padding: 20px; background-color: #f9f9f9; }}
                .master-key {{ font-family: monospace; background-color: #e9e9e9; 
                               padding: 10px; margin: 10px 0; display: block; }}
                .footer {{ font-size: 12px; color: #666; margin-top: 20px; 
                          border-top: 1px solid #eee; padding-top: 10px; }}
                .warning {{ color: #e74c3c; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>IMPORTANT: STORE THIS INFORMATION SECURELY</h2>
                </div>
                <div class="content">
                    <p>Dear User,</p>
                    <p>You have successfully encrypted data using the DSSE tool. 
                    Please save the following information securely. You will need 
                    the master key to decrypt your data in the future.</p>
                    
                    <h3>ENCRYPTION DETAILS:</h3>
                    <ul>
                        <li><strong>Input Type:</strong> {input_type}</li>
                        <li><strong>Original Filename:</strong> {filename}</li>
                        <li><strong>Created At:</strong> {created_at}</li>
                    </ul>
                    
                    <h3>MASTER KEY:</h3>
                    <code class="master-key">{master_key}</code>
                    
                    <p class="warning">WARNING: This key cannot be recovered if lost. 
                    We recommend storing it in a secure password manager.</p>
                    
                    <p>Do not share this key with anyone.</p>
                    
                    <p>Best regards,<br>DSSE Tool</p>
                </div>
                <div class="footer">
                    This is an automated message. Please do not reply to this email.
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text version for email clients that don't support HTML
        text_content = f"""
IMPORTANT: STORE THIS INFORMATION SECURELY

Dear User,

You have successfully encrypted data using the DSSE tool. 
Please save the following information securely. You will need 
the master key to decrypt your data in the future.

ENCRYPTION DETAILS:
- Input Type: {input_type}
- Original Filename: {filename}
- Created At: {created_at}

MASTER KEY:
{master_key}

WARNING: This key cannot be recovered if lost. We recommend storing 
it in a secure password manager.

Do not share this key with anyone.

Best regards,
DSSE Tool
        """
        
        # Log that we're sending an email
        logger.info(f"Sending encryption key email to {user_email}")
        
        # Send the email via SparkPost
        response = sp.transmissions.send(
            recipients=[user_email],
            html=html_content,
            text=text_content,
            from_email='dsse-tool@sparkpostmail.com',  # Use your verified sending domain here
            subject=subject
        )
        
        # Log successful sending
        logger.info(f"Email sent successfully to {user_email}. SparkPost response: {response}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send encryption key email: {str(e)}")
        return False
