import base64
import logging
from flask import render_template, redirect, url_for, flash, request, abort, jsonify, send_file, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
import os
import tempfile

from app import db
from models import User, EncryptedData
from forms import RegisterForm, LoginForm, EncryptForm, DecryptForm, SearchForm, UpdateForm
from crypto import DSSE
from utils import process_input, format_key_for_display, parse_key_from_input

logger = logging.getLogger(__name__)
dsse = DSSE()

def register_routes(app):
    @app.route('/')
    def index():
        """Homepage route."""
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """User registration route."""
        # Redirect if user is already logged in
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
            
        form = RegisterForm()
        if form.validate_on_submit():
            # Create new user
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=hashed_password
            )
            
            try:
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Registration error: {str(e)}")
                flash('An error occurred during registration. Please try again.', 'danger')
                
        return render_template('register.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """User login route."""
        # Redirect if user is already logged in
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
            
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            
            if user and check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('Login successful!', 'success')
                
                # Redirect to the requested page or dashboard
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Login failed. Please check your username and password.', 'danger')
                
        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        """User logout route."""
        logout_user()
        # Clear session data
        session.pop('recent_master_key', None)
        session.pop('recent_data_info', None)
        flash('You have been logged out.', 'info')
        return redirect(url_for('index'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        """User dashboard showing encrypted data."""
        encrypted_data = EncryptedData.query.filter_by(user_id=current_user.id).all()
        
        # Get master key from session if available (from recent encryption)
        recent_master_key = session.get('recent_master_key')
        recent_data_info = session.get('recent_data_info')
        
        return render_template('dashboard.html', 
                               encrypted_data=encrypted_data,
                               recent_master_key=recent_master_key,
                               recent_data_info=recent_data_info)

    @app.route('/encrypt', methods=['GET', 'POST'])
    @login_required
    def encrypt():
        """Route for encrypting data."""
        form = EncryptForm()
        
        if form.validate_on_submit():
            try:
                # Process input based on type
                input_type = form.input_type.data
                text_input = form.text_input.data
                file_input = request.files.get('file_input')
                
                # Validate input
                if input_type == 'text' and not text_input:
                    flash('Please enter text to encrypt.', 'danger')
                    return render_template('encrypt.html', form=form)
                    
                if input_type in ['txt', 'pdf', 'voice'] and not file_input:
                    flash(f'Please select a {input_type} file to encrypt.', 'danger')
                    return render_template('encrypt.html', form=form)
                
                # Process input
                content, original_filename = process_input(input_type, text_input, file_input)
                
                # Generate a master key
                master_key = dsse.generate_key()
                
                # Encrypt the content
                encrypted_content, search_index, iv, search_key = dsse.encrypt(content, master_key)
                
                # Save to database
                encrypted_data = EncryptedData(
                    user_id=current_user.id,
                    original_filename=original_filename,
                    input_type=input_type,
                    encrypted_content=encrypted_content,
                    search_index=search_index,
                    iv=iv,
                    search_key=search_key
                )
                
                db.session.add(encrypted_data)
                db.session.commit()
                
                # Format master key for display and email
                master_key_b64 = format_key_for_display(master_key)
                
                # Send email with master key to user
                from utils import send_encryption_key_email
                data_info = {
                    'input_type': input_type,
                    'filename': original_filename or 'Unnamed',
                    'created_at': encrypted_data.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'id': encrypted_data.id
                }
                
                # Store master key in session for the dashboard to display
                session['recent_master_key'] = master_key_b64
                session['recent_data_info'] = data_info
                
                # Attempt to send email with SparkPost
                email_sent = send_encryption_key_email(current_user.email, master_key_b64, data_info)
                
                if email_sent:
                    flash(f'Data encrypted successfully! The master key has been sent to your email ({current_user.email}). Please check your inbox (and spam folder) and save the key securely.', 'success')
                else:
                    flash('Data encrypted successfully! Please save your master key from the dashboard.', 'success')
                    flash('We were unable to send the master key to your email. Make sure to copy it from the dashboard now - it cannot be recovered if lost!', 'warning')
                    
                return redirect(url_for('dashboard'))
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"Encryption error: {str(e)}")
                flash(f'Encryption failed: {str(e)}', 'danger')
                
        return render_template('encrypt.html', form=form)

    @app.route('/decrypt', methods=['GET', 'POST'])
    @login_required
    def decrypt():
        """Route for decrypting data."""
        # Get user's encrypted data for selection
        user_data = EncryptedData.query.filter_by(user_id=current_user.id).all()
        
        # Create form and set choices
        form = DecryptForm()
        form.data_id.choices = [(data.id, f"{data.input_type}: {data.original_filename or 'Unnamed'} ({data.created_at.strftime('%Y-%m-%d %H:%M')})") 
                               for data in user_data]
        
        if not user_data:
            flash('You have no encrypted data to decrypt. Please encrypt some data first.', 'info')
            
        if form.validate_on_submit():
            try:
                # Get data and master key
                data_id = form.data_id.data
                master_key_b64 = form.master_key.data
                if master_key_b64 is None:
                    flash('Master key is required.', 'danger')
                    return render_template('decrypt.html', form=form)
                    
                master_key_b64 = master_key_b64.strip()  # Remove potential whitespace
                
                # Find the data
                encrypted_data = EncryptedData.query.get_or_404(data_id)
                
                # Verify ownership
                if encrypted_data.user_id != current_user.id:
                    abort(403)
                
                # Parse the master key
                try:
                    master_key = parse_key_from_input(master_key_b64)
                except ValueError as e:
                    flash(str(e), 'danger')
                    return render_template('decrypt.html', form=form)
                
                # Decrypt the data with improved error handling
                try:
                    decrypted_content = dsse.decrypt(
                        encrypted_data.encrypted_content,
                        encrypted_data.iv,
                        master_key
                    )
                    
                    # Handle different input types
                    if encrypted_data.input_type == 'text':
                        # For plain text content - ensure proper display
                        try:
                            decrypted_text = decrypted_content.decode('utf-8', errors='replace')
                            return render_template('decrypt.html', form=form, 
                                                decrypted_text=decrypted_text,
                                                data_type=encrypted_data.input_type)
                        except Exception as e:
                            logger.error(f"Error decoding text content: {str(e)}")
                            decrypted_text = decrypted_content.decode('latin-1', errors='replace')
                            return render_template('decrypt.html', form=form, 
                                                decrypted_text=decrypted_text,
                                                data_type=encrypted_data.input_type)
                                                
                    elif encrypted_data.input_type == 'txt':
                        # For text files
                        try:
                            decrypted_text = decrypted_content.decode('utf-8', errors='replace')
                            return render_template('decrypt.html', form=form, 
                                                decrypted_text=decrypted_text,
                                                data_type=encrypted_data.input_type,
                                                filename=encrypted_data.original_filename)
                        except Exception as e:
                            logger.error(f"Error decoding text file: {str(e)}")
                            decrypted_text = decrypted_content.decode('latin-1', errors='replace')
                            return render_template('decrypt.html', form=form, 
                                                decrypted_text=decrypted_text,
                                                data_type=encrypted_data.input_type,
                                                filename=encrypted_data.original_filename)
                                                
                    elif encrypted_data.input_type == 'pdf':
                        # For PDF files - should be plaintext extracted from the PDF
                        try:
                            decrypted_text = decrypted_content.decode('utf-8', errors='replace')
                            return render_template('decrypt.html', form=form, 
                                                decrypted_text=decrypted_text,
                                                data_type=encrypted_data.input_type,
                                                filename=encrypted_data.original_filename)
                        except Exception as e:
                            logger.error(f"Error decoding PDF content: {str(e)}")
                            decrypted_text = decrypted_content.decode('latin-1', errors='replace')
                            return render_template('decrypt.html', form=form, 
                                                decrypted_text=decrypted_text,
                                                data_type=encrypted_data.input_type,
                                                filename=encrypted_data.original_filename)
                                                
                    elif encrypted_data.input_type == 'voice':
                        # For voice files - this should be the transcribed text
                        try:
                            decrypted_text = decrypted_content.decode('utf-8', errors='replace')
                            
                            # Check if it's an error message from transcription
                            is_error = (
                                decrypted_text.startswith('[') and 
                                decrypted_text.endswith(']') and
                                any(err in decrypted_text for err in ['error', 'failed', 'could not'])
                            )
                            
                            return render_template('decrypt.html', form=form, 
                                                decrypted_text=decrypted_text,
                                                data_type=encrypted_data.input_type,
                                                filename=encrypted_data.original_filename,
                                                is_transcription_error=is_error)
                        except Exception as e:
                            logger.error(f"Error handling voice transcription: {str(e)}")
                            decrypted_text = decrypted_content.decode('latin-1', errors='replace')
                            return render_template('decrypt.html', form=form, 
                                                decrypted_text=decrypted_text,
                                                data_type=encrypted_data.input_type,
                                                filename=encrypted_data.original_filename)
                    
                    else:
                        # Unknown type - show as text
                        try:
                            decrypted_text = decrypted_content.decode('utf-8', errors='replace')
                        except Exception:
                            decrypted_text = "[Binary content]"
                            
                        return render_template('decrypt.html', form=form, 
                                            decrypted_text=decrypted_text,
                                            data_type="unknown")
                
                except ValueError as e:
                    logger.error(f"Decryption error with master key: {str(e)}")
                    flash(f'Decryption failed: {str(e)}', 'danger')
                    return render_template('decrypt.html', form=form)
                    
            except Exception as e:
                logger.error(f"General decryption error: {str(e)}")
                flash(f'Decryption failed: {str(e)}', 'danger')
                
        return render_template('decrypt.html', form=form)

    @app.route('/download/<int:data_id>', methods=['POST'])
    @login_required
    def download_decrypted(data_id):
        """Download decrypted content as a file."""
        # Get the encrypted data
        encrypted_data = EncryptedData.query.get_or_404(data_id)
        
        # Verify ownership
        if encrypted_data.user_id != current_user.id:
            abort(403)
            
        # Get master key from form
        master_key_b64 = request.form.get('master_key')
        if not master_key_b64:
            flash('Master key is required to download the file.', 'danger')
            return redirect(url_for('decrypt'))
            
        try:
            # Parse the master key
            master_key = parse_key_from_input(master_key_b64)
            
            # Decrypt the content
            decrypted_content = dsse.decrypt(
                encrypted_data.encrypted_content,
                encrypted_data.iv,
                master_key
            )
            
            # Prepare filename
            original_filename = encrypted_data.original_filename
            if not original_filename:
                if encrypted_data.input_type == 'text':
                    original_filename = "decrypted_text.txt"
                elif encrypted_data.input_type == 'voice':
                    original_filename = "transcribed_voice.txt"
                else:
                    original_filename = f"decrypted_{encrypted_data.id}.txt"
                    
            # Create BytesIO object for file download
            if encrypted_data.input_type in ['text', 'txt', 'pdf', 'voice']:
                # For text-based content, ensure proper encoding
                if isinstance(decrypted_content, bytes):
                    # Try to decode to ensure it's valid text
                    try:
                        decrypted_content = decrypted_content.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        # If it fails, use a more permissive encoding
                        decrypted_content = decrypted_content.decode('latin-1', errors='replace')
                        
                # Convert back to bytes for file download
                if isinstance(decrypted_content, str):
                    decrypted_content = decrypted_content.encode('utf-8')
                    
            # Create memory file and send
            memory_file = BytesIO(decrypted_content)
            memory_file.seek(0)
            
            return send_file(
                memory_file,
                download_name=original_filename,
                as_attachment=True,
                mimetype='text/plain'
            )
            
        except Exception as e:
            logger.error(f"Download error: {str(e)}")
            flash(f'Download failed: {str(e)}', 'danger')
            return redirect(url_for('decrypt'))

    @app.route('/search', methods=['GET', 'POST'])
    @login_required
    def search():
        """Route for searching in encrypted data."""
        # Get user's encrypted data for selection
        user_data = EncryptedData.query.filter_by(user_id=current_user.id).all()
        
        # Create form and set choices
        form = SearchForm()
        form.data_id.choices = [(data.id, f"{data.input_type}: {data.original_filename or 'Unnamed'} ({data.created_at.strftime('%Y-%m-%d %H:%M')})") 
                               for data in user_data]
        
        if not user_data:
            flash('You have no encrypted data to search. Please encrypt some data first.', 'info')
            
        search_results = None
        if form.validate_on_submit():
            try:
                # Get data and search term
                data_id = form.data_id.data
                search_term = form.search_term.data
                
                # Find the data
                encrypted_data = EncryptedData.query.get_or_404(data_id)
                
                # Verify ownership
                if encrypted_data.user_id != current_user.id:
                    abort(403)
                
                # Perform search
                positions = dsse.search(search_term, encrypted_data.search_index, encrypted_data.search_key)
                
                # Return results
                if positions:
                    search_results = {
                        'term': search_term,
                        'count': len(positions),
                        'positions': positions,
                        'data_type': encrypted_data.input_type,
                        'filename': encrypted_data.original_filename
                    }
                else:
                    flash(f'No matches found for "{search_term}".', 'info')
                
            except Exception as e:
                logger.error(f"Search error: {str(e)}")
                flash(f'Search failed: {str(e)}', 'danger')
                
        return render_template('search.html', form=form, results=search_results)

    @app.route('/update', methods=['GET', 'POST'])
    @login_required
    def update():
        """Route for updating encrypted data."""
        # Get user's encrypted data for selection
        user_data = EncryptedData.query.filter_by(user_id=current_user.id).all()
        
        # Create form and set choices
        form = UpdateForm()
        form.data_id.choices = [(data.id, f"{data.input_type}: {data.original_filename or 'Unnamed'} ({data.created_at.strftime('%Y-%m-%d %H:%M')})") 
                               for data in user_data]
        
        if not user_data:
            flash('You have no encrypted data to update. Please encrypt some data first.', 'info')
            return render_template('update.html', form=form)
            
        if form.validate_on_submit():
            try:
                # Get data and master key
                data_id = form.data_id.data
                master_key_b64 = form.master_key.data
                input_type = form.input_type.data
                text_input = form.text_input.data
                file_input = request.files.get('file_input')
                
                # Find the data
                encrypted_data = EncryptedData.query.get_or_404(data_id)
                
                # Verify ownership
                if encrypted_data.user_id != current_user.id:
                    abort(403)
                
                # Parse the master key
                try:
                    master_key = parse_key_from_input(master_key_b64)
                except ValueError as e:
                    flash(str(e), 'danger')
                    return render_template('update.html', form=form)
                
                # Validate input
                if input_type == 'text' and not text_input:
                    flash('Please enter text to encrypt.', 'danger')
                    return render_template('update.html', form=form)
                    
                if input_type in ['txt', 'pdf', 'voice'] and not file_input:
                    flash(f'Please select a {input_type} file to encrypt.', 'danger')
                    return render_template('update.html', form=form)
                
                # Process input
                content, original_filename = process_input(input_type, text_input, file_input)
                
                # Update the encrypted data
                encrypted_content, search_index, iv = dsse.update(
                    encrypted_data, content, master_key
                )
                
                # Update database record
                encrypted_data.encrypted_content = encrypted_content
                encrypted_data.search_index = search_index
                encrypted_data.iv = iv
                encrypted_data.input_type = input_type
                if original_filename:
                    encrypted_data.original_filename = original_filename
                
                db.session.commit()
                
                flash('Data updated successfully!', 'success')
                return redirect(url_for('dashboard'))
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"Update error: {str(e)}")
                flash(f'Update failed: {str(e)}', 'danger')
                
        return render_template('update.html', form=form)

    @app.route('/delete/<int:data_id>', methods=['POST'])
    @login_required
    def delete_data(data_id):
        """Delete encrypted data."""
        # Find the data
        encrypted_data = EncryptedData.query.get_or_404(data_id)
        
        # Verify ownership
        if encrypted_data.user_id != current_user.id:
            abort(403)
            
        try:
            db.session.delete(encrypted_data)
            db.session.commit()
            flash('Data deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Delete error: {str(e)}")
            flash(f'Delete failed: {str(e)}', 'danger')
            
        return redirect(url_for('dashboard'))

    @app.errorhandler(404)
    def page_not_found(e):
        """404 error handler."""
        return render_template('404.html'), 404
        
    @app.errorhandler(500)
    def server_error(e):
        """500 error handler."""
        logger.error(f"Server error: {str(e)}")
        return render_template('500.html'), 500
