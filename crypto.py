import os
import json
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

class DSSE:
    """
    Dynamic Searchable Symmetric Encryption implementation using AES-GCM.
    
    This class provides methods for encryption, decryption, search, and update operations.
    It uses AES-GCM (Galois/Counter Mode) for authenticated encryption, which provides
    both confidentiality and integrity without the need for padding. This eliminates
    padding-related issues that can occur with other encryption modes like CBC.
    """
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_key(self):
        """Generate a random 256-bit encryption key."""
        return os.urandom(32)
    
    def _derive_search_key(self, master_key):
        """Derive a search key from the master key."""
        h = hashlib.sha256()
        h.update(master_key + b"search_key_derivation")
        return h.digest()
    
    def _encrypt_aes(self, key, plaintext):
        """
        Encrypt data using AES-GCM (Galois/Counter Mode).
        This mode provides authenticated encryption and doesn't require padding.
        Returns (nonce, ciphertext) tuple where nonce is similar to an IV.
        """
        # Ensure plaintext is bytes
        if not isinstance(plaintext, bytes):
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            else:
                raise ValueError("Plaintext must be bytes or string")
                
        # Generate a random 96-bit nonce (12 bytes)
        nonce = os.urandom(12)
        
        # Create an AESGCM object
        aesgcm = AESGCM(key)
        
        # Encrypt the plaintext - no padding needed with GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        logger.debug(f"Encrypted {len(plaintext)} bytes -> {len(ciphertext)} bytes")
        
        return nonce, ciphertext
        
    def _decrypt_aes(self, key, nonce, ciphertext):
        """
        Decrypt data using AES-GCM or fall back to AES-CBC for backward compatibility.
        
        This method will first try to decrypt with AES-GCM. If that fails and the nonce
        is 16 bytes (suggesting it might be a CBC IV), it will fall back to CBC mode.
        """
        try:
            # Ensure ciphertext is properly formatted
            if not isinstance(ciphertext, bytes):
                logger.error("Ciphertext is not in bytes format")
                raise ValueError("Ciphertext must be in bytes format")
                
            # Ensure nonce is properly formatted
            if not isinstance(nonce, bytes):
                logger.error("Nonce is not in bytes format")
                raise ValueError("Nonce must be in bytes format")
            
            # Try GCM mode first (our new preferred mode)
            try:
                if len(nonce) == 12:  # Standard GCM nonce length
                    # Create an AESGCM object
                    aesgcm = AESGCM(key)
                    
                    # Decrypt and authenticate the ciphertext
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                    
                    logger.debug(f"Decrypted {len(ciphertext)} bytes with GCM -> {len(plaintext)} bytes")
                    return plaintext
                elif len(nonce) == 16:
                    # This might be old data encrypted with CBC mode
                    # Let's first try GCM anyway (with a warning)
                    logger.warning("Attempting GCM decryption with non-standard 16-byte nonce")
                    try:
                        aesgcm = AESGCM(key)
                        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                        logger.debug(f"Successfully decrypted with GCM despite 16-byte nonce")
                        return plaintext
                    except Exception as gcm_error:
                        # GCM failed, try CBC as fallback
                        logger.warning(f"GCM decryption failed: {str(gcm_error)}. Trying CBC mode as fallback.")
                        
                        # We'll use CBC mode from the imports at the top of the file
                        
                        # Create CBC cipher
                        cipher = Cipher(
                            algorithms.AES(key),
                            modes.CBC(nonce),  # In CBC mode, nonce is used as IV
                            backend=self.backend
                        )
                        
                        # Decrypt the data
                        decryptor = cipher.decryptor()
                        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                        
                        # Try to remove padding
                        try:
                            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                            logger.info("Successfully decrypted with CBC mode (backward compatibility)")
                            return plaintext
                        except ValueError as padding_error:
                            logger.error(f"CBC padding error: {str(padding_error)}")
                            
                            # Try manual padding removal as last resort
                            if "Invalid padding bytes" in str(padding_error):
                                # For file content, remove trailing zeros
                                i = len(padded_plaintext) - 1
                                while i >= 0 and padded_plaintext[i] == 0:
                                    i -= 1
                                
                                logger.warning("Attempting manual padding removal for CBC mode")
                                return padded_plaintext[:i+1]
                            else:
                                raise ValueError("Failed to decrypt with both GCM and CBC modes.")
                else:
                    raise ValueError(f"Unsupported nonce/IV length: {len(nonce)}")
                    
            except Exception as e:
                logger.error(f"Decryption error: {str(e)}")
                raise
                
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            if "authentication" in str(e).lower() or "tag" in str(e).lower():
                raise ValueError("Invalid master key or corrupted data. Please ensure you're using the correct master key provided during encryption.")
            else:
                raise ValueError(f"Decryption failed: {str(e)}")
        
    def _create_keyword_index(self, content, search_key):
        """
        Create a searchable index from the content.
        Returns a dictionary mapping encrypted keywords to positions.
        """
        # For text content, split by whitespace and punctuation
        if isinstance(content, bytes):
            try:
                content = content.decode('utf-8', errors='replace')
            except Exception as e:
                logger.error(f"Error decoding content: {str(e)}")
                content = str(content)
            
        # Simple tokenization by splitting on whitespace
        words = content.lower().split()
        
        # Create index
        search_index = {}
        for position, word in enumerate(words):
            if len(word) < 2:  # Skip very short words
                continue
                
            # Create secure keyword hash using HMAC
            word_hash = self._hmac_hash(search_key, word)
            
            # Store position
            if word_hash in search_index:
                search_index[word_hash].append(position)
            else:
                search_index[word_hash] = [position]
                
        return search_index
        
    def _hmac_hash(self, key, message):
        """Create a deterministic hash of the message using HMAC."""
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        h = hmac.new(key, message, hashlib.sha256)
        return base64.b64encode(h.digest()).decode('utf-8')
        
    def encrypt(self, plaintext, master_key=None):
        """
        Encrypt content and create search index.
        Returns (encrypted_content, search_index, nonce, search_key).
        """
        if master_key is None:
            master_key = self.generate_key()
            
        search_key = self._derive_search_key(master_key)
        
        # Convert plaintext to bytes if it's a string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        # Encrypt the content
        nonce, encrypted_content = self._encrypt_aes(master_key, plaintext)
        
        # Create searchable index
        search_index = self._create_keyword_index(plaintext, search_key)
        
        # Convert search index to JSON string
        search_index_json = json.dumps(search_index)
        
        logger.debug(f"Encrypted {len(plaintext)} bytes of data with {len(nonce)}-byte nonce")
        
        return encrypted_content, search_index_json, nonce, search_key
        
    def decrypt(self, encrypted_content, nonce, master_key):
        """
        Decrypt encrypted content using AES-GCM with backward compatibility for AES-CBC.
        
        This method first attempts to decrypt using AES-GCM (our new preferred method).
        If that fails and the nonce appears to be a CBC IV (16 bytes), it will try
        AES-CBC as a fallback for backward compatibility with existing encrypted data.
        
        Args:
            encrypted_content (bytes): The encrypted content to decrypt
            nonce (bytes): The nonce (for GCM) or IV (for CBC) used during encryption
            master_key (bytes or str): The encryption key (will be decoded if string)
            
        Returns:
            bytes: The decrypted content
            
        Raises:
            ValueError: If the master key is invalid or if decryption fails with both methods
        """
        # Enhanced error handling for master key decoding
        if not isinstance(master_key, bytes):
            try:
                master_key = base64.b64decode(master_key)
            except Exception as e:
                logger.error(f"Error decoding master key: {str(e)}")
                raise ValueError("Invalid master key format. Please provide a valid encryption key.")
        
        if len(master_key) != 32:  # AES-256 requires 32-byte key
            logger.error(f"Invalid master key length: {len(master_key)}")
            raise ValueError("Invalid master key length. The key must be 32 bytes for AES-256.")
        
        # Enhanced error handling for nonce decoding
        if not isinstance(nonce, bytes):
            try:
                nonce = base64.b64decode(nonce)
            except Exception as e:
                logger.error(f"Error decoding nonce: {str(e)}")
                raise ValueError("Invalid nonce format.")
        
        # For backward compatibility: we used to use 16-byte IV for CBC mode
        # If this is actually a CBC IV (16 bytes), we'll log it but still try to use it
        # New GCM nonces are 12 bytes
        if len(nonce) != 12:
            logger.warning(f"Unexpected nonce length: {len(nonce)}. GCM mode typically uses 12-byte nonces.")
            # We'll still try to use it - it might be data from a previous encryption method
        
        # Additional logging to help debug decryption issues
        try:
            logger.debug(f"Attempting to decrypt {len(encrypted_content)} bytes with {len(nonce)}-byte nonce")
            return self._decrypt_aes(master_key, nonce, encrypted_content)
        except ValueError as e:
            logger.error(f"Decryption failed with detailed error: {str(e)}")
            raise
        
    def search(self, keyword, search_index, search_key):
        """
        Search for a keyword in the encrypted index.
        Returns a list of positions where the keyword appears.
        """
        if isinstance(search_index, str):
            try:
                search_index = json.loads(search_index)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding search index: {str(e)}")
                return []
            
        # Convert keyword to lowercase for case-insensitive search
        keyword = keyword.lower()
        
        # Hash the keyword
        keyword_hash = self._hmac_hash(search_key, keyword)
        
        # Return positions if found, empty list otherwise
        return search_index.get(keyword_hash, [])
    
    def update(self, old_encrypted_data, new_plaintext, master_key):
        """
        Update encrypted data with new content while preserving the master key.
        """
        # Derive search key from master key
        search_key = self._derive_search_key(master_key)
        
        # Convert new plaintext to bytes if it's a string
        if isinstance(new_plaintext, str):
            new_plaintext = new_plaintext.encode('utf-8')
            
        # Encrypt the new content
        nonce, encrypted_content = self._encrypt_aes(master_key, new_plaintext)
        
        # Create new searchable index
        search_index = self._create_keyword_index(new_plaintext, search_key)
        
        # Convert search index to JSON string
        search_index_json = json.dumps(search_index)
        
        return encrypted_content, search_index_json, nonce
