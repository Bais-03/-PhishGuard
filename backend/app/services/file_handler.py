"""
File Handler Service - Handles .eml file uploads and validation
"""
import os
import hashlib
from typing import Dict, Any
import tempfile


class FileUploadHandler:
    """
    Handles file upload validation, parsing, and temporary storage
    """
    
    def __init__(self, max_size_mb: int = 10):
        self.max_size_mb = max_size_mb
        self.allowed_extensions = {'.eml', '.msg'}
    
    def validate_file(self, file) -> Dict[str, Any]:
        """
        Validate uploaded file
        Returns: {'valid': bool, 'error': str (if invalid)}
        """
        # Check filename
        if not hasattr(file, 'filename') or not file.filename:
            return {'valid': False, 'error': 'No filename provided'}
        
        # Check extension
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in self.allowed_extensions:
            return {
                'valid': False, 
                'error': f'Invalid file type. Allowed: {", ".join(self.allowed_extensions)}'
            }
        
        return {'valid': True, 'error': None}
    
    def parse_eml_content(self, content: bytes) -> str:
        """
        Parse .eml file content and return RFC 2822 formatted email string
        """
        try:
            # .eml files are already in RFC 2822 format
            return content.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            # Try other encodings
            try:
                return content.decode('latin-1')
            except Exception as e:
                raise ValueError(f"Failed to decode .eml file: {str(e)}")
    
    def generate_file_hash(self, content: bytes) -> str:
        """
        Generate SHA256 hash of file content for caching
        """
        return hashlib.sha256(content).hexdigest()
    
    def save_temp_file(self, content: bytes, filename: str) -> str:
        """
        Save uploaded file to temporary location
        """
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, f"phishguard_{hashlib.md5(filename.encode()).hexdigest()}.eml")
        
        with open(temp_path, 'wb') as f:
            f.write(content)
        
        return temp_path
    
    def cleanup_temp_file(self, filepath: str):
        """
        Remove temporary file
        """
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception:
            pass