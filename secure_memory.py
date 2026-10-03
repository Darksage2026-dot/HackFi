import secrets
import sys
from typing import Optional, Union
import ctypes
from ctypes import c_char, c_int


class SecureBuffer:
    """
    Memory buffer that attempts to securely clear sensitive data.
    
    This class holds sensitive data in memory and attempts to overwrite
    it with random data before deallocation to prevent memory scraping.
    """
    
    def __init__(self, data: Union[str, bytes]):
        self._data = data if isinstance(data, bytes) else data.encode('utf-8')
        self._cleared = False
        
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()
        return False
    
    def clear(self) -> None:
        """Securely clear the buffer."""
        if self._cleared or not self._data:
            return
            
        # Overwrite with random data
        try:
            if isinstance(self._data, bytearray):
                for i in range(len(self._data)):
                    self._data[i] = secrets.randbelow(256)
            else:
                # For immutable bytes, we can't truly clear, but we can
                # dereference and hope for garbage collection
                pass
        except Exception:
            pass
            
        self._data = b''
        self._cleared = True
    
    def get(self) -> bytes:
        """Get the buffer contents."""
        if self._cleared:
            raise ValueError("Buffer has been cleared")
        return self._data
    
    def __del__(self):
        """Destructor - attempt to clear on garbage collection."""
        self.clear()


class SecureString:
    """
    String wrapper that attempts secure memory handling.
    
    Note: Python's string interning and immutability make true secure
    string handling difficult. This is a best-effort implementation.
    """
    
    def __init__(self, value: str):
        self._buffer = SecureBuffer(value)
        self._value = value  # Reference for active use
        
    def get(self) -> str:
        """Get the string value."""
        return self._value
    
    def clear(self) -> None:
        """Clear the secure buffer."""
        self._buffer.clear()
        self._value = ''
        
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()
        return False
