import hashlib
import hmac
from typing import Optional
from dataclasses import dataclass

from capture_parser import WPAHandshake


@dataclass
class VerificationResult:
    """Result of password verification."""
    password: str
    is_valid: bool
    handshake_ssid: str


class Verifier:
    """
    High-performance password verification engine.
    
    Implements WPA/WPA2 MIC verification using PBKDF2 and
    proper PTK derivation.
    """
    
    def __init__(self, handshake: WPAHandshake):
        self.handshake = handshake
        
    def verify(self, password: str) -> bool:
        """
        Verify if password is correct for the handshake.
        
        Args:
            password: Candidate password to test
            
        Returns:
            True if password is correct, False otherwise
        """
        try:
            # Generate PMK using PBKDF2
            pmk = hashlib.pbkdf2_hmac(
                'sha1',
                password.encode('utf-8'),
                self.handshake.ssid.encode('utf-8'),
                4096,
                32
            )
            
            # Derive PTK
            ptk = self._derive_ptk(pmk)
            
            # Calculate MIC
            calculated_mic = self._calculate_mic(ptk)
            
            # Compare MICs
            return hmac.compare_digest(calculated_mic, self.handshake.mic)
            
        except Exception:
            return False
            
    def _derive_ptk(self, pmk: bytes) -> bytes:
        """Derive Pairwise Transient Key."""
        # PTK = PRF(PMK, "Pairwise key expansion", 
        #           Min(AA, SA) || Max(AA, SA) || Min(ANonce, SNonce) || Max(ANonce, SNonce))
        
        # Get addresses in correct order
        addr_ordered = self._order_bytes(self.handshake.mac_ap, self.handshake.mac_client)
        nonce_ordered = self._order_bytes(self.handshake.anonce, self.handshake.snonce)
        
        data = b"Pairwise key expansion\x00" + addr_ordered + nonce_ordered
        
        # PRF using HMAC-SHA1
        ptk = b''
        for i in range(4):  # 512 bits = 4 * 128 bits
            h = hmac.new(pmk, data + bytes([i]), hashlib.sha1).digest()
            ptk += h
            
        return ptk[:64]  # Return 512 bits
        
    def _order_bytes(self, a: bytes, b: bytes) -> bytes:
        """Order bytes for PTK derivation."""
        return min(a, b) + max(a, b)
        
    def _calculate_mic(self, ptk: bytes) -> bytes:
        """Calculate MIC using KCK from PTK."""
        kck = ptk[:16]  # First 128 bits are KCK
        
        if self.handshake.key_version == 1:
            # WPA - HMAC-MD5
            return hmac.new(kck, self.handshake.eapol_frame, hashlib.md5).digest()[:16]
        else:
            # WPA2 - HMAC-SHA1-128
            return hmac.new(kck, self.handshake.eapol_frame, hashlib.sha1).digest()[:16]
