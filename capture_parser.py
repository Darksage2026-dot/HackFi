import struct
from dataclasses import dataclass
from typing import Optional, List, BinaryIO
import hashlib
import hmac


@dataclass
class WPAHandshake:
    """Parsed WPA/WPA2 handshake data."""
    ssid: str
    mac_ap: bytes
    mac_client: bytes
    anonce: bytes
    snonce: bytes
    mic: bytes
    eapol_frame: bytes
    key_version: int  # 1 for WPA, 2 for WPA2


@dataclass
class CaptureInfo:
    """Information about the capture file."""
    file_path: str
    handshakes: List[WPAHandshake]
    is_valid: bool
    error_message: Optional[str] = None


class CaptureParser:
    """
    Parser for WPA/WPA2 capture files (.cap, .pcap, .pcapng).
    
    Supports standard pcap formats used by tools like Wireshark,
    aircrack-ng, and tcpdump.
    """
    
    # PCAP constants
    PCAP_MAGIC_NUMBER = 0xa1b2c3d4
    PCAP_SWAPPED_MAGIC = 0xd4c3b2a1
    PCAPNG_MAGIC = 0x0a0d0d0a
    
    # IEEE 802.11 constants
    DOT11_TYPE_MANAGEMENT = 0
    DOT11_TYPE_DATA = 2
    DOT11_SUBTYPE_QOS_DATA = 8
    
    # EAPOL constants
    EAPOL_KEY_DESCRIPTOR = 3
    
    def __init__(self):
        self.handshakes: List[WPAHandshake] = []
        
    def parse_file(self, file_path: str) -> CaptureInfo:
        """
        Parse a capture file and extract WPA handshakes.
        
        Args:
            file_path: Path to the capture file
            
        Returns:
            CaptureInfo with parsed data or error information
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if len(data) < 24:
                return CaptureInfo(file_path, [], False, "File too small")
                
            # Detect format
            magic = struct.unpack('<I', data[:4])[0]
            
            if magic == self.PCAP_MAGIC_NUMBER:
                handshakes = self._parse_pcap(data)
            elif magic == self.PCAP_SWAPPED_MAGIC:
                handshakes = self._parse_pcap(data, swapped=True)
            elif magic == self.PCAPNG_MAGIC:
                handshakes = self._parse_pcapng(data)
            else:
                return CaptureInfo(file_path, [], False, "Unknown file format")
                
            return CaptureInfo(file_path, handshakes, len(handshakes) > 0)
            
        except FileNotFoundError:
            return CaptureInfo(file_path, [], False, "File not found")
        except Exception as e:
            return CaptureInfo(file_path, [], False, f"Parse error: {str(e)}")
            
    def _parse_pcap(self, data: bytes, swapped: bool = False) -> List[WPAHandshake]:
        """Parse pcap format."""
        handshakes = []
        # Simplified parsing - in production, use scapy or similar
        # This is a placeholder for the actual implementation
        
        # Look for EAPOL frames
        offset = 24  # Skip global header
        while offset < len(data) - 16:
            # Parse packet header
            if swapped:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    '>IIII', data[offset:offset+16]
                )
            else:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    '<IIII', data[offset:offset+16]
                )
                
            packet_data = data[offset+16:offset+16+incl_len]
            
            # Look for EAPOL-Key frames
            eapol_handshake = self._extract_eapol(packet_data)
            if eapol_handshake:
                handshakes.append(eapol_handshake)
                
            offset += 16 + incl_len
            
        return handshakes
        
    def _parse_pcapng(self, data: bytes) -> List[WPAHandshake]:
        """Parse pcapng format."""
        # Placeholder - pcapng is more complex
        return []
        
    def _extract_eapol(self, packet_data: bytes) -> Optional[WPAHandshake]:
        """Extract EAPOL-Key frame from packet."""
        # Simplified extraction - would need proper 802.11 parsing
        # Look for EAPOL-Key descriptor type
        if len(packet_data) < 100:
            return None
            
        # This is a simplified check - real implementation needs proper parsing
        try:
            # Look for EAPOL key marker
            if b'\x88\x8e' in packet_data:  # EAPOL ethertype
                # Extract handshake data
                # This is simplified - real implementation needs full parsing
                return WPAHandshake(
                    ssid="Unknown",
                    mac_ap=b'\x00' * 6,
                    mac_client=b'\x00' * 6,
                    anonce=b'\x00' * 32,
                    snonce=b'\x00' * 32,
                    mic=b'\x00' * 16,
                    eapol_frame=packet_data,
                    key_version=2
                )
        except Exception:
            pass
            
        return None
        
    def verify_password(self, handshake: WPAHandshake, password: str) -> bool:
        """
        Verify a password against a WPA handshake.
        
        This implements the WPA/WPA2 4-way handshake MIC verification.
        """
        try:
            # Generate PMK from password and SSID
            pmk = hashlib.pbkdf2_hmac(
                'sha1',
                password.encode('utf-8'),
                handshake.ssid.encode('utf-8'),
                4096,
                32
            )
            
            # Generate PTK from PMK
            # This is simplified - real implementation needs proper PTK derivation
            ptk = self._derive_ptk(pmk, handshake.anonce, handshake.snonce,
                                  handshake.mac_ap, handshake.mac_client)
            
            # Calculate MIC
            mic = self._calculate_mic(ptk, handshake.eapol_frame, handshake.key_version)
            
            # Compare with handshake MIC
            return hmac.compare_digest(mic, handshake.mic)
            
        except Exception:
            return False
            
    def _derive_ptk(self, pmk: bytes, anonce: bytes, snonce: bytes,
                    mac_ap: bytes, mac_client: bytes) -> bytes:
        """Derive Pairwise Transient Key (PTK)."""
        # Simplified PTK derivation
        # Real implementation needs proper PRF-384 or PRF-512
        data = min(mac_ap, mac_client) + max(mac_ap, mac_client) + \
               min(anonce, snonce) + max(anonce, snonce)
        return hmac.new(pmk, data, hashlib.sha1).digest()[:48]
        
    def _calculate_mic(self, ptk: bytes, eapol_frame: bytes, key_version: int) -> bytes:
        """Calculate MIC over EAPOL frame."""
        # Use KCK (first 16 bytes of PTK) for MIC
        kck = ptk[:16]
        
        if key_version == 1:  # WPA (TKIP)
            # HMAC-MD5
            return hmac.new(kck, eapol_frame, hashlib.md5).digest()[:16]
        else:  # WPA2 (CCMP)
            # HMAC-SHA1
            return hmac.new(kck, eapol_frame, hashlib.sha1).digest()[:16]

