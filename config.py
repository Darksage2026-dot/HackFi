from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Set
import os


class GenerationStrategy(Enum):
    """Password generation strategies."""
    NUMERIC = auto()
    LOWERCASE = auto()
    UPPERCASE = auto()
    ALPHANUMERIC = auto()
    CUSTOM = auto()
    PATTERN = auto()
    MASK = auto()
    AI_PRIORITIZED = auto()


class CharSet:
    """Character sets for password generation."""
    NUMERIC = "0123456789"
    LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
    UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ALPHANUMERIC = LOWERCASE + UPPERCASE + NUMERIC
    SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    ALL = ALPHANUMERIC + SPECIAL


@dataclass
class AuditConfig:
    """Configuration for Wi-Fi audit session."""
    
    # Capture settings
    capture_path: Optional[str] = None
    target_ssid: Optional[str] = None
    
    # Generation settings
    strategy: GenerationStrategy = GenerationStrategy.ALPHANUMERIC
    min_length: int = 8
    max_length: int = 8
    custom_charset: str = ""
    pattern: str = ""
    mask: str = ""
    
    # AI settings
    use_ai: bool = True
    organization: Optional[str] = None
    known_prefix: Optional[str] = None
    known_suffix: Optional[str] = None
    common_patterns: Optional[list] = None
    
    # Performance settings
    target_rate: int = 500  # candidates per second
    max_workers: int = os.cpu_count() or 4
    batch_size: int = 1000
    
    # Security settings
    require_authorization: bool = True
    secure_memory: bool = True
    
    def get_charset(self) -> str:
        """Get the active character set based on strategy."""
        if self.strategy == GenerationStrategy.NUMERIC:
            return CharSet.NUMERIC
        elif self.strategy == GenerationStrategy.LOWERCASE:
            return CharSet.LOWERCASE
        elif self.strategy == GenerationStrategy.UPPERCASE:
            return CharSet.UPPERCASE
        elif self.strategy == GenerationStrategy.ALPHANUMERIC:
            return CharSet.ALPHANUMERIC
        elif self.strategy == GenerationStrategy.CUSTOM:
            return self.custom_charset or CharSet.ALPHANUMERIC
        else:
            return CharSet.ALPHANUMERIC
