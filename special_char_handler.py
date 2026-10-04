"""
special_char_handler.py - Enhanced Special Character Support
===========================================================

Comprehensive handling of special characters in password generation,
including custom charsets, escaping, and substitution patterns.
"""

import re
import random
from typing import Iterator, List, Set, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum, auto


class SpecialCharMode(Enum):
    """Modes for special character handling."""
    NONE = auto()           # No special characters
    END_ONLY = auto()       # Only at end (e.g., password!)
    START_ONLY = auto()     # Only at start (e.g., !password)
    ENDS = auto()           # Start and/or end
    MIDDLE = auto()         # Only in middle
    ANYWHERE = auto()       # Any position
    SPECIFIC = auto()       # Specific positions only


@dataclass
class SpecialCharConfig:
    """Configuration for special character usage."""
    mode: SpecialCharMode = SpecialCharMode.ANYWHERE
    charset: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    min_count: int = 0
    max_count: int = 2
    required_positions: Optional[List[int]] = None  # 0-indexed positions


class SpecialCharHandler:
    """
    Handles special character generation and validation.
    
    Supports various placement modes and substitution patterns
    commonly found in real-world passwords.
    """
    
    # Extended special character sets
    BASIC_SPECIAL = "!@#$%^&*"
    EXTENDED_SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
    BRACKET_SPECIAL = "()[]{}<>"
    MATH_SPECIAL = "+-*/=^~"
    PUNCTUATION = ".,;:!?'\""
    CURRENCY_SPECIAL = "$€£¥¢"
    
    # Common substitutions (leet speak)
    LEET_SUBSTITUTIONS: Dict[str, List[str]] = {
        'a': ['@', '4', '/\\', '∂'],
        'b': ['8', '|3', 'ß', '13'],
        'e': ['3', '€', '£', '∑'],
        'g': ['9', '6', '&'],
        'i': ['1', '!', '|', '¡', ':'],
        'l': ['1', '|', '£', '¬', '∟'],
        'o': ['0', '()', '[]', '{}', 'ø', '¤'],
        's': ['$', '5', '§', '∫', 'z'],
        't': ['7', '+', '†', '┬'],
        'z': ['2', '%', 'ζ', '≥'],
    }
    
    # Common special character patterns in passwords
    COMMON_PATTERNS = [
        "{word}!", "{word}@", "{word}#", "{word}$", "{word}123!",
        "{word}!!", "{word}1!", "{word}@123",
        "!{word}", "@{word}", "#{word}",
        "{word}2024!", "{word}2025!",
        "{word}.*", "{word}**",
        "{word}!!!", "{word}???",
    ]
    
    def __init__(self, config: Optional[SpecialCharConfig] = None):
        self.config = config or SpecialCharConfig()
        
    def get_charset(self) -> str:
        """Get the active special character set."""
        return self.config.charset
        
    def apply_substitutions(self, word: str, probability: float = 0.3) -> Iterator[str]:
        """
        Apply leet substitutions to a word.
        
        Args:
            word: Base word to transform
            probability: Chance of applying each substitution (0.0-1.0)
            
        Yields:
            Transformed versions with substitutions
        """
        yield word  # Original
        
        # Generate variations with substitutions
        for i, char in enumerate(word.lower()):
            if char in self.LEET_SUBSTITUTIONS:
                for sub in self.LEET_SUBSTITUTIONS[char]:
                    if random.random() < probability:
                        # Replace at position i
                        new_word = word[:i] + sub + word[i+1:]
                        yield new_word
                        
    def generate_with_special(self, base: str, mode: Optional[SpecialCharMode] = None) -> Iterator[str]:
        """
        Generate password variations with special characters.
        
        Args:
            base: Base password string
            mode: Special character placement mode
            
        Yields:
            Passwords with special characters added
        """
        mode = mode or self.config.mode
        
        # Always yield base
        yield base
        
        if mode == SpecialCharMode.NONE:
            return
            
        specials = self.config.charset
        
        # Generate based on mode
        if mode in (SpecialCharMode.END_ONLY, SpecialCharMode.ENDS, SpecialCharMode.ANYWHERE):
            for special in specials[:10]:  # Limit for performance
                yield base + special
                yield base + special + special
                
        if mode in (SpecialCharMode.START_ONLY, SpecialCharMode.ENDS, SpecialCharMode.ANYWHERE):
            for special in specials[:10]:
                yield special + base
                
        if mode == SpecialCharMode.ANYWHERE:
            # Insert at various positions
            for i in range(1, len(base)):
                for special in specials[:5]:
                    yield base[:i] + special + base[i:]
                    
        if mode == SpecialCharMode.SPECIFIC and self.config.required_positions:
            for pos in self.config.required_positions:
                if 0 <= pos <= len(base):
                    for special in specials[:5]:
                        yield base[:pos] + special + base[pos:]
                        
    def generate_special_combinations(self, length: int, 
                                      min_special: int = 1,
                                      max_special: int = 2) -> Iterator[str]:
        """
        Generate passwords with guaranteed special characters.
        
        Args:
            length: Total password length
            min_special: Minimum special characters
            max_special: Maximum special characters
            
        Yields:
            Passwords meeting special character requirements
        """
        alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        specials = self.config.charset
        
        # For small lengths, use direct generation
        if length <= 4:
            for combo in self._generate_small(length, min_special, max_special):
                yield combo
            return
            
        # Generate with random placement
        while True:  # Infinite generator
            num_specials = random.randint(min_special, min(max_special, length))
            num_alpha = length - num_specials
            
            # Build password
            chars = []
            chars.extend(random.choices(specials, k=num_specials))
            chars.extend(random.choices(alphanumeric, k=num_alpha))
            random.shuffle(chars)
            
            yield ''.join(chars)
            
    def _generate_small(self, length: int, min_s: int, max_s: int) -> Iterator[str]:
        """Generate small passwords with special chars."""
        alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        specials = self.config.charset
        
        from itertools import product
        
        for num_specials in range(min_s, min(max_s + 1, length + 1)):
            num_alpha = length - num_specials
            
            for special_positions in product(range(length), repeat=num_specials):
                if len(set(special_positions)) != num_specials:
                    continue
                    
                for special_chars in product(specials, repeat=num_specials):
                    for alpha_chars in product(alphanumeric, repeat=num_alpha):
                        # Build password
                        chars = list(alpha_chars)
                        for pos, special in zip(special_positions, special_chars):
                            chars.insert(pos, special)
                        yield ''.join(chars[:length])
                        
    def escape_for_pattern(self, char: str) -> str:
        """
        Escape special characters for use in patterns.
        
        Args:
            char: Character to escape
            
        Returns:
            Escaped character safe for pattern strings
        """
        # Pattern syntax: ?d=digit, ?l=lower, ?u=upper, ?s=special, ??=literal ?
        if char == '?':
            return '??'
        return char
        
    def unescape_pattern(self, pattern: str) -> List[str]:
        """
        Parse pattern string into character sets.
        
        Pattern syntax:
            ?d = digit
            ?l = lowercase
            ?u = uppercase
            ?a = alphanumeric
            ?s = special
            ?S = specific special set
            ?? = literal ?
            * = wildcard (any char)
            
        Args:
            pattern: Pattern string
            
        Returns:
            List of character sets for each position
        """
        result = []
        i = 0
        while i < len(pattern):
            if pattern[i] == '?' and i + 1 < len(pattern):
                next_char = pattern[i + 1]
                if next_char == 'd':
                    result.append('0123456789')
                elif next_char == 'l':
                    result.append('abcdefghijklmnopqrstuvwxyz')
                elif next_char == 'u':
                    result.append('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
                elif next_char == 'a':
                    result.append('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                elif next_char == 's':
                    result.append(self.config.charset)
                elif next_char == 'S':
                    result.append(self.EXTENDED_SPECIAL)
                elif next_char == '?':
                    result.append('?')
                i += 2
            elif pattern[i] == '*':
                result.append('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' + 
                            self.config.charset)
                i += 1
            else:
                result.append(pattern[i])
                i += 1
                
        return result
        
    def validate_special_requirements(self, password: str) -> Tuple[bool, Dict]:
        """
        Validate that password meets special character requirements.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, details_dict)
        """
        special_count = sum(1 for c in password if c in self.config.charset)
        
        details = {
            'special_count': special_count,
            'min_required': self.config.min_count,
            'max_allowed': self.config.max_count,
            'specials_found': [c for c in password if c in self.config.charset]
        }
        
        is_valid = self.config.min_count <= special_count <= self.config.max_count
        
        if self.config.mode == SpecialCharMode.END_ONLY:
            is_valid = is_valid and (password[-1] in self.config.charset if password else False)
        elif self.config.mode == SpecialCharMode.START_ONLY:
            is_valid = is_valid and (password[0] in self.config.charset if password else False)
            
        return is_valid, details


# Enhanced Candidate Engine with Special Character Support

class EnhancedCandidateEngine:
    """
    Enhanced candidate generator with full special character support.
    """
    
    def __init__(self, config: 'AuditConfig', special_config: Optional[SpecialCharConfig] = None):
        from config import AuditConfig, GenerationStrategy
        
        self.config = config
        self.special_handler = SpecialCharHandler(special_config)
        self.special_config = special_config
        
    def generate(self) -> Iterator[str]:
        """
        Generate candidates with special character support.
        """
        from config import GenerationStrategy
        import itertools
        
        strategy = self.config.strategy
        
        if strategy == GenerationStrategy.CUSTOM and self.config.custom_charset:
            charset = self.config.custom_charset
        else:
            charset = self._get_charset_for_strategy(strategy)
            
        # Check if we need special character handling
        if self.special_config and self.special_config.mode != SpecialCharMode.NONE:
            yield from self._generate_with_special_handling(charset)
        else:
            yield from self._generate_standard(charset)
            
    def _get_charset_for_strategy(self, strategy) -> str:
        """Get character set for strategy."""
        from config import GenerationStrategy, CharSet
        
        if strategy == GenerationStrategy.NUMERIC:
            return CharSet.NUMERIC
        elif strategy == GenerationStrategy.LOWERCASE:
            return CharSet.LOWERCASE
        elif strategy == GenerationStrategy.UPPERCASE:
            return CharSet.UPPERCASE
        elif strategy == GenerationStrategy.ALPHANUMERIC:
            return CharSet.ALPHANUMERIC
        else:
            return CharSet.ALPHANUMERIC + SpecialCharHandler.EXTENDED_SPECIAL
            
    def _generate_standard(self, charset: str) -> Iterator[str]:
        """Standard generation without special handling."""
        import random
        
        for length in range(self.config.min_length, self.config.max_length + 1):
            # For small lengths, generate all combinations
            total_combos = len(charset) ** length
            if total_combos < 1000000:  # Generate all if reasonable
                import itertools
                for combo in itertools.product(charset, repeat=length):
                    yield ''.join(combo)
            else:
                # Random sampling for large spaces
                for _ in range(min(100000, total_combos)):
                    yield ''.join(random.choices(charset, k=length))
                    
    def _generate_with_special_handling(self, charset: str) -> Iterator[str]:
        """Generate with special character constraints."""
        if not self.special_config:
            yield from self._generate_standard(charset)
            return
            
        # Generate ensuring special character requirements
        yield from self.special_handler.generate_special_combinations(
            self.config.min_length,
            self.special_config.min_count,
            self.special_config.max_count
        )
        
        # Also generate with substitutions if using AI mode
        if self.config.strategy.name == 'AI_PRIORITIZED':
            base_words = ["password", "admin", "welcome", "login", "master"]
            for word in base_words:
                for variant in self.special_handler.apply_substitutions(word):
                    if self.config.min_length <= len(variant) <= self.config.max_length:
                        yield variant


# CLI Extensions for Special Characters

def add_special_char_args(parser):
    """Add special character arguments to CLI parser."""
    group = parser.add_argument_group('Special Character Options')
    
    group.add_argument('--special-mode', 
                      choices=['none', 'end', 'start', 'ends', 'middle', 'anywhere', 'specific'],
                      default='anywhere',
                      help='Special character placement mode')
    
    group.add_argument('--special-charset',
                      default='!@#$%^&*()_+-=[]{}|;:,.<>?',
                      help='Custom special character set')
    
    group.add_argument('--min-special', type=int, default=0,
                      help='Minimum special characters required')
    
    group.add_argument('--max-special', type=int, default=2,
                      help='Maximum special characters allowed')
    
    group.add_argument('--special-positions',
                      help='Comma-separated positions for special chars (0-indexed)')
    
    group.add_argument('--leet', action='store_true',
                      help='Enable leet speak substitutions')
    
    group.add_argument('--common-special', action='store_true',
                      help='Generate common special character patterns first')
    
    return group


# Example usage and testing

def demo_special_characters():
    """Demonstrate special character handling."""
    print("\n" + "=" * 70)
    print("SPECIAL CHARACTER HANDLING DEMO")
    print("=" * 70)
    
    # Demo 1: Basic special character generation
    print("\n1. Passwords with special characters at end:")
    handler = SpecialCharHandler(SpecialCharConfig(mode=SpecialCharMode.END_ONLY))
    
    count = 0
    for pwd in handler.generate_with_special("password123"):
        print(f"   {pwd}")
        count += 1
        if count >= 10:
            break
            
    # Demo 2: Leet substitutions
    print("\n2. Leet speak variations of 'password':")
    for pwd in handler.apply_substitutions("password", probability=1.0):
        print(f"   {pwd}")
        if pwd == "password":  # Skip original
            continue
        # Just show a few
        if '7' in pwd or '@' in pwd or '$' in pwd:
            print(f"   → {pwd}")
            break
            
    # Demo 3: Pattern parsing with special chars
    print("\n3. Pattern '?l?l?l?d?d?s' (3 lower + 2 digits + 1 special):")
    pattern = "?l?l?l?d?d?s"
    charsets = handler.unescape_pattern(pattern)
    print(f"   Pattern: {pattern}")
    print(f"   Parses to: {charsets}")
    
    # Generate a few examples
    import random
    for _ in range(5):
        pwd = ''.join(random.choice(c) for c in charsets)
        print(f"   → {pwd}")
        
    # Demo 4: Validation
    print("\n4. Special character validation:")
    test_passwords = ["hello", "hello!", "!hello", "h@ll0!", "hello!!"]
    config = SpecialCharConfig(mode=SpecialCharMode.END_ONLY, min_count=1)
    handler = SpecialCharHandler(config)
    
    for pwd in test_passwords:
        is_valid, details = handler.validate_special_requirements(pwd)
        status = "✓" if is_valid else "✗"
        print(f"   {status} '{pwd}' - {details['special_count']} special chars")
        
    print("\n" + "=" * 70)


if __name__ == '__main__':
    demo_special_characters()