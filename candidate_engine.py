import itertools
import random
import string
from typing import Iterator, Optional, Callable
from dataclasses import dataclass
import threading

from config import AuditConfig, GenerationStrategy, CharSet
from ai_prioritizer import AIPrioritizer, AIPrioritizationContext


@dataclass
class GenerationStats:
    """Statistics for generation process."""
    total_generated: int = 0
    current_rate: float = 0.0
    is_running: bool = False


class CandidateEngine:
    """
    Modular password candidate generation engine.
    
    Supports multiple generation strategies with high-throughput
    in-memory generation. No passwords are written to disk.
    """
    
    def __init__(self, config: AuditConfig):
        self.config = config
        self.stats = GenerationStats()
        self._cancelled = False
        self._lock = threading.Lock()
        self._ai_prioritizer: Optional[AIPrioritizer] = None
        
        if config.use_ai and config.strategy == GenerationStrategy.AI_PRIORITIZED:
            ctx = AIPrioritizationContext(
                organization=config.organization,
                known_prefix=config.known_prefix,
                known_suffix=config.known_suffix,
                charset=config.get_charset(),
                min_length=config.min_length,
                max_length=config.max_length
            )
            self._ai_prioritizer = AIPrioritizer(ctx)
            
    def cancel(self) -> None:
        """Cancel generation."""
        self._cancelled = True
        self.stats.is_running = False
        
    def generate(self) -> Iterator[str]:
        """
        Generate password candidates based on configuration.
        
        Yields candidates one at a time for memory-efficient processing.
        """
        self.stats.is_running = True
        self._cancelled = False
        
        try:
            if self.config.strategy == GenerationStrategy.AI_PRIORITIZED and self._ai_prioritizer:
                yield from self._generate_ai_prioritized()
            elif self.config.strategy == GenerationStrategy.PATTERN:
                yield from self._generate_pattern()
            elif self.config.strategy == GenerationStrategy.MASK:
                yield from self._generate_mask()
            else:
                yield from self._generate_brute_force()
        finally:
            self.stats.is_running = False
            
    def _generate_ai_prioritized(self) -> Iterator[str]:
        """Generate AI-prioritized candidates first, then fall back."""
        charset = self.config.get_charset()
        
        # First yield AI-prioritized candidates
        if self._ai_prioritizer:
            for candidate in self._ai_prioritizer.get_prioritized_candidates(10000):
                if self._cancelled:
                    return
                if self.config.min_length <= len(candidate) <= self.config.max_length:
                    self._increment_count()
                    yield candidate
                    
        # Then fall back to random generation
        yield from self._generate_random(charset)
        
    def _generate_brute_force(self) -> Iterator[str]:
        """Generate all combinations (brute force)."""
        charset = self.config.get_charset()
        
        for length in range(self.config.min_length, self.config.max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                if self._cancelled:
                    return
                candidate = ''.join(combo)
                self._increment_count()
                yield candidate
                
    def _generate_random(self, charset: str) -> Iterator[str]:
        """Generate random candidates (for large spaces)."""
        while not self._cancelled:
            length = random.randint(self.config.min_length, self.config.max_length)
            candidate = ''.join(random.choices(charset, k=length))
            self._increment_count()
            yield candidate
            
    def _generate_pattern(self) -> Iterator[str]:
        """Generate based on pattern."""
        # Pattern syntax: ?d=digit, ?l=lower, ?u=upper, ?a=any
        pattern = self.config.pattern
        
        if not pattern:
            # Default pattern
            yield from self._generate_brute_force()
            return
            
        charsets = []
        for i, char in enumerate(pattern):
            if char == '?' and i + 1 < len(pattern):
                next_char = pattern[i + 1]
                if next_char == 'd':
                    charsets.append(CharSet.NUMERIC)
                elif next_char == 'l':
                    charsets.append(CharSet.LOWERCASE)
                elif next_char == 'u':
                    charsets.append(CharSet.UPPERCASE)
                elif next_char == 'a':
                    charsets.append(self.config.get_charset())
            elif char != '?' or (i > 0 and pattern[i-1] == '?'):
                # Literal character
                if char != '?':
                    charsets.append(char)
                    
        for combo in itertools.product(*[c if isinstance(c, str) else c for c in charsets]):
            if self._cancelled:
                return
            candidate = ''.join(combo)
            self._increment_count()
            yield candidate
            
    def _generate_mask(self) -> Iterator[str]:
        """Generate based on mask."""
        # Similar to pattern but with more flexibility
        mask = self.config.mask or "?" * self.config.min_length
        
        # Parse mask and generate
        charset = self.config.get_charset()
        
        # For now, use random generation with mask length
        target_length = len(mask)
        while not self._cancelled:
            candidate = ''.join(random.choices(charset, k=target_length))
            self._increment_count()
            yield candidate
            
    def _increment_count(self) -> None:
        """Increment generation counter."""
        with self._lock:
            self.stats.total_generated += 1
            
    def estimate_total(self) -> Optional[int]:
        """
        Estimate total candidates to be generated.
        
        Returns None for infinite/random generation.
        """
        if self.config.strategy in [GenerationStrategy.AI_PRIORITIZED]:
            return None  # Indeterminate
            
        charset_size = len(self.config.get_charset())
        total = 0
        
        for length in range(self.config.min_length, self.config.max_length + 1):
            total += charset_size ** length
            
        return total
