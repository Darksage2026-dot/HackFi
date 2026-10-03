import random
import re
from typing import Iterator, List, Optional, Dict
from dataclasses import dataclass


@dataclass
class AIPrioritizationContext:
    """Context for AI prioritization."""
    organization: Optional[str] = None
    known_prefix: Optional[str] = None
    known_suffix: Optional[str] = None
    common_patterns: Optional[List[str]] = None
    charset: str = ""
    min_length: int = 8
    max_length: int = 8


class AIPrioritizer:
    """
    AI-assisted password candidate prioritization.
    
    This module uses pattern analysis and heuristics to prioritize
    likely password candidates over random generation.
    
    Note: This is a local, privacy-preserving implementation that
    does not send data to external AI services.
    """
    
    # Common password patterns (based on research)
    COMMON_PATTERNS = [
        "{word}{year}", "{word}{num}",
        "{word}123", "{word}1234", "{word}12345",
        "{word}!", "{word}@", "{word}#",
        "{word}2023", "{word}2024", "{word}2025",
        "{num}{word}", "{year}{word}",
        "12345678", "password", "qwerty",
        "admin", "login", "welcome",
        "{org}{num}", "{org}{year}",
    ]
    
    # Common substitutions
    SUBSTITUTIONS = {
        'a': ['@', '4'],
        'e': ['3'],
        'i': ['1', '!'],
        'o': ['0'],
        's': ['$', '5'],
        't': ['7'],
    }
    
    def __init__(self, context: AIPrioritizationContext):
        self.context = context
        self._pattern_queue: List[str] = []
        self._pattern_index = 0
        self._generate_patterns()
        
    def _generate_patterns(self) -> None:
        """Generate prioritized patterns based on context."""
        patterns = []
        
        # Add organization-based patterns
        if self.context.organization:
            org = self.context.organization.lower()
            patterns.extend([
                org, org + "123", org + "2024", org + "2025",
                org + "!", org + "@", org + "#",
                "admin" + org, org + "admin",
            ])
            
        # Add prefix/suffix patterns
        if self.context.known_prefix:
            prefix = self.context.known_prefix
            for i in range(10000):
                patterns.append(f"{prefix}{i:04d}")
                
        if self.context.known_suffix:
            suffix = self.context.known_suffix
            for word in ["admin", "user", "test", "demo", "pass"]:
                patterns.append(f"{word}{suffix}")
                
        # Add common patterns with substitutions
        base_words = ["password", "admin", "welcome", "login", "master", "default"]
        for word in base_words:
            patterns.append(word)
            patterns.extend(self._apply_substitutions(word))
            
        # Filter by length requirements
        filtered = []
        for p in patterns:
            if self.context.min_length <= len(p) <= self.context.max_length:
                filtered.append(p)
                
        self._pattern_queue = filtered
        
    def _apply_substitutions(self, word: str) -> List[str]:
        """Apply common leet substitutions."""
        results = [word]
        for char, subs in self.SUBSTITUTIONS.items():
            new_results = []
            for w in results:
                for sub in subs:
                    new_results.append(w.replace(char, sub))
            results.extend(new_results)
        return results
        
    def get_prioritized_candidates(self, count: int) -> Iterator[str]:
        """
        Get AI-prioritized candidates.
        
        Yields candidates in order of likelihood based on the context.
        """
        # First yield pattern-based candidates
        while self._pattern_index < len(self._pattern_queue) and count > 0:
            yield self._pattern_queue[self._pattern_index]
            self._pattern_index += 1
            count -= 1
            
    def get_priority_score(self, candidate: str) -> float:
        """
        Calculate a priority score for a candidate.
        
        Higher scores indicate more likely passwords.
        """
        score = 0.0
        
        # Length preference (8-12 is common)
        if 8 <= len(candidate) <= 12:
            score += 10
            
        # Common patterns
        if re.search(r'\d{4}$', candidate):  # Ends with year
            score += 15
        if re.search(r'[!@#$%]$', candidate):  # Ends with special
            score += 10
            
        # Organization match
        if self.context.organization:
            org_lower = self.context.organization.lower()
            if org_lower in candidate.lower():
                score += 20
                
        # Dictionary words
        common_words = ["admin", "pass", "word", "login", "user", "test"]
        for word in common_words:
            if word in candidate.lower():
                score += 5
                
        return score


