import time
from dataclasses import dataclass, field
from typing import Optional
from collections import deque
import threading


@dataclass
class PerformanceMetrics:
    """Real-time performance metrics for the audit process."""
    
    candidates_generated: int = 0
    candidates_tested: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    success_time: Optional[float] = None
    found_password: Optional[str] = None
    
    # Rate tracking
    _generation_rates: deque = field(default_factory=lambda: deque(maxlen=10))
    _testing_rates: deque = field(default_factory=lambda: deque(maxlen=10))
    _last_gen_count: int = 0
    _last_test_count: int = 0
    _last_update_time: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def start(self) -> None:
        """Start performance tracking."""
        self.start_time = time.perf_counter()
        self._last_update_time = self.start_time
        
    def stop(self) -> None:
        """Stop performance tracking."""
        self.end_time = time.perf_counter()
        
    def mark_success(self, password: str) -> None:
        """Mark successful password discovery."""
        self.success_time = time.perf_counter()
        self.found_password = password
        
    def update_generation(self, count: int) -> None:
        """Update generation count."""
        with self._lock:
            self.candidates_generated = count
            self._update_rates()
            
    def update_testing(self, count: int) -> None:
        """Update testing count."""
        with self._lock:
            self.candidates_tested = count
            self._update_rates()
            
    def _update_rates(self) -> None:
        """Update rate calculations."""
        current_time = time.perf_counter()
        elapsed = current_time - self._last_update_time
        
        if elapsed >= 1.0:  # Update every second
            gen_rate = (self.candidates_generated - self._last_gen_count) / elapsed
            test_rate = (self.candidates_tested - self._last_test_count) / elapsed
            
            self._generation_rates.append(gen_rate)
            self._testing_rates.append(test_rate)
            
            self._last_gen_count = self.candidates_generated
            self._last_test_count = self.candidates_tested
            self._last_update_time = current_time
            
    def get_generation_rate(self) -> float:
        """Get current generation rate (candidates/sec)."""
        with self._lock:
            if not self._generation_rates:
                return 0.0
            return sum(self._generation_rates) / len(self._generation_rates)
    
    def get_testing_rate(self) -> float:
        """Get current testing rate (candidates/sec)."""
        with self._lock:
            if not self._testing_rates:
                return 0.0
            return sum(self._testing_rates) / len(self._testing_rates)
            
    def get_elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        if not self.start_time:
            return 0.0
        end = self.end_time or self.success_time or time.perf_counter()
        return end - self.start_time
        
    def get_estimated_progress(self, total_candidates: Optional[int] = None) -> Optional[float]:
        """Get estimated progress percentage."""
        if total_candidates and total_candidates > 0:
            return (self.candidates_tested / total_candidates) * 100
        return None
        
    def format_report(self) -> str:
        """Format a human-readable performance report."""
        lines = [
            f"Candidates Generated: {self.candidates_generated:,}",
            f"Candidates Tested: {self.candidates_tested:,}",
            f"Generation Rate: {self.get_generation_rate():.1f}/sec",
            f"Testing Rate: {self.get_testing_rate():.1f}/sec",
            f"Elapsed Time: {self.get_elapsed_time():.2f}s",
        ]
        
        if self.found_password:
            lines.append(f"\nSUCCESS - Password found: {self.found_password}")
            if self.success_time and self.start_time:
                lines.append(f"Time to discovery: {self.success_time - self.start_time:.2f}s")
                
        return "\n".join(lines)

