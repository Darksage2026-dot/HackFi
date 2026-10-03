import threading
from typing import Optional, Callable
from dataclasses import dataclass


@dataclass
class SuccessEvent:
    """Event data for successful password discovery."""
    password: str
    candidate_number: int
    timestamp: float


class SuccessDetector:
    """
    Thread-safe success detection and cancellation coordinator.
    
    This class provides a shared success signal that all workers
    check to determine if they should stop processing.
    """
    
    def __init__(self):
        self._success = False
        self._result: Optional[SuccessEvent] = None
        self._lock = threading.RLock()
        self._callbacks: list[Callable[[SuccessEvent], None]] = []
        self._cancel_event = threading.Event()
        
    def check(self) -> bool:
        """Check if success has been detected."""
        with self._lock:
            return self._success
            
    def is_cancelled(self) -> bool:
        """Check if cancellation has been requested."""
        return self._cancel_event.is_set() or self._success
            
    def signal_success(self, password: str, candidate_number: int, timestamp: float) -> None:
        """
        Signal successful password discovery.
        
        This immediately sets the success flag and triggers cancellation
        of all workers.
        """
        with self._lock:
            if self._success:
                return  # Already succeeded
                
            self._success = True
            self._result = SuccessEvent(password, candidate_number, timestamp)
            self._cancel_event.set()
            
        # Notify callbacks outside the lock to prevent deadlocks
        for callback in self._callbacks:
            try:
                callback(self._result)
            except Exception:
                pass
                
    def get_result(self) -> Optional[SuccessEvent]:
        """Get the success result if any."""
        with self._lock:
            return self._result
            
    def register_callback(self, callback: Callable[[SuccessEvent], None]) -> None:
        """Register a callback to be called on success."""
        with self._lock:
            self._callbacks.append(callback)
            
    def reset(self) -> None:
        """Reset the detector for a new session."""
        with self._lock:
            self._success = False
            self._result = None
            self._cancel_event.clear()

