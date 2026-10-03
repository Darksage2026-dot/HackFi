import threading
import queue
from typing import Optional, Callable, List
from dataclasses import dataclass
import time

from candidate_engine import CandidateEngine
from verifier import Verifier
from success_detector import SuccessDetector, SuccessEvent
from performance import PerformanceMetrics


@dataclass
class WorkerConfig:
    """Configuration for worker pool."""
    num_workers: int = 4
    batch_size: int = 100
    queue_size: int = 1000


class WorkerManager:
    """
    Manages worker threads for parallel candidate generation and testing.
    
    Coordinates between candidate generation, verification, and
    success detection with immediate cancellation support.
    """
    
    def __init__(self, candidate_engine: CandidateEngine,
                 verifier: Verifier,
                 success_detector: SuccessDetector,
                 metrics: PerformanceMetrics,
                 config: WorkerConfig):
        self.candidate_engine = candidate_engine
        self.verifier = verifier
        self.success_detector = success_detector
        self.metrics = metrics
        self.config = config
        
        self._workers: List[threading.Thread] = []
        self._candidate_queue: queue.Queue = queue.Queue(maxsize=config.queue_size)
        self._lock = threading.Lock()
        self._tested_count = 0
        
    def start(self) -> None:
        """Start all workers."""
        self.metrics.start()
        
        # Start generator thread
        generator_thread = threading.Thread(target=self._generator_worker)
        generator_thread.daemon = True
        generator_thread.start()
        self._workers.append(generator_thread)
        
        # Start tester threads
        for i in range(self.config.num_workers):
            worker = threading.Thread(target=self._tester_worker, name=f"Tester-{i}")
            worker.daemon = True
            worker.start()
            self._workers.append(worker)
            
    def stop(self) -> None:
        """Stop all workers."""
        self.success_detector.signal_success("", -1, time.time())  # Signal cancellation
        
        for worker in self._workers:
            if worker.is_alive():
                worker.join(timeout=1.0)
                
        self.metrics.stop()
        
    def wait_for_completion(self) -> Optional[SuccessEvent]:
        """Wait for completion (success or exhaustion)."""
        # Wait for success or all workers to finish
        while any(w.is_alive() for w in self._workers):
            if self.success_detector.check():
                return self.success_detector.get_result()
            time.sleep(0.1)
            
        return self.success_detector.get_result()
        
    def _generator_worker(self) -> None:
        """Worker that generates candidates and puts them in queue."""
        try:
            for candidate in self.candidate_engine.generate():
                if self.success_detector.is_cancelled():
                    break
                    
                # Put in queue with timeout to allow cancellation checks
                while not self.success_detector.is_cancelled():
                    try:
                        self._candidate_queue.put(candidate, timeout=0.1)
                        self.metrics.update_generation(
                            self.candidate_engine.stats.total_generated
                        )
                        break
                    except queue.Full:
                        continue
                        
        except Exception as e:
            print(f"Generator error: {e}")
        finally:
            # Signal end of generation
            for _ in range(self.config.num_workers):
                try:
                    self._candidate_queue.put(None, timeout=1.0)
                except queue.Full:
                    pass
                    
    def _tester_worker(self) -> None:
        """Worker that tests candidates from queue."""
        while not self.success_detector.is_cancelled():
            try:
                candidate = self._candidate_queue.get(timeout=0.5)
                
                if candidate is None:  # Poison pill
                    break
                    
                if self.success_detector.is_cancelled():
                    break
                    
                # Test the candidate
                if self.verifier.verify(candidate):
                    self.success_detector.signal_success(
                        candidate,
                        self._tested_count,
                        time.perf_counter()
                    )
                    self.metrics.mark_success(candidate)
                    break
                    
                with self._lock:
                    self._tested_count += 1
                    if self._tested_count % 100 == 0:
                        self.metrics.update_testing(self._tested_count)
                        
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Tester error: {e}")
                continue

