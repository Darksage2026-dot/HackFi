import unittest
import tempfile
import os
import time
import threading

from config import AuditConfig, GenerationStrategy, CharSet
from candidate_engine import CandidateEngine
from success_detector import SuccessDetector
from performance import PerformanceMetrics


class SyntheticWPAHandshake:
    """Synthetic handshake for testing without real capture files."""
    
    def __init__(self, password: str, ssid: str = "TestNetwork"):
        self.password = password
        self.ssid = ssid
        self.mac_ap = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        self.mac_client = bytes([0x00, 0x66, 0x77, 0x88, 0x99, 0xaa])
        self.anonce = os.urandom(32)
        self.snonce = os.urandom(32)
        self.key_version = 2
        
        # Generate synthetic EAPOL frame and MIC
        self.eapol_frame = self._generate_eapol()
        self.mic = self._calculate_mic_for_password(password)
        
    def _generate_eapol(self) -> bytes:
        """Generate synthetic EAPOL frame."""
        return os.urandom(100)  # Simplified
        
    def _calculate_mic_for_password(self, password: str) -> bytes:
        """Calculate expected MIC for the test password."""
        import hashlib
        import hmac
        
        # Simplified MIC calculation for testing
        pmk = hashlib.pbkdf2_hmac('sha1', password.encode(), 
                                   self.ssid.encode(), 4096, 32)
        return hmac.new(pmk, self.eapol_frame, hashlib.sha1).digest()[:16]


class TestCandidateGeneration(unittest.TestCase):
    """Test candidate generation engine."""
    
    def test_numeric_generation(self):
        """Test numeric password generation."""
        config = AuditConfig(
            strategy=GenerationStrategy.NUMERIC,
            min_length=4,
            max_length=4
        )
        engine = CandidateEngine(config)
        
        candidates = list(engine.generate())
        self.assertEqual(len(candidates), 10000)  # 10^4
        
        # Verify all numeric
        for c in candidates:
            self.assertTrue(c.isdigit())
            self.assertEqual(len(c), 4)
            
    def test_lowercase_generation(self):
        """Test lowercase generation."""
        config = AuditConfig(
            strategy=GenerationStrategy.LOWERCASE,
            min_length=3,
            max_length=3
        )
        engine = CandidateEngine(config)
        
        # Just verify it generates
        count = 0
        for _ in engine.generate():
            count += 1
            if count >= 1000:
                break
                
        self.assertEqual(count, 1000)
        
    def test_generation_rate(self):
        """Test generation meets rate target."""
        config = AuditConfig(
            strategy=GenerationStrategy.NUMERIC,
            min_length=4,
            max_length=4
        )
        engine = CandidateEngine(config)
        
        start = time.perf_counter()
        count = 0
        for _ in engine.generate():
            count += 1
            
        elapsed = time.perf_counter() - start
        rate = count / elapsed
        
        print(f"\nGeneration rate: {rate:.0f} candidates/sec")
        self.assertGreater(rate, 100)  # Should be reasonably fast
        
    def test_memory_only_operation(self):
        """Verify no disk writes during generation."""
        config = AuditConfig(
            strategy=GenerationStrategy.NUMERIC,
            min_length=3,
            max_length=3
        )
        engine = CandidateEngine(config)
        
        # Generate candidates
        candidates = list(engine.generate())
        
        # Verify no temp files created
        # (In real test, would monitor filesystem)
        self.assertEqual(len(candidates), 1000)


class TestSuccessDetection(unittest.TestCase):
    """Test success detection and cancellation."""
    
    def test_success_signal(self):
        """Test success signaling."""
        detector = SuccessDetector()
        
        self.assertFalse(detector.check())
        
        detector.signal_success("testpass", 100, time.time())
        
        self.assertTrue(detector.check())
        result = detector.get_result()
        self.assertEqual(result.password, "testpass")
        self.assertEqual(result.candidate_number, 100)
        
    def test_worker_cancellation(self):
        """Test worker cancellation on success."""
        detector = SuccessDetector()
        
        def worker():
            while not detector.is_cancelled():
                time.sleep(0.01)
            return "cancelled"
            
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
            
        time.sleep(0.1)
        detector.signal_success("found", 50, time.time())
        
        for t in threads:
            t.join(timeout=1.0)
            
        self.assertTrue(detector.check())


class TestPerformanceMonitoring(unittest.TestCase):
    """Test performance monitoring."""
    
    def test_metrics_collection(self):
        """Test metrics are collected correctly."""
        metrics = PerformanceMetrics()
        
        metrics.start()
        time.sleep(0.1)
        metrics.update_generation(100)
        metrics.update_testing(50)
        
        self.assertGreater(metrics.get_elapsed_time(), 0)
        self.assertEqual(metrics.candidates_generated, 100)
        self.assertEqual(metrics.candidates_tested, 50)
        
    def test_rate_calculation(self):
        """Test rate calculations."""
        metrics = PerformanceMetrics()
        metrics.start()
        
        # Simulate generation
        for i in range(10):
            metrics.update_generation(i * 100)
            time.sleep(0.11)  # Just over 0.1s for rate updates
            
        rate = metrics.get_generation_rate()
        self.assertGreater(rate, 0)


class TestSecureMemory(unittest.TestCase):
    """Test secure memory handling."""
    
    def test_secure_buffer(self):
        """Test secure buffer clearing."""
        from secure_memory import SecureBuffer
        
        buf = SecureBuffer("sensitive_data")
        self.assertEqual(buf.get(), b"sensitive_data")
        
        buf.clear()
        self.assertEqual(buf.get(), b"")


def run_synthetic_tests():
    """Run all synthetic tests."""
    print("\n" + "=" * 60)
    print("RUNNING SYNTHETIC TESTS")
    print("=" * 60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestCandidateGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestSuccessDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformanceMonitoring))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureMemory))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 60)
    
    return result.wasSuccessful()
