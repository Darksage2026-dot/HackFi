import argparse
import sys
import time
from typing import Optional

from config import AuditConfig, GenerationStrategy, CharSet
from capture_parser import CaptureParser
from candidate_engine import CandidateEngine
from verifier import Verifier
from success_detector import SuccessDetector
from worker_manager import WorkerManager, WorkerConfig
from performance import PerformanceMetrics
from secure_memory import SecureString


def get_authorization() -> bool:
    """Get explicit authorization from user."""
    print("\n" + "=" * 60)
    print("AUTHORIZATION REQUIRED")
    print("=" * 60)
    print("\nThis tool is for AUTHORIZED security testing only.")
    print("You must have explicit permission to test the target network.")
    print("\nUnauthorized access to computer networks is illegal.")
    print("=" * 60)
    
    response = input("\nType 'YES' to confirm: ").strip().upper()
    return response == "YES"


def parse_strategy(value: str) -> GenerationStrategy:
    """Parse strategy string to enum."""
    strategies = {
        'numeric': GenerationStrategy.NUMERIC,
        'lowercase': GenerationStrategy.LOWERCASE,
        'uppercase': GenerationStrategy.UPPERCASE,
        'alnum': GenerationStrategy.ALPHANUMERIC,
        'alphanumeric': GenerationStrategy.ALPHANUMERIC,
        'custom': GenerationStrategy.CUSTOM,
        'pattern': GenerationStrategy.PATTERN,
        'mask': GenerationStrategy.MASK,
        'ai': GenerationStrategy.AI_PRIORITIZED,
    }
    return strategies.get(value.lower(), GenerationStrategy.ALPHANUMERIC)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        description="Wi-Fi AI Auditor - Authorized Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --capture lab.cap --length 8 --charset alnum
  %(prog)s --capture lab.cap --min 8 --max 12 --strategy ai --org "Company"
  %(prog)s --capture lab.cap --pattern "?l?l?l?d?d?d?d" --workers 8
        """
    )
    
    # Capture options
    parser.add_argument('--capture', '-c', required=True,
                        help='Path to WPA/WPA2 capture file')
    parser.add_argument('--ssid', '-s',
                        help='Target SSID (optional)')
    
    # Generation options
    parser.add_argument('--length', '-l', type=int, default=8,
                        help='Password length (default: 8)')
    parser.add_argument('--min-length', type=int,
                        help='Minimum password length')
    parser.add_argument('--max-length', type=int,
                        help='Maximum password length')
    parser.add_argument('--charset', choices=['numeric', 'lowercase', 'uppercase', 
                                               'alnum', 'alphanumeric', 'custom'],
                        default='alnum',
                        help='Character set for generation')
    parser.add_argument('--custom-charset',
                        help='Custom character set (with --charset custom)')
    parser.add_argument('--strategy', choices=['numeric', 'lowercase', 'uppercase',
                                                'alnum', 'custom', 'pattern', 
                                                'mask', 'ai'],
                        default='alnum',
                        help='Generation strategy')
    parser.add_argument('--pattern',
                        help='Pattern for generation (?d=digit, ?l=lower, etc.)')
    parser.add_argument('--mask',
                        help='Mask for generation')
    
    # AI options
    parser.add_argument('--no-ai', action='store_true',
                        help='Disable AI prioritization')
    parser.add_argument('--org', '--organization',
                        help='Organization name for AI context')
    parser.add_argument('--prefix',
                        help='Known password prefix')
    parser.add_argument('--suffix',
                        help='Known password suffix')
    
    # Performance options
    parser.add_argument('--rate', '-r', type=int, default=500,
                        help='Target generation rate (default: 500/sec)')
    parser.add_argument('--workers', '-w', type=int,
                        help='Number of worker threads (default: CPU count)')
    parser.add_argument('--batch-size', type=int, default=1000,
                        help='Batch size for generation')
    
    # Output options
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Minimal output')
    parser.add_argument('--no-auth-skip', action='store_true',
                        help='Skip authorization prompt (for testing)')
    
    return parser


def run_audit(config: AuditConfig, skip_auth: bool = False) -> Optional[str]:
    """
    Run the password audit with the given configuration.
    
    Returns the discovered password or None if not found.
    """
    # Authorization check
    if not skip_auth and config.require_authorization:
        if not get_authorization():
            print("Authorization denied. Exiting.")
            return None
    
    # Parse capture file
    parser = CaptureParser()
    capture_info = parser.parse_file(config.capture_path)
    
    if not capture_info.is_valid:
        print(f"Error: {capture_info.error_message}")
        return None
        
    if not capture_info.handshakes:
        print("Error: No WPA handshakes found in capture file")
        return None
        
    handshake = capture_info.handshakes[0]
    print(f"\nTarget: {handshake.ssid or 'Unknown'}")
    print(f"Handshakes found: {len(capture_info.handshakes)}")
    
    # Setup components
    candidate_engine = CandidateEngine(config)
    verifier = Verifier(handshake)
    success_detector = SuccessDetector()
    metrics = PerformanceMetrics()
    
    worker_config = WorkerConfig(
        num_workers=config.max_workers,
        batch_size=config.batch_size
    )
    
    manager = WorkerManager(candidate_engine, verifier, success_detector,
                           metrics, worker_config)
    
    # Display configuration
    print(f"\nMode: {'AI-assisted' if config.use_ai else 'Deterministic'} candidate generation")
    print(f"Strategy: {config.strategy.name}")
    print(f"Length: {config.min_length}-{config.max_length}")
    print(f"Workers: {config.max_workers}")
    print(f"\nStarting audit...\n")
    
    # Progress display
    def display_progress():
        while not success_detector.check():
            time.sleep(0.5)
            if success_detector.check():
                break
            rate = metrics.get_testing_rate()
            tested = metrics.candidates_tested
            elapsed = metrics.get_elapsed_time()
            print(f"\rRate: {rate:.0f}/sec | Tested: {tested:,} | "
                  f"Time: {elapsed:.1f}s", end='', flush=True)
    
    # Start progress thread
    import threading
    progress_thread = threading.Thread(target=display_progress)
    progress_thread.daemon = True
    
    # Run audit
    manager.start()
    progress_thread.start()
    
    result = manager.wait_for_completion()
    manager.stop()
    
    # Final output
    print("\n" + "=" * 60)
    if result and result.password:
        print("SUCCESS")
        print("=" * 60)
        print(f"\nPassword discovered: {result.password}")
        print(f"Candidates tested: {metrics.candidates_tested:,}")
        print(f"Time elapsed: {metrics.get_elapsed_time():.2f} seconds")
        
        # Secure handling of result
        with SecureString(result.password) as secure_pw:
            return secure_pw.get()
    else:
        print("Password not found")
        print(f"Candidates tested: {metrics.candidates_tested:,}")
        print(f"Time elapsed: {metrics.get_elapsed_time():.2f} seconds")
        return None


def main():
    """Main entry point."""
    arg_parser = create_parser()
    args = arg_parser.parse_args()
    
    # Build configuration
    min_len = args.min_length or args.length
    max_len = args.max_length or args.length
    
    config = AuditConfig(
        capture_path=args.capture,
        target_ssid=args.ssid,
        strategy=parse_strategy(args.strategy),
        min_length=min_len,
        max_length=max_len,
        custom_charset=args.custom_charset or "",
        pattern=args.pattern or "",
        mask=args.mask or "",
        use_ai=not args.no_ai,
        organization=args.org,
        known_prefix=args.prefix,
        known_suffix=args.suffix,
        target_rate=args.rate,
        max_workers=args.workers or (import os; os.cpu_count() or 4),
        batch_size=args.batch_size
    )
    
    # Run audit
    result = run_audit(config, skip_auth=args.no_auth_skip)
    
    return 0 if result else 1

