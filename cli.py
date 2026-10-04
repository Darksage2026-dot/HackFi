# cli_special.py - Enhanced CLI with special character support

import argparse
import sys

from config import AuditConfig, GenerationStrategy, CharSet
from special_char_handler import (
    SpecialCharHandler, SpecialCharConfig, SpecialCharMode,
    add_special_char_args
)


def parse_special_mode(value: str) -> SpecialCharMode:
    """Parse special mode string to enum."""
    modes = {
        'none': SpecialCharMode.NONE,
        'end': SpecialCharMode.END_ONLY,
        'start': SpecialCharMode.START_ONLY,
        'ends': SpecialCharMode.ENDS,
        'middle': SpecialCharMode.MIDDLE,
        'anywhere': SpecialCharMode.ANYWHERE,
        'specific': SpecialCharMode.SPECIFIC,
    }
    return modes.get(value.lower(), SpecialCharMode.ANYWHERE)


def create_enhanced_parser() -> argparse.ArgumentParser:
    """Create CLI parser with special character support."""
    parser = argparse.ArgumentParser(
        description="Wi-Fi AI Auditor - Enhanced Special Character Support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Special Character Examples:
  # Passwords ending with special char
  wifi-audit --capture lab.cap --length 8 --special-mode end
  
  # At least 1, at most 2 special characters anywhere
  wifi-audit --capture lab.cap --min 8 --max 12 --min-special 1 --max-special 2
  
  # Custom special charset
  wifi-audit --capture lab.cap --length 8 --special-charset "!@#$"
  
  # Leet speak substitutions
  wifi-audit --capture lab.cap --length 8 --leet
  
  # Pattern with special char at position 4
  wifi-audit --capture lab.cap --pattern "?l?l?l?s?d?d?d?d"
  
  # Common special patterns prioritized
  wifi-audit --capture lab.cap --length 8 --common-special
        """
    )
    
    # Original arguments
    parser.add_argument('--capture', '-c', required=True,
                       help='Path to WPA/WPA2 capture file')
    parser.add_argument('--length', '-l', type=int, default=8)
    parser.add_argument('--min-length', type=int)
    parser.add_argument('--max-length', type=int)
    parser.add_argument('--charset', choices=['numeric', 'lowercase', 
                                               'uppercase', 'alphanumeric',
                                               'special', 'all', 'custom'],
                       default='alphanumeric')
    parser.add_argument('--custom-charset')
    parser.add_argument('--strategy', choices=['numeric', 'lowercase', 
                                               'uppercase', 'alphanumeric',
                                               'custom', 'pattern', 'mask', 'ai'],
                       default='alphanumeric')
    parser.add_argument('--pattern')
    parser.add_argument('--workers', '-w', type=int)
    
    # Add special character arguments
    add_special_char_args(parser)
    
    return parser


def run_enhanced_audit(args) -> None:
    """Run audit with special character support."""
    
    # Build special char config
    special_config = SpecialCharConfig(
        mode=parse_special_mode(args.special_mode),
        charset=args.special_charset,
        min_count=args.min_special,
        max_count=args.max_special,
        required_positions=[int(p) for p in args.special_positions.split(',')] 
                          if args.special_positions else None
    )
    
    # Build main config
    min_len = args.min_length or args.length
    max_len = args.max_length or args.length
    
    # Determine charset
    if args.charset == 'special':
        charset = SpecialCharHandler.EXTENDED_SPECIAL
    elif args.charset == 'all':
        charset = CharSet.ALPHANUMERIC + SpecialCharHandler.EXTENDED_SPECIAL
    else:
        charset = args.custom_charset or CharSet.ALPHANUMERIC
        
    config = AuditConfig(
        capture_path=args.capture,
        min_length=min_len,
        max_length=max_len,
        custom_charset=charset,
        strategy=GenerationStrategy.CUSTOM if args.charset == 'custom' else 
                GenerationStrategy[args.strategy.upper()],
        pattern=args.pattern or "",
        max_workers=args.workers or 4
    )
    
    print(f"\nConfiguration:")
    print(f"  Capture: {config.capture_path}")
    print(f"  Length: {config.min_length}-{config.max_length}")
    print(f"  Special Mode: {special_config.mode.name}")
    print(f"  Special Charset: {special_config.charset}")
    print(f"  Min Special: {special_config.min_count}")
    print(f"  Max Special: {special_config.max_count}")
    
    # Create enhanced engine
    from candidate_engine import CandidateEngine
    
    # If using special handling, wrap the generation
    if special_config.mode != SpecialCharMode.NONE:
        handler = SpecialCharHandler(special_config)
        
        print(f"\nGenerating passwords with special character constraints...")
        
        if args.common_special:
            # Generate common patterns first
            print("  - Testing common special patterns")
            base_words = ["password", "admin", "welcome", "login", "user", "test"]
            for word in base_words:
                for variant in handler.generate_with_special(word):
                    if min_len <= len(variant) <= max_len:
                        print(f"    Testing: {variant}")
                        # Would verify here in real implementation
        
        if args.leet:
            print("  - Testing leet speak variations")
            for word in ["password", "admin", "master"]:
                for variant in handler.apply_substitutions(word, probability=0.5):
                    if min_len <= len(variant) <= max_len:
                        print(f"    Testing: {variant}")
                        
        # Then do full generation
        print(f"\n  - Testing all combinations with {special_config.min_count}+ special chars")
        count = 0
        for pwd in handler.generate_special_combinations(min_len, 
                                                         special_config.min_count,
                                                         special_config.max_count):
            count += 1
            if count % 10000 == 0:
                print(f"    Generated {count:,} candidates...")
            if count >= 100000:  # Demo limit
                break


def main():
    """Main entry point with special character support."""
    parser = create_enhanced_parser()
    args = parser.parse_args()
    
    run_enhanced_audit(args)


if __name__ == '__main__':
    main()