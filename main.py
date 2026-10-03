import sys

from Synthetic import run_synthetic_tests


def print_banner():
    """Print application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║           Wi-Fi AI Auditor - Security Testing Tool            ║
    ║                                                               ║
    ║     Authorized Wi-Fi Security Auditing & Penetration Testing  ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    WARNING: This tool is for AUTHORIZED security testing only.
    Unauthorized access to computer networks is illegal.
    
    """
    print(banner)


def main():
    """Main entry point."""
    print_banner()
    
    # Check for GUI mode
    if len(sys.argv) > 1 and sys.argv[1] == '--gui':
        launch_gui()
        return
        
    # Check for test mode
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        success = run_synthetic_tests()
        sys.exit(0 if success else 1)
        
    # CLI mode
    from cli import main as cli_main
    sys.exit(cli_main())


if __name__ == '__main__':
    main()