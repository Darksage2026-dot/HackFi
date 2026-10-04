# README.md

# Wi-Fi AI Auditor

A professional, AI-assisted Wi-Fi security auditing tool for authorized penetration testing and security research.

## ⚠️ Legal Notice

**This tool is for AUTHORIZED security testing only.** You must have explicit written permission to test any network. Unauthorized access to computer networks is illegal under various laws including the Computer Fraud and Abuse Act (CFAA) and similar legislation worldwide.

## Features

- **AI-Assisted Generation**: Prioritizes likely passwords using pattern analysis
- **High Performance**: Multi-threaded architecture targeting 500+ candidates/second
- **Memory-Only Operation**: No passwords written to disk
- **Immediate Cancellation**: Stops all workers instantly on success
- **Multiple Strategies**: Numeric, alphabetic, alphanumeric, pattern-based, mask-based
- **Modern GUI**: Real-time dashboard with progress visualization
- **Comprehensive Testing**: Synthetic test environment for verification

## Installation

```bash
# Clone repository
git clone https://github.com/Darksage2026-dot/HackFi.git
cd HackFi

# Install dependencies
pip install -r requirements.txt

# Run tests
python main.py --test