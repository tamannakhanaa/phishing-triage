#!/usr/bin/env python3
"""Quick start script for the Phishing Triage System."""

import os
import sys
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Load configuration
import config

def check_environment():
    """Check if environment is properly configured."""
    print("🔍 Checking Environment Configuration...")
    
    # Check if we're in virtual environment
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    print(f"Virtual Environment: {'✅' if in_venv else '⚠️ Not detected'}")
    
    # Check directories
    dirs = ["storage", "ml/metrics", "logs", "data"]
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    print("✅ Directories created")
    
    # Check configuration
    config.Config.print_status()
    
    return True

def test_apis():
    """Test configured APIs."""
    print("\n🧪 Testing API Connections...")
    
    # Test URLhaus
    try:
        from enrich.urlhaus import lookup_url
        result = lookup_url('http://example.com')
        if result.get('query_status') in ['no_results', 'ok']:
            print("✅ URLhaus API: Working")
        else:
            print(f"⚠️ URLhaus API: {result}")
    except Exception as e:
        print(f"❌ URLhaus API: {e}")
    
    # Test VirusTotal
    try:
        from enrich.free_intel import check_virustotal_public
        result = check_virustotal_public('http://example.com')
        if result.get('source') == 'virustotal':
            print("✅ VirusTotal API: Working")
        else:
            print(f"⚠️ VirusTotal API: {result}")
    except Exception as e:
        print(f"❌ VirusTotal API: {e}")

def start_basic_server():
    """Start the basic API server without ML model."""
    print("\n🚀 Starting Phishing Triage API Server...")
    print("📖 API Documentation: http://localhost:8000/docs")
    print("🔍 Health Check: http://localhost:8000/health")
    print("📊 Metrics: http://localhost:8000/metrics")
    print("\n⚠️ Note: ML model not available (scikit-learn installation needed)")
    print("The system will run with basic threat intelligence only.\n")
    
    try:
        import uvicorn
        # Start with basic configuration
        uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
    except Exception as e:
        print(f"❌ Server error: {e}")

def main():
    """Main entry point."""
    print("🛡️  Phishing Triage System - Quick Start")
    print("=" * 50)
    
    try:
        # Check environment
        check_environment()
        
        # Test APIs
        test_apis()
        
        # Ask user what to do
        print("\n🎯 What would you like to do?")
        print("1. Start API server (basic mode)")
        print("2. Run configuration test only")
        print("3. Exit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == "1":
            start_basic_server()
        elif choice == "2":
            print("\n✅ Configuration test completed!")
        elif choice == "3":
            print("👋 Goodbye!")
        else:
            print("❌ Invalid choice")
            
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()

