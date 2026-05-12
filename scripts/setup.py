#!/usr/bin/env python
"""Setup script for Phishing Triage System."""
import os
import sys
import subprocess
from pathlib import Path


def run_command(cmd, description):
    """Run a command with error handling."""
    print(f"\n{description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✓ {description} completed")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed")
        if e.stderr:
            print(f"Error: {e.stderr}")
        return False


def setup_environment():
    """Set up the development environment."""
    print("=== Phishing Triage System Setup ===\n")
    
    # Check Python version
    print("Checking Python version...")
    if sys.version_info < (3, 11):
        print("✗ Python 3.11+ is required")
        sys.exit(1)
    print(f"✓ Python {sys.version.split()[0]} detected")
    
    # Create necessary directories
    print("\nCreating directories...")
    dirs = ["data", "storage", "ml/metrics", "logs"]
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    print("✓ Directories created")
    
    # Check if in virtual environment
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("\n⚠️  Not in a virtual environment. It's recommended to use one.")
        print("Create one with: python -m venv .venv")
        print("Activate with: source .venv/bin/activate (Linux/Mac) or .venv\\Scripts\\activate (Windows)")
        response = input("\nContinue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Install dependencies
    if not run_command("pip install -r requirements.txt", "Installing dependencies"):
        sys.exit(1)
    
    # Create .env file if it doesn't exist
    if not Path(".env").exists():
        print("\nCreating .env file...")
        try:
            with open(".env.example", "r") as src, open(".env", "w") as dst:
                dst.write(src.read())
            print("✓ .env file created from .env.example")
            print("⚠️  Please edit .env and add your API keys")
        except Exception as e:
            print(f"✗ Failed to create .env: {e}")
    
    # Initialize database
    print("\nInitializing database...")
    try:
        from api.models import init_db
        init_db()
        print("✓ Database initialized")
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")
        sys.exit(1)
    
    # Check for model
    if not Path("ml/model.joblib").exists():
        print("\n⚠️  No trained model found.")
        print("You need to train a model before using the system.")
        print("\nTo train with sample data, run:")
        print("  python -m ml.train")
        print("\nFor production, download the PhiUSIIL dataset:")
        print("  https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset")
        print("  Place the CSV file in data/phiusiil.csv and run training")
    
    print("\n=== Setup Complete ===")
    print("\nNext steps:")
    print("1. Edit .env file with your API keys (optional)")
    print("2. Train the model: python -m ml.train")
    print("3. Start the server: uvicorn api.main:app --reload")
    print("4. Test the API: python test_api.py")
    print("\nAPI documentation will be available at:")
    print("  http://localhost:8000/docs")


if __name__ == "__main__":
    setup_environment()
