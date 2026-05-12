"""Configuration management for the phishing triage system."""
import os
from pathlib import Path
from typing import Optional

# Load environment variables from .env file
def load_env():
    """Load environment variables from .env file."""
    env_path = Path(".env")
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    # Only set if not already in environment
                    if key not in os.environ:
                        os.environ[key] = value

# Load environment variables on import
load_env()

# Configuration class
class Config:
    """Configuration settings for the phishing triage system."""
    
    # Service configuration
    SERVICE_HOST = os.getenv("SERVICE_HOST", "0.0.0.0")
    SERVICE_PORT = int(os.getenv("SERVICE_PORT", "8000"))
    
    # Database configuration
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///storage/submissions.db")
    
    # Model configuration
    RISK_THRESHOLD = float(os.getenv("RISK_THRESHOLD", "0.85"))
    MODEL_PATH = os.getenv("MODEL_PATH", "ml/model.joblib")
    
    # API Keys
    URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")
    VT_API_KEY = os.getenv("VT_API_KEY")
    PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")
    ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY")
    JOE_API_KEY = os.getenv("JOE_API_KEY")
    JOE_API_URL = os.getenv("JOE_API_URL", "https://jbxcloud.joesecurity.org/api")
    CUCKOO_API_KEY = os.getenv("CUCKOO_API_KEY")
    CUCKOO_API_URL = os.getenv("CUCKOO_API_URL", "http://localhost:8090")
    
    # Sandbox configuration
    MAX_DAILY_DETONATIONS = int(os.getenv("MAX_DAILY_DETONATIONS", "20"))
    SANDBOX_TIMEOUT_SECONDS = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "300"))
    
    # MLflow configuration
    MLFLOW_TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")
    
    # Logging configuration
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", "logs/phish-triage.log")
    
    @classmethod
    def get_configured_services(cls) -> dict:
        """Get list of configured services."""
        services = {
            "urlhaus": bool(cls.URLHAUS_AUTH_KEY),
            "virustotal": bool(cls.VT_API_KEY),
            "phishtank": bool(cls.PHISHTANK_API_KEY),
            "anyrun": bool(cls.ANYRUN_API_KEY),
            "joesandbox": bool(cls.JOE_API_KEY),
            "cuckoo": bool(cls.CUCKOO_API_KEY)
        }
        return services
    
    @classmethod
    def print_status(cls):
        """Print configuration status."""
        print("=== Phishing Triage Configuration ===")
        print(f"Service: {cls.SERVICE_HOST}:{cls.SERVICE_PORT}")
        print(f"Database: {cls.DATABASE_URL}")
        print(f"Risk Threshold: {cls.RISK_THRESHOLD}")
        print(f"Model Path: {cls.MODEL_PATH}")
        print("\n=== API Services ===")
        
        services = cls.get_configured_services()
        for service, configured in services.items():
            status = "✅ Configured" if configured else "❌ Not configured"
            print(f"{service.upper()}: {status}")
        
        print(f"\n=== Sandbox Settings ===")
        print(f"Max daily detonations: {cls.MAX_DAILY_DETONATIONS}")
        print(f"Timeout: {cls.SANDBOX_TIMEOUT_SECONDS}s")


# Test configuration loading
if __name__ == "__main__":
    Config.print_status()

