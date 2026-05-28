# 100% Free Phishing Triage Setup

This guide shows how to run the entire phishing triage system without any paid services.

## 🆓 Free Components Used

### Core System (Already Implemented)
- ✅ **FastAPI** - Web API (MIT license)
- ✅ **scikit-learn** - Machine learning (BSD-3 license)  
- ✅ **SQLite** - Database (public domain)
- ✅ **MLflow** - Experiment tracking (Apache-2.0)
- ✅ **River ADWIN** - Drift detection (BSD-3)

### Threat Intelligence (Free APIs)
- ✅ **URLhaus** - Free API with auth key
- ✅ **PhishTank** - Free API (rate limited)
- ✅ **OpenPhish** - Free feed
- ✅ **VirusTotal** - Free tier (4 requests/minute)

### Sandbox Analysis (Free Options)
- ✅ **Cuckoo Sandbox** - Self-hosted (GPLv3)
- ✅ **Joe Sandbox Basic** - Limited free tier
- ✅ **Hatching Triage** - Free individual accounts

### LLM Enhancement (Local/Free)
- ✅ **Ollama + Llama 3.1** - Free local LLM
- ✅ **Rule-based fallback** - No dependencies

## 🚀 Quick Free Setup

### 1. Basic Setup
```bash
cd phish-triage
python setup.py
python -m ml.train
```

### 2. Enable Free Threat Intel
```bash
# Edit .env file
echo "PHISHTANK_API_KEY=your_free_key" >> .env
echo "VT_API_KEY=your_free_virustotal_key" >> .env
echo "URLHAUS_AUTH_KEY=your_free_urlhaus_key" >> .env
```

### 3. Setup Local LLM (Optional)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Download free model
ollama pull llama3.1:8b

# Test
ollama run llama3.1:8b "Hello!"
```

### 4. Setup Cuckoo Sandbox (Optional)
```bash
# See: https://cuckoo.readthedocs.io/en/latest/installation/
# Requires VM setup - more complex but completely free
```

## 🔧 Free API Keys Setup

### URLhaus (Required - Free)
1. Visit: https://urlhaus.abuse.ch/api/
2. Request free auth key
3. Add to `.env`: `URLHAUS_AUTH_KEY=your_key`

### PhishTank (Optional - Free)
1. Visit: https://www.phishtank.com/api_info.php  
2. Request free API key
3. Add to `.env`: `PHISHTANK_API_KEY=your_key`

### VirusTotal (Optional - Free Tier)
1. Visit: https://www.virustotal.com/gui/join-us
2. Get free API key (4 requests/minute)
3. Add to `.env`: `VT_API_KEY=your_key`

## 🧪 Test Free Setup

```bash
# Test with free threat intel
curl -X POST http://localhost:8000/submit \
  -H "Content-Type: application/json" \
  -d '{"url": "http://suspicious-site.com/login"}'

# Check enhanced free intel
python -c "
from enrich.free_intel import multi_intel_lookup
result = multi_intel_lookup('http://test.com')
print(result)
"

# Test local LLM (if installed)
python -c "
from reports.local_llm import enhance_report_with_llm
result = enhance_report_with_llm('http://test.com', 0.8, {})
print(result)
"
```

## 📊 Free vs Paid Comparison

| Feature | Free Option | Paid Option |
|---------|-------------|-------------|
| **Core ML** | ✅ scikit-learn | Same |
| **API Framework** | ✅ FastAPI | Same |
| **Database** | ✅ SQLite | PostgreSQL |
| **Threat Intel** | ✅ URLhaus + PhishTank | Premium feeds |
| **Sandbox** | ✅ Cuckoo (self-hosted) | ANY.RUN/Joe Pro |
| **LLM Reports** | ✅ Ollama + Llama 3.1 | OpenAI/Claude |
| **Monitoring** | ✅ MLflow | Commercial APM |

## 🎯 Recommended Free Stack

**Minimal Setup (5 minutes):**
```bash
make setup && make train && make serve
```

**Enhanced Free Setup (30 minutes):**
1. Core system ✅
2. URLhaus API key ✅  
3. PhishTank API key ✅
4. Ollama + Llama 3.1 ✅

**Advanced Free Setup (2+ hours):**
1. Everything above ✅
2. Cuckoo Sandbox setup ✅
3. Custom threat feeds ✅
4. Advanced monitoring ✅

## 🔒 Security Notes

- All free APIs have rate limits - respect them
- Cuckoo requires proper VM isolation  
- Local LLM requires GPU for good performance
- Monitor resource usage on free tiers

## 📈 Scaling from Free

When you outgrow free tiers:
1. **Database**: SQLite → PostgreSQL  
2. **Sandbox**: Cuckoo → ANY.RUN/Joe Pro
3. **LLM**: Local → Cloud APIs
4. **Intel**: Free feeds → Premium feeds
5. **Hosting**: Local → Cloud/Docker

The beauty of this architecture is you can upgrade components individually as needed!

## 🆘 Troubleshooting Free Setup

**"No API key" errors:**
- Get free URLhaus key (required)
- Other intel sources are optional

**"Ollama not found":**
- Install from https://ollama.ai/
- System falls back to rule-based enhancement

**"Cuckoo connection failed":**
- Cuckoo is optional, system works without it
- Use Joe Sandbox Basic free tier instead

**Rate limit errors:**
- Expected with free tiers
- System continues with available data
