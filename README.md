```
   ▄██████▄   ▄█  ▀█████████▄     ▄████████  ▄██████▄  ███▄▄▄▄   
  ███    ███ ███    ███    ███   ███    ███ ███    ███ ███▀▀▀██▄ 
  ███    █▀  ███▌   ███    ███   ███    █▀  ███    ███ ███   ███ 
 ▄███        ███▌  ▄███▄▄▄██▀    ███        ███    ███ ███   ███ 
▀▀███ ████▄  ███▌ ▀▀███▀▀▀██▄  ▀███████████ ███    ███ ███   ███ 
  ███    ███ ███    ███    ██▄          ███ ███    ███ ███   ███ 
  ███    ███ ███    ███    ███    ▄█    ███ ███    ███ ███   ███ 
  ████████▀  █▀   ▄█████████▀   ▄████████▀   ▀██████▀   ▀█   █▀  
```

# Gibson Framework 🛡️

> "Hack the planet!" - Dade Murphy, Hackers (1995)

**AI/ML Security Testing Framework** - The ultimate hacker's toolkit for penetrating AI systems and democratizing security research

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Tests](https://img.shields.io/badge/tests-passing-green)
![Coverage](https://img.shields.io/badge/coverage-85%25-green)


## 🎯 What is Gibson?

Gibson is the first **community-driven AI security testing framework** built by hackers, for hackers. It's designed to find the cracks in the black box of modern AI systems. Every payload shared, every vulnerability found, makes the collective stronger.

**Think Metasploit for AI/ML systems** - but open source, community-powered, and built for the modern threat landscape.

## 🚀 Current Features & Capabilities

> "This is our world now... the world of the electron and the switch" - The Mentor

### 🔥 **Production-Ready Core**
- ✅ **Module Management System** - Install, update, and manage security modules from Git/Registry
- ✅ **5 Attack Domains** - Prompts, Data, Model, System, Output vectors
- ✅ **Type-Safe Architecture** - Full Pydantic v2 validation with IDE autocomplete
- ✅ **Async-First Design** - High-performance concurrent testing
- ✅ **Rich CLI Interface** - Beautiful terminal output with progress bars
- ✅ **Database Integration** - SQLite with migrations for scan history
- ✅ **Distributed Payloads** - Git-based community payload sharing
- ✅ **Professional Reporting** - Multiple formats (JSON, HTML, Markdown, PDF)
- ✅ **Credential Management** - Encrypted storage for API keys
- ✅ **Performance Monitoring** - Resource limits and execution tracking

### ⚡ **Advanced Capabilities**
- ✅ **Chain Attack Sequences** - Orchestrate complex multi-step attacks
- ✅ **Interactive Console** - Real-time testing and exploration mode  
- ✅ **AI Research Assistant** - Use AI to analyze AI vulnerabilities
- ✅ **Target Management** - Organize and track your test targets
- ✅ **Health Monitoring** - Code quality analysis and dependency tracking
- ✅ **Schema Validation** - Ensure data integrity across all operations

### 🛡️ **Security Testing Arsenal**
- **Prompt Injection** - Bypass safety filters and extract system prompts
- **Data Poisoning** - Test model training data integrity
- **Model Extraction** - Attempt to steal proprietary model parameters
- **Output Manipulation** - Control and steer AI responses
- **System Enumeration** - Probe infrastructure and configurations
- **Membership Inference** - Detect private training data
- **Jailbreaking** - Circumvent AI safety mechanisms
- **Resource Exhaustion** - DoS testing for AI endpoints

## 🛠️ Installation & Setup

### Quick Start
```bash
# Clone the underground
git clone https://github.com/zero-day-ai/gibson-framework
cd gibson-framework

# Join the resistance
make install-dev

# Initialize your base
gibson config init

```

### Production Installation
```bash
# Coming soon to PyPI
pip install gibson-framework

# Or build from source
git clone https://github.com/zero-day-ai/gibson-framework
cd gibson-framework
make build
pip install dist/gibson_framework-*.whl
```

### Requirements
- **Python 3.9+** (because legacy is for legacy systems)
- **Git** (for payload distribution)
- **SQLite** (local database, no cloud dependencies)
- **Modern terminal** (Rich output needs Rich terminals)

## 📖 Complete Usage Guide

> "Mess with the best, die like the rest" - Dade Murphy

### 🎯 **Basic Scanning Operations**

```bash
# Quick reconnaissance scan
gibson scan quick https://api.openai.com

# Full OWASP Top 10 assessment  
gibson scan full https://your-llm-api.com --output-format json

# Custom targeted scan
gibson scan custom https://target.com \
    --modules prompt-injection,system-extraction \
    --severity high,critical \
    --max-concurrent 10

# Scan with authentication
gibson scan full https://api.anthropic.com \
    --auth-type bearer \
    --auth-token "your-token-here"
```

### 🔧 **Module Management**

```bash
# Install from the underground
gibson module install github:security-collective/advanced-prompts
gibson module install https://github.com/ai-red-team/model-extraction.git

# Manage your arsenal
gibson module list --domain prompts
gibson module info prompt-injection-v2
gibson module update --all

# Install specific versions
gibson module install github:user/repo@v2.1.0

# Local development modules
gibson module install ./my-custom-module/
```

### 💣 **Payload Operations**

```bash
# Fetch community payloads
gibson payloads fetch advanced --source github:owasp/llm-payloads

# List your ammunition  
gibson payloads list --category injection --severity critical

# Update payload database
gibson payloads sync --all

# Export payloads for offline use
gibson payloads export --format json --output ./my-payloads.json
```

### 🔗 **Attack Chain Orchestration**

```bash
# Run predefined attack sequences
gibson chain run owasp-top-10 --target https://api.example.com
gibson chain run red-team-assessment --config ./engagement.yaml

# Create custom chains
gibson chain create --name "my-assessment" \
    --modules prompt-injection,data-extraction,privilege-escalation

# Chain with conditional logic
gibson chain run advanced-recon \
    --if-finding "system-prompt" then "privilege-escalation" \
    --max-depth 5
```

### 🎮 **Interactive Console Mode**

```bash
# Enter the matrix
gibson console

# Inside the console:
> target add https://api.example.com
> module load prompt-injection  
> attack run --payload "Ignore all previous instructions"
> findings show --severity high
> report generate
```

### 🎯 **Target Management**

```bash
# Add targets to your scope
gibson target add https://api.openai.com --name "OpenAI GPT"
gibson target add https://claude.ai --name "Anthropic Claude"

# Organize your targets
gibson target tag openai-gpt --tags "llm,commercial,high-value"
gibson target list --tags commercial

# Target-specific configurations
gibson target config openai-gpt \
    --auth-type bearer \
    --rate-limit 10/minute \
    --timeout 30s
```

### 📊 **Reporting & Analysis**

```bash
# Generate professional reports
gibson report generate --format html --output ./pentest-report.html
gibson report generate --format pdf --template executive-summary

# Historical analysis  
gibson report history --target-name "OpenAI GPT" --last-30-days
gibson report trends --metric "vulnerabilities-found" --group-by target

# Export findings
gibson report export --format csv --severity high,critical
gibson report compliance --framework "OWASP-LLM" --output compliance.json
```

### 🔐 **Credential & Configuration Management**

```bash
# Manage API credentials securely
gibson credentials add openai --type api-key --key "sk-..."
gibson credentials list
gibson credentials test openai

# Environment configuration
gibson config set global.timeout 60
gibson config set scanning.max-concurrent 20
gibson config show --section database
```


## 🏗️ Advanced Architecture

> "It's in that place where I put that thing that time" - Cereal Killer

### **Multi-Domain Attack Framework**
```
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│   PROMPTS       │     DATA        │     MODEL       │     SYSTEM      │     OUTPUT      │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ • Injection     │ • Poisoning     │ • Extraction    │ • Enumeration   │ • Manipulation  │
│ • Jailbreaking  │ • Inference     │ • Fingerprinting│ • Escalation    │ • Steering      │
│ • Extraction    │ • Leakage       │ • Inversion     │ • Side-channels │ • Hallucination │
│ • Bypass        │ • Membership    │ • Distillation  │ • Resource DoS  │ • Content Inject│
└─────────────────┴─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```
### **Distributed Payload Ecosystem (coming soon)**
```bash
# Community-driven security research
gibson community contribute ./my-zero-day-payload/
gibson community vote --payload "gpt4-system-extraction" --rating 5
gibson community stats --researcher @ai-security-ninja

# Automatic payload sharing
gibson config set community.auto-share-payloads true
gibson config set community.auto-update-modules true
```

### **Enterprise Integration**
```bash
# CI/CD Pipeline Integration
gibson scan ci \
    --baseline ./security-baseline.json \
    --fail-on "severity:high" \
    --export-sarif ./gibson-results.sarif

# Integration with security tools  (coming soon)
gibson export --format nuclei-templates ./nuclei-ai-templates/
gibson export --format burp-extensions ./burp-ai-scanner/
gibson import --from nessus-scan ./ai-infrastructure-scan.nessus
```

## 💎 Type-Safe Development Experience

> "Type safety separates the hackers from the script kiddies" - Modern Wisdom

### **Full IDE Support**
```python
from gibson.models.domain import PromptInjectionRequest, Finding, Severity
from gibson.core.modules.base import BaseModule

class AdvancedJailbreak(BaseModule):
    """Advanced jailbreak module with full type safety."""
    
    async def run(self, request: PromptInjectionRequest) -> Finding:
        # IDE provides full autocomplete and validation
        if request.evasion_techniques.character_substitution:
            payload = self.build_substitution_attack(
                request.target_prompt,
                substitution_method=request.evasion_techniques.method
            )
        
        result = await self.execute_attack(payload)
        
        return Finding(
            severity=Severity.CRITICAL,  # Enum with validation
            title="System Prompt Extracted",
            description="Successfully bypassed content filter",
            confidence=0.98,  # Float validation (0-1)
            evidence=result.extracted_data,
            remediation="Implement input sanitization",
            owasp_category="LLM01"  # Validated OWASP categories
        )
```

### **Module Development Template**
```bash
# Generate new module scaffolding
gibson module create my-attack \
    --domain prompts \
    --category injection \
    --template advanced

# Auto-generated type-safe module structure:
# - my_attack/
#   ├── __init__.py
#   ├── module.py (BaseModule implementation)
#   ├── models.py (Pydantic request/response models)  
#   ├── payloads/ (attack payloads)
#   ├── tests/ (pytest test suite)
#   └── metadata.yaml (module configuration)
```

### **Building Your Arsenal**
Create a Gibson-compatible security research repository:

```yaml
# gibson.yaml - Module manifest
metadata:
  name: "Advanced AI Jailbreaks"
  version: "2.0.0" 
  author: "AI Security Researcher"
  license: "Apache-2.0"
  
modules:
  - name: universal-jailbreak
    path: modules/universal_jailbreak.py
    description: "Universal jailbreak technique for any LLM"
    domain: prompts
    category: injection
    severity: critical
    targets: ["openai/gpt-*", "anthropic/claude-*", "google/bard"]
    
  - name: system-prompt-extractor
    path: modules/system_extractor.py  
    description: "Extract system prompts from any AI assistant"
    domain: prompts
    category: extraction
    severity: high

payloads:
  - directory: payloads/jailbreaks/
    format: yaml
    count: 1337
    
  - directory: payloads/prompt-injection/
    format: json
    count: 2048
```


## 🚀 Performance & Scale

### **Concurrent Testing**
- **Multi-threaded execution** - Test hundreds of endpoints simultaneously
- **Rate limiting** - Respect API limits while maximizing throughput  
- **Resource monitoring** - Prevent system overload during large scans
- **Distributed mode** - Scale across multiple machines (coming soon)

### **Optimized for Speed**
```bash
# High-performance scanning
gibson scan turbo https://api.example.com \
    --max-concurrent 100 \
    --timeout 5s \
    --batch-size 50 \
    --fast-fail true

# Results in seconds, not hours
gibson benchmark --target-count 1000 --report-performance
```

## 🛡️ Responsible Security Research


### **Community Guidelines**
- Only test systems you own or have explicit permission to test
- Respect rate limits and don't DDoS AI services
- Share findings responsibly with affected vendors
- Contribute back to the community with new techniques

### **Enterprise Compliance (coming soon)**
```bash
# Compliance reporting
gibson compliance check --frameworks "SOC2,ISO27001,NIST" 
gibson compliance report --audit-trail --legal-review
gibson compliance export --format "governance-report"
```

## 🔧 Development & Contribution

### **Local Development**
```bash
# Set up development environment
git clone https://github.com/zero-day-ai/gibson-framework
cd gibson-framework
make install-dev

# Run tests
make test-unit
make test-integration  
make test-cov

# Code quality
make lint
make format
make security
```


## 🤝 Join the Revolution

> "You wanted to know who I am, Zero Cool? Well, let me explain the New World Order" - The Plague

### **For Security Researchers**
- Discover novel AI vulnerabilities
- Contribute to cutting-edge research
- Build reputation in the community
- Access to exclusive research datasets

### **For Red Teams**
- Automated AI security assessments
- Enterprise-grade reporting  
- Integration with existing security tools
- Continuous monitoring capabilities

### **For Bug Bounty Hunters**
- Systematic vulnerability discovery
- Automated report generation
- Community payload sharing
- Performance tracking and rankings

### **For Academic Researchers**
- Reproducible research methodologies
- Statistical analysis built-in
- Publication-ready reporting
- Collaboration with industry experts

## 🌐 Community & Support

### **Get Involved**
- 🐛 **Report Bugs**: [GitHub Issues](https://github.com/zero-day-ai/gibson-framework/issues)
- 💡 **Feature Requests**: [Discussions](https://github.com/zero-day-ai/gibson-framework/discussions)
- 🔧 **Contribute Code**: Pull requests always welcome
- 📚 **Documentation**: Help improve our guides
- 🎯 **Share Payloads**: Build Gibson-compatible modules

### **Connect with the Community**

🐙 **GitHub**: [zero-day-ai/gibson-framework](https://github.com/zero-day-ai/gibson-framework)

💬 **Discord**: [Gibson Framework Community](https://discord.gg/mkqd6mU3)
- `#general` - Community discussion
- `#research` - Academic collaboration  
- `#modules` - Module development
- `#payloads` - Payload sharing
- `#support` - Technical help

📧 **Email**: anthony@zero-day.ai

📖 **Documentation**: [Docs](https://github.com/zero-day-ai/gibson-framework/docs)

### **Commercial Support**
Enterprise support and custom development available through Zero-Day.ai:
- Priority support and SLAs
- Custom module development
- Enterprise security audits  
- Training and workshops
- Compliance consulting

## 📝 License

Gibson Framework is released under **Apache License 2.0** - Free as in freedom, open as in source.

See [LICENSE](LICENSE) for full details.

## 🙏 Credits & Acknowledgments

```
 ╔═══════════════════════════════════════════════════════╗
 ║  Built with ❤️ by Zero-Day.ai for the hacker community ║
 ╚═══════════════════════════════════════════════════════╝
```


**Remember**: With great power comes great responsibility. Gibson is for authorized testing only. Don't be a black hat - hack responsibly, hack ethically, **hack the planet** 🌍.

> "We are the future. We are the digital underground." - The Gibson Collective
