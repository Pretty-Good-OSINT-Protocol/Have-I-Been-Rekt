# PGOP OSINT Research Platform

**A SpiderFoot-powered automated OSINT research platform for journalists, investigators, and researchers.**

Built on the HIBR foundation, this fork focuses on traditional OSINT methodology with intelligent automation, pivot sequences, and comprehensive data collection workflows.

---

## 🎯 Core Mission

Democratize access to professional-grade OSINT capabilities through:
- **Automated data collection** using SpiderFoot's 234+ modules
- **Intelligent pivot sequences** following OSINT best practices
- **Form-driven workflows** reducing manual research overhead
- **Privacy-first processing** with local-first architecture
- **Research documentation** with audit trails and source attribution

---

## 🛠️ Key Features

### Automated Data Collection
- **SpiderFoot Integration**: Leverage 234+ OSINT modules automatically
- **Form-Driven Intake**: Structured data collection templates
- **Intelligent Queuing**: Optimize API calls and avoid rate limits
- **Result Aggregation**: Consolidate findings from multiple sources

### Pivot Sequence Engine
- **IF-THEN-THAT Logic**: Automated decision trees for research paths
- **Domain → Email → Social**: Follow natural OSINT progression
- **Configurable Workflows**: Customize pivot logic for different use cases
- **Evidence Chain**: Track the path from initial seed to final findings

### Research Documentation
- **Automated Reports**: Generate comprehensive investigation summaries
- **Source Attribution**: Link every finding to its data source
- **Timeline Construction**: Chronological view of research progression
- **Export Formats**: PDF, JSON, CSV for further analysis

---

## 📋 Workflow Overview

1. **Research Intake** - Structured form captures initial targets and objectives
2. **Automated Scanning** - SpiderFoot modules run in optimized sequence
3. **Pivot Detection** - System identifies new research vectors from findings
4. **Intelligent Expansion** - Automated follow-up research on discovered leads
5. **Report Generation** - Comprehensive documentation with source tracking
6. **Manual Review** - Human-in-the-loop validation and additional analysis

---

## 🏗️ Architecture

```
├── intake/                 # Data collection forms and workflows
├── spiderfoot-automation/  # SpiderFoot integration and management
├── pivot-engine/          # IF-THEN-THAT automation logic
├── reporting/             # Report generation and documentation
├── api/                   # REST API for web interface
└── ui/                    # Web interface for researchers
```

---

## 🔐 Privacy & Ethics

- **Researcher Protection**: No logging of research targets
- **Source Methods Protection**: Anonymize API usage patterns
- **Evidence Integrity**: Cryptographic verification of findings
- **Legal Compliance**: Built-in checks for jurisdiction-appropriate methods

---

## 🚀 Getting Started

```bash
# Clone and setup
git clone https://github.com/Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt.git
cd Have-I-Been-Rekt/osint-research-fork

# Install dependencies
pip install -r requirements.txt

# Setup SpiderFoot
docker-compose up spiderfoot

# Start research platform
python osint_platform.py
```

Visit `http://localhost:5000` to begin research.

---

## 🤝 Community

This platform is designed for the OSINT community including:
- **Journalists** investigating stories
- **Security Researchers** tracking threats
- **Activists** documenting abuse
- **Academics** studying information operations
- **Law Enforcement** (where legally appropriate)

All research should comply with applicable laws and ethical guidelines.

---

## 📚 Documentation

- [Research Workflows](docs/workflows.md) - Common OSINT patterns
- [SpiderFoot Guide](docs/spiderfoot-integration.md) - Module configuration
- [Pivot Sequences](docs/pivot-logic.md) - Automation decision trees
- [API Reference](docs/api.md) - Integration endpoints
- [Privacy Guide](docs/privacy.md) - Operational security best practices

---

Built with ❤️ for the global OSINT community. Privacy-first, community-funded, open source.