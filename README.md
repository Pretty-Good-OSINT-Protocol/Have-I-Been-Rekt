
# Pretty Good OSINT Protocol (PGOP)

**“Now not only the bad guys have these tools.”**

PGOP is a modular, open-source intelligence platform designed to democratize access to advanced investigative tools for journalists, researchers, activists, and public-interest technologists. It combines OSINT, blockchain forensics, and AI-powered automation into one privacy-first, accessible toolkit.

---

## 🌐 Features

- **🔎 OSINT Engine** – Automated profiling with SpiderFoot + enhanced modules
- **🧠 AI Assistant** – Summarize scans, classify targets, and suggest next steps using OpenAI, Claude, and more
- **🖼 Multimedia Analysis** – ExifTool, facial similarity, image geolocation
- **🔗 Blockchain Forensics** – Wallet & contract tracing using Etherscan, Bitquery, Web3
- **📦 Immutable Reporting** – Publish findings to IPFS + Orbit Chain or Base
- **🕵️ Privacy Layer** – Optional zero-knowledge redaction using Holonym
- **💱 Crypto Payments** – Pay for API services using cryptocurrency
- **🧰 CLI + Web UI** – Power-user CLI & beginner-friendly Streamlit GUI
- **🧪 Optional Non-Web3 Mode** – No blockchain storage, local-only reports

---

## 🚀 Getting Started

### 1. Clone this repo
```bash
git clone https://github.com/M0nkeyFl0wer/Pretty-Good-OSINT-Protocol.git
cd Pretty-Good-OSINT-Protocol
```

### 2. Add your API keys (note: this will be live when the project is available in BETA)
Copy `.env.example` to `.env` and fill in:
```
OPENAI_API_KEY=your-key
SERPAPI_KEY=your-key
WHOISXML_API_KEY=your-key
HUNTER_API_KEY=your-key
```

### 3. Run locally with Docker
```bash
docker-compose up --build
```


---

## 📦 Folder Structure

```
app/
├── core/              # OSINT, blockchain, AI modules
├── ui/                # Streamlit GUI
├── cli/               # Command-line tool
modules/               # SpiderFoot plugins
deploy/                # Cloud-init, Docker, automation
data/reports/          # Saved reports (CSV/JSON)
```

---

## 💡 Want to Contribute?

Check back soon as we will be creating and populating information here: [CONTRIBUTING.md](CONTRIBUTING.md) and [PGOP_Task_Board.md](PGOP_Task_Board.md) to get started.

---

## 🧭 Project Vision

> To give the public access to high-integrity intelligence tools—open, ethical, and secure.  
> Whether you're a journalist, researcher, DAO delegate, or just OSINT-curious, PGOP is built to empower you.

---

## 🛠 Building With

- [SpiderFoot](https://github.com/smicallef/spiderfoot)
- [Open LLama](https://github.com/openlm-research/open_llama)
- [Streamlit](https://streamlit.io/)
- [IPFS](https://ipfs.io/)
- [Orbit Chain](https://bridge.orbit.network/)
- [Holonym / Human.Tech](https://human.tech/)

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
