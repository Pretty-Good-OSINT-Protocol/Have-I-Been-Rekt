
# Pretty Good OSINT Protocol (PGOP)

**“Now not only the bad guys have these tools.”**

PGOP is a modular, open-source intelligence platform designed to democratize access to advanced investigative tools for journalists, researchers, activists, and public-interest technologists. It combines OSINT, blockchain forensics, and AI-powered automation into one privacy-first, accessible toolkit.

## 🚀 MVP Focus: Have I Been Rekt (May 2025)
This MVP focuses on building a front-end experience where users can assess if their wallet has been compromised, optionally triggering deeper OSINT analysis and payment-based advanced tools.

📄 [View full MVP plan and issues →](docs/mvp.md)


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
