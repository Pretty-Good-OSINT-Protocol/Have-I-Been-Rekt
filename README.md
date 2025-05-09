
# Pretty Good OSINT Protocol (PGOP)

**“Now not only the bad guys have these tools.”**

PGOP is a modular, open-source intelligence platform designed to democratize access to advanced investigative tools for journalists, researchers, activists, and public-interest technologists. It combines OSINT, blockchain forensics, and AI-powered automation into one privacy-first, accessible toolkit.

# Have I Been Rekt

**Have I Been Rekt** is a public interest, open-source crypto incident response tool designed to help users assess whether their wallet has been compromised. It provides a user-friendly interface to submit wallet information and receive a risk assessment based on on-chain activity and AI analysis.

---

## 🛡️ Our Commitment to Privacy, Security & Fairness

This project is built around a simple but rare principle in Web3: **users deserve fairness, transparency, and control**.

- We don’t rely on cloud surveillance infrastructure like AWS by default.
- We prioritize **self-hosted, privacy-respecting AI agents**.
- We avoid third-party APIs unless absolutely necessary, and when used, they’re fully disclosed.
- Our mission is **to democratize access to blockchain forensics**, support public interest investigations, and empower people who've been harmed by crypto fraud.

This is a nonprofit project focused on **community protection and education**, not data extraction.

We’re building what Web3 didn’t expect: **accountability and empathy**.

---

## 🚀 MVP Scope: Have I Been Rekt

The MVP delivers a basic end-to-end investigation flow with the following features:

### Features

- **Wallet Compromise Form**: Front-end form to collect user symptoms (wallet address, time of loss, description)
- **Input Validation**: Regex-based wallet format check and required fields
- **Privacy Notice**: User consent checkbox with disclaimer
- **Deployment**: Hosted on Vercel or privacy-first alt-host (CanHost, Hetzner, etc.)
- **API Endpoint**: Receives and processes form submissions
- **Self-Hosted AI Integration**: Uses Ollama + local LLMs to summarize likely attack vector
- **Wallet Connect**: Enables direct wallet linking using wagmi/web3modal
- **Payment Gateway**: Stripe and/or on-chain payments (USDC, ETH)
- **Report Access**: Gate OSINT output behind confirmed payment
- **README + Study Guide**: Contributor documentation for onboarding
- **Community Testing**: Feedback channels and opt-in usage analytics

---

## 🧪 Future Scope & Stretch Goals

- **SpiderFoot Plugin** for deep passive OSINT
- **KINT**: a self-hosted AI agent for automated wallet forensics
- **Blockchain Tracing** via Etherscan, Bitquery, and heuristics
- **Privacy Enhancements**: ZK redaction via Holonym, encrypted submissions
- **Immutable Reports**: IPFS/OrbitDB export + audit trail
- **Offline and CLI Modes**: For use in high-censorship or private environments
- **Multi-chain Payment Support**: Monero, zkUSD, BTC Lightning, etc.
- **Public Interest Toolkits**: Exportable reporting for police, exchanges, and media

---

## 🛠️ Tech Stack

- **Frontend**: React, Tailwind CSS
- **Backend**: Node.js or Express-compatible API (or Vercel Functions)
- **AI Integration**: Self-hosted Ollama, LLaMA, Mistral or GGUF models
- **Blockchain Connect**: wagmi, web3modal
- **Payments**: Stripe API, Ethereum-compatible smart contracts
- **Deployment**: CanHost, Hetzner, or any Docker/VPS stack

---

## 🤝 Contributing

We welcome anyone who wants to help make Web3 safer, fairer, and more transparent. Whether you're a dev, designer, translator, or survivor of a crypto scam — you're welcome here.

---

## 📄 License

MIT — because everyone deserves tools that fight back.

---

## 📫 Contact

Questions, ideas, or feedback? DM [@M0nkeyFl0wer](https://github.com/M0nkeyFl0wer) or open an issue.

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
