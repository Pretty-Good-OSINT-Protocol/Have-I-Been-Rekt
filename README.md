
# Pretty Good OSINT Protocol (PGOP)

**“Now not only the bad guys have these tools.”**

PGOP is a modular, open-source intelligence platform designed to democratize access to advanced investigative tools for journalists, researchers, activists, and public-interest technologists. It combines OSINT, blockchain forensics, and AI-powered automation into one privacy-first, accessible toolkit.

# Have I Been Rekt

**Have I Been Rekt** is an open-source crypto incident response tool designed to help users assess whether their wallet has been compromised. It provides a user-friendly interface to submit wallet information and receive a risk assessment based on on-chain activity and AI analysis.

## 🚀 MVP Scope: Have I Been Rekt

The goal of this MVP is to deliver a functional, crypto-native incident response tool that enables users to determine if their wallet has been compromised. The MVP includes:

### Features

- **Wallet Compromise Form**: Front-end form to collect user symptoms (address, time of loss, description)
- **Input Validation**: Regex-based wallet format check and required fields
- **Privacy Notice**: User consent checkbox with legal disclaimer
- **Deployment**: Hosted on Vercel or AWS with `.env` support
- **API Endpoint**: Backend route to receive and process submissions
- **AI Integration**: Use OpenAI GPT to summarize wallet behavior and likely attack vector
- **Wallet Connect**: Support for wagmi or web3modal to connect directly
- **Payment Gateway**: Stripe and/or on-chain (ETH, USDC) payments
- **OSINT Report Access**: Premium report gated behind payment
- **README + Study Guide**: Clear contributor onboarding and system diagram
- **Community Testing**: Feedback loop and real-world validation

---

## 🧪 Future Scope & Stretch Goals

Post-MVP development plans include:

- **SpiderFoot Plugin**: Full integration with SpiderFoot for advanced OSINT
- **AI Agent (KINT)**: Open-source autonomous wallet forensics agent
- **Multimedia Analysis**: ExifTool, geolocation, image matching
- **Blockchain Forensics**: Path tracing via Etherscan, Bitquery, and custom heuristics
- **Privacy Tools**: Optional redaction using ZK tools like Holonym
- **Immutable Publishing**: IPFS, OrbitDB, and verifiable audit logs
- **CLI + GUI**: Expand beyond form-based access to a full OSINT toolkit
- **Crypto + Fiat Payments**: Multi-chain payments and privacy-preserving invoicing
- **Collaboration Tools**: Sub-issue tracking, saved investigations, team access

This roadmap represents our commitment to open infrastructure for blockchain safety and transparency.

---

## 🛠️ Tech Stack

- **Frontend**: React, Tailwind CSS
- **Backend**: Node.js, Express
- **AI Integration**: OpenAI GPT API
- **Blockchain Interaction**: wagmi, web3modal
- **Payments**: Stripe API, Ethereum smart contracts
- **Deployment**: Vercel, AWS

---

## 📄 License

This project is licensed under the MIT License.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or suggestions.


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
