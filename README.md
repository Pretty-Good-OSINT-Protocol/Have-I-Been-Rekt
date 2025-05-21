# Pretty Good OSINT Protocol (PGOP)

**“Now not only the bad guys have these tools.”**

PGOP is a modular, open-source intelligence platform designed to democratize access to advanced investigative tools for journalists, researchers, activists, and public-interest technologists. It combines OSINT, blockchain forensics, and AI-powered automation into one privacy-first, accessible toolkit.

---

# Have I Been Rekt (HIBR)

**Have I Been Rekt** is a public-interest, open-source crypto incident response tool that helps users assess whether their wallet has been compromised using open-source intelligence and self-hosted AI.

---

## MVP Scope & Features

- Wallet input form
- AI-generated summary (local model via Ollama/llama.cpp)
- Optional deeper report unlocked with payment
- Consent-first interface and privacy disclaimer
- Report output in human-readable format

---

## Roadmap & Project Management

All planning and development is tracked transparently:
- [GitHub Issues](https://github.com/Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt/issues)
- [MVP Project Board](https://github.com/orgs/Pretty-Good-OSINT-Protocol/projects)

**Labels** help organize work:
- `dev-task`: Developer work (backend, payment, security)
- `docs`: Documentation and educational materials
- `deployment`: Hosting, CI/CD, Dockerization
- `estimate:Xh`: Estimated time in hours

---

## Cost Model

- **Free Tier**: Local AI summary (fully self-hosted, no API calls)
- **Paid Tier**: Deeper OSINT reports using third-party data sources
- User-pays design: we don’t track, log, or subsidize use—every request is yours alone

---

## Tech Stack

- **Frontend**: React, Tailwind CSS
- **Backend**: Node.js / Express-compatible API (or Vercel Functions)
- **AI**: Ollama, LLaMA, Mistral, or GGUF models (run locally)
- **Blockchain Connect**: wagmi, web3modal
- **Payments**: Stripe API + WalletConnect (ETH, USDC)
- **Deployment**: CanHost (CA), Futo (US), or Docker-ready

## Deployment Strategy

This project uses a hybrid deployment approach:

- **Initial MVP** runs on OpenAI + Supabase + Vercel for rapid iteration
- **Long-term migration** targets a self-hosted stack using tools like Ollama, Postgres, and CanHost

See [`MVP-Deployment-Plan.md`](./MVP-Deployment-Plan.md) for the full architecture and migration strategy.

---

## Local Dev Setup

> The codebase is still under construction. Here’s how to prepare for contributing:

### Clone the Repo

```bash
git clone https://github.com/Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt.git
cd Have-I-Been-Rekt
```

### Install CLI Tools

We recommend:

- GitHub CLI (`gh`)
- PNPM
- Termux (for mobile devs)
- Node.js (v18+)

Once the code is pushed, you'll be able to:

```bash
pnpm install
pnpm dev
```

Docker instructions and scripts are coming soon.

---

## Privacy Principles

HIBR is built from the ground up for:

- **User control** (no central logs or analytics)
- **Transparent hosting** (CanHost + Futo only)
- **Consent-first reporting** (checkbox before submission)
- **Self-sovereign tools** (run locally, if desired)

A full `PRIVACY.md` is planned for v0.1. Contributions welcome.

---

## Feature Set

- **Wallet Compromise Form**: Collect symptoms from users (wallet, loss time, what happened)
- **Input Validation**: Check ETH address format + required fields
- **Consent Layer**: Explicit privacy checkbox with disclaimer
- **API Endpoint**: Accepts form input for AI + OSINT analysis
- **Self-Hosted AI**: Uses Ollama to summarize likely attack vector
- **Wallet Connect**: Use wagmi/web3modal to auto-fill wallet address
- **Payment Gateway**: Stripe (credit card) + Ethereum (ETH/USDC)
- **Report Gating**: Show premium OSINT output after payment
- **README + Study Guide**: For onboarding contributors
- **Community Testing**: Feedback channels, bug bounty, and opt-in analytics (if ever added, user-controlled)

---

## Future Scope

- SpiderFoot integration for passive OSINT
- KINT: local AI agent for wallet tracing
- Blockchain trace API support (Bitquery, Etherscan)
- Privacy tools: Holonym for redacted reports
- Immutable storage: IPFS + OrbitDB for case logs
- CLI and offline mode for censorship-resistance
- Multi-chain payment: Monero, zkUSD, Lightning
- Public safety exports: auto-generated reports for law enforcement or exchanges

---

## Contributing

We welcome anyone who wants to help make Web3 safer, fairer, and more transparent. Whether you're a dev, designer, translator, or survivor of a crypto scam—you’re welcome here.

See [`help wanted`](https://github.com/Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt/issues?q=label%3A%22help+wanted%22) issues or ping [@M0nkeyFl0wer](https://github.com/M0nkeyFl0wer).

---

## Built With

- [SpiderFoot](https://github.com/smicallef/spiderfoot)
- [Open LLama](https://github.com/openlm-research/open_llama)
- [Streamlit](https://streamlit.io/)
- [IPFS](https://ipfs.io/)
- [Orbit Chain](https://bridge.orbit.network/)
- [Holonym / Human.Tech](https://human.tech/)

---

## License

MIT — because everyone deserves tools that fight back.
