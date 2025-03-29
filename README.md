
# Pretty Good OSINT Protocol (PGOP)

**“Now not only the bad guys have these tools.”**

Pretty Good OSINT Protocol (PGOP) is a modular, open-source intelligence platform designed to democratize access to powerful investigative tools for journalists, researchers, activists, and public-interest technologists.

## Features

- **Modular OSINT Scanning**: Uses SpiderFoot and enhanced modules to gather public data on individuals, organizations, and domains.
- **Social & Multimedia Intelligence**: Extracts and analyzes image metadata, social profiles, and publication footprints.
- **Blockchain Investigation**: Tracks wallets, contracts, and transactions using tools like Etherscan, Bitquery, and Web3.
- **Immutable Reporting**: Stores findings on IPFS and logs to Orbit Chain or Base for permanent and verifiable recordkeeping.
- **Privacy Layer**: Integrates zero-knowledge proof-based identity protection using Holonym (Human.Tech).
- **Crypto Payments for APIs**: Pay-as-you-go usage of APIs (e.g., WHOISXML, Hunter.io) using cryptocurrency.
- **Web UI & CLI**: Accessible through a Streamlit GUI (“Have I Been Rekt”) and a powerful command-line interface for automation.
- **Publishing Engine**: Outputs reports in JSON/CSV and supports journalism, research, and civic publishing.

---

## Getting Started

### Deploy with Docker

```bash
git clone https://github.com/YOUR_USERNAME/Pretty-Good-OSINT-Protocol.git
cd Pretty-Good-OSINT-Protocol
docker-compose up --build
```

Visit `http://localhost:8501` to launch the "Have I Been Rekt" interface.

### One-Click Cloud VM Setup

For fast deployment on a new Ubuntu VM (AWS, Azure, DigitalOcean):

```bash
wget https://yourdomain.com/cloud-init.sh
bash cloud-init.sh
```

---

## Project Structure

See `pgop_repo_structure.txt` for a complete breakdown of modules and services.

---

## Contributing

We welcome contributions from the public interest, OSINT, and blockchain communities. Please fork the repo and submit pull requests.

---

## License

MIT License

---

## Credits

PGOP is inspired by the need to provide open-access tools for truth-seeking, accountability, and privacy-preserving investigations.

Built using:
- [SpiderFoot](https://github.com/smicallef/spiderfoot)
- [Streamlit](https://streamlit.io/)
- [Orbit Chain](https://orbitbridge.io/)
- [Holonym](https://human.tech/)
- [Etherscan](https://etherscan.io/)
- [Bitquery](https://bitquery.io/)
