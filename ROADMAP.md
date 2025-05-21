🛣️ Project Roadmap: Have I Been Rekt (2025)
A living roadmap for the development of the Have I Been Rekt (HIBR) platform within the Pretty Good OSINT Protocol (PGOP) ecosystem.

✅ Phase 0 – Foundation
- GitHub repo setup (under PGOP org)
- Initial planning, architecture sketch, role alignment
- README and contributor onboarding docs
- Labeling conventions, master-task system, CLI tooling begins

🚀 Phase 1 – MVP Delivery (May 2025)
**Goal**: A working, privacy-first crypto incident response tool with frontend and backend components.

## Deployment Roadmap

### MVP Launch (Hosted)
- [x] Integrate with OpenAI API
- [x] Connect to Supabase/Firebase for basic backend
- [x] Deploy static front end via Vercel or Netlify
- [ ] Enable early user testing

### Migration Phase (Self-Hosted)
- [ ] Swap OpenAI for local Ollama model
- [ ] Replace Supabase with local Postgres instance
- [ ] Implement Docker-based deployment
- [ ] Test on CanHost or local VM setup

🎯 Features
- TypeScript React form for wallet compromise symptoms
- Regex/Zod validation, privacy notice, and consent checkbox
- Backend API endpoint to receive and log submissions
- Wallet Connect integration via wagmi/web3modal
- GitHub Issues for dev tracking (Project archived)
- `PROJECT_STATUS.md` Kanban with CLI sync

🧠 Dev Tools
- Termux + GitHub CLI + Windsurfer dev environment
- PowerShell script to bulk-edit issues and sync project snapshot
- Consolidated `master-task` structure for milestone tracking

🔮 Phase 2 – AI & Payments (June–July 2025)
**Goal**: Add backend intelligence + gated payments for deeper scan output

🧠 AI Integration
- Ollama self-hosted GPT model (e.g., Mistral) for wallet risk summary
- Prompt design and JSON schema output
- API bridge from frontend to AI inference

💸 Payment UX
- Stripe and/or ETH/USDC payments
- Premium scan gating (paid access only)
- Post-payment result rendering

🌍 Phase 3 – Community & Outreach (Q3 2025)
**Goal**: Enable contribution, testing, and expansion

- Onboarding docs for contributors (Termux, Windsurfer, Cursor)
- Feedback flow for wallet reports and scan accuracy
- Community testing + red team feedback loop
- Partner outreach, Discord onboarding

🧪 Future Ideas (Backlog)
- Telegram/Discord address threat monitoring
- SpiderFoot and Maltego plugin bridges
- Holonym/ZK redaction mode
- Non-Web3 wallet mode for mobile/email users
- Immutable report storage (IPFS or OrbitDB)

_Last updated: May 2025_
