# MVP Deployment Plan: Hybrid Stack Approach

## Goal

Deliver a working MVP using off-the-shelf tools to enable early testing and feedback—while laying the groundwork for a future migration to a fully self-hosted, privacy-preserving stack aligned with PGOP and PrivID’s values.

---

## Phase 1: Rapid MVP Launch (Hosted Stack)

### Stack
- **Model API**: OpenAI (or Hugging Face Inference API)
- **Backend**: Supabase or Firebase
- **Frontend**: Vercel or Netlify (optional proxy layer)
- **CI/CD**: GitHub Actions
- **Secrets Management**: GitHub Secrets

### Pros
- Fast development with minimal setup
- Reliable developer experience and ecosystem
- Easy to test, share, and iterate

### Cons
- Vendor lock-in risks
- Data privacy and ethical concerns
- Limited insight or control over model behavior

---

## Phase 2: Transition to Self-Hosted Stack (CanHost or Local)

### Stack
- **Model Hosting**: Ollama or LM Studio via Docker
- **Storage**: Self-hosted Postgres or SQLite
- **Frontend**: Static export or custom-hosted UI (e.g. with Caddy/nginx)
- **Orchestration**: Docker Compose or Podman
- **Optional**: LangChain, OpenDevin-style wrappers, or local agent orchestration

### Pros
- Full control of infrastructure and data
- Better long-term cost predictability
- Alignment with privacy-first and decentralization goals

### Tradeoffs
- Slower initial setup
- Manual debugging and monitoring
- Less commercial support

---

## Migration Strategy

1. **Design abstraction layers from the start**
   - Use interface-like functions (e.g. `getResponse()`) that can swap between OpenAI and local model calls
   - Avoid hard-coding infrastructure-specific logic

2. **Use environment variables for configuration**
   - Example: `MODEL_PROVIDER=openai` or `MODEL_PROVIDER=ollama`
   - Consistent `DATABASE_URL` structure for easy migration

3. **Containerize early**
   - Use `Dockerfile` and `docker-compose.yml` to define portable environments
   - Keep development and production parity

4. **Maintain parallel local infrastructure scripts**
   - Place local infra setup in `/infra` or `/docker`
   - Ensure developer onboarding is documented for both hosted and self-hosted setups

---

## Success Criteria

- The MVP should demonstrate key functionality using a hosted stack
- The codebase must support a clean migration to self-hosting without major rewrites
- Deployment scripts and environment variables should support both modes

---

## Summary

This approach allows us to:
- Move forward without stalling on infra decisions
- Iterate quickly with a working MVP
- Preserve our long-term values and architectural freedom
