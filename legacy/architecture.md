# PGOP System Architecture

PGOP consists of the following major components:

1. **CLI Tools** – Command-line interface for power users
2. **Streamlit UI** – Friendly GUI interface hosted on Hugging Face
3. **Core Services** – Domain/wallet/contract analysis, AI wrappers, plugins
4. **Plugin Loader** – Scans `plugins/` directory for dynamic modules
5. **Storage Layer** – Optional IPFS, Orbit Chain or local DB for result history
6. **ZK Identity** – Optional verification via Holonym zk-passport

```
          +---------------------+
          |  Streamlit GUI      |
          +----------+----------+
                     |
              +------+------+
              |   Core API   |
              +------+------+
                     |
     +---------------+---------------+
     |               |               |
 [Plugins]   [Blockchain Tools]   [AI Workflows]
```

This architecture allows contributors to extend core features or add new OSINT modules as independent plugins.
