# Contributing to Pretty Good OSINT Protocol (PGOP)

Thanks for your interest in contributing to PGOP — a public good project focused on ethical, open-source intelligence.

This guide outlines how to set up your environment, follow project standards, and submit high-quality contributions.

---

## 🚀 Quick Start

1. **Fork** this repository
2. **Create a branch** for your feature or fix:
   ```bash
   git checkout -b feature/your-feature-name

3. Install dependencies:

pip install -r requirements.txt


4. Run tests:

python -m unittest discover tests


5. Make your changes


6. Submit a pull request with a clear description




---

🧪 Development Standards

Write clear, descriptive commit messages

Follow PEP8 style for Python code

Use Black for formatting:

black .

Include tests for new features where possible

Keep plugin code modular and well-documented



---

🧩 Plugin Development

Plugins live in the /plugins directory. Each plugin should:

Be a standalone Python file or package

Define a clear run() or analyze() method

Include docstrings and usage examples

Handle exceptions gracefully


Plugins are loaded dynamically by plugin_loader.py.


---

✅ Submitting a Pull Request

Once you're ready:

1. Push your branch:

git push origin feature/your-feature-name


2. Go to your fork and submit a Pull Request to the main branch



We’ll review your code, provide feedback if needed, and merge it once approved.


---

📫 Questions or Ideas?

Open an issue or start a discussion.

Thanks again for helping build a more open, accessible OSINT future!

---

Let me know once you’ve updated it, and I’ll help you publish this to the GitHub Pages site or offer a matching `CONTRIBUTING.md` stub for the root.

