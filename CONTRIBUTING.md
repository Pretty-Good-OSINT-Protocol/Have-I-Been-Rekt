# Contributing to PGOP

Thanks for considering contributing to Pretty Good OSINT Protocol (PGOP)! We welcome issues, pull requests, and feature suggestions.

## Setup

1. Clone the repo:
```bash
git clone https://github.com/M0nkeyFl0wer/Pretty-Good-OSINT-Protocol.git
cd Pretty-Good-OSINT-Protocol
```

2. Create a virtual environment (optional but recommended):
```bash
python -m venv env
source env/bin/activate  # or .\env\Scripts\activate on Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run tests:
```bash
python -m unittest discover tests
```

## Coding Standards

- Follow [PEP8](https://peps.python.org/pep-0008/) guidelines
- Use `black .` for code formatting
- Write meaningful commit messages
- Add or update unit tests for your changes

## Submitting Changes

1. Create a new branch:
```bash
git checkout -b feature/your-feature-name
```

2. Commit your work:
```bash
git commit -m "Add your message here"
```

3. Push and open a pull request:
```bash
git push origin feature/your-feature-name
```

We review all PRs and aim to provide feedback or merge within 72 hours.
