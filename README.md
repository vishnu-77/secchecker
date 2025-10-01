[![PyPI version](https://img.shields.io/pypi/v/secchecker.svg)](https://pypi.org/project/secchecker/)  
[![Python versions](https://img.shields.io/pypi/pyversions/secchecker.svg)](https://pypi.org/project/secchecker/)  
[![Build Status](https://github.com/vishnu-77/secchecker/actions/workflows/ci.yml/badge.svg)](https://github.com/vishnu-77/secchecker/actions)  
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)  




# secchecker  

`secchecker` is a Python package + CLI tool to detect hidden or untracked hardcoded secrets in repositories, helping developers keep their projects secure and audit-ready.  



## ✨ Features  
- Detects common secret types:  
  - Database credentials (Postgres, MySQL, Mongo)  
  - Cloud keys (AWS, GCP, Azure)  
  - Authentication tokens (JWTs, Private Keys)  
  - Generic API keys & passwords in configs  
- Generates **JSON** and **Markdown** reports  
- Easy CLI usage for **DevSecOps pipelines**  


## 🚀 Installation  

Clone the repository and install in editable mode:  

```bash
git clone https://github.com/yourusername/secchecker.git
cd secchecker
pip install -e .
````

## 🛠 Usage

Scan a repository or project folder:

```bash
secchecker path/to/scan --format md
```

Options:

* `--format json` → generate JSON report
* `--format md` → generate Markdown report

Example:

```bash
secchecker . --format json
```

---

## ⚠️ Disclaimer

`secchecker` is intended **only** for security auditing of repositories you own or have explicit permission to test.

* Misuse of this tool to access, scan, or extract information from systems you do not own is **strictly prohibited** and may violate the law.
* The author(s) assume **no liability** for misuse or damages caused by this software.

---

## 📜 Terms & Conditions

By using `secchecker`, you agree to the following:

1. You will only use this tool on codebases you own or have explicit authorization to audit.
2. You will not use this software for malicious purposes, including but not limited to unauthorized access, exploitation, or data theft.
3. The software is provided **“as is,” without warranty of any kind**, express or implied.
4. The author(s) are not responsible for any damages, losses, or legal consequences arising from the use or misuse of this software.
5. You accept full responsibility for ensuring that your use of this tool complies with applicable laws and regulations in your jurisdiction.

---

## 🤝 Contributing

Contributions are welcome!

* Fork the repo
* Create a feature branch
* Submit a pull request 🚀


