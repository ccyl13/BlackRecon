# BlackRecon

**Release Date:** 27 de abril de 2025  
**Developed by:** Thomas O'Neil Álvarez  
**License:** MIT  
**Repository:** [GitHub](https://github.com/ccyl13/BlackRecon)  
**Project Status:** Active 

---

## 📖 Table of Contents

- [Description](#description)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Step 1: Clone the Repository](#step-1-clone-the-repository)
  - [Step 2: Install Dependencies](#step-2-install-dependencies)
  - [Step 3: Run BlackRecon](#step-3-run-blackrecon)
- [Usage](#usage)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)
- [Changelog](#changelog)
- [Support](#support)

---

## 📝 Description

**BlackRecon** is an automated reconnaissance tool designed for ethical hacking and security assessments.  
It performs subdomain enumeration, IP resolution, technology detection, and open port scanning, all in a professional and colorful terminal interface.  
Optionally, you can save the results into a detailed audit report.

---

## ✨ Features

- **Subdomain Enumeration** with `subfinder`.
- **IP Resolution** for each subdomain.
- **Technology Detection** with `whatweb`.
- **Open Port Scanning** with `nmap` (common ports 80, 443, 8080, 8443).
- **Professional Output**: color-coded and structured in the terminal.
- **Optional Report Generation**: export results to a text file.
- **Automatic Dependency Check and Installation**.
- **ASCII Art Banner** and polished UX.

---

## 🛠️ Requirements

### Software Dependencies
- **subfinder**
- **nmap**
- **whatweb**
- **httpx**

> BlackRecon will automatically check and offer to install any missing tools.

### Tested Systems
- Kali Linux
- Parrot OS
- Ubuntu 22.04+

---

## 📦 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/ccyl13/BlackRecon.git
cd BlackRecon
```

### Step 2: Install Dependencies

If needed manually:

```bash
sudo apt update
sudo apt install nmap whatweb
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
```

### Step 3: Run BlackRecon

```bash
python3 blackrecon.py
```

---

## 🚀 Usage

When launched, BlackRecon will display:

![BlackRecon Start](https://github.com/ccyl13/BlackRecon/blob/main/ingresar%20url.png?raw=true)

You will be prompted to enter a domain (example: `example.com`).

The tool will then:

- Enumerate subdomains.
- Resolve their IPs.
- Detect technologies.
- Scan for open ports.

Example of results:

![BlackRecon Results](https://github.com/ccyl13/BlackRecon/blob/main/results.png?raw=true)
![BlackRecon Scanning](https://github.com/ccyl13/BlackRecon/blob/main/scaning.png?raw=true)

After completion, you will have the option to save a report:

![BlackRecon Report](https://github.com/ccyl13/BlackRecon/blob/main/txt.png?raw=true)

Reports are saved inside the `BlackRecon-Reports/` folder.

---

## ⚡ Limitations

- Only scans common ports (80, 443, 8080, 8443).
- Technology detection depends on HTTP response availability.
- No brute-force or exploitation modules (reconnaissance only).

---

## 🤝 Contributing

Contributions are welcome!  
Feel free to fork this repository, create a feature branch, and submit a pull request.

---

## 📜 License

**MIT License**  
Free for personal and commercial use, with attribution.

---

## 📈 Changelog

- **(27-Apr-2025):** First official release of BlackRecon.

---

## 🛡️ Support

If you find any issues, please open a GitHub issue or contact me through the repository.  
Happy auditing!🥷🏻
