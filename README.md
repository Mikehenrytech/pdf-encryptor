# PDF-Cypher

**PDF-Cypher** is a lightweight desktop application for **password-protecting PDF files**, built with **Python** and **PySide6**, and based entirely on **Open Source software**.

It allows users to select a PDF file, define a password (with confirmation), and generate a **new encrypted PDF** compatible with standard PDF viewers such as Adobe Reader or Okular.

---

![App](/img/pdf_encryptor_app.png)


## ✨ Features

- Simple and clean graphical interface (PySide6 / Qt)
- Password-based PDF encryption
- **AES-256 encryption** when supported by the installed `pypdf` version
- Input validation (file, passwords, output path)
- Windows standalone `.exe` build support
- 100% Open Source

---

## 🖥️ Requirements

### To run from source
- Windows 10 / 11
- Ubuntu +22.04
- MacOS
- Linux (AppImage)
- Python **3.11+**
- pip


### Python dependencies

Install dependencies:
```bash
pip install -r requirements.txt
```

Activate the virtual environment:
```bash
.venv\Scripts\activate
```

Usage
```bash
python main.py
```

Create executable file Windows:
```bash
build_exe.bat
```

Create executable file Linux:
```bash
build_linux.sh
```


Create executable file Debian:
```bash
sudo apt-get update

sudo apt-get install ./PDF_Cypher_1.1.6_amd64.deb
```




## License

This project is licensed under the GNU GPL v3.
The author retains full copyright and may offer
alternative licensing terms in the future.

See the LICENSE file.

## Author
M.E.
