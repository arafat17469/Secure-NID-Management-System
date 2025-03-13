# 🚀 Secure NID Management System

A **highly secure and efficient** National ID (NID) management system built in C, designed to **register, authenticate, and manage** citizen data with encryption and role-based access control.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows, macOS, Linux](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-green)](#installation)
[![C Programming](https://img.shields.io/badge/Language-C-orange.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Security: OpenSSL](https://img.shields.io/badge/Security-OpenSSL-yellow.svg)](https://www.openssl.org/)

---

## 📖 Table of Contents
- [🔹 Features](#-features)
- [🔹 Technical Highlights](#-technical-highlights)
- [🔹 Security System](#-security-system)
- [🔹 Installation Guide](#-installation-guide)
  - [🖥 Windows Installation](#-windows-installation)
  - [🍏 macOS Installation](#-macos-installation)
  - [🐧 Linux Installation](#-linux-installation)
- [🔹 Usage](#-usage)
- [🔹 Database & Security](#-database--security)
- [🔹 API Integration (Future)](#-api-integration-future)
- [🔹 Roadmap](#-roadmap)
- [🔹 Contribution](#-contribution)
- [🔹 License](#-license)
- [🔹 Frequently Asked Questions (FAQ)](#-frequently-asked-questions-faq)

---

## 🔹 Features
✅ **Secure Registration** – Collects user details and generates a **unique 10-digit** National ID.  
✅ **Role-Based Access Control** – Supports **Admin, Officer, and Auditor** roles.  
✅ **Advanced Authentication** – Password hashing & encryption using **OpenSSL**.  
✅ **Audit Logging** – Tracks all actions (e.g., register, update, delete).  
✅ **Secure Data Storage** – Uses AES/RSA encryption for storing sensitive data.  
✅ **Cross-Platform Support** – Works on **Windows, macOS, and Linux**.  
✅ **Command-Line Interface (CLI)** – Simple and efficient terminal-based UI.  

---

## 🔹 Technical Highlights
🔒 **Security & Performance Enhancements**
- **SHA-256 Hashing**: Secure password storage with **10,000 PBKDF2 iterations**.
- **Real-Time Logging**: Stores up to **1,000 audit entries** for accountability.
- **Data Integrity**: Automatic timestamps (`created_at`, `last_modified`).
- **Input Sanitization**: Buffer overflow protection via fixed-size inputs.

---

## 🔹 Security System
Our **Secure NID Management System** implements multiple layers of security:

🔑 **Encryption & Hashing**
- **AES-256 Encryption**: Protects stored citizen data from unauthorized access.
- **RSA Encryption**: Secures data transmission between system components.
- **SHA-256 Password Hashing**: Prevents password leaks and brute-force attacks.

🛡 **Access Control & Authentication**
- **Role-Based Access Control (RBAC)**: Ensures only authorized users can access specific data.
- **Multi-Factor Authentication (Planned Feature)**: Enhances security by requiring OTP verification.

📝 **Logging & Auditing**
- **Audit Logs**: Tracks all user actions for compliance and forensic analysis.
- **Intrusion Detection**: Detects multiple failed login attempts and locks accounts temporarily.

🚨 **Security Best Practices**
- **Regular Updates**: Keeps dependencies and cryptographic libraries up-to-date.
- **Code Reviews & Penetration Testing**: Ensures system integrity against attacks.
- **Secure Coding Standards**: Mitigates risks such as SQL injection and buffer overflow.

---

## 🔹 Installation Guide

### 🖥 Windows Installation
1. **Install GCC Compiler**
   - Download and install [MinGW-w64](https://www.mingw-w64.org/).
   - Add `C:\mingw\bin` to your **System PATH**.

2. **Install OpenSSL**
   - Download OpenSSL from [slproweb](https://slproweb.com/products/Win32OpenSSL.html).
   - Install and add OpenSSL’s `bin` folder to your **System PATH**.

3. **Compile & Run**
   ```sh
   gcc Secure_NID_Management_System.c -o nid_management.exe -lssl -lcrypto
   nid_management.exe
   ```

### 🍏 macOS Installation
1. **Install Xcode Command Line Tools**
   ```sh
   xcode-select --install
   ```

2. **Install Homebrew & OpenSSL**
   ```sh
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   brew install openssl
   ```

3. **Compile & Run**
   ```sh
   gcc Secure_NID_Management_System.c -o nid_management -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
   ./nid_management
   ```

### 🐧 Linux Installation
1. **Install GCC & OpenSSL**
   ```sh
   sudo apt update && sudo apt install gcc libssl-dev
   ```

2. **Compile & Run**
   ```sh
   gcc Secure_NID_Management_System.c -o nid_management -lssl -lcrypto
   ./nid_management
   ```

---

## 🔹 Frequently Asked Questions (FAQ)

### Q1: Can I use this system for a real government NID database?
No, this project is designed for educational and research purposes. It lacks legal compliance and large-scale database integration.

### Q2: How can I add new authentication features?
You can modify the authentication logic in the `authenticate_user()` function to add Multi-Factor Authentication (MFA).

### Q3: How can I integrate this with a MySQL database?
Replace the current file-based storage with MySQL queries. You will need to link with the `libmysqlclient` library.

---

## 🔹 Contribution
Contributions are welcome! Feel free to open an issue or submit a pull request.

---

## 🔹 License
This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).
