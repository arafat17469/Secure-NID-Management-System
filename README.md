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
- [🔹 Installation Guide](#-installation-guide)
  - [Windows](#windows-installation)
  - [macOS](#macos-installation)
  - [Linux](#linux-installation)
- [🔹 Usage](#-usage)
- [🔹 Database & Security](#-database--security)
- [🔹 API Integration (Future)](#-api-integration-future)
- [🔹 Roadmap](#-roadmap)
- [🔹 Contribution](#-contribution)
- [🔹 License](#-license)

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
