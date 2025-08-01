# FADEVEIL - Ransomware Simulation and Decryption Platform

> **“Eclipse of Encryption” – A Research-Driven Ransomware Simulation and Analysis System**

![Fadeveil Badge](https://img.shields.io/badge/Project-Fadeveil-blueviolet)

**Team Members:**

- T A Asma (21CSA64)
- Amal S (21CSA66) 
- Gokul Gopi (21CSA68)  
- Manikandan S (21CSA69)  

**Institution:**  
Department of Computer Engineering  
Model Engineering College, Thrikkakara  
APJ Abdul Kalam Technological University  
📅 April 2025


## 📄 Research Paper

You can access the full research paper for this project here:  
🔗 [View FADEVEIL Research Paper](https://drive.google.com/file/d/1zejqUl4zRSvkBvhzyOiliA__-gN_E7x2/view)

---

## 🔒 Overview

**FADEVEIL** is a simulated ransomware platform developed as a part of an academic project to study the behavior, detection, and decryption of ransomware threats. It simulates real-world ransomware attacks using cryptographic methods (AES + RSA) and allows users to analyze and decrypt infected files in a controlled, research-oriented environment.

---

## 🧠 Key Features

- 🔐 **Hybrid Detection**: Combines static signature analysis with entropy-based anomaly detection.
- 🔍 **Ransomware Analysis**: Detects file encryption methods and ransomware signatures.
- 🧬 **AES + RSA Encryption**: Simulates ransomware-like file encryption using industry-standard cryptography.
- 🔓 **Decryption Module**: Recovers files using RSA private keys and AES decryption.
- 📊 **Detailed Reporting**: Shows analysis results, entropy values, encryption methods, and ransomware family.
- 🌐 **React-based GUI**: For researchers and responders to interact with the system easily.
- 👥 **Role-based Access**: Includes roles like Cyber Researcher and Incident Responder with distinct dashboards.

---

## 🛠️ Technologies Used

### Backend
- Python 3.x
- `cryptography`, `pycryptodome`, `python-dotenv`, `magic`, `subprocess`, `opencv-python`, `pillow`, `ffpyplayer`, `pygetwindow`

### Frontend
- React.js (Vite)
- SCSS

### Backend Server
- Node.js + Express.js

### Database
- MongoDB

---

<pre> ## 📂 Folder Structure ``` FadeVeil/ ├── Backend/ # Python scripts for encryption, decryption, analysis ├── Frontend/ # React.js frontend ├── package.json # Node.js backend dependencies └── README.md # This file ``` </pre>

---

## 🚀 Getting Started

### 📦 Prerequisites

- Python 3.x installed
- Node.js and npm
- MongoDB (local/cloud)
- RSA key pair (`private_key.pem`, `public_key.pem`)
- `.env` file with required environment variables

### 🔧 Setup Instructions

```bash
# Backend
cd Backend
pip install -r requirements.txt

# Frontend
cd ../Frontend
npm install
npm run dev
```


🔄 Ransomware Simulation Flow

Place files in the TARGET_FOLDER.
Run the ransomware encryption script (Python).
Upload the encrypted files via the React GUI.
View the analysis and decryption report.
Download recovered files (if decryption successful).


👨‍💻 User Roles

### Role	Description
Cyber Researcher	Upload encrypted files, analyze encryption patterns, download decrypted files
Incident Responder	View active threats, apply decryption, manage incident files

⚙️ Functional Modules

📁 Static Analysis: Examines file entropy, extensions, and MIME types.
🔑 RSA-AES Decryption: Hybrid key decryption for secure recovery.
🔄 Automated Scanning: Recursively scans directories.
📋 Logging & Notifications: Displays scan and decryption results.
🔐 Authentication: JWT-based login with role-based access.
✅ Testing Results

### ✅ Testing Results

| **Test Case**                               | **Status** |
| ------------------------------------------- | ---------- |
| Detect encrypted files                      | ✅ PASS     |
| Identify ransomware extensions              | ✅ PASS     |
| Calculate entropy                           | ✅ PASS     |
| AES key decryption                          | ✅ PASS     |
| Decrypt multiple files with multiprocessing | ✅ PASS     |
| File integrity after decryption             | ✅ PASS     |
| Role-based login and access                 | ✅ PASS     |
| System testing (end-to-end)                 | ✅ PASS     |


### 📊 Project Results

- ✅ Successfully decrypted multiple ransomware-encrypted files.
- 📂 Accurately identified file types using MIME and entropy.
- 🖥️ GUI enabled seamless interaction for researchers and responders.
- ⏱️ Achieved analysis time within 10 minutes per folder.




