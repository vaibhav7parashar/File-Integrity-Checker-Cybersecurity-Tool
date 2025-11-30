# File Integrity Checker

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Category](https://img.shields.io/badge/Cybersecurity-Tool-red)

A Python tool that checks if files are modified, corrupted, or tampered with using hashing and digital signatures.

---

## Why use it?

- Detects unwanted file modifications
- Alerts if data gets corrupted
- Helps ensure files remain original and safe
- Simple interface, easy to use

---

## Who Can Use This?

- Students learning cybersecurity
- Developers protecting sensitive project files
- IT security teams monitoring system files
- Anyone concerned about tampering and data integrity

---

## How to Run

Follow these steps:

1. Install Python 3.11 or above on your system.
2. Open the project folder in terminal / command prompt.
3. Install required libraries:
    ```bash
    pip install -r requirements.txt
    ```
4. Start the application:
    ```bash
    python gui_fic.py
    ```

The GUI will open and you can:
- Select a file
- Generate hash & digital signature
- Save integrity records
- Verify anytime if a file is modified or safe

---

## How It Works

1. Choose a file to protect  
2. App generates its secure hash and signature  
3. History is stored locally  
4. When re-verified later, hashes are compared  
5. If different → immediate alert  

---

## Project Files

- `gui_fic.py` — Main graphical program
- `hash_utils.py` — Hash and signature logic
- `assets/` — UI icons and screenshots
- `requirements.txt` — Dependencies list

---

## Screenshots

### Main Interface

![Main UI](assets/main_ui.png)

---

## Keywords

Cybersecurity, File Integrity Tools, Hash Verification, Tamper Detection, Python Security
