# File Integrity Checker

A Python tool that protects important files by checking if they have been changed, corrupted, or tampered with.  
It uses secure hashing and digital signatures to verify file integrity.

---

## Why use it?

- Detects unwanted file modifications
- Alerts if data gets corrupted
- Helps ensure files remain original and safe
- Simple interface, easy to use

---

## How to Run

Follow these simple steps:

1. Install Python 3.11 or above on your system.
2. Open the project folder in a terminal or command prompt.
3. Install required libraries:
    ```bash
    pip install -r requirements.txt
    ```
4. Run the application:
    ```bash
    python gui_fic.py
    ```
5. The graphical interface will open. You can:
   - Select a file
   - Generate its hash and digital signature
   - Save integrity records
   - Verify anytime if the file is modified or safe

---

## How It Works

1. Select any file you want to protect
2. The app generates a secure hash and signature for that file
3. It stores these records safely
4. Later, when you verify the file again, it compares the hash values
5. If anything changed → it warns you

---

## Project Files

- `gui_fic.py` — Main graphical program
- `hash_utils.py` — Hash and signature logic
- `assets/` — UI icons and resources
- `requirements.txt` — Required dependencies

---

## Screenshots

### Main Interface

![Main UI](assets/main_ui.png)

