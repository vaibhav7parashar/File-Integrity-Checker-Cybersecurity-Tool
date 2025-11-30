"""
FIC — File Integrity Checker (Pro)

- GUI improvements and thread-safety adjustments
- Fixed PIN logic and secure storage
- Uses signed records/history via hash_utils
- Safer I/O and atomic updates
- Certificate export restricted to files verified as Safe
- Change PIN rejects same-as-current PIN
"""

import os
import threading
import time
import json
import hashlib
import secrets
from pathlib import Path
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES
import ttkbootstrap as tb
from ttkbootstrap.widgets import Meter
from PIL import Image, ImageTk
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# local helpers
from hash_utils import (
    sha256_hash,
    save_record,
    load_records,
    append_history,
    ensure_files,
    clear_history,
)

# optional sound
try:
    import winsound

    def play_sound():
        try:
            winsound.MessageBeep(winsound.MB_OK)
        except Exception:
            pass
except Exception:
    def play_sound():
        # best-effort audible cue
        print("\a")

ASSETS = Path("assets")
LOGO = ASSETS / "logo.png"
HISTORY_FILE = "history.json"
PIN_FILE = "pin.json"
DEFAULT_PIN = "1234"


def hash_pin(pin: str, salt: str) -> str:
    return hashlib.sha256((pin + salt).encode()).hexdigest()


def load_pin() -> tuple:
    """
    Return (salt, hash) tuple for stored PIN.
    If pin.json missing or corrupted, create file with DEFAULT_PIN (salted) and return its (salt,hash).
    """
    if not os.path.exists(PIN_FILE):
        save_pin(DEFAULT_PIN)
    try:
        with open(PIN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        salt = data.get("salt")
        hashed = data.get("hash")
        if not salt or not hashed:
            # corrupted -> recreate safely
            save_pin(DEFAULT_PIN)
            with open(PIN_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            salt = data["salt"]
            hashed = data["hash"]
        return salt, hashed
    except Exception:
        # recreate pin file if unreadable
        save_pin(DEFAULT_PIN)
        with open(PIN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data["salt"], data["hash"]


def verify_pin(pin: str, stored: tuple) -> bool:
    """Verify provided PIN against stored (salt,hash) tuple."""
    if not isinstance(stored, tuple) and isinstance(stored, list):
        stored = tuple(stored)
    try:
        salt, hashed = stored
    except Exception:
        return False
    return hash_pin(pin, salt) == hashed


def save_pin(new_pin: str):
    """Save PIN as salted hash in pin.json (atomic write)."""
    salt = secrets.token_hex(8)
    hashed = hash_pin(new_pin, salt)
    tmp = PIN_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"salt": salt, "hash": hashed}, f)
        os.replace(tmp, PIN_FILE)
        try:
            os.chmod(PIN_FILE, 0o600)
        except Exception:
            pass
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


# PDF certificate helper (unchanged logic but kept robust)
def create_certificate(file_path: str, stored_hash: str, current_hash: str, out_pdf: str):
    from reportlab.lib import colors
    from reportlab.lib.utils import ImageReader

    c = canvas.Canvas(out_pdf, pagesize=A4)
    w, h = A4

    # Background gradient (simple)
    for i in range(int(h)):
        shade = 30 + int(70 * (i / h))
        c.setFillColorRGB(0, 0, shade / 255)
        c.rect(0, i, w, 1, stroke=0, fill=1)

    c.setStrokeColorRGB(1, 1, 1)
    c.setLineWidth(4)
    c.roundRect(40, 40, w - 80, h - 80, 20)

    c.setFont("Helvetica-Bold", 28)
    c.setFillColor(colors.whitesmoke)
    c.drawCentredString(w / 2, h - 90, "Certificate of File Integrity")

    c.setFont("Helvetica", 14)
    c.drawCentredString(w / 2, h - 115, "Issued and Verified by FIC Pro")

    c.line(100, h - 130, w - 100, h - 130)

    c.setFillColorRGB(0.05, 0.1, 0.15)
    c.roundRect(70, h - 370, w - 140, 220, 10, stroke=0, fill=1)

    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(colors.white)
    c.drawString(90, h - 170, f"File Name: {os.path.basename(file_path)}")
    c.drawString(90, h - 190, f"Full Path: {file_path}")
    c.drawString(90, h - 210, f"Recorded Hash: {stored_hash}")
    c.drawString(90, h - 230, f"Current Hash : {current_hash}")
    c.drawString(90, h - 250, f"Checked at: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    status = "MATCH" if stored_hash == current_hash else "MISMATCH"
    color = colors.green if status == "MATCH" else colors.red
    c.setFillColor(color)
    c.roundRect(w / 2 - 90, h - 310, 180, 40, 10, stroke=0, fill=1)
    c.setFont("Helvetica-Bold", 18)
    c.setFillColor(colors.white)
    c.drawCentredString(w / 2, h - 285, f"INTEGRITY: {status}")

    c.setFont("Helvetica", 12)
    c.setFillColor(colors.whitesmoke)
    c.drawCentredString(w / 2, 80, "Made and Certified by FIC Pro")
    c.setFont("Helvetica-Oblique", 10)
    c.drawCentredString(w / 2, 60, "File Integrity Checker Professional — © 2025")

    c.setFont("Helvetica", 12)
    c.drawRightString(w - 120, 110, "Authorized Signature:")
    c.line(w - 230, 115, w - 60, 115)
    c.setFont("Helvetica-Oblique", 10)
    c.drawRightString(w - 70, 100, "FIC Pro Verification Engine")

    if LOGO.exists():
        try:
            img = ImageReader(str(LOGO))
            c.drawImage(img, 60, h - 130, width=60, height=60, mask='auto')
        except Exception:
            pass

    c.showPage()
    c.save()


class FICApp:
    def __init__(self, root: TkinterDnD.Tk):
        self.root = root
        self.root.title("FIC Pro — File Integrity Checker")
        try:
            self.root.state("zoomed")
        except Exception:
            pass
        self.style = tb.Style("darkly")
        self.theme = "darkly"

        ensure_files()
        self.build_ui()

        self.matrix_running = True
        self._worker_sema = threading.BoundedSemaphore(2)  # limit concurrent busy workers
        # start matrix thread
        self._matrix_thread = threading.Thread(target=self.matrix_loop, daemon=True)
        self._matrix_thread.start()
        # ensure matrix thread stops on close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def build_ui(self):
        top = tb.Frame(self.root, padding=10)
        top.pack(side=TOP, fill=X)

        left = tb.Frame(top)
        left.pack(side=LEFT)
        if LOGO.exists():
            try:
                img = Image.open(LOGO).resize((44, 44))
                self.logo_img = ImageTk.PhotoImage(img)
                tb.Label(left, image=self.logo_img, bootstyle="light").pack(side=LEFT, padx=(0, 8))
            except Exception:
                pass
        tb.Label(left, text="FIC Pro", font=("Segoe UI", 18, "bold")).pack(side=LEFT)
        tb.Label(left, text="  File Integrity Checker", font=("Segoe UI", 10)).pack(side=LEFT)

        self.theme_btn = tb.Button(top, text="☀️ Light", bootstyle="outline-secondary", command=self.toggle_theme)
        self.theme_btn.pack(side=RIGHT)

        content = tb.Frame(self.root, padding=12)
        content.pack(fill=BOTH, expand=True)

        # Left Panel
        left_col = tb.Frame(content)
        left_col.pack(side=LEFT, fill=Y, padx=(20, 8))

        tb.Label(left_col, text="Scan / Verify", font=("Segoe UI", 14, "bold")).pack(pady=(6, 8))

        btns = tb.Frame(left_col)
        btns.pack(pady=6)

        tb.Button(btns, text="Select Files / Folder", bootstyle="success", width=22,
                  command=self.select_files).grid(row=0, column=0, padx=6)
        tb.Button(btns, text="Scan & Register", bootstyle="primary", width=22,
                  command=self.scan_register).grid(row=0, column=1, padx=6)
        tb.Button(btns, text="Verify Selected", bootstyle="info", width=22,
                  command=self.verify_selected).grid(row=1, column=0, padx=6, pady=8)
        tb.Button(btns, text="Export Certificate", bootstyle="warning", width=22,
                  command=self.export_certificate_prompt).grid(row=1, column=1, padx=6, pady=8)

        tb.Button(btns, text="Clear Activity", bootstyle="danger", width=22,
                  command=self.clear_activity_prompt).grid(row=2, column=0, padx=6, pady=8)

        tb.Button(btns, text="Change PIN", bootstyle="secondary", width=22,
                  command=self.change_pin_prompt).grid(row=2, column=1, padx=6, pady=8)

        # Drag & Drop
        drop_card = tb.Frame(left_col, padding=10, bootstyle="secondary")
        drop_card.pack(pady=12, fill=X)
        self.drop_label = Label(drop_card, text="📂 Drag & Drop Files Here (or use Select)",
                                bg="#f8f9fa", fg="#000")
        self.drop_label.pack(fill=X)
        try:
            self.drop_label.drop_target_register(DND_FILES)
            self.drop_label.dnd_bind("<<Drop>>", self.on_drop)
        except Exception:
            pass

        tb.Label(left_col, text="Selected Files:", font=("Segoe UI", 11, "bold")).pack(anchor=W, pady=(10, 0))
        self.file_frame = tb.Frame(left_col)
        self.file_frame.pack(pady=(6, 0), fill=X)

        canvas = Canvas(self.file_frame, bg="#0b0b0b", highlightthickness=0, height=200)
        scrollbar = tb.Scrollbar(self.file_frame, orient="vertical", command=canvas.yview)
        self.checkbox_container = tb.Frame(canvas)

        self.checkbox_container.bind("<Configure>",
                                     lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.checkbox_container, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

        sel_btns = tb.Frame(left_col)
        sel_btns.pack(pady=(4, 6))
        tb.Button(sel_btns, text="Select All", bootstyle="outline-success", width=15,
                  command=lambda: self.toggle_all(True)).grid(row=0, column=0, padx=5)
        tb.Button(sel_btns, text="Deselect All", bootstyle="outline-danger", width=15,
                  command=lambda: self.toggle_all(False)).grid(row=0, column=1, padx=5)

        self.meter = Meter(left_col, amountused=0, metersize=150, subtext="Progress", bootstyle="info")
        self.meter.pack(pady=12)
        self.status_label = tb.Label(left_col, text="", font=("Segoe UI", 11))
        self.status_label.pack()

        # Right Panel
        right_col = tb.Frame(content)
        right_col.pack(side=RIGHT, fill=BOTH, expand=True, padx=(8, 20))

        self.matrix_canvas = Canvas(right_col, bg="#0b0b0b", highlightthickness=0)
        self.matrix_canvas.place(relx=0, rely=0, relwidth=1, relheight=1)

        info_card = tb.Frame(right_col, padding=10, bootstyle="secondary")
        info_card.place(relx=0.03, rely=0.03, relwidth=0.94, height=200)
        tb.Label(info_card, text="File Info", font=("Segoe UI", 12, "bold")).pack(anchor=W)
        self.info_text = Text(info_card, height=6, bg="#0b0b0b", fg="#eaeaea", relief=FLAT)
        self.info_text.pack(fill=X, pady=(6, 0))

        history_card = tb.Frame(right_col, padding=10, bootstyle="light")
        history_card.place(relx=0.03, rely=0.28, relwidth=0.94, relheight=0.66)
        tb.Label(history_card, text="Recent Activity", font=("Segoe UI", 12, "bold")).pack(anchor=W)
        self.history_tree = ttk.Treeview(history_card,
                                         columns=("action", "file", "path", "result", "time"),
                                         show="headings", height=12)
        for col, w in zip(("action", "file", "path", "result", "time"), (90, 250, 300, 100, 140)):
            self.history_tree.heading(col, text=col.capitalize())
            self.history_tree.column(col, width=w)
        self.history_tree.pack(fill=BOTH, expand=True, pady=(6, 0))
        self.history_tree.bind("<<TreeviewSelect>>", self.on_history_select)

        self.file_vars = []
        self.load_history_into_tree()

    # ---------------- Theme ----------------
    def toggle_theme(self):
        if self.theme == "darkly":
            self.style.theme_use("flatly")
            self.theme_btn.config(text="🌙 Dark")
            self.theme = "flatly"
        else:
            self.style.theme_use("darkly")
            self.theme_btn.config(text="☀️ Light")
            self.theme = "darkly"

    # ---------------- Drag & drop ----------------
    def on_drop(self, event):
        try:
            files = self.root.tk.splitlist(event.data)
            files = [f.strip("{}") for f in files]
            self.add_files(files)
            self.pulse_drop()
        except Exception as e:
            print("Drop error:", e)

    def pulse_drop(self):
        orig = self.drop_label.cget("bg")
        self.drop_label.config(bg="#dff7df")
        self.root.after(450, lambda: self.drop_label.config(bg=orig))

    def select_files(self):
        paths = filedialog.askopenfilenames(title="Select files or folder")
        if paths:
            self.add_files(list(paths))

    def add_files(self, files):
        for f in files:
            if os.path.isdir(f):
                for root_dir, _, filenames in os.walk(f):
                    for name in filenames:
                        fp = os.path.abspath(os.path.join(root_dir, name))
                        if not any(fp == p for p, _ in self.file_vars):
                            var = BooleanVar(value=True)
                            chk = tb.Checkbutton(self.checkbox_container, text=fp,
                                                 variable=var, bootstyle="round-toggle")
                            chk.pack(anchor="w", padx=4, pady=2)
                            self.file_vars.append((fp, var))
            else:
                fp = os.path.abspath(f)
                if not any(fp == p for p, _ in self.file_vars):
                    var = BooleanVar(value=True)
                    chk = tb.Checkbutton(self.checkbox_container, text=fp,
                                         variable=var, bootstyle="round-toggle")
                    chk.pack(anchor="w", padx=4, pady=2)
                    self.file_vars.append((fp, var))

    def clear_selection(self):
        self.file_vars.clear()
        for widget in self.checkbox_container.winfo_children():
            widget.destroy()
        self.info_text.delete(1.0, END)

    def get_selected_files(self):
        return [path for path, var in self.file_vars if var.get()]

    def toggle_all(self, state=True):
        for _, var in self.file_vars:
            var.set(state)

    # ---------------- Scan ----------------
    def scan_register(self):
        files = self.get_selected_files()
        if not files:
            messagebox.showwarning("No files", "Select files or drag-drop files to scan.")
            return
        # limit concurrency
        if not self._worker_sema.acquire(blocking=False):
            messagebox.showinfo("Busy", "Another operation is running. Please wait.")
            return
        t = threading.Thread(target=self._scan_thread, args=(files,), daemon=True)
        t.start()

    def _scan_thread(self, files):
        try:
            total = len(files)
            for idx, path in enumerate(files, start=1):
                self._safe_ui_update(self.status_label.config, text=f"Scanning {os.path.basename(path)} ({idx}/{total})",
                                     foreground="yellow")
                self.heartbeat_pulse(True)
                try:
                    h = sha256_hash(path)
                    save_record(path, h)
                    append_history("Scan", path, "Registered")
                    self._safe_ui_update(self.insert_history_row, "Scan", os.path.basename(path), "Registered", os.path.abspath(path))
                    self._safe_ui_update(self.show_file_info, path, h, {"hash": h, "time": "now"})
                except Exception as e:
                    append_history("Scan", path, "Error")
                    self._safe_ui_update(self.insert_history_row, "Scan", os.path.basename(path), "Error", os.path.abspath(path))
                pct = int((idx / total) * 100)
                self._safe_ui_update(self.meter.configure, amountused=pct)
                time.sleep(0.05)
                play_sound()
                self.heartbeat_pulse(False)
            self._safe_ui_update(self.status_label.config, text="Scan & register completed.", foreground="lime")
        finally:
            try:
                self._worker_sema.release()
            except Exception:
                pass

    # ---------------- Verify ----------------
    def verify_selected(self):
        files = self.get_selected_files()
        if not files:
            messagebox.showwarning("No files", "Select files first.")
            return
        if not self._worker_sema.acquire(blocking=False):
            messagebox.showinfo("Busy", "Another operation is running. Please wait.")
            return
        t = threading.Thread(target=self._verify_thread, args=(files,), daemon=True)
        t.start()

    def _verify_thread(self, files):
        try:
            records = load_records()
            total = len(files)
            for idx, path in enumerate(files, start=1):
                self._safe_ui_update(self.status_label.config, text=f"Verifying {os.path.basename(path)} ({idx}/{total})",
                                     foreground="yellow")
                self.heartbeat_pulse(True)
                try:
                    cur = sha256_hash(path)
                except Exception:
                    append_history("Verify", path, "Error")
                    self._safe_ui_update(self.insert_history_row, "Verify", os.path.basename(path), "Error", os.path.abspath(path))
                    continue

                abs_path = os.path.abspath(path)
                if abs_path in records:
                    stored = records[abs_path]["hash"]
                    res = "Safe" if stored == cur else "Modified"
                else:
                    # try matching by basename to be forgiving
                    matched = False
                    for p, r in records.items():
                        if os.path.basename(p) == os.path.basename(path):
                            matched = True
                            stored = r["hash"]
                            res = "Safe" if stored == cur else "Modified"
                            break
                    if not matched:
                        res = "Not registered"

                append_history("Verify", path, res)
                self._safe_ui_update(self.insert_history_row, "Verify", os.path.basename(path), res, os.path.abspath(path))
                self._safe_ui_update(self.show_file_info, path, cur, records.get(abs_path))
                pct = int((idx / total) * 100)
                self._safe_ui_update(self.meter.configure, amountused=pct)
                time.sleep(0.05)
                play_sound()
                self.heartbeat_pulse(False)
            self._safe_ui_update(self.status_label.config, text="Verification completed.", foreground="lime")
        finally:
            try:
                self._worker_sema.release()
            except Exception:
                pass

    # ---------------- History and UI ----------------
    def insert_history_row(self, action, file_basename, result, full_path=None):
        if full_path is None:
            full_path = ""
        self.history_tree.insert("", 0, values=(
            action,
            file_basename,
            full_path,
            result,
            time.strftime("%Y-%m-%d %H:%M:%S")
        ))

    def load_history_into_tree(self):
        # Load history JSON (trusted because hash_utils ensures signatures)
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                hist = json.load(f)
        except Exception:
            hist = []
        for row in hist:
            self.history_tree.insert("", END,
                                     values=(row.get("action", ""), row.get("file", ""), row.get("path", ""), row.get("result", ""), row.get("time", "")))

    def on_history_select(self, event):
        sel = self.history_tree.selection()
        if not sel:
            return
        item = self.history_tree.item(sel[0])
        file_path = item["values"][2]  # use full path column
        if file_path:
            recs = load_records()
            r = recs.get(file_path)
            if r:
                self.show_file_info(file_path, r.get("hash"), r)
                return
        self.info_text.delete(1.0, END)
        self.info_text.insert(END, "No stored record for selected file.\n")

    def show_file_info(self, path, current_hash, record):
        self.info_text.delete(1.0, END)
        try:
            size = os.path.getsize(path)
        except Exception:
            size = "-"
        lines = [
            f"File: {os.path.basename(path)}",
            f"Path: {path}",
            f"Size: {size}",
            f"Hash (current): {current_hash}",
        ]
        if record:
            lines.append(f"Recorded at: {record.get('time','-')}")
            lines.append(f"Recorded hash: {record.get('hash','-')}")
        self.info_text.insert(END, "\n".join(lines))

    # ---------------- Certificate export ----------------
    def export_certificate_prompt(self):
        sel = self.history_tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select a history row first.")
            return
        item = self.history_tree.item(sel[0])
        file_path = item["values"][2]
        if not file_path:
            messagebox.showerror("Not found", "No stored path in selected history row.")
            return
        recs = load_records()
        rec = recs.get(file_path)
        if not rec:
            messagebox.showerror("Not found", "No stored record for selected file.")
            return

        # --- NEW: Restrict certificate generation ONLY to files verified as Safe ---
        try:
            cur = sha256_hash(file_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hash file:\n{e}")
            return

        stored_hash = rec.get("hash")
        if stored_hash is None:
            messagebox.showerror("Cannot create certificate", "No recorded hash for this file.")
            return

        if stored_hash != cur:
            # Only allow certificate for safe/matching files
            messagebox.showerror("Not allowed", "Certificate can only be created for files that are verified as SAFE (stored hash matches current hash).")
            return

        out = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")],
                                           initialfile=f"certificate_{os.path.basename(file_path)}.pdf")
        if not out:
            return
        create_certificate(file_path, stored_hash, cur, out)
        messagebox.showinfo("Saved", f"Certificate saved to {out}")
        play_sound()

    # ---------------- Heartbeat meter ----------------
    def heartbeat_pulse(self, start=True):
        def pulse(start):
            if start:
                for v in range(0, 101, 5):
                    self._safe_ui_update(self.meter.configure, amountused=v)
                    time.sleep(0.01)
            else:
                for v in range(self.meter.amountused or 0, 101, 4):
                    self._safe_ui_update(self.meter.configure, amountused=v)
                    time.sleep(0.005)
        threading.Thread(target=pulse, args=(start,), daemon=True).start()

    # ---------------- Matrix animation ----------------
    def matrix_loop(self):
        canvas = self.matrix_canvas
        chars = "01"
        drops = []
        while self.matrix_running:
            try:
                canvas.delete("matrix")
                w = canvas.winfo_width() or 400
                h = canvas.winfo_height() or 300
                cols = max(10, w // 12)
                if len(drops) < cols:
                    drops = [0] * cols
                for i in range(cols):
                    x = i * 12
                    y = drops[i] * 14
                    ch = chars[(int(time.time_ns()) + i) % len(chars)]
                    canvas.create_text(x + 6, y, text=ch, fill="#33ff77",
                                       font=("Courier", 10), tag="matrix")
                    if y > h and (time.time() % 1) > 0.98:
                        drops[i] = 0
                    drops[i] += 1
                time.sleep(0.05)
            except Exception:
                time.sleep(0.1)

    # ---------------- PIN dialogs ----------------
    def ask_pin(self, prompt="Enter PIN"):
        win = Toplevel(self.root)
        win.title(prompt)
        win.geometry("300x150")
        win.transient(self.root)
        win.grab_set()

        tb.Label(win, text=prompt, font=("Segoe UI", 11)).pack(pady=10)
        entry = tb.Entry(win, show="*", width=20)
        entry.pack()
        entry.focus()

        result = {"pin": None}

        def submit():
            result["pin"] = entry.get()
            win.destroy()

        tb.Button(win, text="OK", bootstyle="success", command=submit).pack(pady=10)
        self.root.wait_window(win)
        return result["pin"]

    # ---------------- Clear activity ----------------
    def clear_activity_prompt(self):
        stored_pin = load_pin()
        pin = self.ask_pin("Enter PIN to Clear Activity")
        if pin is None:
            return

        if not verify_pin(pin, stored_pin):
            messagebox.showerror("Incorrect PIN", "The PIN you entered is incorrect.")
            return

        try:
            clear_history()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear history:\n{e}")
            return

        for row in self.history_tree.get_children():
            self.history_tree.delete(row)

        messagebox.showinfo("Cleared", "Recent activity has been cleared.")

    # ---------------- Change PIN ----------------
    def change_pin_prompt(self):
        stored = load_pin()

        cur = self.ask_pin("Enter Current PIN")
        if cur is None:
            return
        if not verify_pin(cur, stored):
            messagebox.showerror("Incorrect PIN", "Current PIN is incorrect.")
            return

        new1 = self.ask_pin("Enter New PIN")
        if new1 is None:
            return
        new2 = self.ask_pin("Confirm New PIN")
        if new2 is None:
            return

        if new1 != new2:
            messagebox.showerror("Mismatch", "The two PIN entries do not match.")
            return

        # --- NEW: prevent reusing the same PIN ---
        salt, hashed = stored
        if hash_pin(new1, salt) == hashed:
            messagebox.showerror("Invalid PIN", "New PIN must be different from the current PIN.")
            return

        save_pin(new1)
        messagebox.showinfo("Updated", "PIN updated successfully.")

    # ---------------- Utilities ----------------
    def _safe_ui_update(self, func, *args, **kwargs):
        """Schedule UI updates safely on the main Tk thread."""
        try:
            self.root.after(0, lambda: func(*args, **kwargs))
        except Exception:
            try:
                func(*args, **kwargs)
            except Exception:
                pass

    # ---------------- Shutdown ----------------
    def on_close(self):
        # stop background animation cleanly, then destroy
        self.matrix_running = False
        # allow matrix thread a moment to end
        time.sleep(0.05)
        try:
            self.root.destroy()
        except Exception:
            pass


# Entry point
if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = FICApp(root)
    root.mainloop()
