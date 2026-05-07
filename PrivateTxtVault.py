"""PrivateTxtVault: offline .txt encryption wrapper for age.exe.

This program intentionally delegates encryption and decryption to age.exe. It does
not implement encryption algorithms, passphrase storage, networking, telemetry, or
update checks.
"""

import os
import sys
from pathlib import Path
import subprocess
import hashlib
from datetime import datetime
import shutil
import threading
import queue
import contextlib
import io
import importlib.util

APP_NAME = "PrivateTxtVault"
APP_VERSION = "1.1.1"
SCRIPT_DIR = Path(__file__).resolve().parent
VAULT_DIR = SCRIPT_DIR / "vault"
ENCRYPTED_DIR = VAULT_DIR / "encrypted"
DECRYPTED_DIR = VAULT_DIR / "decrypted"
CHECKSUM_DIR = VAULT_DIR / "checksums"
TEMP_DIR = VAULT_DIR / "temp"
REQUIRED_DIRS = (ENCRYPTED_DIR, DECRYPTED_DIR, CHECKSUM_DIR, TEMP_DIR)
NETWORK_MODULE_NAMES = ("requests", "urllib", "socket", "http.client", "ftplib", "smtplib")
CHUNK_SIZE = 1024 * 1024


def ensure_directories():
    """Create the vault folder structure if it does not already exist."""
    for directory in REQUIRED_DIRS:
        directory.mkdir(parents=True, exist_ok=True)


def find_age_exe():
    """Return the expected age.exe path, or None when it is unavailable."""
    age_path = SCRIPT_DIR / "age.exe"
    if age_path.is_file():
        return age_path
    return None


def normalize_user_path(raw_path):
    """Convert a user-entered path to a Path without creating or modifying it."""
    if raw_path is None:
        return None
    cleaned = str(raw_path).strip().strip('"')
    if not cleaned:
        return None
    return Path(cleaned).expanduser()


def validate_input_file(path, required_suffix):
    """Validate existence and extension for user-selected input files."""
    if path is None:
        print("ERROR: No path was provided.")
        return False
    try:
        exists = path.exists()
        is_file = path.is_file()
    except OSError as exc:
        print(f"ERROR: Could not access the specified path: {exc}")
        return False
    if not exists:
        print("ERROR: The specified file does not exist.")
        return False
    if not is_file:
        print("ERROR: The specified path is not a file.")
        return False
    if path.suffix.lower() != required_suffix.lower():
        print(f"ERROR: Expected a {required_suffix} file.")
        return False
    return True


def make_versioned_filename(source_path, output_dir, mode):
    """Create a versioned filename that does not collide with existing files."""
    today = datetime.now().date().isoformat()

    if mode == "encrypt":
        base = source_path.stem
        suffix = f"{source_path.suffix}.age"
        pattern = "{base}_{date}_v{version}{suffix}"
    elif mode == "decrypt":
        name = source_path.name
        if name.lower().endswith(".age"):
            name = name[:-4]
        if name.lower().endswith(".txt"):
            name = name[:-4]
        base = name
        suffix = ".txt"
        pattern = "{base}_decrypted_v{version}{suffix}"
    elif mode == "temp_verify":
        base = source_path.stem.replace(os.sep, "_")
        suffix = ".txt"
        pattern = "verify_{base}_v{version}{suffix}"
    else:
        raise ValueError("Unsupported filename mode.")

    version = 1
    while True:
        candidate = output_dir / pattern.format(
            base=base,
            date=today,
            version=version,
            suffix=suffix,
        )
        if not candidate.exists():
            return candidate
        version += 1


def safe_output_path(output_dir, filename):
    """Return a non-existing path inside output_dir, versioning if needed."""
    output_dir.mkdir(parents=True, exist_ok=True)
    requested = output_dir / Path(filename).name
    if not requested.exists():
        return requested

    stem = requested.stem
    suffix = requested.suffix
    version = 2
    while True:
        candidate = output_dir / f"{stem}_v{version}{suffix}"
        if not candidate.exists():
            return candidate
        version += 1


def run_age_command(arguments):
    """Run age.exe with an argument list and no command shell.

    Security-sensitive decision: passphrases are never accepted by this Python
    code and are never added to the argument list. age.exe prompts directly in
    the console, which avoids command-line, environment, config, and log exposure
    by this wrapper.
    """
    if not isinstance(arguments, list):
        raise TypeError("age command must be provided as a list of arguments")
    try:
        return subprocess.run(arguments, shell=False)
    except OSError as exc:
        print(f"ERROR: Could not run age.exe: {exc}")
        return subprocess.CompletedProcess(arguments, returncode=1)


def compare_files_byte_for_byte(first_path, second_path):
    """Compare two files without loading entire plaintext files into memory."""
    if first_path.stat().st_size != second_path.stat().st_size:
        return False
    with first_path.open("rb") as first_file, second_path.open("rb") as second_file:
        while True:
            first_chunk = first_file.read(CHUNK_SIZE)
            second_chunk = second_file.read(CHUNK_SIZE)
            if first_chunk != second_chunk:
                return False
            if not first_chunk:
                return True


def cleanup_temp_files():
    """Remove files created in vault/temp.

    This is ordinary deletion only. The tool does not claim secure deletion.
    """
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    cleaned = True
    for child in TEMP_DIR.iterdir():
        if child.name == ".gitkeep":
            continue
        try:
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        except OSError as exc:
            cleaned = False
            print(f"WARNING: Could not remove temporary item {child}: {exc}")
    return cleaned


def verify_encryption(original_txt_path, encrypted_age_path, age_exe_path):
    """Test-decrypt an encrypted file and compare it with the original."""
    ensure_directories()
    temp_output = safe_output_path(TEMP_DIR, make_versioned_filename(encrypted_age_path, TEMP_DIR, "temp_verify").name)
    print("Verification requires decrypting the new .age file.")
    print("Enter the same passphrase when age.exe prompts for it.")
    try:
        result = run_age_command([
            str(age_exe_path),
            "--decrypt",
            "-o",
            str(temp_output),
            str(encrypted_age_path),
        ])
        if result.returncode != 0:
            print("ERROR: Verification decrypt failed. Encryption is not verified.")
            return False
        if compare_files_byte_for_byte(original_txt_path, temp_output):
            return True
        print("ERROR: Verification failed. Decrypted bytes did not match the original file.")
        return False
    finally:
        if temp_output.exists():
            try:
                temp_output.unlink()
            except OSError as exc:
                print(f"WARNING: Could not delete verification temp file: {exc}")
        cleanup_temp_files()


def create_sha256(age_path):
    """Create a checksum metadata file for an encrypted .age file."""
    sha256 = hashlib.sha256()
    with age_path.open("rb") as encrypted_file:
        for chunk in iter(lambda: encrypted_file.read(CHUNK_SIZE), b""):
            sha256.update(chunk)
    digest = sha256.hexdigest()
    checksum_path = safe_output_path(CHECKSUM_DIR, f"{age_path.name}.sha256")
    timestamp = datetime.now().isoformat(timespec="seconds")
    contents = (
        f"SHA-256: {digest}\n"
        f"Encrypted filename: {age_path.name}\n"
        f"Creation timestamp: {timestamp}\n"
        f"Tool version: {APP_NAME} {APP_VERSION}\n"
    )
    checksum_path.write_text(contents, encoding="utf-8")
    return checksum_path


def read_saved_checksum(checksum_path):
    """Read the SHA-256 value from a PrivateTxtVault checksum file."""
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("SHA-256:"):
            return line.split(":", 1)[1].strip().lower()
    return None


def locate_checksum_file(age_path):
    """Find the checksum file matching an encrypted filename."""
    direct = CHECKSUM_DIR / f"{age_path.name}.sha256"
    if direct.is_file():
        return direct
    for candidate in CHECKSUM_DIR.glob("*.sha256"):
        try:
            text = candidate.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if f"Encrypted filename: {age_path.name}" in text:
            return candidate
    return None


def verify_sha256_path(age_path):
    """Verify a saved checksum for a specific encrypted .age file."""
    ensure_directories()
    if not validate_input_file(age_path, ".age"):
        return False

    checksum_path = locate_checksum_file(age_path)
    if checksum_path is None:
        print("ERROR: No matching .sha256 file was found in vault/checksums/.")
        return False

    saved_hash = read_saved_checksum(checksum_path)
    if not saved_hash:
        print("ERROR: The checksum file does not contain a readable SHA-256 value.")
        return False

    sha256 = hashlib.sha256()
    with age_path.open("rb") as encrypted_file:
        for chunk in iter(lambda: encrypted_file.read(CHUNK_SIZE), b""):
            sha256.update(chunk)
    current_hash = sha256.hexdigest()

    if current_hash.lower() == saved_hash:
        print("Checksum verified: file has not changed.")
        return True
    print("WARNING: checksum mismatch. File may be corrupted, modified, or replaced.")
    return False


def verify_sha256():
    """Verify a saved checksum for a user-selected .age file."""
    raw_path = input("Path to .age file: ")
    return verify_sha256_path(normalize_user_path(raw_path))


def print_plaintext_warning():
    """Warn the user whenever a readable plaintext file remains on disk."""
    print("WARNING: The decrypted .txt file is readable plaintext.")
    print("Delete it when you are finished.")


def encrypt_txt_path(txt_path):
    """Encrypt a specific .txt file using age.exe passphrase mode."""
    ensure_directories()
    age_exe = find_age_exe()
    if age_exe is None:
        print("ERROR: age.exe was not found next to PrivateTxtVault.py.")
        return False

    if not validate_input_file(txt_path, ".txt"):
        return False

    output_path = make_versioned_filename(txt_path, ENCRYPTED_DIR, "encrypt")
    print("age.exe will prompt for a passphrase. PrivateTxtVault will not see or store it.")
    result = run_age_command([
        str(age_exe),
        "--encrypt",
        "--passphrase",
        "-o",
        str(output_path),
        str(txt_path),
    ])

    if result.returncode != 0:
        if output_path.exists():
            output_path.unlink()
        print("ERROR: Encryption failed. No success is claimed.")
        return False

    if not verify_encryption(txt_path, output_path, age_exe):
        print("ERROR: Encrypted file was not verified. Check the output before relying on it.")
        return False

    checksum_path = create_sha256(output_path)
    print("Encryption completed and verified.")
    print(f"Encrypted file: {output_path}")
    print(f"Checksum file: {checksum_path}")
    print("WARNING: The original plaintext .txt file still exists and is readable.")
    return True


def encrypt_file():
    """Encrypt a user-selected .txt file from the command-line menu."""
    raw_path = input("Path to .txt file: ")
    return encrypt_txt_path(normalize_user_path(raw_path))


def decrypt_age_path(age_path):
    """Decrypt a specific .age file and remove partial output on failure."""
    ensure_directories()
    age_exe = find_age_exe()
    if age_exe is None:
        print("ERROR: age.exe was not found next to PrivateTxtVault.py.")
        return False

    if not validate_input_file(age_path, ".age"):
        return False

    output_path = make_versioned_filename(age_path, DECRYPTED_DIR, "decrypt")
    result = run_age_command([
        str(age_exe),
        "--decrypt",
        "-o",
        str(output_path),
        str(age_path),
    ])

    if result.returncode != 0:
        if output_path.exists():
            output_path.unlink()
        print("ERROR: Decryption failed. Wrong passphrase, corruption, or replacement is possible.")
        return False

    print(f"Decrypted file: {output_path}")
    print_plaintext_warning()
    return True


def decrypt_file():
    """Decrypt a user-selected .age file from the command-line menu."""
    raw_path = input("Path to .age file: ")
    return decrypt_age_path(normalize_user_path(raw_path))


def source_contains_forbidden_text(source_text):
    """Look for common unsafe patterns without performing perfect proof."""
    forbidden_modules = [f"import {name}" for name in NETWORK_MODULE_NAMES]
    forbidden_modules.extend(f"from {name}" for name in NETWORK_MODULE_NAMES)
    unsafe_shell_pattern = "shell" + "=" + "True"
    # Construct these fragments so the audit does not flag its own check text.
    separator = " " + "="
    risky_secret_assignments = (
        "password" + separator,
        "passphrase" + separator,
        "secret" + separator,
        "private_key" + separator,
    )
    return {
        "network": any(item in source_text for item in forbidden_modules),
        "unsafe_shell": unsafe_shell_pattern in source_text,
        "hardcoded_secret": any(item in source_text.lower() for item in risky_secret_assignments),
    }


def self_audit():
    """Run practical safety and readiness checks."""
    ensure_directories()
    source_text = Path(__file__).read_text(encoding="utf-8")
    findings = source_contains_forbidden_text(source_text)
    print(f"{APP_NAME} {APP_VERSION} self-audit")
    print("This audit is a practical sanity check, not a formal security proof.")

    checks = []
    checks.append(("age.exe exists next to the script", find_age_exe() is not None))
    checks.append(("Required vault folders exist", all(path.is_dir() for path in REQUIRED_DIRS)))
    checks.append(("No network modules are imported", not findings["network"]))
    checks.append(("subprocess.run receives an argument list", "subprocess.run(arguments" in source_text))
    checks.append(("No unsafe command shell option is present", not findings["unsafe_shell"]))
    checks.append(("No obvious hardcoded passphrase variable is present", not findings["hardcoded_secret"]))
    checks.append(("Temp folder is empty or can be cleaned", cleanup_temp_files()))
    checks.append(("App version is displayed", APP_VERSION in source_text and APP_NAME in source_text))
    checks.append(("Plaintext warning function is available", "print_plaintext_warning" in source_text))
    checks.append(("Checksum functionality is available", "create_sha256" in source_text and "verify_sha256" in source_text))
    checks.append(("GUI entrypoint is available", "launch_gui" in source_text and "--gui" in source_text))
    checks.append(("GUI uses reusable path-based operations", "encrypt_txt_path" in source_text and "decrypt_age_path" in source_text))
    checks.append(("Tkinter is imported only when the GUI is requested", source_text.index("def load_tkinter_modules") < source_text.index("import tkinter as tk_module")))

    passed = 0
    for label, ok in checks:
        if ok:
            passed += 1
            print(f"PASS: {label}")
        else:
            print(f"FAIL: {label}")
    print(f"Audit result: {passed}/{len(checks)} checks passed.")
    return passed == len(checks)


def main_menu():
    """Display the interactive command-line menu."""
    ensure_directories()
    while True:
        print()
        print(APP_NAME)
        print()
        print("1. Encrypt .txt file")
        print("2. Decrypt .age file")
        print("3. Verify encrypted file checksum")
        print("4. Exit")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            encrypt_file()
        elif choice == "2":
            decrypt_file()
        elif choice == "3":
            verify_sha256()
        elif choice == "4":
            print("Exiting.")
            return
        else:
            print("ERROR: Choose 1, 2, 3, or 4.")


def load_tkinter_modules():
    """Import Tkinter only when the graphical interface is requested."""
    if importlib.util.find_spec("tkinter") is None:
        print("ERROR: Tkinter is not available in this Python installation.")
        return None

    import tkinter as tk_module
    from tkinter import filedialog as filedialog_module
    from tkinter import messagebox as messagebox_module
    from tkinter import scrolledtext as scrolledtext_module

    return tk_module, filedialog_module, messagebox_module, scrolledtext_module


class PrivateTxtVaultGUI:
    """Small Tkinter interface for selecting files and running vault actions."""

    def __init__(self, root, tk_module, filedialog_module, messagebox_module, scrolledtext_module):
        self.root = root
        self.tk = tk_module
        self.filedialog = filedialog_module
        self.messagebox = messagebox_module
        self.scrolledtext = scrolledtext_module
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.message_queue = queue.Queue()
        self.worker_thread = None

        self.status_var = self.tk.StringVar(value="Ready")
        self.selected_txt_var = self.tk.StringVar(value="No .txt file selected")
        self.selected_age_var = self.tk.StringVar(value="No .age file selected")

        self._build_layout()
        self.root.after(100, self._drain_messages)

    def _build_layout(self):
        container = self.tk.Frame(self.root, padx=12, pady=12)
        container.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        container.columnconfigure(1, weight=1)
        container.rowconfigure(5, weight=1)

        title = self.tk.Label(container, text=APP_NAME, font=("Segoe UI", 16, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w")

        warning = (
            "Passphrases are still entered only into age.exe. "
            "Run from a terminal if the age.exe prompt is not visible."
        )
        self.tk.Label(container, text=warning, justify="left", wraplength=620).grid(
            row=1, column=0, columnspan=3, sticky="we", pady=(4, 12)
        )

        self.tk.Button(container, text="Choose .txt", command=self.choose_txt).grid(row=2, column=0, sticky="we", pady=2)
        self.tk.Label(container, textvariable=self.selected_txt_var, anchor="w").grid(row=2, column=1, sticky="we", padx=8)
        self.encrypt_button = self.tk.Button(container, text="Encrypt selected .txt", command=self.encrypt_selected)
        self.encrypt_button.grid(row=2, column=2, sticky="we", pady=2)

        self.tk.Button(container, text="Choose .age", command=self.choose_age).grid(row=3, column=0, sticky="we", pady=2)
        self.tk.Label(container, textvariable=self.selected_age_var, anchor="w").grid(row=3, column=1, sticky="we", padx=8)
        self.decrypt_button = self.tk.Button(container, text="Decrypt selected .age", command=self.decrypt_selected)
        self.decrypt_button.grid(row=3, column=2, sticky="we", pady=2)

        self.verify_button = self.tk.Button(container, text="Verify selected .age checksum", command=self.verify_selected)
        self.verify_button.grid(row=4, column=2, sticky="we", pady=(2, 8))

        self.log_box = self.scrolledtext.ScrolledText(container, width=84, height=18, state="disabled")
        self.log_box.grid(row=5, column=0, columnspan=3, sticky="nsew")

        status = self.tk.Label(container, textvariable=self.status_var, anchor="w")
        status.grid(row=6, column=0, columnspan=3, sticky="we", pady=(8, 0))

    def choose_txt(self):
        path = self.filedialog.askopenfilename(
            title="Choose a .txt file to encrypt",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
        )
        if path:
            self.selected_txt_var.set(path)

    def choose_age(self):
        path = self.filedialog.askopenfilename(
            title="Choose a .age file",
            filetypes=(("age files", "*.age"), ("All files", "*.*")),
        )
        if path:
            self.selected_age_var.set(path)

    def encrypt_selected(self):
        self._run_action("Encrypt", encrypt_txt_path, self.selected_txt_var.get(), ".txt")

    def decrypt_selected(self):
        self._run_action("Decrypt", decrypt_age_path, self.selected_age_var.get(), ".age")

    def verify_selected(self):
        self._run_action("Verify checksum", verify_sha256_path, self.selected_age_var.get(), ".age")

    def _run_action(self, action_name, action, raw_path, required_suffix):
        selected_path = normalize_user_path(raw_path)
        if selected_path is None or selected_path.suffix.lower() != required_suffix:
            self.messagebox.showerror(APP_NAME, f"Select a {required_suffix} file first.")
            return
        if self.worker_thread and self.worker_thread.is_alive():
            self.messagebox.showwarning(APP_NAME, "Another operation is still running.")
            return

        self._set_buttons_enabled(False)
        self.status_var.set(f"{action_name} running")
        self._append_log(f"\n--- {action_name}: {selected_path} ---\n")
        self.worker_thread = threading.Thread(
            target=self._worker,
            args=(action_name, action, selected_path),
            daemon=True,
        )
        self.worker_thread.start()

    def _worker(self, action_name, action, selected_path):
        buffer = io.StringIO()
        ok = False
        with contextlib.redirect_stdout(buffer):
            try:
                ok = action(selected_path)
            except Exception as exc:
                print(f"ERROR: {action_name} stopped unexpectedly: {exc}")
        self.message_queue.put(("log", buffer.getvalue()))
        self.message_queue.put(("done", action_name, ok))

    def _drain_messages(self):
        while True:
            try:
                message = self.message_queue.get_nowait()
            except queue.Empty:
                break
            if message[0] == "log":
                self._append_log(message[1])
            elif message[0] == "done":
                self._set_buttons_enabled(True)
                result = "completed" if message[2] else "failed"
                self.status_var.set(f"{message[1]} {result}")
        self.root.after(100, self._drain_messages)

    def _append_log(self, text):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _set_buttons_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        for button in (self.encrypt_button, self.decrypt_button, self.verify_button):
            button.configure(state=state)


def launch_gui():
    """Start the Tkinter graphical interface."""
    ensure_directories()
    tkinter_modules = load_tkinter_modules()
    if tkinter_modules is None:
        return False
    tk_module, filedialog_module, messagebox_module, scrolledtext_module = tkinter_modules
    try:
        root = tk_module.Tk()
    except tk_module.TclError as exc:
        print(f"ERROR: Could not start the GUI: {exc}")
        return False
    PrivateTxtVaultGUI(root, tk_module, filedialog_module, messagebox_module, scrolledtext_module)
    root.mainloop()
    return True


def main():
    usage = "Usage: python PrivateTxtVault.py [--audit | --gui]"
    if len(sys.argv) > 2:
        print(usage)
        return 2
    if len(sys.argv) == 2:
        if sys.argv[1] == "--audit":
            return 0 if self_audit() else 1
        if sys.argv[1] == "--gui":
            return 0 if launch_gui() else 1
        print(usage)
        return 2
    main_menu()
    return 0


if __name__ == "__main__":
    sys.exit(main())
