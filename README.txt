PrivateTxtVault 1.1.1
======================

PrivateTxtVault is a small offline command-line and GUI wrapper for age.exe. It
encrypts and decrypts .txt files on a Windows computer using age passphrase
encryption.
It does not implement custom encryption and does not use internet, telemetry,
cloud, update, analytics, or network features.

Project layout
--------------

PrivateTxtVault/
  PrivateTxtVault.py
  age.exe
  vault/
    encrypted/
    decrypted/
    checksums/
    temp/
  README.txt

How to place age.exe
--------------------

1. Obtain age.exe from a trusted source before moving to the offline computer.
2. Copy age.exe into the same folder as PrivateTxtVault.py.
3. The expected path is:

   PrivateTxtVault/age.exe

4. Run this check from the PrivateTxtVault folder:

   python PrivateTxtVault.py --audit

The audit should report that age.exe exists. If age.exe is missing, encryption
and decryption will refuse to run and will print a clear error.

Running the tool
----------------

From the PrivateTxtVault folder, run the command-line menu with:

  python PrivateTxtVault.py

Or run the simple graphical interface with:

  python PrivateTxtVault.py --gui

The GUI lets you choose .txt and .age files with file picker buttons, then run
encrypt, decrypt, or checksum verification actions while status messages are
shown in a log panel. The command-line menu and audit do not require Tkinter;
Tkinter is imported only when --gui is used. Passphrases are still entered only
into age.exe. If the age.exe passphrase prompt is not visible from the GUI, start
the GUI from a terminal window so age.exe has a console for passphrase entry.

The command-line menu is:

  PrivateTxtVault

  1. Encrypt .txt file
  2. Decrypt .age file
  3. Verify encrypted file checksum
  4. Exit

Passphrase handling
-------------------

PrivateTxtVault does not ask Python to read, store, log, print, or save your
passphrase. age.exe prompts for the passphrase directly. The passphrase is never
passed as a command-line argument and is never stored in an environment variable
or config file by this tool.

During encryption, PrivateTxtVault verifies the result by test-decrypting the
new .age file into vault/temp/ and comparing that temporary file byte-for-byte
against the original .txt file. You may need to enter the same passphrase again
for this verification step. The temporary verification file is deleted afterward.

Important plaintext warnings
----------------------------

Encrypted files are durable. Decrypted files are temporary.

After encryption, the original .txt file still exists and is readable. Delete or
manage it yourself if you no longer want plaintext on disk. PrivateTxtVault does
not claim secure deletion.

After decryption, the created .txt file in vault/decrypted/ is readable
plaintext. Delete it when you are finished.

Output behavior
---------------

Encrypted files are written to vault/encrypted/ using versioned names such as:

  notes_2026-05-07_v1.txt.age
  notes_2026-05-07_v2.txt.age

Checksum files are written to vault/checksums/ and include:

  SHA-256 hash
  encrypted filename
  creation timestamp
  tool version

Decrypted files are written to vault/decrypted/ using versioned names. Existing
files are not silently overwritten.

Manual test matrix
------------------

Run these tests on the intended offline Windows computer after placing age.exe
next to PrivateTxtVault.py.

1. Encrypt valid .txt
   Steps:
   - Create sample.txt containing a short test message.
   - Run python PrivateTxtVault.py.
   - Choose option 1.
   - Enter the path to sample.txt.
   - Enter and confirm a passphrase when age.exe prompts.
   - Enter the same passphrase again if prompted for verification.
   Expected:
   - A .age file appears in vault/encrypted/.
   - A matching .sha256 file appears in vault/checksums/.
   - The program prints: Encryption completed and verified.
   - The program warns that the original plaintext .txt still exists.

2. Encrypt non-.txt
   Steps:
   - Create sample.md or sample.doc.
   - Choose option 1 and enter that path.
   Expected:
   - The tool refuses with a clear .txt extension error.
   - No encrypted output is created.

3. Encrypt missing file
   Steps:
   - Choose option 1.
   - Enter a path that does not exist.
   Expected:
   - The tool prints a clear missing-file error.
   - No encrypted output is created.

4. Decrypt valid .age
   Steps:
   - Choose option 2.
   - Enter the path to a valid .age file created by test 1.
   - Enter the correct passphrase when age.exe prompts.
   Expected:
   - A readable .txt file appears in vault/decrypted/.
   - The program warns that the decrypted .txt file is readable plaintext.

5. Decrypt with wrong passphrase
   Steps:
   - Choose option 2.
   - Enter a valid .age file path.
   - Enter an incorrect passphrase.
   Expected:
   - Decryption fails safely.
   - Any partial output file is deleted.
   - The program prints a conservative failure message.

6. Decrypt corrupted .age
   Steps:
   - Make a copy of a valid .age file.
   - Modify a few bytes in the copy using a safe test method.
   - Choose option 2 and enter the corrupted .age path.
   Expected:
   - Decryption fails safely or warns clearly.
   - Any partial output file is deleted.

7. Verify valid checksum
   Steps:
   - Choose option 3.
   - Enter the path to an unchanged .age file created by test 1.
   Expected:
   - The program prints: Checksum verified: file has not changed.

8. Verify modified .age
   Steps:
   - Make a copy of a valid .age file and its matching checksum metadata if
     needed for the test.
   - Modify the .age file after the checksum was created.
   - Choose option 3 and enter the modified .age path.
   Expected:
   - The program prints: WARNING: checksum mismatch. File may be corrupted,
     modified, or replaced.
   - The program does not attempt to repair the file.

9. Existing output file
   Steps:
   - Encrypt the same .txt file twice on the same day.
   - Decrypt the same .age file twice.
   Expected:
   - New versioned output filenames are created.
   - Existing files are not silently overwritten.

10. Missing age.exe
    Steps:
    - Temporarily rename age.exe to age.exe.bak.
    - Run python PrivateTxtVault.py --audit.
    - Try menu option 1 or 2.
    Expected:
    - The audit reports that age.exe is missing.
    - Encryption and decryption refuse to run with a clear error.
    - Rename age.exe.bak back to age.exe after the test.

11. Temp file cleanup
    Steps:
    - Complete an encryption verification.
    - Inspect vault/temp/.
    Expected:
    - No decrypted verification file remains in vault/temp/.

12. GUI smoke test
    Steps:
    - Run python PrivateTxtVault.py --gui from a terminal.
    - Use Choose .txt to select a sample .txt file.
    - Click Encrypt selected .txt and enter the age.exe passphrase prompts in
      the terminal if they appear there.
    - Use Choose .age to select a valid .age file.
    - Click Verify selected .age checksum or Decrypt selected .age.
    Expected:
    - The window stays responsive while the operation runs.
    - The log panel shows the same success, warning, or failure messages as the
      command-line workflow.
    - Passphrases are not typed into the PrivateTxtVault GUI.

13. Offline machine
    Steps:
    - Disconnect the computer from all networks.
    - Run encryption, decryption, checksum verification, --gui, and --audit.
    Expected:
    - The tool works normally without internet access.
    - No network connection is required.

Self-audit
----------

Run:

  python PrivateTxtVault.py --audit

The audit checks for age.exe, required vault folders, absence of network imports,
argument-list subprocess usage, absence of unsafe command-shell usage, obvious
hardcoded passphrase variables, temp cleanup, version display, plaintext warnings,
checksum functionality, GUI entrypoint wiring, and lazy Tkinter imports. It is a
practical sanity check, not a formal security proof.
