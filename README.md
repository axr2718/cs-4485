# EHR De-Identification Tool

## Description

This application enables users to securely de-identify and re-identify text files containing Protected Health Information (PHI). It uses pattern-based detection to identify sensitive information and replaces it with standardized placeholders. Optionally, users can encrypt the PHI mapping with a password for secure re-identification at a later time.

The tool features a web-based interface built with Gradio, allowing for file upload, text preview, and downloading of de-identified or re-identified files—all without writing any code.

---

## Features

- Secure encryption of PHI mappings using password-based key derivation
- Optional re-identification capability
- No programming required; all operations are done via a web interface
- Supports downloading as plain `.txt` or encrypted `.zip` bundle
- Built-in redaction for common PHI types (e.g., names, addresses, MRNs, SSNs, dates, and contact details)

---

## Getting Started

### 1. Launch the Application

To start the tool, run the Python script:

```bash
python3 main.py
```

> **Note**: Requires Python 3.7 or higher and the following packages: `gradio`, `cryptography`, and standard Python libraries.

---

## De-Identification Process

1. **Upload the EHR File**  
   Upload a `.txt` file containing PHI.

2. **(Optional) Set a Password**  
   If re-identification will be needed later, enter a password to encrypt the mapping data.

3. **Preview and Download**  
   - Review the de-identified text in the interface
   - Download the plain `.txt` version
   - Or download a `.zip` file that includes the de-identified text and encrypted mapping

---

## Re-Identification Process

1. **Upload the Encrypted Bundle**  
   Upload the `.zip` file created during de-identification.

2. **Enter the Password**  
   Use the same password that was used to encrypt the mapping.

3. **Download the Original File**  
   The file will be restored with the original PHI and made available for download.

---

## Output Files

- **De-Identified Text File**:  
  Saved as `De-Identified_<YourFileName>.txt`

- **Encrypted Bundle (optional)**:  
  Saved as `<YourFileName>_DeidBundle.zip`, and contains:
  - De-identified text
  - Encrypted PHI mapping (`EncryptedMapping.bin`)
  - Salt file for key derivation (`Salt.bin`)

- **Re-Identified File**:  
  Reconstructed `.txt` file matching the original input

---

## Technical Details

- PHI is detected using regular expressions and replaced with labeled placeholders (e.g., `*name*`, `*address*`, `*date*`)
- Supported identifiers include:
  - Patient names, provider names, addresses
  - Social Security Numbers, phone/fax numbers, email, URLs
  - Medical record numbers, insurance/group/account numbers
  - Dates, device identifiers, biometric data, and more
- Mapping is encrypted using Fernet symmetric encryption (AES-based), with a password-derived key using PBKDF2 and SHA256

---

## Installation Requirements

Install dependencies using:

```bash
pip install -r requirements.txt
```

The `requirements.txt` should include:
- gradio
- cryptography

---

## Best Practices

- Always preview the output before distributing any files
- Use strong passwords if re-identification may be necessary
- Retain a backup of original files
- Ensure PHI terms follow consistent formatting for accurate redaction

---

## Example Workflow

1. Upload `ehr_sample.txt` using the **De-Identify** tab.
2. Optionally, set a password for secure mapping encryption.
3. Download either the de-identified `.txt` or a `.zip` bundle for later re-identification.
4. To restore the original file, use the **Re-Identify** tab, upload the bundle, and provide the correct password.