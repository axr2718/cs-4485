import re
import json
import uuid
import zipfile
import shutil
from pathlib import Path
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import gradio as gr
from typing import Tuple

backend = default_backend()

# --- Utility Functions ---
def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_mapping(mapping: dict, password: str) -> Tuple[bytes, bytes]:
    salt = uuid.uuid4().bytes
    key = derive_key(password, salt)
    fernet = Fernet(key)
    data = json.dumps(mapping).encode()
    encrypted = fernet.encrypt(data)
    return encrypted, salt

def decrypt_mapping(encrypted_data: bytes, salt: bytes, password: str) -> dict:
    key = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data)
    return json.loads(decrypted)

# --- PHI Functions ---
def deidentify_PHI_with_mapping(text):
    phi_map = {}

    def replace_and_map(pattern, replacement_template, key, text, value_group=None, flags=0):
        matches = []

        def replace_func(match):
            if value_group is not None:
                original = match.group(value_group)
            else:
                original = match.group(0)
            matches.append(original)
            return replacement_template

        new_text = re.sub(pattern, replace_func, text, flags=flags)

        if matches:
            if key in phi_map and isinstance(phi_map[key], list):
                phi_map[key].extend(matches)
            else:
                phi_map[key] = matches if len(matches) > 1 else matches[0]

        return new_text

    text = replace_and_map(r'(?i)Patient name:\s*(.*)', 'Patient name: *name*', 'name', text, value_group=1)
    text = replace_and_map(r'(?i)Patient:\s*(.*)', 'Patient: *name*', 'name', text, value_group=1)
    text = replace_and_map(r'(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s*[A-Z][a-z]+ [A-Z][a-z]+', '*name*', 'name', text)
    text = replace_and_map(r'(?:^|\s)(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s*[A-Z][a-z]+', '*name*', 'name', text)
    text = replace_and_map(r'Ms\.\s*([A-Z][a-z]+)', '*name*', 'name', text, value_group=1)
    text = replace_and_map(r'(?i)Medical record number:\s*([A-Z0-9\-]+)', 'Medical record number: *mrn*', 'mrn', text, value_group=1)
    text = replace_and_map(r'Provider:\s*(?:Dr\.|Ms\.|Mr\.)?\s*([A-Z][a-z]+ [A-Z][a-z]+)', 'Provider: *provider_name*, MD', 'provider_name', text, value_group=1)
    text = replace_and_map(r'Social Worker:\s*(?:Dr\.|Ms\.|Mr\.)?\s*([A-Z][a-z]+ [A-Z][a-z]+)', '\nSocial Worker: *social_worker_name*', 'social_worker_name', text, value_group=1)
    text = replace_and_map(r'Address:\s*(.*?)(?=\n|$)', 'Address: *address*', 'address', text, value_group=1)
    text = replace_and_map(r'Hospital Name:\s*(.*?)(?=\n|$)', 'Hospital Name: *hospital*', 'hospital', text, value_group=1)
    text = replace_and_map(r'\b(\d{2}/\d{2}/\d{4})\b', '*date*', 'date', text, value_group=1)
    text = replace_and_map(r'SSN:\s*(\d{3}-\d{2}-\d{4})', 'SSN: *ssn*', 'ssn', text, value_group=1)
    text = replace_and_map(r'Phone:\s*(\d{3}[-\s]?\d{3}[-\s]?\d{4})', 'Phone: *phone_number*', 'phone_number', text, value_group=1)
    text = replace_and_map(r'Fax (?:number|no\.|\.):\s*(\d{3}[-\s]?\d{3}[-\s]?\d{4})', 'Fax no.: *fax_number*', 'fax_number', text, value_group=1)
    text = replace_and_map(r'[Ee]mail:\s*([\w\.-]+@[\w\.-]+\.\w+)', 'Email: *email*', 'email', text, value_group=1)
    text = replace_and_map(r'URL:\s*([\w:\/\.\-]+)', 'URL: *url*', 'url', text, value_group=1)
    text = replace_and_map(r'Health plan beneficiary number:\s*([\d\-]+)', 'Health plan beneficiary number: *beneficiary*', 'beneficiary', text, value_group=1)
    text = replace_and_map(r'Health Insurance:\s*([^\s\n]+)', 'Health Insurance: *insurance*', 'insurance', text, value_group=1)
    text = replace_and_map(r'Group no\.:\s*([\d\-]+)', 'Group no.: *group_number*', 'group_number', text, value_group=1)
    text = replace_and_map(r'Medicaid account:\s*(\d+(?:\s+\d+)*)', 'Medicaid account: *medicaid*', 'medicaid', text, value_group=1)
    text = replace_and_map(r'Account:\s*([\d\s]+)', 'Account: *account*\n', 'account', text, value_group=1)
    text = replace_and_map(r'Certificate number:\s*(.*?)(?=\n|$)', 'Certificate number: *certificate*', 'certificate', text, value_group=1)
    text = replace_and_map(r'license number:\s*([A-Z]{2}\d{2}-\d{6})', 'license number: *license_number*', 'license_number', text, value_group=1)
    text = replace_and_map(r'Pacemaker serial numbers:([A-Z0-9\-]+)', 'Pacemaker serial numbers:*serial_number*', 'serial_number', text, value_group=1)
    text = replace_and_map(r'Device identifier:([A-Z0-9\-]+)', 'Device identifier:*device_identifier*', 'device_identifier', text, value_group=1)
    text = replace_and_map(r'Biometric:\s*(.*?)(?=\n|$)', 'Biometric: *biometric_identifier*', 'biometric_identifier', text, value_group=1)
    text = replace_and_map(r'Lab Results \((\d{2}/\d{2}/\d{4})\):\n+((?:.|\n)*?)\n(?=Follow-up Appointments:)', 'Lab Results (\1):\n\n*lab_results*\n', 'lab_results', text, value_group=2, flags=re.DOTALL)
    text = replace_and_map(r'Code:(\d+)', 'Code:*code*', 'code', text, value_group=1)

    return text, phi_map

def reidentify_PHI(de_identified_text, phi_map):
    reidentified_text = de_identified_text
    for key, value in phi_map.items():
        placeholder = f'*{key}*'
        if isinstance(value, list):
            for item in value:
                reidentified_text = reidentified_text.replace(placeholder, item, 1)
        else:
            reidentified_text = reidentified_text.replace(placeholder, value)
    return reidentified_text

# --- File Handling ---
def package_zip(deidentified_text: str, encrypted_mapping: bytes, salt: bytes, base_name: str) -> Path:
    temp_dir = Path("temp") / uuid.uuid4().hex[:6]
    temp_dir.mkdir(parents=True)

    deid_path = temp_dir / f"{base_name}_Deidentified.txt"
    mapping_path = temp_dir / "EncryptedMapping.bin"
    salt_path = temp_dir / "Salt.bin"

    deid_path.write_text(deidentified_text)
    mapping_path.write_bytes(encrypted_mapping)
    salt_path.write_bytes(salt)

    zip_path = Path(f"{base_name}_DeidBundle.zip")
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.write(deid_path, arcname=deid_path.name)
        zf.write(mapping_path, arcname=mapping_path.name)
        zf.write(salt_path, arcname=salt_path.name)

    shutil.rmtree(temp_dir)
    return zip_path

def extract_zip(zip_file: Path) -> dict:
    temp_dir = Path("temp") / uuid.uuid4().hex[:6]
    temp_dir.mkdir(parents=True)

    with zipfile.ZipFile(zip_file, 'r') as zf:
        zf.extractall(temp_dir)

    deid_file = next(temp_dir.glob("*_Deidentified.txt"))
    mapping_file = temp_dir / "EncryptedMapping.bin"
    salt_file = temp_dir / "Salt.bin"

    return {
        "deid_path": deid_file,
        "mapping_path": mapping_file,
        "salt_path": salt_file,
        "temp_dir": temp_dir
    }

# --- Gradio Interfaces ---
def deidentify_interface(file: gr.File, password):
    try:
        with open(file.name, 'r') as f:
            text = f.read()
        deid_text, phi_map = deidentify_PHI_with_mapping(text)
        encrypted_map, salt = encrypt_mapping(phi_map, password)

        base_name = Path(file.name).stem.replace(" ", "_")
        zip_path = package_zip(deid_text, encrypted_map, salt, base_name)
        return str(zip_path), "✅ De-identification complete!"
    except Exception as e:
        return None, f"❌ Error: {str(e)}"

def reidentify_interface(zip_file, password):
    try:
        paths = extract_zip(Path(zip_file.name))
        deid_text = paths["deid_path"].read_text()
        encrypted_map = paths["mapping_path"].read_bytes()
        salt = paths["salt_path"].read_bytes()

        phi_map = decrypt_mapping(encrypted_map, salt, password)
        reid_text = reidentify_PHI(deid_text, phi_map)

        reid_path = Path(f"Reidentified_{paths['deid_path'].name}")
        reid_path.write_text(reid_text)

        shutil.rmtree(paths['temp_dir'])
        return str(reid_path), "✅ Re-identification complete!"
    except Exception as e:
        return None, f"❌ Error: {str(e)}"

# --- Gradio UI ---
deid_ui = gr.Interface(
    fn=deidentify_interface,
    inputs=[
        gr.File(label="Upload EHR File"),
        gr.Textbox(label="Set a Password", type="password")
    ],
    outputs=[
        gr.File(label="Download De-Identification Bundle (.zip)"),
        gr.Textbox(label="Status")
    ],
    title="Secure EHR De-Identifier",
    description="Upload your EHR file and set a password to download an encrypted .zip with de-identified data."
)

reid_ui = gr.Interface(
    fn=reidentify_interface,
    inputs=[
        gr.File(label="Upload De-Identification Bundle (.zip)"),
        gr.Textbox(label="Enter Password", type="password")
    ],
    outputs=[
        gr.File(label="Download Re-Identified File"),
        gr.Textbox(label="Status")
    ],
    title="Secure EHR Re-Identifier",
    description="Upload the encrypted .zip bundle and enter the password to recover original PHI."
)

demo = gr.TabbedInterface([deid_ui, reid_ui], ["De-Identify", "Re-Identify"])

if __name__ == "__main__":
    demo.launch(share=True)
