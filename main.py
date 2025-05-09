import re
import json
import uuid
import zipfile
import shutil
import tempfile
from pathlib import Path
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import gradio as gr
from typing import Tuple
from datetime import datetime
import pandas as pd
import time
backend = default_backend()

# --- Key Derivation ---
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

# --- PHI Redaction ---
def deidentify_PHI_with_mapping(text):
    phi_map = {}

    def replace_and_map(pattern, replacement_template, key, text, value_group=None, flags=0):
        matches = []
        def replace_func(match):
            # Use specified group or the entire match.
            original = match.group(value_group) if value_group else match.group(0)
            matches.append(original)
            return replacement_template
        new_text = re.sub(pattern, replace_func, text, flags=flags)
        if matches:
            if key in phi_map:
                if isinstance(phi_map[key], list):
                    phi_map[key].extend(matches)
                else:
                    phi_map[key] = [phi_map[key]] + matches
            else:
                phi_map[key] = matches if len(matches) > 1 else matches[0]
        return new_text

    # De-identify explicit Patient Name line.
    text = replace_and_map(
        r'(?i)^Patient name:\s*(.*)$', 
        'Patient Name: *patient_name*', 
        'patient_name', text, value_group=1, flags=re.MULTILINE
    )
    
    # De-identify Patient: line.
    text = replace_and_map(
        r'(?i)^Patient:\s*(.*)$', 
        'Patient: *patient*', 
        'patient', text, value_group=1, flags=re.MULTILINE
    )
    
    # De-identify Allergy section.
    text = replace_and_map(
        r'(?i)Allergies:\s*\n((?:-.*(?:\n|$))+)',
        'Allergies: *allergies*',
        'allergies', text, value_group=1, flags=re.MULTILINE
    )

    # De-identify Social History.
    text = replace_and_map(
        r'(?i)Social History:\s*((?:.|\n)*?)(?=\n[A-Z][a-z]+:|\Z)',
        'Social History: *social_history*',
        'social_history', text, value_group=1, flags=re.DOTALL
    )

    # --- Updated Provider Pattern ---
    text = replace_and_map(
        r'(?i)^(Provider:\s*((?:Dr\.|Ms\.|Mr\.)\s*[A-Z][a-z]+ [A-Z][a-z]+)(,\s*MD)?)',
        '*provider_name*',
        'provider_name', text, value_group=1, flags=re.MULTILINE
    )

    # --- Updated Social Worker Pattern ---
    text = replace_and_map(
        r'(?i)^(Social Worker:\s*((?:Dr\.|Ms\.|Mr\.)\s*[A-Z][a-z]+ [A-Z][a-z]+))',
        '*social_worker_name*',
        'social_worker_name', text, value_group=1, flags=re.MULTILINE
    )

    # De-identify full names in the format "Dr. John Smith" not caught above.
    text = replace_and_map(
        r'(?:Dr\.)\s*[A-Z][a-z]+ [A-Z][a-z]+',
        '*doctor_name*', 'doctor_name', text
    )

    # De-identify single honorific names like "Dr. Smith".
    text = replace_and_map(
        r'(?:^|\s)(?:Dr\.)\s*[A-Z][a-z]+',
        '*doctor_name*', 'doctor_name', text
    )

    # De-identify short "Ms. Jane" (if applicable).
    text = replace_and_map(
        r'Ms\.\s*([A-Z][a-z]+)',
        '*patient_name*', 'patient_name', text, value_group=1
    )

    # Medical Record Number.
    text = replace_and_map(
        r'(?i)Medical record number:\s*([A-Z0-9\-]+)',
        'Medical Record Number: *mrn*', 'mrn', text, value_group=1
    )

    # Full address.
    text = replace_and_map(
        r'Address:\s*(.*?)(?=\n|$)',
        'Address: *address*', 'address', text, value_group=1
    )

    # Hospital Name.
    text = replace_and_map(
        r'(?i)Hospital name:\s*(.*?)(?=\n|$)',
        'Hospital Name: *hospital*', 'hospital', text, value_group=1
    )

    # Dates in MM/DD/YYYY format.
    text = replace_and_map(
        r'\b(\d{2}/\d{2}/\d{4})\b',
        '*date*', 'date', text, value_group=1
    )

    # SSN.
    text = replace_and_map(
        r'SSN:\s*([*\d]{3}-[*\d]{2}-[*\d]{4})',
        'SSN: *ssn*', 'ssn', text, value_group=1
    )

    # Phone numbers.
    text = replace_and_map(
        r'Phone:\s*(\d{3}[-\s]?\d{3}[-\s]?\d{4})',
        'Phone: *phone_number*', 'phone_number', text, value_group=1
    )

    # Fax numbers.
    text = replace_and_map(
        r'Fax (?:number|no\.|\.):\s*(\d{3}[-\s]?\d{3}[-\s]?\d{4})',
        'Fax Number: *fax_number*', 'fax_number', text, value_group=1
    )

    # Email addresses.
    text = replace_and_map(
        r'[Ee]mail:\s*([\w\.-]+@[\w\.-]+\.\w+)',
        'Email: *email*', 'email', text, value_group=1
    )

    # URLs.
    text = replace_and_map(
        r'URL:\s*([\w:\/\.\-]+)',
        'URL: *url*', 'url', text, value_group=1
    )

    # Health plan beneficiary number.
    text = replace_and_map(
        r'Health plan beneficiary number:\s*([\d\-]+)',
        'Health Plan Beneficiary Number: *beneficiary*', 'beneficiary', text, value_group=1
    )

    # Health Insurance details.
    text = replace_and_map(
        r'Health Insurance:\s*([^\s\n]+)',
        'Health Insurance: *insurance*', 'insurance', text, value_group=1
    )

    # Group numbers.
    text = replace_and_map(
        r'Group no\.:\s*([\d\-]+)',
        'Group Number: *group_number*', 'group_number', text, value_group=1
    )

    # Medicaid account numbers.
    text = replace_and_map(
        r'Medicaid account:\s*(\d+(?:\s+\d+)*)',
        'Medicaid Account: *medicaid*', 'medicaid', text, value_group=1
    )

    # Bank account numbers.
    text = replace_and_map(
        r'Account:\s*([\d\s]+)',
        'Account: *account*\n', 'account', text, value_group=1
    )

    # Certificate number.
    text = replace_and_map(
        r'Certificate number:\s*(.*?)(?=\n|$)',
        'Certificate Number: *certificate*', 'certificate', text, value_group=1
    )

    # License numbers.
    text = replace_and_map(
        r'license number:\s*([A-Z]{2}\d{2}-\d{6})',
        'License Number: *license_number*', 'license_number', text, value_group=1
    )

    # Pacemaker serial numbers.
    text = replace_and_map(
        r'Pacemaker serial numbers:([A-Z0-9\-]+)',
        'Pacemaker Serial Numbers: *serial_number*', 'serial_number', text, value_group=1
    )

    # Medical device identifiers.
    text = replace_and_map(
        r'Device identifier:([A-Z0-9\-]+)',
        'Device Identifier: *device_identifier*', 'device_identifier', text, value_group=1
    )

    # Biometric descriptors.
    text = replace_and_map(
        r'Biometric:\s*(.*?)(?=\n|$)',
        'Biometric: *biometric_identifier*', 'biometric_identifier', text, value_group=1
    )

    # Multiline lab results with date.
    text = replace_and_map(
        r'Lab Results $(\d{2}/\d{2}/\d{4})$:\n+((?:.|\n)*?)\n(?=Follow-up Appointments:)',
        'Lab Results (\\1):\n\n*lab_results*\n', 'lab_results', text, value_group=2, flags=re.DOTALL
    )

    # Codes such as ICD.
    text = replace_and_map(
        r'Code:(\d+)',
        'Code: *code*', 'code', text, value_group=1
    )

    return text, phi_map

def reidentify_PHI(de_identified_text, phi_map):
    # Replace each placeholder with its stored original.
    for key, value in phi_map.items():
        placeholder = f'*{key}*'
        if isinstance(value, list):
            for item in value:
                de_identified_text = de_identified_text.replace(placeholder, item, 1)
        else:
            de_identified_text = de_identified_text.replace(placeholder, value)
    return de_identified_text


def package_zip_to_path(deidentified_text: str, encrypted_mapping: bytes, salt: bytes, out_path: Path, original_filename: str):
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)
        deid_name = f"De-Identified_{original_filename}"
        deid_path = temp_dir / deid_name
        map_path = temp_dir / "EncryptedMapping.bin"
        salt_path = temp_dir / "Salt.bin"

        deid_path.write_text(deidentified_text)
        map_path.write_bytes(encrypted_mapping)
        salt_path.write_bytes(salt)

        with zipfile.ZipFile(out_path, 'w') as zipf:
            zipf.write(deid_path, arcname=deid_path.name)
            zipf.write(map_path, arcname=map_path.name)
            zipf.write(salt_path, arcname=salt_path.name)

def extract_zip(zip_file: Path) -> dict:
    temp_dir = Path(tempfile.mkdtemp())
    with zipfile.ZipFile(zip_file, 'r') as zf:
        zf.extractall(temp_dir)
    return {
        "deid_path": next(temp_dir.glob("De-Identified_*")),
        "mapping_path": temp_dir / "EncryptedMapping.bin",
        "salt_path": temp_dir / "Salt.bin",
        "temp_dir": temp_dir
    }

def deidentify_interface(file: gr.File, username: str, password: str):
    if username == "":
        return "", None, None, "", "❌ Invalid username"
    
    start_time = time.time()
    try:
        original_name = Path(file.name).name
        base_name = Path(file.name).stem.replace(' ', '_')

        with open(file.name, 'r') as f:
            text = f.read()

        deid_text, phi_map = deidentify_PHI_with_mapping(text)

        temp_dir = Path(tempfile.mkdtemp())
        deid_filename = f"De-Identified_{original_name}"
        deid_temp_path = temp_dir / deid_filename
        deid_temp_path.write_text(deid_text)

        zip_path = None
        if password.strip():
            encrypted_map, salt = encrypt_mapping(phi_map, password)
            zip_path = temp_dir / f"{base_name}_DeidBundle.zip"
            package_zip_to_path(deid_text, encrypted_map, salt, zip_path, original_name)

        execution_time = time.time() - start_time
        
        # Log the request with execution time
        df = pd.read_csv("user_logs.csv")
        new_row = pd.DataFrame([{
            "Username": username,
            "Timestamp": datetime.now(),
            "Action": "De-Identification Request",
            "Filename": file.name.split('/')[-1],
            "Execution Time": f"{execution_time:.2f}"
        }])
        df = pd.concat([df, new_row], ignore_index=True)
        df.to_csv("user_logs.csv", index=False)

        instructions = "⬇ Click the file name or blue text to download. Use the .zip bundle only if re-identification is needed."
        return deid_text, str(deid_temp_path), str(zip_path) if zip_path else None, instructions, f"✅ De-Identification complete! (Execution time: {execution_time:.2f}s)"
    except Exception as e:
        execution_time = time.time() - start_time
        # Log the failed request
        df = pd.read_csv("user_logs.csv")
        new_row = pd.DataFrame([{
            "Username": username,
            "Timestamp": datetime.now(),
            "Action": "De-Identification Request (Failed)",
            "Filename": file.name.split('/')[-1],
            "Execution Time": f"{execution_time:.2f} seconds"
        }])
        df = pd.concat([df, new_row], ignore_index=True)
        df.to_csv("user_logs.csv", index=False)
        return f"❌ Invalid username or password", None, None, "", f"❌ Error: {str(e)} (Execution time: {execution_time:.2f}s)"

def reidentify_interface(zip_file, username, password):
    if username == "":
        return "", None, "❌ Invalid username"
    
    start_time = time.time()
    try:
        paths = extract_zip(Path(zip_file.name))
        deid_text = paths["deid_path"].read_text()
        encrypted_map = paths["mapping_path"].read_bytes()
        salt = paths["salt_path"].read_bytes()

        phi_map = decrypt_mapping(encrypted_map, salt, password)
        reid_text = reidentify_PHI(deid_text, phi_map)

        original_name = Path(paths["deid_path"]).name.replace("De-Identified_", "")
        output_name = f"Re-Identified_{original_name}"
        output_dir = Path(tempfile.mkdtemp())
        output_path = output_dir / output_name
        output_path.write_text(reid_text)

        execution_time = time.time() - start_time
        
        # Log the request with execution time
        df = pd.read_csv("user_logs.csv")
        new_row = pd.DataFrame([{
            "Username": username,
            "Timestamp": datetime.now(),
            "Action": "Re-Identification Request",
            "Filename": (zip_file.name).split('/')[-1],
            "Execution Time": f"{execution_time:.2f}"
        }])
        df = pd.concat([df, new_row], ignore_index=True)
        df.to_csv("user_logs.csv", index=False)

        shutil.rmtree(paths["temp_dir"])
        return reid_text, str(output_path), f"✅ Re-Identification complete! (Execution time: {execution_time:.2f}s)"
    except Exception as e:
        execution_time = time.time() - start_time
        # Log the failed request
        df = pd.read_csv("user_logs.csv")
        new_row = pd.DataFrame([{
            "Username": username,
            "Timestamp": datetime.now(),
            "Action": "Re-Identification Request (Failed)",
            "Filename": (zip_file.name).split('/')[-1],
            "Execution Time": f"{execution_time:.2f}"
        }])
        df = pd.concat([df, new_row], ignore_index=True)
        df.to_csv("user_logs.csv", index=False)
        return f"❌ Invalid username or password", None, f"❌ Error: {str(e)} (Execution time: {execution_time:.2f}s)"

def deidentify_log(name, password):
    #open file containing approved username and password
    with open("approved_users.txt", "r") as f:
        approved_users = f.readlines()
    #check if username and password are in the approved_users list
    if f"{name} {password}" in approved_users:
        #log the request
        df = pd.read_csv("user_logs.csv")
        new_row = pd.DataFrame([{
            "Username": name,
            "Timestamp": datetime.now(),
            "Action": "Logs Request",
            "Filename": "User_Logs.csv",
            "Execution Time": 0.0,
        }])
        df = pd.concat([df, new_row], ignore_index=True)
        df.to_csv("user_logs.csv", index=False)
        return df.to_string(), "user_logs.csv", "✅ Approved user"
    else:
        return f"❌ Invalid username or password", None, None

deid_ui = gr.Interface(
    fn=deidentify_interface,
    inputs=[
        gr.File(label="📄 Upload EHR File"),
        gr.Textbox(label="Identification Name", type="text", placeholder="Enter your Name", value=""),
        gr.Textbox(label="🔐 Set Password (for re-identification if needed)", type="password", placeholder="Leave blank if not needed", value=""),
    ],
    outputs=[
        gr.Textbox(label="📝 De-Identified Text (Preview)", lines=15),
        gr.File(label="⬇ Download De-Identified File (.txt)"),
        gr.File(label="⬇ Download Re-Identifiable Bundle (.zip)"),
        gr.Textbox(label="💡 Instructions"),
        gr.Textbox(label="✅ Status")
    ],
    title="Secure EHR De-Identification",
    description="De-identify an EHR file. Preview the result, download just the de-ID'd text, or get a secure encrypted bundle for re-identification later."
)

reid_ui = gr.Interface(
    fn=reidentify_interface,
    inputs=[
        gr.File(label="📦 Upload De-Identification Bundle (.zip)"),
        gr.Textbox(label="Username", type="text", placeholder="Enter your Username"),
        gr.Textbox(label="🔐 Enter Password", type="password", placeholder="Enter your Password")
    ],
    outputs=[
        gr.Textbox(label="📝 Re-Identified Text (Preview)", lines=15),
        gr.File(label="⬇ Download Re-Identified File"),
        gr.Textbox(label="✅ Status")
    ],
    title="Secure EHR Re-Identification",
    description="Recover original PHI from an encrypted bundle using your password."
)

log_ui = gr.Interface(
    fn=deidentify_log,
    inputs=[
        gr.Textbox(label="Username", type="text", placeholder="Enter your Username"),
        gr.Textbox(label="🔐 Password", type="password", placeholder="Enter your Password")
    ],
    outputs=[
        gr.Textbox(label=" 📝 Log preview", lines=15),
        gr.File(label="⬇ Download Logs"),
        gr.Textbox(label="✅ Status")
    ],
    title="Log file Request",
    description="View the logs of de-identification requests."
)


demo = gr.TabbedInterface([deid_ui, reid_ui, log_ui], ["De-Identify", "Re-Identify", "Log file Request"])

if __name__ == "__main__":
    if not Path("user_logs.csv").exists():
        pd.DataFrame(columns=["Username", "Timestamp", "Action", "Filename", "Execution Time"]).to_csv("user_logs.csv", index=False)
    demo.launch(share=True)
