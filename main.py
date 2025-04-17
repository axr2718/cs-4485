import re
import json
from pathlib import Path
import uuid
from cryptography.fernet import Fernet
import gradio as gr

def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    encrypted_data = fernet.encrypt(file_data)
    
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    
    decrypted_data = fernet.decrypt(encrypted_data)
    
    decrypted_file_path = file_path.replace(".json", "_decrypted.json")
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    return decrypted_file_path

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

def generate_mapping_filename(ehr_file: str, ext: str = 'json') -> str:
    base_name = Path(ehr_file).stem.replace(' ', '_') 
    shortid = uuid.uuid4().hex[:4]
    return f"{base_name}_Mapping_{shortid}.{ext}"

def process_ehr_file(ehr_file, de_identify=True, re_identify=False, mapping_file=None):
    key = generate_key()
    
    with open(ehr_file, 'r') as file:
        text = file.read()

    if de_identify:
        deidentified_text, phi_map = deidentify_PHI_with_mapping(text)

        deidentified_filename = f"De-Identified_{Path(ehr_file).name}"
        with open(deidentified_filename, 'w') as file:
            file.write(deidentified_text)

        if mapping_file is None:
            mapping_file = generate_mapping_filename(ehr_file)

        with open(mapping_file, 'w') as file:
            json.dump(phi_map, file, indent=2)

        encrypt_file(mapping_file, key)

        print(f"De-identification complete. Output saved to {deidentified_filename}")
        print(f"PHI mapping saved to {mapping_file} (encrypted)")

        return deidentified_filename, mapping_file, key

    if re_identify:
        if mapping_file is None:
            raise ValueError("Mapping file is required for re-identification")

        decrypted_mapping_file = decrypt_file(mapping_file, key)

        with open(decrypted_mapping_file, 'r') as file:
            phi_map = json.load(file)

        if not de_identify:
            deidentified_filename = ehr_file
            with open(deidentified_filename, 'r') as file:
                deidentified_text = file.read()

        reidentified_text = reidentify_PHI(deidentified_text, phi_map)

        reidentified_filename = f"Re-Identified_{ehr_file.replace('De-Identified_', '')}"
        with open(reidentified_filename, 'w') as file:
            file.write(reidentified_text)

        Path(decrypted_mapping_file).unlink()
        Path(mapping_file).unlink()
        
        print(f"Re-identification complete. Output saved to {reidentified_filename}")
        print(f"Mapping file {decrypted_mapping_file} and {mapping_file} deleted.")

        return reidentified_filename

def deidentify_interface(file):
    try:
        deidentified_file, _, _ = process_ehr_file(file.name, de_identify=True)
        return deidentified_file, "✅ De-identification successful!"
    except Exception as e:
        return None, f"❌ Error: {str(e)}"

demo = gr.Interface(
    fn=deidentify_interface,
    inputs=gr.File(label="Upload your EHR file"),
    outputs=[gr.File(label="Download De-identified File"), gr.Textbox(label="Status")],
    title="EHR PHI De-identifier",
    description="Upload a file and get a de-identified version with mapped PHI removed."
)

if __name__ == "__main__":
    demo.launch()

