# %%
import re
import json
import os
from datetime import datetime

# %%
def deidentify_PHI_with_mapping(text):
    # mapping between the replaced and the original text
    phi_map = {}
    
    def replace_and_map(pattern, replacement_template, key, text, flags=0):
        matches = []
        
        def replace_func(match):
            original = match.group(0)
            matches.append(original)
            if isinstance(replacement_template, str):
                return replacement_template
            else:
                return replacement_template(original)
        
        new_text = re.sub(pattern, replace_func, text, flags=flags)
        
        if matches:
            if key in phi_map and isinstance(phi_map[key], list):
                phi_map[key].extend(matches)
            else:
                phi_map[key] = matches if len(matches) > 1 else matches[0]
                
        return new_text
    
    # Patient Name (including various formats)   
    text = replace_and_map(r'(?i)Patient name:\s*.*?[A-Z][a-z]+ [A-Z][a-z]+', 
                           r'Patient name: *name*', 
                           'name', 
                           text)
    
    # Salutations
    text = replace_and_map(r'(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s*[A-Z][a-z]+ [A-Z][a-z]+', 
                           '*name*', 
                           'name', 
                           text)
    
    text = replace_and_map(r'(?:^|\s)(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s*[A-Z][a-z]+', 
                           '*name*', 
                           'name', 
                           text)
    
    text = replace_and_map(r'Ms\.\s*[A-Z][a-z]+', 
                           '*name*', 
                           'name', 
                           text)
      
    # Medical Record Number
    text = replace_and_map(r'Medical record number:\s*[A-Z0-9\-]+', 
                           r'Medical record number: *mrn*', 
                           'mrn', 
                           text)
    
    # Provider Name and Details
    text = replace_and_map(r'Provider name:.*?(?:MD|$)', 
                           r'Provider name: *name*, MD', 
                           'provider_name', 
                           text)
    
    text = replace_and_map(r'Provider:\s*(?:Dr\.)?\s*[A-Z][a-z]+ [A-Z][a-z]+,\s*MD', 
                           r'Provider: *name*, MD', 
                           'provider_name', 
                           text)
    
    # Address
    text = replace_and_map(r'Address:\s*.*?(?=\n|$)', 
                           'Address: *address*', 
                           'address', 
                           text)
    
    # Hospital Name
    text = replace_and_map(r'Hospital Name:\s*[A-Za-z\s]+(?=\n|$)', 
                           r'Hospital Name: *hospital*', 
                           'hospital', 
                           text)
    
    # Dates
    text = replace_and_map(r'\b\d{2}/\d{2}/\d{4}\b', 
                           r'*date*', 
                           'date', 
                           text)
    
    # Social Security Number
    text = replace_and_map(r'SSN:\s*(?:\d{3}-\d{2}-\d{4}|\*{3}-\*\d-\d{4})', 
                           r'SSN: *ssn*', 
                           'ssn', 
                           text)
    
    # Phone Numbers
    text = replace_and_map(r'Phone:\s*(?:\+?1[-\s]?)?\d{3}[-\s]?\d{3}[-\s]?\d{4}', 
                           'Phone: *phone_number*', 
                           'phone_number', 
                           text)
    
    # Fax Numbers 
    text = replace_and_map(r'Fax number:\s*(?:\+?1[-\s]?)?\d{3}[-\s]?\d{3}[-\s]?\d{4}', 
                           'Fax number: *fax_number*', 
                           'fax_number', 
                           text)
    
    text = replace_and_map(r'Fax no\.:\s*(?:\+?1[-\s]?)?\d{3}[-\s]?\d{3}[-\s]?\d{4}', 
                           'Fax no.: *fax_number*', 
                           'fax_number', 
                           text)
    
    text = replace_and_map(r'Fax\.:\s*(?:\+?1[-\s]?)?\d{3}[-\s]?\d{3}[-\s]?\d{4}', 
                           'Fax no.: *fax_number*', 
                           'fax_number', 
                           text)
    
    # Email Addresses
    text = replace_and_map(r'[Ee]mail:?\s*[\w\.-]+@[\w\.-]+\.\w+', 
                           r'Email: *email*', 
                           'email', 
                           text)
    
    text = replace_and_map(r'[\w\.-]+@[\w\.-]+\.\w+', 
                           '*email*', 
                           'email', 
                           text)

    # Health Plan beneficiary numbers
    text = replace_and_map(r'Health plan beneficiary number:\s*[\d\-]+', 
                           r'Health plan beneficiary number: *beneficiary*', 
                           'beneficiary', 
                           text, 
                           flags=re.IGNORECASE)
    
    # Health Insurance
    text = replace_and_map(r'Health Insurance:\s*[A-Z0-9\-]+', 
                           r'Health Insurance: *insurance*', 
                           'insurance', 
                           text)
        
    # Group Number
    text = replace_and_map(r'Group no\.:\s*[\d\-]+', 
                           r'Group no.: *group_number*', 
                           'group_number', 
                           text, 
                           flags=re.IGNORECASE)
    
    # Medicaid Account
    text = replace_and_map(r'Medicaid account:\s*(\d+(?:\s+\d+)*)', 
                           r'Medicaid account: *medicaid*', '' \
                           'medicaid', 
                           text)
    
    # Social Worker
    text = replace_and_map(r'Social worker:\s*(?:Mr\.|Mrs\.|Ms\.|Dr\.)?\s*[A-Z][a-z]+ [A-Z][a-z]+', 
                           r'Social worker: *name*', 
                           'social_worker_name', 
                           text)

    # Account Numbers
    text = replace_and_map(r'Account:\s*[\d\s]+', 
                           r'Account: *account*', 
                           'account', 
                           text)

    # Certificate Numbers
    text = replace_and_map(r'Certificate number:.*?(?=\n|$)', 
                           r'Certificate number: *certificate*', 
                           'certificate', 
                           text)
    
    # License Numbers
    text = replace_and_map(r'license number:\s*[A-Z]{2}\d{2}-\d{6}', 
                           r'license number: *license_number*', 
                           'license_number', 
                           text)

    # Serial Numbers
    text = replace_and_map(r'Pacemaker serial numbers:[A-Z0-9\-]+', 
                           r'Pacemaker serial numbers: *serial_number*', 
                           'serial_number', 
                           text)
    
    # Device Identifiers
    text = replace_and_map(r'Device identifier:[A-Z0-9\-]+', 
                           'Device identifier: *device_identifier*', 
                           'device_identifier', 
                           text)
    
    # Biometric identifiers
    text = replace_and_map(r'Biometric:.*?(?=\n|$)', 
                           'Biometric: *biometric_identifier*', 
                           'biometric_identifier', 
                           text)
    
    # Lab Results
    text = replace_and_map(r'Lab Results.*?(?=Follow-up Appointments:)', 
                           r'Lab Results: *results*\n\n', 
                           'lab_results', 
                           text, 
                           flags=re.DOTALL)
    
    # Codes
    text = replace_and_map(r'Code:\d+', 
                           r'Code: *code*', 
                           'code', 
                           text)
    
    # URL
    text = replace_and_map(r'URL:.*?(?=\n|$)', 
                           r'URL: *url*', 
                           'url', 
                           text)
    
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

def process_ehr_file(ehr_file, de_identify=True, re_identify=False, mapping_file=None):
    with open(ehr_file, 'r') as file:
        text = file.read()
    
    if de_identify:
        deidentified_text, phi_map = deidentify_PHI_with_mapping(text)
        
        deidentified_filename = f"De-Identified_{ehr_file}"
        with open(deidentified_filename, 'w') as file:
            file.write(deidentified_text)
        
        if mapping_file is None:
            mapping_file = f"mapping_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(mapping_file, 'w') as file:
            json.dump(phi_map, file, indent=2)
        
        print(f"De-identification complete. Output saved to {deidentified_filename}")
        print(f"PHI mapping saved to {mapping_file}")
        
        return deidentified_filename, mapping_file
    
    if re_identify:
        if mapping_file is None:
            raise ValueError("Mapping file is required for re-identification")
        
        with open(mapping_file, 'r') as file:
            phi_map = json.load(file)
        
        if not de_identify:
            deidentified_filename = ehr_file
            with open(deidentified_filename, 'r') as file:
                deidentified_text = file.read()
        
        # Re-identify
        reidentified_text = reidentify_PHI(deidentified_text, phi_map)
        
        reidentified_filename = f"Re-Identified_{ehr_file.replace('De-Identified_', '')}"
        with open(reidentified_filename, 'w') as file:
            file.write(reidentified_text)
        
        print(f"Re-identification complete. Output saved to {reidentified_filename}")
        
        return reidentified_filename

# %%
if __name__ == "__main__":
    ehr_file = 'ehr EC 3 .txt'
    
    deidentified_file, mapping_file = process_ehr_file(ehr_file, de_identify=True)
    
    process_ehr_file(deidentified_file, de_identify=False, re_identify=True, mapping_file=mapping_file)
    
# %%
