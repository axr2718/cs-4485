# %%
import re

# %%
def deidentify_PHI(text):
    # Patient Name (including various formats)   
    text = re.sub(r'(?i)Patient name:\s*.*?[A-Z][a-z]+ [A-Z][a-z]+', r'Patient name: *name*', text)
    
    # Salutations
    text = re.sub(r'(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s*[A-Z][a-z]+ [A-Z][a-z]+', '*name*', text)
    text = re.sub(r'(?:^|\s)(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s*[A-Z][a-z]+', '*name*', text)
    text = re.sub(r'Ms\.\s*[A-Z][a-z]+', '*name*', text)  # Catch remaining name formats
      
    # Medical Record Number (updated pattern)
    text = re.sub(r'Medical record number:\s*[A-Z0-9\-]+', r'Medical record number: *mrn*', text)
    
    # Provider Name and Details
    text = re.sub(r'Provider name:.*?(?:MD|$)', r'Provider name: *name*, MD', text)
    
    # Address
    text = re.sub(r'Address:\s*.*?(?=\n|$)', 'Address: *address*', text)  # Any remaining addresses
    
    # Hospital Name
    text = re.sub(r'Hospital Name:\s*[A-Za-z\s]+(?=\n|$)', r'Hospital Name: *hospital*', text)
    
    # Dates
    #text = re.sub(r'Date of Birth:\s*(\d{2}/\d{2}/\d{4})', r'Date of Birth: *date*', text)
    text = re.sub(r'\b\d{2}/\d{2}/\d{4}\b', r'*date*', text)
    
    # Social Security Number
    text = re.sub(r'SSN:\s*(?:\d{3}-\d{2}-\d{4}|\*{3}-\*\d-\d{4})', r'SSN: *ssn*', text)
    
    # Phone Numbers
    text = re.sub(r'Phone:\s*(?:\+?1[-\s]?)?\d{3}[-\s]?\d{3}[-\s]?\d{4}', 'Phone: *phone_number*', text) 
    
    # Fax Numbers 
    text = re.sub(r'\b(?:\+?1[-\s]?)?\d{3}[-\s]?\d{3}[-\s]?\d{4}\b', '*fax_number*', text)
    
    # Email Addresses (more comprehensive)
    text = re.sub(r'[Ee]mail:?\s*[\w\.-]+@[\w\.-]+\.\w+', r'Email: *email*', text)
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '*email*', text)  # Catch any remaining email addresses

    # Health Plan beneficiary numbers
    text = re.sub(r'Health plan beneficiary number:\s*[\d\-]+', r'Health plan beneficiary number: *beneficiary*', text, flags=re.IGNORECASE)
    
    # Health Insurance (updated pattern)
    text = re.sub(r'Health Insurance:\s*[A-Z0-9\-]+', r'Health Insurance: *insurance*', text)
        
    # Group Number
    text = re.sub(r'Group no.:\s*[\d\-]+', r'Group no.: *group_number*', text, flags=re.IGNORECASE)
    
    
    # Medicaid Account
    text = re.sub(r'Medicaid account:\s*(\d+(?:\s+\d+)*)', r'Medicaid account: *medicaid*', text)
    
    # Social Worker
    text = re.sub(r'Social worker:\s*(?:Mr\.|Mrs\.|Ms\.|Dr\.)?\s*[A-Z][a-z]+ [A-Z][a-z]+', r'Social worker: *name*', text)

    # Sulfa drugs (e.g., Bactrium)
    text = re.sub(r'-\s*Sulfa drugs\s*\(.*?\)', '*allergy*', text)

    # Morphine
    text = re.sub(r'-\s*Morphine.*?(?=\n|$)', '*allergy*', text, flags=re.IGNORECASE)

    # Account Numbers (updated pattern)
    text = re.sub(r'Account:.*?(?:\d[\d\s]+)(?:\s+\d+)?', r'Account: *account*\n', text)

    # Certificate Numbers (fixed pattern)
    text = re.sub(r'Certificate number:.*?(?=\n|$)', r'Certificate number: *certificate*', text)
    
    # Health Insurance (fixed pattern)
    text = re.sub(r'Health Insurance:.*?(?=\n|$)', r'Health Insurance: *insurance*', text)

    # License Numbers
    text = re.sub(r'license number:\s*[A-Z]{2}\d{2}-\d{6}', r'license number: *license_number*', text)

    # Serial Numbers (more comprehensive)
    text = re.sub(r'(?:[Ss]erial [Nn]umbers?:?\s*|[Ss]erial [Nn]o\.?:?\s*|[A-Za-z]+\s+[Ss]erial\s+[Nn]umbers?:?\s*)[A-Z0-9\-]+', r'Pacemaker serial numbers: *serial_number*', text)
    
    # Fix for standalone codes
    text = re.sub(r'Code:\s*\d+', r'Code: *code*', text)

    # Device Identifiers
    text = re.sub(r'Device identifier:\s*.*?(?=\n|$)', 'Device identifier: *device_identifier*', text, flags=re.IGNORECASE)
    
    # Biometric identifiers
    text = re.sub(r'Biometric:\s*.*?(?=\n|$)', 'Biometric: *biometric_identifier*', text, flags=re.IGNORECASE)
    
    # Lab Results (complete section)
    text = re.sub(r'Lab Results.*?(?=\n\n|\Z)', r'Lab Results: *results*', text, flags=re.DOTALL)
    
    # IP Address
    text = re.sub(r'IP Address:\s*(?:\d{1,3}\.){3}\d{1,3}', r'IP Address: *ip_address*', text)

    # URL
    text = re.sub(r'URL:\s*www?://[^\s]+', r'URL: *url*', text)

    # URL (updated pattern)
    text = re.sub(r'URL:.*?(?=\n|$)', r'URL: *url*', text)
    
    # Lab Results section until Follow-up Appointments
    text = re.sub(
        r'Lab Results:.*?(?=Follow-up Appointments:)',
        r'Lab Results: *results*\n\n',
        text,
        flags=re.DOTALL
    )
    return text


# %%
ehr_file = 'ehr EC 3 .txt'

with open(ehr_file, 'r') as file:
    text = file.read()

with open(f"De-Identified_{ehr_file}", 'w') as file:
    file.write(deidentify_PHI(text))

print(f"De-identification complete. Output saved to De-Identified_{ehr_file}.")

# %%
