# %%
import re

# %%
def deidentify_PHI(text):
    # Patient Name (including various formats)
    text = re.sub(r'Patient name:.*?([A-Z][a-z]+ [A-Z][a-z]+)', r'Patient name: *name*', text)
    text = re.sub(r'Patient name:\s*\*name\*\s*[A-Z][a-z]+ [A-Z][a-z]+', r'Patient name: *name*', text)
    text = re.sub(r'(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s*[A-Z][a-z]+ [A-Z][a-z]+', '*name*', text)
    text = re.sub(r'(?:^|\s)(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s*[A-Z][a-z]+', '*name*', text)
    text = re.sub(r'Ms\.\s*[A-Z][a-z]+', '*name*', text)  # Catch remaining name formats
    
    # Remove lines containing "Name"
    text = re.sub(r'Name:.*?$', r'Name: *name*', text)
    
    # Medical Record Number
    text = re.sub(r'Medical Record Number:\s*\d+', r'Medical Record Number: *mrn*', text)
    
    # Provider Name and Details
    text = re.sub(r'Provider name:.*?(?:MD|$)', r'Provider name: *name*, MD', text)
    
    # Hospital Name and Address
    text = re.sub(r'Hospital name:\s*([A-Za-z0-9\s]+)', r'Hospital name: *hospital*', text)
    text = re.sub(r'(?<=Hospital name: \*hospital\*):?\s*.*?(?=\n|$)', '', text)  # Remove hospital address
    text = re.sub(r'Address:\s*.*?(?=\n|$)', 'Address: *address*', text)  # Any remaining addresses
    
    # Date of Birth only
    text = re.sub(r'(?:Date of Birth|DoB):\s*\d{2}/\d{2}/\d{4}', r'DoB: *dob*', text)
    
    # Social Security Number
    text = re.sub(r'SSN:\s*(?:\d{3}-\d{2}-\d{4}|\*{3}-\*\d-\d{4})', r'SSN: *ssn*', text)
    
    # Phone Numbers (more comprehensive)
    text = re.sub(r'Phone:\s*(?:\+?1[-\s]?)?\d{3}[-\s]?\d{3}[-\s]?\d{4}', 'Phone: *phone*', text) #replace phone numbers with "Phone" label
    text = re.sub(r'\b(?:\+?1[-\s]?)?\d{3}[-\s]?\d{3}[-\s]?\d{4}\b', '*phone*', text) #replace phone numbers without label
    
    # Fax Numbers 
    text = re.sub(r'Fax number:\s*(?:\+?1[-\s]?)?\d{3}[-\s]?\d{3}[-\s]?\d{4}', 'Fax number: *fax*', text) #replace fax numbers with "Fax" label 
    
    # Email Addresses (more comprehensive)
    text = re.sub(r'[Ee]mail:?\s*[\w\.-]+@[\w\.-]+\.\w+', r'Email: *email*', text)
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '*email*', text)  # Catch any remaining email addresses

    # Health Plan beneficiary numbers
    text = re.sub(r'Health plan beneficiary number:\s*[\d\-]+', r'Health plan beneficiary number: *beneficiary*', text, flags=re.IGNORECASE)
    
    # Account Numbers
    text = re.sub(r'Account:\s*\d+', r'Account: *account*', text)
    
    # Medicaid Account
    text = re.sub(r'Medicaid account:\s*(\d+(?:\s+\d+)*)', r'Medicaid account: *medicaid*', text)
    
    # Social Worker
    text = re.sub(r'Social worker:\s*(?:Mr\.|Mrs\.|Ms\.|Dr\.)?\s*[A-Z][a-z]+ [A-Z][a-z]+', r'Social worker: *name*', text)

    # Sulfa drugs (e.g., Bactrium)
    text = re.sub(r'-\s*Sulfa drugs\s*\(.*?\)', '*allergy*', text)

    # Morphine
    text = re.sub(r'-\s*Morphine.*?(?=\n|$)', '*allergy*', text, flags=re.IGNORECASE)

    # Certificate Numbers
    text = re.sub(r'Certificate number:\s*\d+', r'Certificate number: *certificate_number*', text)
    
    # License Numbers
    text = re.sub(r'License number:\s*\d+', r'License number: *license_number*', text)

    # Serial Numbers
    text = re.sub(r'Serial number:\s*\d+', r'Serial number: *serial_number*', text)
    
    # Lab Results (complete section)
    text = re.sub(r'Lab Results.*?(?=\n\n|\Z)', r'Lab Results: *results*', text, flags=re.DOTALL)

    return text


# %%
ehr_file = 'ehr EC 3 .txt'

with open(ehr_file, 'r') as file:
    text = file.read()

with open(f"De-Identified_{ehr_file}", 'w') as file:
    file.write(deidentify_PHI(text))

print(f"De-identification complete. Output saved to De-Identified_{ehr_file}.")

# %%
