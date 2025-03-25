# %%
import re

# %%
def deidentify_PHI(text):
    # Patient Name (including various formats)
    text = re.sub(r'Patient name:\s*([A-Z][a-z]+ [A-Z][a-z]+)', r'Patient name: *name*', text)
    text = re.sub(r'(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s*[A-Z][a-z]+ [A-Z][a-z]+', '*name*', text)
    text = re.sub(r'(?:^|\s)(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s*[A-Z][a-z]+', '*name*', text)
    text = re.sub(r'Ms\.\s*[A-Z][a-z]+', '*name*', text)  # Catch remaining name formats
    
    # Provider Name and Details
    text = re.sub(r'Provider name:\s*(?:Dr\.)?\s*[A-Z][a-z]+ [A-Z][a-z]+,?\s*(?:MD)?', r'Provider name: *name*, MD', text)
    
    # Hospital Name and Address
    text = re.sub(r'Hospital name:\s*([A-Za-z0-9\s]+)', r'Hospital name: *hospital*', text)
    text = re.sub(r'(?<=Hospital name: \*hospital\*):?\s*.*?(?=\n|$)', '', text)  # Remove hospital address
    text = re.sub(r'Address:\s*.*?(?=\n|$)', 'Address: *address*', text)  # Any remaining addresses
    
    # Date of Birth only
    text = re.sub(r'(?:Date of Birth|DoB):\s*\d{2}/\d{2}/\d{4}', r'DoB: *dob*', text)
    
    # Social Security Number
    text = re.sub(r'SSN:\s*(?:\d{3}-\d{2}-\d{4}|\*{3}-\*\d-\d{4})', r'SSN: *ssn*', text)
    
    # Phone Numbers (more comprehensive)
    text = re.sub(r'Phone:\s*(?:\+?1[-\s]?)?\d{3}[-\s]?\d{3}[-\s]?\d{4}', r'Phone: *phone*', text)
    text = re.sub(r'\d{3}-\d{3}-\d{4}', '*phone*', text)  # Catch any remaining phone numbers
    
    # Email Addresses (more comprehensive)
    text = re.sub(r'[Ee]mail:?\s*[\w\.-]+@[\w\.-]+\.\w+', r'Email: *email*', text)
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '*email*', text)  # Catch any remaining email addresses
    
    # Medicaid Account
    text = re.sub(r'Medicaid account:\s*(\d+(?:\s+\d+)*)', r'Medicaid account: *medicaid*', text)
    
    # Social Worker
    text = re.sub(r'Social worker:\s*(?:Mr\.|Mrs\.|Ms\.|Dr\.)?\s*[A-Z][a-z]+ [A-Z][a-z]+', r'Social worker: *name*', text)
    
    # Allergies (complete section)
    text = re.sub(r'Allergies:(?:\s*-[^\n]+\n?)*', 'Allergies: *allergies*\n', text)
    
    # Lab Results (complete section)
    text = re.sub(r'Lab Results.*?(?=\n\n|\Z)', r'Lab Results: *results*', text, flags=re.DOTALL)
    
    # Replace gender-specific pronouns with "they"
    text = re.sub(r'\b(She|He)\b', 'They', text)
    text = re.sub(r'\b(she|he)\b', 'they', text)

    return text


# %%
ehr_file = 'ehr_MH_2.txt'

with open(ehr_file, 'r') as file:
    text = file.read()

with open(f"De-Identified_{ehr_file}", 'w') as file:
    file.write(deidentify_PHI(text))

print(f"De-identification complete. Output saved to De-Identified_{ehr_file}.")

# %%
