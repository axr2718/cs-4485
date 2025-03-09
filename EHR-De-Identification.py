# %%
import re

# %%
def deidentify_PHI(text):
    # For Full Name
    text = re.sub(r'Patient:\s*([A-Z][a-z]+ [A-Z][a-z]+)', r'Patient: *name*', text)
    
    # For Provider Name
    text = re.sub(r'Provider:\s*Dr\.\s*([A-Z][a-z]+ [A-Z][a-z]+),\s*MD', r'Provider: Dr. *name*, MD', text)
    
    # For Salutations/Titles
    text = re.sub(r'\b(Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z][a-z]+\b', '*name*', text)
    
    # For Address
    text = re.sub(r'Address:\s*([\d\w\s,\.]+\d{5})', r'Address: *address*', text)
    
    # For DOB
    text = re.sub(r'Date of Birth:\s*(\d{2}/\d{2}/\d{4})', r'Date of Birth: *dob*', text)
    
    # For Medical Record Number
    text = re.sub(r'Medical Record Number:\s*(\d+)', r'Medical Record Number: *ssn*', text)
    
    # For Phone Number
    text = re.sub(r'Phone:\s*(\d{3}-\d{3}-\d{4})', r'Phone: *phone*', text)
    
    # For Email
    text = re.sub(r'email:\s*([\w\.-]+@[\w\.-]+\.\w+)', r'email: *email*', text)
    
    return text


# %%
ehr_file = 'ehr JMS.txt'

with open(ehr_file, 'r') as file:
    text = file.read()

with open(f"De-Identified_{ehr_file}", 'w') as file:
    file.write(deidentify_PHI(text))

print(f"De-identification complete. Output saved to De-Identified_{ehr_file}.")

# %%
