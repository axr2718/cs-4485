# EHR De-Identification Tool

## 📌 Description
This application enables users to de-identify text files containing Protected Health Information (PHI) efficiently and securely. It reads a given PHI-containing file, processes the text to remove or anonymize identifiable information (as specified in PHI.txt), and saves a de-identified version in the same directory.

## 🛠 How to Use

Follow these steps to use the EHR De-Identification tool:

### 1. Download the Script
Download the `EHR-De-Identification.py` file to a local directory on your computer.

### 2. Prepare Your PHI File
Place the PHI text file you want to de-identify in the same directory as `EHR-De-Identification.py`.

### 3. Specify the PHI File Name
1. Open `EHR-De-Identification.py` in a text editor or Python IDE.
2. Locate the following line of code:
   ```python
   ehr_file = 'ehr JMS.txt'
   ```
3. Replace `'ehr JMS.txt'` with the name of your PHI file.
4. Save the file after making the change.

### 4. Navigate to the Directory
1. Open Terminal (Mac/Linux) or Command Prompt (Windows).
2. Use the `cd` command to navigate to the directory containing `EHR-De-Identification.py` and your PHI file. For example:
   ```sh
   cd /path/to/your/directory
   ```

### 5. Run the Script
Type the following command and press Enter:
```sh
python3 EHR-De-Identification.py
```

### 6. Retrieve the De-Identified File
1. Once the script finishes running, the de-identified file will be saved in the same directory.
2. The output file will follow this naming format:
   ```
   De-Identified_PHIFileName.txt
   ```
3. For example, if your original file was `ehr JMS.txt`, the de-identified file will be named `De-Identified_ehr JMS.txt`.

## Notes
- Ensure you have Python 3 installed on your system.
- Double-check file names and paths to avoid errors.
- Consider making a backup of your original file before running the script.
- To confirm the script is running, open the de-identified file and verify PHI has been replaced. 
