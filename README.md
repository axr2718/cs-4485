# EHR De-Identification Tool

## 📌 Description
This application enables users to de-identify text files containing Protected Health Information (PHI) efficiently and securely. It reads a given PHI-containing file, processes the text to remove or anonymize identifiable information (as specified in PHI.txt), and saves a de-identified version in the same directory. It also allows for re-identification of the de-identified file.

## 🛠 How to Use

Follow these steps to use the EHR De-Identification tool:

### 1. Download the Script
Download the `main.py` file to a local directory on your computer.

### 2. Prepare Your PHI File
Place the PHI text file you want to de-identify in the same directory as `main.py`.

### 3. Specify the PHI File Name
1. Open `main.py` in a text editor or Python IDE.
2. Locate the following line of code:
   ```python
   ehr_file = 'ehr JMS.txt'
   ```
3. Replace `'ehr JMS.txt'` with the name of your PHI file.

The function `process_ehr_file` takes the parameters `de_identify`, `re-identify` and `mapping_file` to handle which operation the user wants to do. To de-identify, simply set `de_identify=True`. To re-identify, note that you will first need to generate a mapping file by setting `de_identify=True`, then passing this mapping along with `re_identify=True` in the function.

### 4. Navigate to the Directory
1. Open Terminal (Mac/Linux) or Command Prompt (Windows).
2. Use the `cd` command to navigate to the directory containing `main.py` and your PHI file. For example:
   ```sh
   cd /path/to/your/directory
   ```

### 5. Run the Script
Type the following command and press Enter:
```sh
python3 main.py
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
- For accurate results, ensure your PHI file is clearly formatted and PHI terms in the PHI.txt file are up-to-date and accurate. 
