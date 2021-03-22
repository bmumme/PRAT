# P.R.A.T.
Password Recovery Analysis Tool

### Overview:
Currently, PRAT is a script for a very specific use-case - The analysis of "recovered" (Some like referring to passwords as "recovered" rather than "cracked" so I leave "recover" in quotations as a subtle protest against this, its just cracked passwords) passwords from an Active Directory Environment. This is useful for penetration testers looking for an automated and meaningful way to educate clients about the overall password hygene of their environment. As well as illustrate the impact of obtaining DA access during an assessment. Also, this tool can be used by any IT/Security professional who is looking for insights into the makeup of their organization's password strength. 

Utilizing DA credentials and secretsdump.py, remotely dump the domain password hashes. Next, leverage Hashcat to "recover" passwords. Take the Hashcat output and the dumped password hashes (secretsdump.py ouptut) and run PRAT.py. 

### Disclaimer:
Ultimately, this tool relies on "recovered" passwords and does not obscure these passwords. Users and their **cleartext** passwords will be listed in the final Excel output. Also, this tool is only for those who have permission to be snooping around Domain Controllers.

### Inputs:
This script requires the two files as inputs
- TXT file of Hashcat output (.pot file)
- TXT file of the secretsdump.py output

### Instructions: 
`python3 prat.py -m 2 -i hashcatoutput.txt -s secretsdumpoutput.txt -o nameofworkbook.xlsx`

- -m - Choose the mode of analysis 
     1. Option 1: This mode will analyze password compliance based on if password contains a special character, a number, an upper and lower case letter, and is at least 8 characters 
     2. Option 2: This mode is the custom mode. This will enable you to specify what types of requirements the password is required to have. (e.g., Is the password required to have special characters?) RECOMMENDED
     3. Option 3: This options is useful for specifying how many requirments out of the four standard requirements the password must have. (e.g., three our of four requirements must be met and the password must be n characters long.)

- -i TXT file of Hashcat output (.pot file)
- -s TXT file of the secretsdump output
- -o Name of the EXCEL file for final results
- -a Optional: You can supply a CSV of active AD usernames and only results for active users will be returned
- Note: You will be prompted to answer questions while the script is running about password requirements and analysis options. For example, you can query the HaveIBeenPwnded API to identify if that specific cleartext password has been assocaited with a breach, indicating the password is likely to be in a password list used in brute force attacks.

### Links:
[Impacket / Secretsdump.py](https://github.com/SecureAuthCorp/impacket)

[Hashcat](https://hashcat.net/hashcat/)


