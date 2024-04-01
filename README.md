# Command Injection - Python Script

Command Injections are part of the OWASP top 10, a vulnerability to know used and understand in the case of web pentest or bug bounty for example.

The script generates payloads that you can test one by one which will be by default encoded at a minimum or at a maximum.
To choose you will need to choose a level, you will see this in the documentation.

**DISCLAIMER**: I decline all responsibility if you use this tool for illegal or unethical purposes!

# Documentation

Install libs: `pip install -r requirements.txt`
Run the script `main.py`

Read the help menu: `main.py -h`

## Levels

Command with the 1st level (default): ```main.py -c 'cat /etc/passwd' -l 1```
- Spaces -> `${IFS}` or `%09`.
- `/` -> ${PATH:0:1}


Command with the 2nd level: ```main.py -c 'cat /etc/passwd' -l 2```
- Execution of level 1
- Add quotes like : `c'a't test`, `g"re"p mysql`.
- Add capital letters / adding special characters, `\ ` (`@$`) (LINUX ONLY) or (`^`) (WINDOWS ONLY): `cAT test`, `gREp mysql`, `gr@$ep mysql`. 


Command with the 3yh level: ```main.py -c 'cat /etc/passwd' -l 3```
- Run level 2
- Encode the command into base64, hex (xxd), rot13.

## Output

You can send the payloads into a file by using `-o` or `--output`: ```main.py -c 'cat /etc/passwd' -l 3 -o file_payloads_cmdinjection```