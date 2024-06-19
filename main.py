from auth import Auth
from commandsCLI import errDisable
from log import logConfiguration
import os
import logging.config
from strings import menuString, greetingString, inputErrorString
from utils import mkdir
from functions import checkIsDigit

def main():    
    mkdir()
    os.system("CLS")
    greetingString()
    logging.config.dictConfig(logConfiguration)
    authLog = logging.getLogger('infoLog')
    validIPs, username, netDevice = Auth()

    while True:
        menuString(validIPs, username), print("\n")
        selection = input("Please choose the option that yyou want: ")
        if checkIsDigit(selection):
            if selection == "1":
                # This option will fix errDisable interfaces
                errDisable(validIPs, username, netDevice)
            if selection == "2":
                authLog.info(f"User {username} disconnected from the devices {validIPs}")
                authLog.info(f"User {username} logged out from the program.")
                break
        else:
            authLog.error(f"Wrong option chosen {selection}")
            inputErrorString()
            os.system("PAUSE")

if __name__ == "__main__":
    main()