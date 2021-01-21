# -*- coding: utf-8 -*-
"""Runs Peloton-to-Garmin.py using encrypted credentials.

This module uses peloton-to-garmin.py, but reads peloton & garmin
credentials encrypted from the configuration file, so that you won't store
credentials in plain-text.

Example:
    To encrypt your credentials and save them to the configuration file:
        1) $ pel2gar -encrypt

        or

        2) $ pel2gar.py -encrypt -pwd MASTER_PASSWORD -email PELOTON_EMAIL
           -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL
           -garmin_password GARMIN_PASSWORD


    To use daily:
        $ pel2gar.py -pwd MASTER_PASSWORD -num 10


Notes:
    1) If running pel2gar.py and no arguments it will ask for encryption info.
    2) It will pass all other arguments to the peloton-to-garmin.py
    3) If -encrypt is not an argument and -emails and -passwords are
       included these will be passed to the peloton-to-garmin.py as-is.

Requires the 'cryptography' package

Works with peloton-to-garmin from Author: Bailey Belvis (
https://github.com/philosowaffle)

Author: Juan Lazarde (01/20/21)
"""

import base64
import sys
from argparse import ArgumentParser
from getpass import getpass
from os import system as run_command
from types import SimpleNamespace as ClearVariables

from cryptography.fernet import Fernet

from lib import config_helper as config

VERSION = 0.1
CONFIG_FILE = 'config.ini'
DEBUG = False


class ReadArguments:
    """Arguments to be passed to Peloton-to-garmin.py and to apply here"""
    master_password = None
    peloton_email, peloton_password = None, None
    garmin_email, garmin_password = None, None
    do_encrypt = False
    pass_through = ""

    def __init__(self):
        arg = ClearVariables(master_password=None, output_dir=None, num_to_download=None, log_level=None,
                             log_file=None, email=None, password=None, garmin_email=None, garmin_password=None,
                             do_encrypt=False)

        if len(sys.argv) > 1:
            arg = self.load_arguments()
            self.do_encrypt = arg.do_encrypt

        self.load_master_password(arg)
        self.load_pass_through(arg)
        self.load_credentials(arg)

    @staticmethod
    def load_arguments():
        """Function that returns all arguments from the pel2gar.py command line.
        Update this section with Configuration within configuration.py from Peloton-to-Garmin.py"""
        arg = ArgumentParser()

        arg.add_argument("-email", help="Peloton email address for download", dest="email", type=str)
        arg.add_argument("-password", help="Peloton password for download", dest="password", type=str)
        arg.add_argument("-garmin_email", help="Garmin email for upload", dest="garmin_email", type=str)
        arg.add_argument("-garmin_password", help="Garmin password for upload", dest="garmin_password", type=str)
        arg.add_argument("-path", help="Path to output directory", dest="output_dir", type=str)
        arg.add_argument("-num", help="Number of activities to download", dest="num_to_download", type=str)
        arg.add_argument("-log", help="Log file name", dest="log_file", type=str)
        arg.add_argument("-loglevel", help="[DEBUG, INFO, ERROR]", dest="log_level", type=str)

        # Needed to operate pel2gar
        arg.add_argument("-pwd", help="Master password to decrypt credentials", dest="master_password", type=str)
        arg.add_argument("-encrypt", help="Encrypt Peloton & Garmin credential", dest="do_encrypt", action="store_true")

        return arg.parse_args()

    def load_master_password(self, arg):
        """Encode pel2gar password to be used as encryption/decryption key"""
        pwd = arg.master_password

        has_password = pwd is not None
        has_encrypt = arg.do_encrypt
        has_credentials = arg.email is not None and arg.password is not None and \
                          arg.garmin_email is not None and arg.garmin_password is not None

        # Skip when we're just serving the pass through to peloton-to-garmin.py
        skip = not has_password and not has_encrypt and has_credentials

        if not skip:
            while pwd == '' or pwd is None or len(pwd) > 32:
                pwd = input("\nEnter your pel2gar password: ").strip()

            _ascii = pwd + "0" * (32 - len(pwd))
            _bytes = _ascii.encode('ascii')
            self.master_password = base64.urlsafe_b64encode(_bytes)

    def load_pass_through(self, arg):
        """Builds string of arguments passed through to peloton-to-garmin.py"""
        chain = []

        if arg.output_dir is not None:
            chain.append("-path " + arg.output_dir)
        if arg.num_to_download is not None:
            chain.append("-num " + arg.num_to_download)
        if arg.log_file is not None:
            chain.append("-log " + arg.log_file)
        if arg.log_level is not None:
            chain.append("-loglevel " + arg.log_level)

        self.pass_through = ' '.join(chain)

    def load_credentials(self, arg):
        """Loads credentials from commandline or config.ini
        Overrides credentials from config.ini with commandline"""

        # Assign credentials from arguments in command line
        self.peloton_email = arg.email
        self.peloton_password = arg.password
        self.garmin_email = arg.garmin_email
        self.garmin_password = arg.garmin_password

        if self.master_password is not None and not self.do_encrypt:
            # Load credentials from config.ini and decrypt
            crypto = Encryption(self.master_password)
            try:
                if self.peloton_email is None:
                    cred = config.ConfigSectionMap("PELOTON").get('email')
                    self.peloton_email = crypto.decrypt(cred)
                if self.peloton_password is None:
                    cred = config.ConfigSectionMap("PELOTON").get('password')
                    self.peloton_password = crypto.decrypt(cred)
                if self.garmin_email is None:
                    cred = config.ConfigSectionMap("GARMIN").get('email')
                    self.garmin_email = crypto.decrypt(cred)
                if self.garmin_password is None:
                    cred = config.ConfigSectionMap("GARMIN").get('password')
                    self.garmin_password = crypto.decrypt(cred)
            except Exception as err:
                sys.exit("\nError reading credentials."
                         "\nCheck the password."
                         "\nFORGOT PASSWORD? Type 'pel2gar.py -encrypt'" + str(err))

            # Exit if credentials are still missing
            if self.peloton_email is None or self.peloton_email.strip() == '' or \
                    self.peloton_password is None or self.peloton_password.strip() == '':
                sys.exit("\nPELOTON credential missing")
            if self.garmin_email is None or self.garmin_email.strip() == '' or \
                    self.garmin_password is None or self.garmin_password.strip() == '':
                sys.exit("\nGARMIN credential missing")


class Encryption:
    """Encryption process using 'cryptography' package."""
    cipher_suite = None

    def __init__(self, key):
        self.cipher_suite = Fernet(key)

    def encrypt(self, text: str):
        """Encode text using master password."""
        _byte = text.encode('ascii')
        encoded_text = self.cipher_suite.encrypt(_byte)
        return encoded_text

    def decrypt(self, text: str):
        """Decode text using master password."""
        _byte = text.encode('ascii')
        decoded_text = self.cipher_suite.decrypt(_byte)
        decoded_text = decoded_text.decode('ascii')
        return decoded_text


class SaveCredentials:
    """"Credential encryption and inclusion in saved to config.ini"""
    credentials = None

    def __init__(self, arg):
        # Run this if -encrypt flag is on
        if arg.do_encrypt:
            print("\nWill not save any plain text information."
                  "\nRemember this password."
                  "\nEncrypted credentials will be appended to '" + CONFIG_FILE + "'\n")

            # Assign default credential values from config.ini or command line
            peloton_email = arg.peloton_email
            peloton_password = arg.peloton_password
            garmin_email = arg.garmin_email
            garmin_password = arg.garmin_password

            # Ask for those credentials missing
            if peloton_email is None:
                peloton_email = input("Enter PELOTON email: ").strip()
            if peloton_password is None:
                peloton_password = getpass("Enter PELOTON password: ").strip()
            if garmin_email is None:
                garmin_email = input("Enter GARMIN email [Leave blank for: {}]:".format(peloton_email)).strip()
                garmin_email = peloton_email if garmin_email == '' else garmin_email
            if garmin_password is None:
                garmin_password = getpass("Enter GARMIN password: ").strip()

            # Encrypt credentials and decode to ascii for ConfigParse compatibility
            crypto = Encryption(arg.master_password)
            peloton_email_encrypted = crypto.encrypt(peloton_email).decode('ascii')
            peloton_password_encrypted = crypto.encrypt(peloton_password).decode('ascii')
            garmin_email_encrypted = crypto.encrypt(garmin_email).decode('ascii')
            garmin_password_encrypted = crypto.encrypt(garmin_password).decode('ascii')

            # Dictionary with encrypted credentials is passed to function that saves it to config.ini
            encrypted_credentials = {'peloton_email': peloton_email_encrypted,
                                     'peloton_password': peloton_password_encrypted,
                                     'garmin_email': garmin_email_encrypted,
                                     'garmin_password': garmin_password_encrypted}
            self.save_to_config(encrypted_credentials)

            # Update credentials to be passed on to peloton-to-garmin.py
            self.credentials = arg
            self.credentials.peloton_email = peloton_email
            self.credentials.peloton_password = peloton_password
            self.credentials.garmin_email = garmin_email
            self.credentials.garmin_password = garmin_password

    @staticmethod
    def save_to_config(item):
        """Save credentials to config.ini"""
        try:
            config.Config["PELOTON"]['email'] = item['peloton_email']
            config.Config["PELOTON"]['password'] = item['peloton_password']
            config.Config["GARMIN"]['email'] = item['garmin_email']
            config.Config["GARMIN"]['password'] = item['garmin_password']
            with open(CONFIG_FILE, 'w') as configfile:
                config.Config.write(configfile)

            print("\nCredentials encrypted and saved to '" + CONFIG_FILE + "'")
        except FileNotFoundError:
            print("\nError '" + CONFIG_FILE + "' not found, please check the file's location")
        except Exception as err:
            print("\nSomething went wrong while saving to '" + CONFIG_FILE + "'."
                                                                             "\nERROR: {}".format(err))


class RunPelotonToGarmin:
    """Finally we run peloton-to-garmin using plain text credentials"""

    def __init__(self, arg):
        command = 'python peloton-to-garmin.py'
        command += " -email " + arg.peloton_email \
                   + " -password " + arg.peloton_password \
                   + " -garmin_email " + arg.garmin_email \
                   + " -garmin_password " + arg.garmin_password
        command += " " + arg.pass_through

        try:
            print(command) if DEBUG else run_command(command.strip())
        except Exception as e:
            print("Problem executing peloton-to-garmin. Check file location or changes to code")


##############################
# Program Starts Here
##############################
if __name__ == "__main__":
    arguments = ReadArguments()
    updated = SaveCredentials(arguments)
    arguments = updated.credentials if updated.credentials is not None else arguments
    RunPelotonToGarmin(arguments)

'''
Scenarios tested successfully
1	pel2gar.py
2	pel2gar.py -encrypt
3	pel2gar.py -encrypt -pwd 123 -email PELOTON_EMAIL -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD
4	pel2gar.py -encrypt -pwd 123 -email PELOTON_EMAIL -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD -num 20 -path OUTPUT
5	pel2gar.py -encrypt -email PELOTON_EMAIL -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD
6	pel2gar.py -encrypt -pwd 123 -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD
7	pel2gar.py -pwd 123
8	pel2gar.py -pwd 123 -email PELOTON_EMAIL -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD
9	pel2gar.py -pwd 123 -email PELOTON_EMAIL 
10	pel2gar.py -pwd 123 -num 20
11	pel2gar.py -pwd svgsdfsds
12	pel2gar.py -email PELOTON_EMAIL -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD
13	Encrypt misspelled
'''
