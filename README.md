# pel2gar 

#### _#Pel2Gar_

Aides peloton-to-garmin.py with encrypted credentials. It reads peloton & garmin
credentials encrypted from the configuration file, so that you won't store
credentials in plain-text.

peloton-to-garmin converts workout data from Peloton into a TCX file that can be uploaded to Garmin.
* Fetch latest workouts from Peloton
* Convert Peloton workout to TCX file
* Upload TCX workout to Garmin
* Maintain Upload History to avoid duplicates in Garmin
* Author: Bailey Belvis (https://github.com/philosowaffle)

Instead of typing Peloton and Garmin login information as plain text and/or saving it to config file. With pel2gar you can encrypt this information so that no one can read it. 

## Quick Start

1. Find the latest peloton-to-garmin release [here](https://github.com/philosowaffle/peloton-to-garmin/releases)
1. Find the latest pel2gar release [here](https://github.com/juanlazarde/pel2gar/releases)
1. Install pel2gar in same root folder as peloton-to-garmin
1. Install `cryptography` package via `pip install cryptography`
1. Run `pel2gar.py -encrypt`, type the Peloton/Garmin settings
1. Run `pel2gar.py`, to upload the activities. Alternatively run `pel2gar.py -pwd 123 -num 5`, if you know the password and the number of activities to upload.  

## Command Line Arguments

Usage:
pel2gar.py [-h] [-email EMAIL] [-password PASSWORD] [-garmin_email GARMIN_EMAIL] [-garmin_password GARMIN_PASSWORD] [-path OUTPUT_DIR] [-num NUM_TO_DOWNLOAD] [-log LOG_FILE] [-loglevel LOG_LEVEL]
                  [-pwd MASTER_PASSWORD] [-encrypt]

optional arguments:
* -h, --help            show this help message and exit
* -email EMAIL          Peloton email address for download
* -password PASSWORD    Peloton password for download
* -garmin_email GARMIN_EMAIL
                    Garmin email for upload
* -garmin_password GARMIN_PASSWORD
                    Garmin password for upload
* -path OUTPUT_DIR      Path to output directory
* -num NUM_TO_DOWNLOAD  Number of activities to download
* -log LOG_FILE         Log file name
* -loglevel LOG_LEVEL   DEBUG, INFO, ERROR
* -pwd MASTER_PASSWORD  Master password to decrypt credentials
* -encrypt              Encrypt Peloton & Garmin credential
  

  Examples:

  * To get the last 10 activities, using password 123:  
        * `pel2gar.py -pwd 123 -num 10`  
  * To encrypt your email and password:  
        * `pel2gar.py -encrypt -pwd 123 -email you@email.com -password mypassword`  
  
  Note: Command line arguments take precedence over values in the configuration file. 


##Notes:
1. If running pel2gar.py and no arguments it will ask for encryption info.
1. It will pass all other arguments to the peloton-to-garmin.py
1. If -encrypt is not an argument and -emails and -passwords are included these will be passed to the peloton-to-garmin.py as-is.
1. Requires the 'cryptography' package


## Scenarios tested:
    1.	pel2gar.py
    2.	pel2gar.py -encrypt
    3.	pel2gar.py -encrypt -pwd 123 -email PELOTON_EMAIL -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD
    4.	pel2gar.py -encrypt -pwd 123 -email PELOTON_EMAIL -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD -num 20 -path OUTPUT
    5.	pel2gar.py -encrypt -email PELOTON_EMAIL -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD
    6.	pel2gar.py -encrypt -pwd 123 -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD
    7.	pel2gar.py -pwd 123
    8.	pel2gar.py -pwd 123 -email PELOTON_EMAIL -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD
    9.	pel2gar.py -pwd 123 -email PELOTON_EMAIL 
    10.	pel2gar.py -pwd 123 -num 20
    11.	pel2gar.py -pwd svgsdfsds
    12.	pel2gar.py -email PELOTON_EMAIL -password PELOTON_PASSWORD -garmin_email GARMIN_EMAIL -garmin_password GARMIN_PASSWORD
    13.	Encrypt misspelled
