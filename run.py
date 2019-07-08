# Requests for web call to REST API
import requests
# System for CLI Args
import sys
# OS for File Validation
import os
# CSV for exporting to CSV
import csv
# Import Time
import time
# Import URLParse library to validate URLS in IOCS
from urllib.parse import urlparse

# Setup the command line args
authorization = ''


# Check to see if IOC is a hash or FQDN then pass to the correct function.
def ioc_check(file):
    # Reading the file that was passed to the function line by line.
    # Long term this should be threaded
    with open(file) as fp:
        for ioc in fp:
            ioc = ioc.strip()
            o = urlparse(ioc)
            # If scheme or netlock is set then deem a URL, else treat as a hash
            if o[0] or o[1]:
                # we need to use the URLParse and get the netlock
                ioc = o[1]
                url_lookup(ioc)
            else:
                hash_lookup(ioc)


# Make the URL Lookup
def url_lookup(ioc):
    url = f'https://de.api.labs.sophos.com/lookup/urls/v1/{ioc}'
    headers = {'Authorization': authorization,
               'content-type': 'application/json'}
    # Make the request
    response = requests.get(url, headers=headers)

    # Get the JSON response in Python DICT
    json_response = response.json()

    # Print response for debugging
    # print(json_response)

    # Processing and error handling currently handled here so data can be processed by an additional
    # Check the see if Detection Name exists in response Dict
    try:
        json_response['error']

    # If error doesn't exist, sets vars for post processing
    except KeyError:
        # Intelix Sends inconsistent Fields so we need to check to see what exists in order for processing.
        # This could be tidied
        # Check to see if Product Category Exists
        try:
            json_response['productivityCategory']
        except KeyError:
            prodcategory = 'Unknown'
        else:
            prodcategory = json_response['productivityCategory']

        # Check to see if Security Category Exists
        try:
            json_response['securityCategory']
        except KeyError:
            securitycategory = 'Unknown'
        else:
            securitycategory = json_response['securityCategory']

        # Check to see if Risk Level Exists
        try:
            json_response['riskLevel']
        except KeyError:
            risklevel = 'Unknown'
        else:
            risklevel = json_response['riskLevel']

    # If there's an error then return values
    else:
        prodcategory = 'Unknown'
        securitycategory = 'Unknown'
        risklevel = 'Unknown'

    # print(f'{ioc}, {prodcategory},{securitycategory},{risklevel}')
    write_csv(ioc, prodcategory, securitycategory, risklevel)


# Make the Hash Lookup
def hash_lookup(ioc):
    url = f'https://de.api.labs.sophos.com/lookup/files/v1/{ioc}'
    headers = {'Authorization': authorization,
               'content-type': 'application/json'}
    # Make the request
    response = requests.get(url, headers=headers)

    # Get the JSON response in Python DICT
    json_response = response.json()

    # Print response for debugging
    # Print(json_response)

    # Processing and error handling currently handled here so data can be processed by an additional
    # Check the see if Detection Name exists in response Dict
    try:
        json_response['error']

    # If error doesn't exist, sets vars for post processing
    except:
        # Test to see if detectionName key exists - if it doesn't it'll mark it unknown
        try:
            json_response['detectionName']
        except KeyError:
            dectectionname = "Unknown"
        else:
            dectectionname = json_response['detectionName']

        # Rep Score and Reputation Interpretation
        repscore = json_response['reputationScore']
        if int(repscore) >= 0 <= 19:
            repclasification = 'Malicous'

        elif int(repscore) >= 20 <= 29:
            repclasification = 'PUA'

        elif int(repscore) >= 30 <= 69:
            repclasification = 'Unknown/Suspicious'

        elif int(repscore) >= 70 <= 100:
            repclasification = 'Known Good'

    # If there's an error then return values
    else:
        repscore = 'Unknown'
        dectectionname = 'Unknown'
        repclasification = 'Unknown'

    # print(f'{ioc}, {repscore},{dectectionname},{repclasification}')
    write_csv(ioc, repscore, dectectionname, repclasification)


# Get all the data and pass it to CSV
def write_csv(ioc, col1, col2, col3):
    # Create the DICT that we'll convert to CSV
    csv_data = [f'{ioc},{col1},{col2},{col3}']
    # print(csv_data)
    # Create and Write the results to CSV
    with open(f'{time}_intelix_result.csv', 'a') as fp:
        wr = csv.writer(fp, delimiter=',')
        wr.writerow(csv_data)


# If no system args are set you'll get an interactive prompt
def user_input():
    # Initial file prompt
    file = input("Enter the path of your file: ")
    # Check to make sure the path is valid and continue
    if os.path.isfile(file):
        print(f'[*] File {file} is valid')
        print('[*] Proceeding to check the IoC against SOPHOS Labs Intelix')
        # Do a hash lookup of the file, if this fails it'll then upload the file
        ioc_check(file)
        # If the file is not valid it'll then ask the question again
    else:
        print(f'[*] File {file} is NOT valid')
        print('[*] Please try again')
        user_input()


# Let's rock the casbah!
if __name__ == "__main__":
    # Time for CSV File, generated at the start so it doesn't change during a large lookup
    time = time.localtime()
    time = f'{time[0]}{time[1]}{time[2]}{time[3]}{time[4]}'

    # Check to see if the arg for a file has been set.
    # This isn't as clean as it should be and will get a facelift at some point.
    try:
        str(sys.argv[1])

    # If system arg isn't set then you'll get the user input prompt
    except:
        user_input()

    # If the File arg is set then we'll validate it and exit out. This is to make it CLI friendly.
    else:
        file = str(sys.argv[1])
        if os.path.isfile(file):
            print(f'[*] File {file} is valid')
            print(f'[*] Starting IoC lookup with SOPHOS Labs Intelix')
            ioc_check(file)
        else:
            print(f'[*] File {file} is NOT valid')

