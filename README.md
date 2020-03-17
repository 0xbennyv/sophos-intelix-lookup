# Description 
This is an initial scratch up of interacting with the SOPHOSLabs Intelix API.
https://api.labs.sophos.com/doc/index.html

The script reads a list of IoC's, makes a check to see if there's a URL or File Hash and then does a URL or Hash lookup piping information into a CSV file.

This has been designed to be picked apart. If there's interest in making the output redirect into another system such as a SIEM the write_csv function would just need to be redirected to something other than a CSV.

There's some broad error checking to see if DICT keys appear from JSON request in url_lookup and hash_lookup. This is due to inconsistant JSON data depending on the URL or file submitted.

Lookup Errors will return a value of LookupFailure within the output.

Sample JSON and IOC's included for testing. This script is in no way suppored by SOPHOS.

# Usage:

Authentication for Intelix is needed, ensure you've read the 'How to Register' at the URL above to obtain a Client ID and Client Secret.
For now, place these within the run.py, within the quotation marks on lines 163 and 164 respectively.

CLI for scripting:

python3 run.py <ioc_file.txt>

NOTE: Your ioc_file.txt should consist of only a list of hashes with carriage return separation.

OR

Interactive Prompt:

python3 run.py

# To come:
- Threading for quicker lookups.