# Description 
This is an initial scratch up of interacting with the SOPHOS Intelix API that's in EAP(July 2019)
http://sophos.com/intelix.

The script reads a list of IoC's, makes a check to see if there's a URL or File Hash and then does a URL or Hash lookup piping information into a CSV file.

This has been designed to be picked apart. If there's interest in making the output redirect into another system such as a SIEM the write_csv function would just need to be redirected to something other than a CSV.

There's some broad error checking to see if DICT keys appear from JSON request in url_lookup and hash_lookup. This is due to inconsistant JSON data depending on the URL or file submitted.

Sample JSON and IOC's included for testing. This script is in no way suppored by SOPHOS.

# Usage:
CLI for scripting
python run.py <ioc_file.txt>
OR
Interactive Prompt
python run.py

# To come:
- Threading for quicker lookups.
- Auto Authorization Token generation
