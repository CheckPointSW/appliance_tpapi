## te_api
A Python client side utility for using Threat Emulation API calls to an appliance.

It includes Upload, Query and Download API calls, using the Cloud API format ( …/tecloud/api/v#/file/..).

### The flow
Going through the input directory and handling each file in order to get its Threat Emulation results.

For each file:

    1. Uploading the file to the appliance for te and te_eb features.
    
    2. If upload result is upload_success then querying te and te_eb until receiving te results.  (Note, te_eb results of early malicious verdict might be received earlier)
    
    3. Writing to output file the last query/upload response info.
    
    4. If te result is found then display the verdict.  If verdict is malicious then also download the TE report.
    
    



### Usage:
~~~~
python te_api.py --help

usage: te_api.py [-h] [-id INPUT_DIRECTORY] [-od OUTPUT_DIRECTORY]
                 [-ip APPLIANCE_IP]

optional arguments:
  -h, --help            show this help message and exit
  -id INPUT_DIRECTORY, --input_directory INPUT_DIRECTORY
                        the input files folder to be scanned by TE
  -od OUTPUT_DIRECTORY, --output_directory OUTPUT_DIRECTORY
                        the output folder with TE results
  -ip APPLIANCE_IP, --appliance_ip APPLIANCE_IP
                        the appliance ip address

~~~~
