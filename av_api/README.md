# av_api
A Python client side utility for using Anti Virus API calls to an appliance.

It includes Upload and Query API calls, using the Cloud API format ( …/tecloud/api/v#/file/..).

### The flow
Going through the input directory and handling each file in order to get its Anti Virus results.

For each file:

> 1. Querying av cache for already existing results by the file md5.

>>> If results exist then goto #4, otherwise- continue to #2
    
> 2. Uploading the file to the appliance for av feature.
    
> 3. If upload result is upload_success then querying av until receiving results.

> 4. Writing to output file the last query/upload response info.
    
> 5. If av result is found malicious then displaying the resulted av signature.

### Usage
~~~~
python av_api.py --help

usage: av_api.py [-h] [-id INPUT_DIRECTORY] [-od OUTPUT_DIRECTORY]
                 [-ip APPLIANCE_IP]

optional arguments:
  -h, --help            show this help message and exit
  -id INPUT_DIRECTORY, --input_directory INPUT_DIRECTORY
                        the input files folder to be scanned by AV
  -od OUTPUT_DIRECTORY, --output_directory OUTPUT_DIRECTORY
                        the output folder with AV results
  -ip APPLIANCE_IP, --appliance_ip APPLIANCE_IP
                        the appliance ip address

~~~~
It is also possible to change the optional arguments default values within av_api.py
