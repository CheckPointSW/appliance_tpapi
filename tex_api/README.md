# tex_api
A Python client side utility for using Threat Extraction API calls to an appliance.

It includes Upload API calls, using the User-Check API format ( …/UserCheck/TPAPI).

There's an option of using SSL certificate.

### The flow
Going through the input directory and handling each file in order to get its Threat Extraction results.

For each file:

      1. Uploading the file to the appliance for handling by scrub (tex) feature.

           Using as default:  scrub-method=clean and a predefined least of scrubbed-parts-codes.
    
      2. Writing scrub (tex) upload results into the output directory.
    
           If tex managed to clean the file, then also writing that cleaned file into the output directory.
    
### Usage
~~~~
python tex_api.py --help

usage: tex_api.py [-h] [-id INPUT_DIRECTORY] [-od OUTPUT_DIRECTORY]
                  [-ip APPLIANCE_IP] [-ak API_KEY] [-ct CERT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -id INPUT_DIRECTORY, --input_directory INPUT_DIRECTORY
                        the input files folder to be handled by TEX
  -od OUTPUT_DIRECTORY, --output_directory OUTPUT_DIRECTORY
                        the output folder with TEX results
  -ip APPLIANCE_IP, --appliance_ip APPLIANCE_IP
                        the appliance ip address (or the appliance FQDN)
  -ak API_KEY, --api_key API_KEY
                        the appliance api key
  -ct CERT_FILE, --cert_file CERT_FILE
                        valid certificate file (full path)
~~~~
It is also possible to change the optional arguments default values within tex_api.py

### References
* Required configurations on the appliance: [sk113599](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk113599)
* Threat Prevention API to appliance using User-Check API format: [sk137032](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk137032&partition=General&product=Threat)
