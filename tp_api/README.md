# tp_api
A Python client side utility for using ALL kinds of Threat Prevention API calls to an appliance :
Threat Emulation, Threat Extraction and Anti Virus.

The utility includes Upload, Query and Download API calls, using the User-Check API format ( …/UserCheck/TPAPI).

There's an option of using SSL certificate.

### The flow
First, creating an output directory (that is a sub-directory of the output root directory) whose
name is current date and time (in the format of DD_MM_YY_HH_MM_SS). Within this directory creating
additonal sub-directories (mentioned as follows).


Then, going through the input directory and handling each file in order to get its Threat Emulation 
 results and if necessary then also to get its Threat Extraction and/or its Anti Virus results.

For each file:

      1. Querying TE cache and AV cache by the file md5.

      2. If not found in TE cache, then :
        
           2.1 If found in AV cache, then writing the av results to av_response_info/ sub-directory.

           2.2 Uploading the file to the appliance for handling by all features:  te, te_eb, scrub (tex) and av

           2.3 If te result is upload_success :

                  2.3.1 Writing scrub (tex) upload results to tex_response_info/ sub-directory.

                     If tex managed to clean the file, then also writing that cleaned file to tex_clean_files/ sub-directory.

                  2.3.2 Querying te, av and te_eb until receiving te results.

                     If in between receiving te_eb found results of the early malicious verdict, then reporting it online.

                     If in between receiving av results, then writing the av results to av_response_info/ sub-directory.

      3. Writing the te results to te_response_info/ sub-directory.

          If result verdict is malicious then also downloading the TE report and write it to te_reports/ sub-directory.

    
### Usage
~~~~
python tp_api.py --help

usage: tp_api.py [-h] [-id INPUT_DIRECTORY] [-od OUTPUT_ROOT_DIRECTORY]
                 [-ip APPLIANCE_IP] [-ak API_KEY] [-ct CERT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -id INPUT_DIRECTORY, --input_directory INPUT_DIRECTORY
                        the input files folder to be handled
  -od OUTPUT_ROOT_DIRECTORY, --output-root-directory OUTPUT_ROOT_DIRECTORY
                        the output root folder of the results
  -ip APPLIANCE_IP, --appliance_ip APPLIANCE_IP
                        the appliance ip address (or the appliance FQDN)
  -ak API_KEY, --api_key API_KEY
                        the appliance api key
  -ct CERT_FILE, --cert_file CERT_FILE
                        valid certificate file (full path)
~~~~
It is also possible to change the optional arguments default values within tp_api.py

### References
* Required configurations on the appliance: [sk113599](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk113599)
* Threat Prevention API to appliance using User-Check API format: [sk137032](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk137032&partition=General&product=Threat)
* Additional Threat Emulation API info: [sk167161](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk167161)
* te_eb feature: [sk117168 chapter 4](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk117168#New%20Public%20API%20Interface)

