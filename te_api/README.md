# te_api
A Python client side utility for using Threat Emulation API calls to an appliance.

It includes Upload, Query and Download API calls, using the Cloud API format ( …/tecloud/api/v#/file/..).

### The flow
Going through the input directory and handling each file in order to get its Threat Emulation results.

For each file:

> 1. Querying te cache for already existing results of the file sha1.

>>> If results exist then goto #4, otherwise- continue to #2
    
> 2. Uploading the file to the appliance for te and te_eb features.
    
> 3. If upload result is upload_success then querying te and te_eb until receiving te results.

>>> (Note, te_eb results of early malicious verdict might be received earlier during the queries in between)
    
> 4. Writing to output file the last query/upload response info.
    
> 5. If te result is found then displaying the verdict.  If verdict is malicious then also downloading the TE report.

### Usage
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
It is also possible to change the optional arguments default values within te_api.py

### References
* Additional Threat Emulation API info: [sk167161](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk167161)
* te_eb feature: [sk117168 chapter 4](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk117168#New%20Public%20API%20Interface)

