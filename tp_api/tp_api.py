"""
tp_api
    A Python client side utility for using Threat Emulation, Threat Extraction and Anti Virus API calls to an appliance.
    You may either set the global variables below (some or all), or assigning their optional
      arguments when running the utility.  Run  tp_api --help  for the arguments details.
"""

import tp_log
from outp_dirs import OutputDirectories
from tp_file_handler import TpFileHandling
import os
import argparse


# Following variables can be assigned and used instead of adding them as arguments when running the tp_api.py .
#  input_directory and output_root_directory have the following default settings.
#  Using the following input directory default setting means - assuming that the input files to handle are in
#   already existing folder :  ..appliance_tpapi/tp_api/input_files
#  Using the following output_root_directory default setting means - creating/using the output root directory :
#   ..appliance_tpapi/tp_api/tp_api_output
input_directory = "input_files"
output_root_directory = "tp_api_output"
appliance_ip = ""
api_key = ""
cert_file = ""


def main():
    """
    1. Get the optional arguments (if any): the input-directory, the output-root-directory,
        the api-key, either the appliance-ip or the appliance-FQDN and the certificate file.
        Note: if using an SSL-certificate then must also use the FQDN.
    2. Accordingly set the api-url, and create the output sub-directories.
    3. Within the output-root-directory, create a subdirectory whose name is current date and time,
         and within create all required output subdirectories for the results.
    4. Go though all input files in the input directory.
        Handling each input file is described in FilesHandler class in tp_file_handler.py:
    """
    global input_directory
    global output_root_directory
    global api_key
    global appliance_ip
    global cert_file
    parser = argparse.ArgumentParser()
    parser.add_argument("-id", "--input_directory", help="the input files folder to be handled")
    parser.add_argument("-od", "--output-root-directory", help="the output root folder of the results")
    parser.add_argument("-ip", "--appliance_ip", help="the appliance ip address (or the appliance FQDN)")
    parser.add_argument("-ak", "--api_key", help="the appliance api key")
    parser.add_argument("-ct", "--cert_file", help="valid certificate file (full path)")
    args = parser.parse_args()
    if args.output_root_directory:
        output_root_directory = args.output_root_directory
    print("The output root directory of the results : {}".format(output_root_directory))
    if not os.path.exists(output_root_directory):
        print("Pre-processing: creating tp_api output root directory {}".format(output_root_directory))
        try:
            os.mkdir(output_root_directory)
        except Exception as E1:
            print("could not create tp_api output root directory, because: {}".format(E1))
            raise
    # Set the logger immediately after getting/creating the output root directory
    tp_log.set_log(output_root_directory)
    tp_log.log("-----------------------------------------------------------------------------")
    tp_log.log("-----------------------------------------------------------------------------")
    tp_log.log("The output root directory of the results : {}".format(output_root_directory))
    if args.input_directory:
        input_directory = args.input_directory
    tp_log.log_and_print("The input files directory to be handled : {}".format(input_directory))
    if not os.path.exists(input_directory):
        print("\n\n  --> The input files directory {} does not exist !\n\n".format(input_directory))
        parser.print_help()
        tp_log.log("The input files directory {} does not exist !".format(input_directory))
        return
    if args.appliance_ip:
        appliance_ip = args.appliance_ip
    if not appliance_ip:
        print("\n\n  --> Missing appliance_ip !\n\n")
        parser.print_help()
        tp_log.log("Missing appliance_ip !")
        return
    tp_log.log_and_print("The appliance ip address : {}".format(appliance_ip))
    if args.api_key:
        api_key = args.api_key
    if not api_key:
        print("\n\n  --> Missing appliance api key !\n\n")
        parser.print_help()
        tp_log.log("Missing appliance api key !")
        return
    tp_log.log_and_print("The appliance api key : {}".format(api_key))
    if args.cert_file:
        cert_file = args.cert_file
    if cert_file:
        tp_log.log_and_print("The certificate file : {}".format(cert_file))
    url = "https://" + appliance_ip + "/UserCheck/TPAPI"
    output_directories = OutputDirectories(output_root_directory)

    # A loop over the files in the input folder
    tp_log.log_and_print("Begin handling input files by TE, AV and TEX")
    for file_name in os.listdir(input_directory):
        try:
            file_path = os.path.join(input_directory, file_name)
            tp = TpFileHandling(url, api_key, file_name, file_path, output_directories, cert_file)
            tp.handle_file()
        except Exception as E:
            tp_log.log_and_print("could not handle file: {} because: {}. Continue to handle next file.".
                                 format(file_name, E))
            continue


if __name__ == '__main__':
    main()
