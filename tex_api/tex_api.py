"""
tex_api
    A Python client side utility for using Threat Extraction API calls to an appliance.
    You may either set the global variables below (some or all), or assigning their optional
      arguments when running the utility.  Run  tex_api --help  for the arguments details.
"""

from tex_file_handler import TEX
import os
import argparse


# Following variables can be assigned and used instead of adding them as arguments when running the tex_api.py .
#  input_directory and output_directory have the following default settings.
#  Using the following input directory default setting means - assuming that the input files to handle are in
#   already existing folder :  ..appliance_tpapi/tex_api/input_files
#  Using the following output_directory default setting means - creating/using the output directory :
#   ..appliance_tpapi/tex_api/tex_response_data
input_directory = "input_files"
output_directory = "tex_response_data"
appliance_ip = ""
api_key = ""
cert_file = ""


def main():
    """
    1. Get the optional arguments (if any): the input-directory, the output-root-directory,
        the api-key, either the appliance-ip or the appliance-FQDN and the certificate file.
    2. Accordingly set the api-url, and create the output directory.
    3. Go though all input files in the input directory.
        Handling each input file is described in TEX class in tex_file_handler.py:
    """
    global input_directory
    global output_directory
    global api_key
    global appliance_ip
    global cert_file
    parser = argparse.ArgumentParser()
    parser.add_argument("-id", "--input_directory", help="the input files folder to be handled by TEX")
    parser.add_argument("-od", "--output_directory", help="the output folder with TEX results")
    parser.add_argument("-ip", "--appliance_ip", help="the appliance ip address (or the appliance FQDN)")
    parser.add_argument("-ak", "--api_key", help="the appliance api key")
    parser.add_argument("-ct", "--cert_file", help="valid certificate file (full path)")
    args = parser.parse_args()
    if args.input_directory:
        input_directory = args.input_directory
    print("The input files directory to be handled by TEX : {}".format(input_directory))
    if not os.path.exists(input_directory):
        print("\n\n  --> The input files directory {} does not exist !\n\n".format(input_directory))
        parser.print_help()
        return
    if args.output_directory:
        output_directory = args.output_directory
    print("The output directory with TEX results : {}".format(output_directory))
    if not os.path.exists(output_directory):
        print("Pre-processing: creating tex_api output directory {}".format(output_directory))
        try:
            os.mkdir(output_directory)
        except Exception as E1:
            print("could not create tex_api output directory, because: {}".format(E1))
            return
    if args.appliance_ip:
        appliance_ip = args.appliance_ip
    if not appliance_ip:
        print("\n\n  --> Missing appliance_ip !\n\n")
        parser.print_help()
        return
    print("The appliance ip address : {}".format(appliance_ip))
    if args.api_key:
        api_key = args.api_key
    if not api_key:
        print("\n\n  --> Missing appliance api key !\n\n")
        parser.print_help()
        return
    print("The appliance api key : {}".format(api_key))
    if args.cert_file:
        cert_file = args.cert_file
    if cert_file:
        print("The certificate file : {}".format(cert_file))
    url = "https://" + appliance_ip + "/UserCheck/TPAPI"

    # A loop over the files in the input folder
    print("Begin handling input files by TEX")
    for file_name in os.listdir(input_directory):
        try:
            full_path = os.path.join(input_directory, file_name)
            print("Handling file: {} by TEX".format(file_name))
            tex = TEX(url, api_key, file_name, full_path, output_directory, cert_file)
            tex.handle_file()
        except Exception as E:
            print("could not handle file: {} because: {}. Continue to handle next file".format(file_name, E))
            continue


if __name__ == '__main__':
    main()
