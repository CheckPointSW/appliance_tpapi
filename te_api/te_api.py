"""
te_api
    A Python client side utility for using Threat Emulation API calls to an appliance.
    You may either set the global variables below (some or all), or assigning their optional
      arguments when running the utility.  Run  te_api --help  for the arguments details.
"""

from te_file_handler import TE
import os
import argparse


# Following variables can be assigned and used instead of adding them as arguments when running the te_api.py .
#  input_directory and output_directory have the following default settings.
#  Using the following input directory default setting means - assuming that the input files to handle are in
#   already existing folder :  ..appliance_tpapi/te_api/input_files
#  Using the following output_directory default setting means - creating/using the output directory :
#   ..appliance_tpapi/te_api/te_response_data
input_directory = "input_files"
output_directory = "te_response_data"
appliance_ip = ""


def main():
    """
    1. Get the optional arguments (if any): the input-directory, the output-directory and appliance-ip.
    2. Accordingly set the api-url, and create the output directory.
    3. Go though all input files in the input directory.
        Handling each input file is described in TE class in te_file_handler.py:
    """
    global input_directory
    global output_directory
    global appliance_ip
    parser = argparse.ArgumentParser()
    parser.add_argument("-id", "--input_directory", help="the input files folder to be scanned by TE")
    parser.add_argument("-od", "--output_directory", help="the output folder with TE results")
    parser.add_argument("-ip", "--appliance_ip", help="the appliance ip address")
    args = parser.parse_args()
    if args.input_directory:
        input_directory = args.input_directory
    print("The input files directory to be scanned by TE : {}".format(input_directory))
    if not os.path.exists(input_directory):
        print("\n\n  --> The input files directory {} does not exist !\n\n".format(input_directory))
        parser.print_help()
        return
    if args.output_directory:
        output_directory = args.output_directory
    print("The output directory with TE results : {}".format(output_directory))
    if not os.path.exists(output_directory):
        print("Pre-processing: creating te_api output directory {}".format(output_directory))
        try:
            os.mkdir(output_directory)
        except Exception as E1:
            print("could not create te_api output directory, because: {}".format(E1))
            return
    if args.appliance_ip:
        appliance_ip = args.appliance_ip
    if not appliance_ip:
        print("\n\n  --> Missing appliance_ip !\n\n")
        parser.print_help()
        return
    print("The appliance ip address : {}".format(appliance_ip))
    url = "https://" + appliance_ip + ":18194/tecloud/api/v1/file/"

    # A loop over the files in the input folder
    print("Begin handling input files by TE")
    for file_name in os.listdir(input_directory):
        try:
            full_path = os.path.join(input_directory, file_name)
            print("Handling file: {} by TE".format(file_name))
            te = TE(url, file_name, full_path, output_directory)
            te.handle_file()
        except Exception as E:
            print("could not handle file: {} because: {}. Continue to handle next file.".format(file_name, E))
            continue


if __name__ == '__main__':
    main()
