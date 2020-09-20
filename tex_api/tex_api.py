"""
tex_api
    A Python client side utility for using Threat Extraction API calls to an appliance.

    You may either set the global variables below (some or all), or assigning their optional
      arguments when running the utility.  Run  tex_api --help  for the arguments details.
"""

from tex_file_handler import TEX
import os
import argparse


input_directory = "/home/admin/TEX_API/input_files"
output_directory = "/home/admin/TEX_API/tex_response_data"
appliance_ip = "NNN.NNN.NNN.NNN"
api_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


def main():
    """
    1. Get the optional arguments (if any): the input-directory, the output-root-directory,
        appliance-ip and the api-key.
    2. Accordingly set the api-url, and create the output directory.
    3. Go though all input files in the input directory.
        Handling each input file is described in TEX class in tex_file_handler.py:
    """
    global input_directory
    global output_directory
    global appliance_ip
    global api_key
    parser = argparse.ArgumentParser()
    parser.add_argument("-id", "--input_directory", help="the input files folder to be scanned by TEX")
    parser.add_argument("-od", "--output_directory", help="the output folder with TEX results")
    parser.add_argument("-ip", "--appliance_ip", help="the appliance ip address")
    parser.add_argument("-ak", "--api_key", help="the appliance api key")
    args = parser.parse_args()
    if args.input_directory:
        input_directory = args.input_directory
    print("The input files directory to be scanned by TEX : {}".format(input_directory))
    if not os.path.exists(input_directory):
        print("The input files directory {} does not exist !".format(input_directory))
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
    print("The appliance ip address : {}".format(appliance_ip))
    if args.api_key:
        api_key = args.api_key
    print("The appliance api key : {}".format(api_key))
    url = "https://" + appliance_ip + "/UserCheck/TPAPI"

    # A loop over the files in the input folder
    print("Begin handling input files by TEX")
    for file_name in os.listdir(input_directory):
        try:
            full_path = os.path.join(input_directory, file_name)
            print("Handling file: {} by TEX".format(file_name))
            tex = TEX(url, api_key, file_name, full_path, output_directory)
            tex.handle_file()
        except Exception as E:
            print("could not handle file: {} because: {}. Continue to handle next file".format(file_name, E))
            continue


if __name__ == '__main__':
    main()
