import json
import requests
import os
import base64
import copy
from enum import Enum
import urllib3
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ~~~~~~~~~ tex statuses ~~~~~~~~~ #

class CpExtractResult(Enum):
    CP_EXTRACT_RESULT_CANCEL_SCRUBBING = -1
    CP_EXTRACT_RESULT_SUCCESS = 0
    CP_EXTRACT_RESULT_FAILURE = 1
    CP_EXTRACT_RESULT_TIMEOUT = 2
    CP_EXTRACT_RESULT_UNSUPPORTED_FILE = 3
    CP_EXTRACT_RESULT_NOT_SCRUBBED = 4
    CP_EXTRACT_RESULT_INTERNAL_ERROR = 5
    CP_EXTRACT_RESULT_DISK_LIMIT_REACHED = 6
    CP_EXTRACT_RESULT_ENCRYPTED_FILE = 7
    CP_EXTRACT_RESULT_DOCSEC_FILE = 8
    CP_EXTRACT_RESULT_OUT_OF_MEMORY = 9
    CP_EXTRACT_RESULT_SKIPPED_BY_SCRIPT = 10
    CP_EXTRACT_RESULT_SKIPPED_BY_TE_CONFIDENCE = 11
    CP_EXTRACT_RESULT_NO_VALID_CONTRACT = 12
    CP_EXTRACT_RESULT_BYPASS_SCRUB = 13
    CP_EXTRACT_RESULT_BYPASS_FILE_SCRUB = 14
    CP_EXTRACT_RESULT_ENCRYPTED_FILE_OR_SIGNED = 15
    CP_EXTRACT_RESULT_WATERMARK_FAILED = 16
    CP_EXTRACT_RESULT_FILE_LARGER_THAN_LIMIT = 17
    CP_EXTRACT_NUM_RESULTS = 18


def return_relevant_enum(status):
    """
    :param status:
    :return: the relevant TEX status
    """
    return CpExtractResult(status).name


class TEX(object):
    """
    This class gets a file as input and handles it as follows (function handle_file) :
      1. Upload the file to the appliance for handling by scrub (tex) feature.
           Using as default:  scrub-method=clean and a predefined least of scrubbed-parts-codes.
      2. Write scrub (tex) upload results into the output folder.
           If tex managed to clean the file, then also write that cleaned file into the output folder.
    """
    def __init__(self, url, api_key, file_name, file_path, output_folder, cert_file):
        self.url = url
        self.api_key = api_key
        self.file_name = file_name
        self.file_path = file_path
        self.upload_request_template = {
            "request": [{
                "protocol_version": "1.1",
                "api_key": "",
                "request_name": "UploadFile",
                "file_orig_name": "",
                "file_enc_data": "",
                "scrub_options": {
                    "scrub_method": 1,
                    "scrubbed_parts_codes": [1018, 1019, 1021, 1025, 1026, 1034, 1137, 1139, 1141, 1142, 1143, 1150,
                                             1151],
                    "save_original_file_on_server": False
                }
            }]
        }
        self.output_folder = output_folder
        self.cert_file = cert_file
        self.clean_file_data = ""
        self.clean_file_name = ""

    def print(self, msg):
        """
        Logging purpose
        """
        print("file {} : {}".format(self.file_name, msg))

    def create_clean_file(self):
        """
        Decode the cleaned file content that had been received as part of the response (in bytes) and
         write the results to a new file with a new proper file name into the output folder.
        :return cleaned file path and name
        """
        text = base64.b64decode(self.clean_file_data)
        self.clean_file_name = self.file_name.split(".")[0]
        self.clean_file_name += ".cleaned."
        self.clean_file_name += self.file_name.split(".")[1]
        output_path = os.path.join(self.output_folder, self.clean_file_name)
        with open(output_path, 'wb') as file:
            file.write(text)
        return output_path

    def create_response_info(self, response):
        """
        Create the TEX response info of handled file and write it into the output folder.
        :param response: handled file upload response (that includes TEX results)
        :return true - if TEX managed to clean the file, false - otherwise.
        """
        scrub_response = response["response"][0]["scrub"]
        is_cleaned = False if scrub_response["file_enc_data"] == "" else True
        file_name = self.file_name
        file_name += ".response.txt"
        output_path = os.path.join(self.output_folder, file_name)
        # copy the clean data to create the clean file
        self.clean_file_data = copy.deepcopy(scrub_response["file_enc_data"])
        if is_cleaned:  # no need to write the whole clean file inside the response info
            scrub_response["file_enc_data"] = "already used. removed because of space issues"
        tex_extract_result = return_relevant_enum(scrub_response["scrub_result"])
        self.print("TEX extract result : {}".format(tex_extract_result))
        with open(output_path, 'w') as file:
            file.write(json.dumps(response))
        return is_cleaned

    def prepare_request_for_upload(self):
        """
        Prepare all upload request required attributes.
        :return the prepared request
        """
        request = copy.deepcopy(self.upload_request_template)
        # update request fields
        request['request'][0]['api_key'] = self.api_key
        request['request'][0]['file_orig_name'] = self.file_name
        with open(self.file_path, 'rb') as f:
            file_encoded = base64.b64encode(f.read())
        file_content = file_encoded.decode("utf-8")
        request['request'][0]['file_enc_data'] = str(file_content)
        return request

    def upload_file(self):
        """
        Upload the file to the appliance for scrub (tex) and get the upload response.
        :return the upload response
        """
        request = self.prepare_request_for_upload()
        data = json.dumps(request)
        self.print("Sending Upload request of tex")
        try:
            response = requests.post(url=self.url, data=data, verify=(self.cert_file if self.cert_file else False))
        except Exception as E:
            self.print("Upload file failed: {}.".format(E))
            raise
        response_j = response.json()
        return response_j

    def handle_file(self):
        """
        (Function description is within above class description)
        """
        upload_response = self.upload_file()
        is_cleaned = self.create_response_info(upload_response)
        if is_cleaned:
            cleaned_file_path = self.create_clean_file()
            self.print("TEX managed to clean the file.  Cleaned file : {}".format(cleaned_file_path))
