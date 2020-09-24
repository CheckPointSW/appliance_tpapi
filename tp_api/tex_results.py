import tp_log
import copy
import json
import base64
import os
from enum import Enum


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


class TexResults(object):
    """
    This class parse the TEX results of handled file Upload response.
    If tex managed to clean the file, then writing TEX cleaned file.
    Writing the results into tex_response_info/ and tex_clean_files/ sub-folders in handled output root folder.
    """
    def __init__(self, url, file_name, output_folder_tex_response_info, output_folder_tex_clean_files):
        self.url = url
        self.file_name = file_name
        self.output_folder_tex_response_info = output_folder_tex_response_info
        self.output_folder_tex_clean_files = output_folder_tex_clean_files
        self.clean_file_data = ""
        self.clean_file_name = ""

    def log(self, msg):
        """
        Logging purpose
        """
        tp_log.log("file {} : {}".format(self.file_name, msg))

    def log_print(self, msg):
        """
        Logging purpose
        """
        tp_log.log_and_print("file {} : {}".format(self.file_name, msg))

    def create_clean_file(self):
        """
        Decode the cleaned file content that had been received as part of the response (in bytes) and
         write the results to a new file with a new proper file name into tex_clean_files/ sub-folder.
        :return cleaned file path and name
        """
        text = base64.b64decode(self.clean_file_data)
        self.clean_file_name = self.file_name.split(".")[0]
        self.clean_file_name += ".cleaned."
        self.clean_file_name += self.file_name.split(".")[1]
        output_path = os.path.join(self.output_folder_tex_clean_files, self.clean_file_name)
        with open(output_path, 'wb') as file:
            file.write(text)
        return output_path

    def create_response_info(self, response):
        """
        Create the TEX response info of handled file and write it into tex_response_info/ sub-folder.
        :param response: handled file upload response (that includes TEX results)
        :return true - if TEX managed to clean the file, false - otherwise.
        """
        scrub_response = response["response"][0]["scrub"]
        is_cleaned = False if scrub_response["file_enc_data"] == "" else True
        file_name = self.file_name
        file_name += ".response.txt"
        output_path = os.path.join(self.output_folder_tex_response_info, file_name)
        # copy the clean data to create the clean file
        self.clean_file_data = copy.deepcopy(scrub_response["file_enc_data"])
        if is_cleaned:  # no need to write the whole clean file inside the response info
            scrub_response["file_enc_data"] = "already used. removed because of space issues"
        self.log("TEX Upload response : {}".format(scrub_response))
        tex_extract_result = return_relevant_enum(scrub_response["scrub_result"])
        self.log_print("TEX extract result : {}".format(tex_extract_result))
        with open(output_path, 'w') as file:
            file.write(json.dumps(scrub_response))
        return is_cleaned

    def write_tex_results(self, response):
        """
        1. Create the TEX response info of handled file and write it into tex_response_info/ sub-folder.
        2. If tex managed to clean the file, then write TEX cleaned file into tex_clean_files/ sub-folder.
        :param response: handled file upload response (that includes TEX results)
        """
        try:
            is_cleaned = self.create_response_info(response)
            if is_cleaned:
                cleaned_file_path = self.create_clean_file()
                self.log_print("TEX managed to clean the file.  Cleaned file : {}".format(cleaned_file_path))
        except Exception as E:
            self.log_print("Writing TEX results failed: {} ".format(E))
            raise
