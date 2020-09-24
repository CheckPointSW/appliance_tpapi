import tp_log
import json
import requests
import base64
import os
import tarfile
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TeResults(object):
    """
    This class parse the TE results of last handled file API response.
    If the file was found malicious then also downloading the TE report.
    Writing the results into te_response_info/ and te_reports/ sub-folders in handled output root folder.
    """
    def __init__(self, url, file_name, output_folder_te_response_info, output_folder_te_reports):
        self.url = url
        self.file_name = file_name
        self.output_folder_te_response_info = output_folder_te_response_info
        self.output_folder_te_reports = output_folder_te_reports
        self.report_id = ""

    def log(self, msg):
        """
        Logging purpose
        """
        tp_log.log("file {} : {}".format(self.file_name, msg))

    def print(self, msg):
        """
        Logging purpose
        """
        print("file {} : {}".format(self.file_name, msg))

    def log_print(self, msg):
        """
        Logging purpose
        """
        tp_log.log_and_print("file {} : {}".format(self.file_name, msg))

    def parse_verdict(self, response, feature):
        """
        Parsing the verdict of handled feature results response, in case the that feature response status is FOUND.
        :param response: the outer te part within the handled response
        :param feature: either "te" or "te_eb"
        :return the verdict
        """
        verdict = response[feature]["combined_verdict"]
        self.print("{} verdict is: {}".format(feature, verdict))
        return verdict

    def download_report(self):
        """
        Download the TE report to the appliance, decode the downloaded archive and extract its files into
         the te_reports/ sub-folder
        """
        try:
            self.log_print("Sending Download request for TE report")
            start_pos = self.url.find("UserCheck") - 1
            curr_url = self.url[:start_pos] + ":18194/tecloud/api/v1/file/"
            response = requests.get(url=curr_url + "download?id=" + self.report_id, verify=False)
            encoded_content_string = response.text
            decoded_content = base64.b64decode(encoded_content_string)
            decoded_report_archive_path = os.path.join(self.output_folder_te_reports, self.file_name + ".report.tar.gz")
            decoded_report_archive_file = open(decoded_report_archive_path, "wb+")
            decoded_report_archive_file.write(decoded_content)
            report_dir = os.path.join(self.output_folder_te_reports, self.file_name + "_report")
            if not os.path.exists(report_dir):
                os.mkdir(report_dir)
            report_tar = tarfile.open(decoded_report_archive_path)
            report_tar.extractall(report_dir)
            report_tar.close()
            self.log_print("TE report is in sub-directory: {}".format(report_dir))
        except Exception as E:
            self.log_print("Downloading TE report failed: {} ".format(E))
            raise

    def create_response_info(self, response):
        """
        Create the TE response info of handled file and write it into te_response_info/ sub-folder
        :param response: the te feature part in handled file last response
        """
        try:
            self.log("TE response with results : {}".format(response))
            output_path = os.path.join(self.output_folder_te_response_info, self.file_name)
            output_path += ".response.txt"
            with open(output_path, 'w') as file:
                file.write(json.dumps(response))
        except Exception as E:
            self.log_print("Create te response info failed: {} ".format(E))
            raise

    def write_te_results(self, outer_te_response):
        """
        1. Create the TE response info of handled file and write it into te_response_info/ sub-folder.
        2. Check if te has "FOUND" status.
        3. If te has "FOUND" status, then parsing the response te verdict.
            If the verdict is malicious then
              Parsing the ("summary") report id.
              Accordingly, downloading the te html ("summary") report and writing the decoded report archive
               extracted files into te_reports/ sub-folder.
        :param outer_te_response: the outer te part within handled file last response
        """
        try:
            inner_te_response = outer_te_response["te"]
            self.create_response_info(inner_te_response)
            te_has_found_status = False  # default init
            combined_status_label = outer_te_response["status"]["label"]
            if combined_status_label == "FOUND":
                te_has_found_status = True
            elif combined_status_label == "PARTIALLY_FOUND":
                te_status_label = inner_te_response["status"]["label"]
                if te_status_label == "FOUND":
                    te_has_found_status = True
            if te_has_found_status:
                verdict = self.parse_verdict(outer_te_response, "te")
                if verdict == "Malicious":
                    self.report_id = inner_te_response["summary_report"]
                    if self.report_id != "":
                        self.download_report()
        except Exception as E:
            self.log_print("Writing TE results failed: {} ".format(E))
            raise
