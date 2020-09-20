import json
import requests
import base64
import os
import hashlib
import time
import tarfile
import copy
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SECONDS_TO_WAIT = 5
MAX_RETRIES = 120


def parse_verdict(response, feature):
    """
    Parsing the verdict of handled feature results response, in case the that feature response status is FOUND.
    :param response: the handled response
    :param feature: either "te" or "te_eb"
    """
    verdict = response["response"][0][feature]["combined_verdict"]
    print("{} verdict is: {}".format(feature, verdict))
    return verdict


class TE(object):
    """
    This class gets a file as input and handles it as follows (function handle_file) :
     1. Query TE cache by the file sha1 for already existing TE results.
     2. If not found in TE cache then :
       2.1 Upload the file to the appliance for handling by te and te_eb features.
       2.2 If upload result is upload_success (meaning no TE results yet) then :
             Query te and te_eb features until receiving TE results.
               If in between receiving te_eb found results of the early malicious verdict, then report online the
                early malicious verdict result.
     3. Write the TE results (last query/upload response info) into the output folder.
          If resulted TE verdict is malicious then also download the TE report and write it into the output folder.
    """
    def __init__(self, url, file_name, file_path, output_folder):
        self.url = url
        self.file_name = file_name
        self.file_path = file_path
        self.request_template = {
            "request": [{
                "features": ["te", "te_eb"],
                "te": {
                    "reports_version_number": 2,
                    "reports": ["summary"],
                    "version_info": True,
                    "return_errors": True
                }
            }]
        }
        self.output_folder = output_folder
        self.sha1 = ""
        self.final_response = ""
        self.final_status_label = ""
        self.report_id = ""

    def set_file_sha1(self):
        """
        Calculates the file's sha1
        """
        sha1 = hashlib.sha1()
        with open(self.file_path, 'rb') as f:
            while True:
                block = f.read(2 ** 10)  # One-megabyte blocks
                if not block:
                    break
                sha1.update(block)
            self.sha1 = sha1.hexdigest()

    def parse_report_id(self, response):
        """
        parse and return the summary report id
        :param response: the (last) response with the handled file TE results
        """
        try:
            self.report_id = response["response"][0]["te"]["summary_report"]
        except Exception as E:
            print("Could not get TE report id, failure: {}. ".format(E))

    def create_response_info(self, response):
        """
        Create the TE response info of handled file and write it into the output folder.
        :param response: last response
        """
        output_path = os.path.join(self.output_folder, self.file_name)
        output_path += ".response.txt"
        with open(output_path, 'w') as file:
            file.write(json.dumps(response))

    def check_te_cache(self):
        """
        Query (for te) the file (before upload) in order to find whether file results already exist in TE cache.
        :return the query response
        """
        self.set_file_sha1()
        request = copy.deepcopy(self.request_template)
        request['request'][0]['features'].remove('te_eb')
        request['request'][0]['sha1'] = self.sha1
        print("file {} sha1: {}".format(self.file_name, self.sha1))
        data = json.dumps(request)
        print("Sending TE Query request before upload in order to check TE cache for file {}".format(self.file_name))
        response = requests.post(url=self.url + "query", data=data, verify=False)
        response_j = response.json()
        return response_j

    def upload_file(self):
        """
        Upload the file to the appliance for te and te_eb and get the upload response.
        :return the upload response
        """
        request = copy.deepcopy(self.request_template)
        data = json.dumps(request)
        curr_file = {
            'request': data,
            'file': open(self.file_path, 'rb')
        }
        print("Sending Upload request of te and te_eb for file {}".format(self.file_name))
        try:
            response = requests.post(url=self.url + "upload", files=curr_file, verify=False)
        except Exception as E:
            print("Upload file failed. file: {} , failure: {}".format(self.file_name, E))
            raise
        response_j = response.json()
        print("te and te_eb Upload response status for file {} : {}".format(self.file_name,
                                                                            response_j["response"][0]["status"]["label"]))
        return response_j

    def query_file(self):
        """
        Query the appliance for te and te_eb of the file every SECONDS_TO_WAIT seconds.
        Repeat query until receiving te results.  te_eb results of early malicious verdict might be received earlier.
        :return the (last) query response with the handled file TE results
        """
        print("Start sending Query requests of te and te_eb after TE upload for file {}".format(self.file_name))
        request = copy.deepcopy(self.request_template)
        request['request'][0]['sha1'] = self.sha1
        data = json.dumps(request)
        response_j = json.loads('{}')
        status_label = False
        te_eb_found = False
        retry_no = 0
        while (not status_label) or (status_label == "PENDING") or (status_label == "PARTIALLY_FOUND"):
            print("Sending Query request of te and te_eb for file {}".format(self.file_name))
            response = requests.post(url=self.url + "query", data=data, verify=False)
            response_j = response.json()
            status_label = response_j['response'][0]['status']['label']
            if (status_label != "PENDING") and (status_label != "PARTIALLY_FOUND"):
                break
            if status_label == "PARTIALLY_FOUND":
                if not te_eb_found:
                    te_eb_status_label = response_j["response"][0]["te_eb"]['status']['label']
                    if te_eb_status_label == "FOUND":
                        te_eb_found = True
                        te_eb_verdict = parse_verdict(response_j, "te_eb")
                        if te_eb_verdict == "Malicious":
                            print("Early verdict is malicious for file {}".format(self.file_name))
                            print("Continue Query until receiving te results for file {}".format(self.file_name))
                te_status_label = response_j["response"][0]["te"]['status']['label']
                if (te_status_label == "FOUND") or (te_status_label == "NOT_FOUND"):
                    break
                elif te_status_label == "PARTIALLY_FOUND":
                    te_images_j_arr = response_j["response"][0]["te"]["images"]
                    no_pending_image = True
                    for image_j in te_images_j_arr:
                        if image_j["status"] == "pending":
                            no_pending_image = False
                            break
                    if no_pending_image:
                        break
            print("te and te_eb Query response status for file {} : {}".format(self.file_name, status_label))
            time.sleep(SECONDS_TO_WAIT)
            retry_no += 1
            if retry_no == MAX_RETRIES:
                print("Reached query max retries.  Stop waiting for te results for file {}".format(self.file_name))
                break
        return response_j

    def download_report(self):
        """
        Download the TE report to the appliance, decode the downloaded archive and extract its files
         into the output folder
        """
        try:
            print("Sending Download request for TE report for file {}".format(self.file_name))
            response = requests.get(url=self.url + "download?id=" + self.report_id, verify=False)
            encoded_content_string = response.text
            decoded_content = base64.b64decode(encoded_content_string)
            decoded_report_archive_path = os.path.join(self.output_folder, self.file_name + ".report.tar.gz")
            decoded_report_archive_file = open(decoded_report_archive_path, "wb+")
            decoded_report_archive_file.write(decoded_content)
            report_dir = os.path.join(self.output_folder, self.file_name + "_report")
            if not os.path.exists(report_dir):
                os.mkdir(report_dir)
            report_tar = tarfile.open(decoded_report_archive_path)
            report_tar.extractall(report_dir)
            report_tar.close()
            print("TE report for file {} is in sub-directory: {}".format(self.file_name, report_dir))
        except Exception as E:
            print("Downloading TE report for file {} failed:  {} ".format(self.file_name, E))

    def handle_file(self):
        """
        (Function description is within above class description)
        """
        query_cache_response = self.check_te_cache()
        cache_status_label = query_cache_response['response'][0]['status']['label']
        if cache_status_label == "FOUND":
            print("Results already exist in TE cache for file {}".format(self.file_name))
            self.final_response = query_cache_response
            self.final_status_label = cache_status_label
        else:
            print("No results in TE cache before upload for file {}".format(self.file_name))
            upload_response = self.upload_file()
            upload_status_label = upload_response["response"][0]["status"]["label"]
            if upload_status_label == "UPLOAD_SUCCESS":
                query_response = self.query_file()
                query_status_label = query_response["response"][0]["status"]["label"]
                print("Receiving Query response with te results for file {}. status: {}".format(self.file_name,
                                                                                                query_status_label))
                self.final_response = query_response
                self.final_status_label = query_status_label
            else:
                self.final_response = upload_response
                self.final_status_label = upload_status_label
        self.create_response_info(self.final_response)
        if self.final_status_label == "FOUND":
            verdict = parse_verdict(self.final_response, "te")
            if verdict == "Malicious":
                self.parse_report_id(self.final_response)
                if self.report_id != "":
                    self.download_report()
