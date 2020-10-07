import json
import requests
import os
import hashlib
import time
import copy
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SECONDS_TO_WAIT = 2
MAX_RETRIES = 20


class AV(object):
    """
    This class gets a file as input and handles it as follows (function handle_file) :
     1. Query AV cache by the file md5 for already existing AV results.
     2. If not found in AV cache then :
       2.1 Upload the file to the appliance for handling by av feature.
       2.2 If upload result is upload_success (meaning no AV results yet) then :
             Query av feature until receiving AV results.
     3. Write the AV results (last query/upload response info) into the relevant output folder.
    """
    def __init__(self, url, file_name, file_path, output_folder):
        self.url = url
        self.file_name = file_name
        self.file_path = file_path
        self.request_template = {
            "request": [{
                "features": ["av"]
            }]
        }
        self.output_folder = output_folder
        self.md5 = ""
        self.final_response = ""
        self.final_status_label = ""
        self.report_id = ""

    def print(self, msg):
        """
        Logging purpose
        """
        print("file {} : {}".format(self.file_name, msg))

    def set_file_md5(self):
        """
        Calculates the file's md5
        """
        md5 = hashlib.md5()
        with open(self.file_path, 'rb') as f:
            while True:
                block = f.read(2 ** 10)  # One-megabyte blocks
                if not block:
                    break
                md5.update(block)
            self.md5 = md5.hexdigest()

    def create_response_info(self, response):
        """
        Create the AV response info of handled file and write it into the output folder.
        :param response: last response
        """
        output_path = os.path.join(self.output_folder, self.file_name)
        output_path += ".response.txt"
        with open(output_path, 'w') as file:
            file.write(json.dumps(response))

    def check_av_cache(self):
        """
        Query (for av) the file (before upload) in order to find whether file results already exist in AV cache.
        :return the query response
        """
        self.set_file_md5()
        request = copy.deepcopy(self.request_template)
        request['request'][0]['md5'] = self.md5
        self.print("md5: {}".format(self.md5))
        data = json.dumps(request)
        self.print("Sending AV Query request before upload in order to check AV cache")
        response = requests.post(url=self.url + "query", data=data, verify=False)
        response_j = response.json()
        return response_j

    def upload_file(self):
        """
        Upload the file to the appliance for av and get the upload response.
        :return the upload response
        """
        request = copy.deepcopy(self.request_template)
        data = json.dumps(request)
        curr_file = {
            'request': data,
            'file': open(self.file_path, 'rb')
        }
        self.print("Sending Upload request of av")
        try:
            response = requests.post(url=self.url + "upload", files=curr_file, verify=False)
        except Exception as E:
            self.print("Upload file failed: {}".format(E))
            raise
        response_j = response.json()
        self.print("av Upload response status : {}".format(response_j["response"][0]["status"]["label"]))
        return response_j

    def query_file(self):
        """
        Query the appliance for av of the file every SECONDS_TO_WAIT seconds.
        Repeat query until receiving av results.
        :return the (last) query response with the handled file AV results
        """
        self.print("Start sending Query requests of av after AV upload")
        request = copy.deepcopy(self.request_template)
        request['request'][0]['md5'] = self.md5
        data = json.dumps(request)
        response_j = json.loads('{}')
        status_label = False
        retry_no = 0
        while (not status_label) or (status_label == "NOT_FOUND"):
            self.print("Sending Query request for av")
            response = requests.post(url=self.url + "query", data=data, verify=False)
            response_j = response.json()
            status_label = response_j['response'][0]['status']['label']
            if status_label != "NOT_FOUND":
                break
            self.print("av Query response status is still pending")
            time.sleep(SECONDS_TO_WAIT)
            retry_no += 1
            if retry_no == MAX_RETRIES:
                self.print("Reached query max retries.  Stop waiting for av results")
                break
        return response_j

    def handle_file(self):
        """
        (Function description is within above class description)
        """
        query_cache_response = self.check_av_cache()
        cache_status_label = query_cache_response['response'][0]['status']['label']
        if cache_status_label == "FOUND":
            self.print("Results already exist in AV cache for")
            self.final_response = query_cache_response
            self.final_status_label = cache_status_label
        else:
            self.print("No results in AV cache before upload")
            upload_response = self.upload_file()
            upload_status_label = upload_response["response"][0]["status"]["label"]
            if upload_status_label == "UPLOAD_SUCCESS":
                query_response = self.query_file()
                query_status_label = query_response["response"][0]["status"]["label"]
                self.print("Receiving Query response with av results. status: {}".format(query_status_label))
                self.final_response = query_response
                self.final_status_label = query_status_label
            else:
                self.final_response = upload_response
                self.final_status_label = upload_status_label
        self.create_response_info(self.final_response)
        if self.final_status_label == "FOUND":
            signature = self.final_response["response"][0]["av"]["malware_info"]["signature_name"]
            if signature:
                self.print("was found malicious by AV.  Signature : {}".format(signature))
            else:
                self.print("was found clean by AV")
