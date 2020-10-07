import tp_log
import tp_req_templates
import te_results
from te_results import TeResults
from tex_results import TexResults
import json
import requests
import base64
import hashlib
import time
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SECONDS_TO_WAIT = 5
MAX_RETRIES = 120


def print_feature(feature, no_print):
    """
    Logging purpose
    """
    return "" if no_print else (", " + feature)


def print_te_eb(found_te_eb):
    """
    Logging purpose
    """
    return print_feature("te_eb", found_te_eb)


class TpFileHandling(object):
    """
    This class gets a file as input and handles it as follows (function handle_file) :
      1. Query TE cache and AV cache by the file md5
      2. If not found in TE cache, then :
        2.1 If found in AV cache, then write the av results to av_response_info/ sub-directory.
        2.2 Upload the file to the appliance for handling by the features:  te, te_eb, scrub (tex) and
              av (if not already found in cache)
        2.3 If te result is upload_success :
          2.3.1 Write scrub (tex) upload results to tex_response_info/ sub-directory.
                 If tex managed to clean the file, then also write that cleaned file to tex_clean_files/ sub-directory.
          2.3.2 Query te, av and te_eb until receiving te results.
                 If in between receiving te_eb found results of the early malicious verdict, then display the verdict.
                 If in between receiving av results, then write the av results to av_response_info/ sub-directory.
      3. Write the te results to te_response_info/ sub-directory.
           If result verdict is malicious then also download the TE report and write it to te_reports/ sub-directory.
    """
    def __init__(self, url, api_key, file_name, file_path, output_folders, cert_file):
        self.url = url
        self.api_key = api_key
        self.file_name = file_name
        self.file_path = file_path
        self.output_folders = output_folders
        self.cert_file = cert_file
        self.upload_request = tp_req_templates.get_te_av_tex_upload_request_template()
        self.query_request = tp_req_templates.get_te_av_query_request_template()
        self.md5 = ""
        self.outer_te_final_response = ""
        self.te_has_found_status = False    # default init
        self.av_has_found_status = False    # default init
        self.av_signature = ""
        self.te = TeResults(url, file_name, output_folders.te_response_info, output_folders.te_reports)

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

    def print_av(self):
        """
        Logging purpose
        """
        return print_feature("av", self.av_has_found_status)

    def get_file_type(self):
        """
        :return the file's extension
        """
        if "." in self.file_name:
            return self.file_name.split('.')[-1]
        return ""

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

    def write_av_response_info(self, response):
        """
        Create the AV response info of handled file and write it into av_response_info/ sub-folder.
        In addition, in case av results include malware signature, then set the av_signature class member accordingly.
        :param response: the outer te part within handled file response that has av results
        """
        try:
            self.av_has_found_status = True
            av_response_info = te_results.create_single_feature_response(response, "te", "te_eb")
            self.log("AV response with results : {}".format(av_response_info))
            output_path = os.path.join(self.output_folders.av_response_info, self.file_name)
            output_path += ".response.txt"
            with open(output_path, 'w') as file:
                file.write(json.dumps(av_response_info))
            self.av_signature = av_response_info["av"]["malware_info"]["signature_name"]
            if self.av_signature:
                self.log_print("Found malicious by AV.  Signature : {}".format(self.av_signature))
            else:
                self.log_print("Not malicious by AV")
        except Exception as E:
            self.log_print("Create av response info failed: {} ".format(E))
            raise

    def query_file_before_upload(self):
        """
        Single query the appliance for TE cache results (if any exist)
        :return the query response
        """
        try:
            request = self.query_request
            request['request'][0]['api_key'] = self.api_key
            request['request'][0]['md5'] = self.md5
            data = json.dumps(request)
            self.log_print("Sending TE and AV Query request before upload in order to check TE cache and AV cache")
            self.log("TE and AV Query request : {}".format(request))
            response = requests.post(url=self.url, data=data, verify=(self.cert_file if self.cert_file else False))
            response_j = response.json()
            return response_j
        except Exception as E:
            self.log_print("Query file before upload failed : {} ".format(E))
            raise

    def check_te_cache_and_av_cache(self):
        """
        Query (before upload) both te cache and av cache by the file md5 in order to find out whether handled file
         results already exist in TE cache and/or in AV cache.
        If results already exist in AV cache then write them into av_response_info/ sub-folder.
        :return true - if results already exist in TE cache,  false - otherwise
        """
        try:
            self.set_file_md5()
            response = self.query_file_before_upload()
            te_av_cache_response = response["response"][0]["te"]    # the outer te part of the response
            combined_status_label = te_av_cache_response["status"]["label"]
            if combined_status_label in ["FOUND", "PARTIALLY_FOUND"]:
                te_status_label = te_av_cache_response["te"]["status"]["label"]
                if te_status_label == "FOUND":
                    self.log_print("Results already exist in TE cache")
                    self.log("Query response with TE cache results : {}".format(te_av_cache_response))
                    self.outer_te_final_response = te_av_cache_response
                    return True
                else:
                    av_status_label = te_av_cache_response["av"]["status"]["label"]
                    if av_status_label == "FOUND":
                        self.log_print("Results already exist in AV cache")
                        self.write_av_response_info(te_av_cache_response)
            if not self.av_has_found_status:
                self.log_print("No results in AV cache")
            self.log_print("No results in TE cache")
            return False
        except Exception as E:
            self.log_print("Check TE & AV cache failed: {} ".format(E))
            raise

    def prepare_request_for_upload(self):
        """
        Prepare all upload request required attributes.
        :return the prepared request
        """
        try:
            request = self.upload_request
            # update request fields
            request['request'][0]['api_key'] = self.api_key
            request['request'][0]['file_orig_name'] = self.file_name
            # update "te_options" fields
            request['request'][0]['te_options']['file_name'] = self.file_name
            request['request'][0]['te_options']['file_type'] = self.get_file_type()
            # If already received av cache results then remove av feature from the upload request
            if self.av_has_found_status:
                request['request'][0]['te_options']['features'].remove('av')
            self.log("Upload request (excluding file_enc_data) : {}".format(request))
            # update file_enc_data as the last one (for the purpose of logging purpose that excludes it)
            with open(self.file_path, 'rb') as f:
                file_encoded = base64.b64encode(f.read())
            file_content = file_encoded.decode("utf-8")
            request['request'][0]['file_enc_data'] = str(file_content)
            return request
        except Exception as E:
            self.log_print("Prepare request for upload failed: {} ".format(E))
            raise

    def upload_file(self):
        """
        Upload the file to the appliance for handling by all features:  te, te_eb, scrub (tex) and
          av (if not already found in cache).
        :return the outer te part within the upload response
        """
        try:
            request = self.prepare_request_for_upload()
            data = json.dumps(request)
            self.log_print("Sending Upload request for te, te_eb, scrub (tex)" + self.print_av())
            try:
                response = requests.post(url=self.url, data=data, verify=(self.cert_file if self.cert_file else False))
            except Exception as E1:
                self.log_print("API Upload file failed. failure: {}".format(E1))
                raise
            response_j = response.json()
            return response_j
        except Exception as E:
            self.log_print("Upload file failed: {} ".format(E))
            raise

    def query_file_after_upload(self):
        """
        Query the appliance for te, te_eb and av of the file every SECONDS_TO_WAIT seconds.
        Repeat query until receiving te results.
        - te_eb results of early malicious verdict might be received earlier.
        - av results might be received earlier.
        :return the outer te part within the (last) query response with the handled file TE results
        """
        try:
            self.log_print("Start sending Query requests of te, te_eb" + self.print_av() + " after upload")
            request = self.query_request
            request['request'][0]['api_key'] = self.api_key
            request['request'][0]['md5'] = self.md5
            request['request'][0]['features'].append("te_eb")
            # If already received av cache results then remove av feature from the upload request
            if self.av_has_found_status:
                request['request'][0]['features'].remove('av')
            data = json.dumps(request)
            outer_te_response = json.loads('{}')
            combined_status_label = False
            te_eb_found = False
            retry_no = 0
            while (not combined_status_label) or (combined_status_label in ["PENDING", "PARTIALLY_FOUND"]):
                try:
                    self.log_print("Sending Query request of te" + print_te_eb(te_eb_found) + self.print_av())
                    if not combined_status_label:
                        self.log("te, te_eb {} Query request (the first one after upload): {}".format(self.print_av(),
                                                                                                      request))
                    response = requests.post(url=self.url, data=data,
                                             verify=(self.cert_file if self.cert_file else False))
                    response_j = response.json()
                    outer_te_response = response_j["response"][0]["te"]
                    combined_status_label = outer_te_response["status"]["label"]
                    self.log_print("te{}{} Query response combined status : {}".format(print_te_eb(te_eb_found),
                                                                                       self.print_av(),
                                                                                       combined_status_label))
                    # Found status for all features means te has results (i.e. status found for te) => exit
                    if combined_status_label == "FOUND":
                        break
                    elif combined_status_label == "PARTIALLY_FOUND":
                        te_status_label = outer_te_response["te"]["status"]["label"]
                        # te status is found means te has results => exit
                        if te_status_label == "FOUND":
                            break
                        # Any te status other than pending and partially-found means te has results => exit
                        elif (te_status_label != "PENDING") and (te_status_label != "PARTIALLY_FOUND"):
                            break
                        if not te_eb_found:
                            te_eb_status_label = outer_te_response["te_eb"]["status"]["label"]
                            if te_eb_status_label == "FOUND":
                                te_eb_found = True
                                te_eb_verdict = self.te.parse_verdict(outer_te_response, "te_eb")
                                self.log("Query response with te_eb results: {}".format(outer_te_response))
                                if te_eb_verdict == "Malicious":
                                    self.log_print("Early verdict is malicious")
                                    self.log_print("Continue Query until receiving te results")
                                request['request'][0]['features'].remove("te_eb")
                                data = json.dumps(request)
                        if not self.av_has_found_status:
                            av_status_label = outer_te_response["av"]["status"]["label"]
                            if av_status_label == "FOUND":
                                self.log_print("Received AV results")
                                self.write_av_response_info(outer_te_response)
                                request['request'][0]['features'].remove("av")
                                data = json.dumps(request)
                        # In case all te images have results (meaning none is pending) => te has results => exit
                        if te_status_label == "PARTIALLY_FOUND":
                            te_images_j_arr = outer_te_response["te"]["images"]
                            no_pending_image = True
                            for image_j in te_images_j_arr:
                                if image_j["status"] == "pending":
                                    no_pending_image = False
                                    break
                            if no_pending_image:
                                break
                    elif combined_status_label != "PENDING":
                        break
                    time.sleep(SECONDS_TO_WAIT)
                    retry_no += 1
                    if retry_no == MAX_RETRIES:
                        self.log_print("Reached query max retries.  Stop waiting for te results")
                        break
                except Exception as E1:
                    self.log_print("Handling query after upload failed. Query retry no.: {} , failure: {} ".
                                   format(retry_no, E1))
                    raise
            last_query_status_label = outer_te_response["status"]["label"]
            self.log_print("Query response status with te results: {}".format(last_query_status_label))
            self.log("Query response with te results : {}".format(outer_te_response))
            return outer_te_response
        except Exception as E:
            self.log_print("Handling query after upload failed: {} ".format(E))
            raise

    def handle_file(self):
        """
        (Function description is within above class description)
        """
        if not self.check_te_cache_and_av_cache():
            self.log_print("Uploading to appliance for TE, TEX" + print_feature("AV", self.av_has_found_status) +
                           " and te_eb handling")
            upload_response = self.upload_file()
            upload_outer_te_response = upload_response["response"][0]["te"]
            upload_status_label = upload_outer_te_response["status"]["label"]
            if upload_status_label == "UPLOAD_SUCCESS":
                self.log_print("File was uploaded")
                tex = TexResults(self.url, self.file_name, self.output_folders.tex_response_info,
                                 self.output_folders.tex_clean_files)
                tex.write_tex_results(upload_response)
                self.log("Upload response (excluding file_enc_data) : {}".format(upload_response))
                self.outer_te_final_response = self.query_file_after_upload()
            else:
                self.outer_te_final_response = upload_outer_te_response
                self.log_print("File was not uploaded. Upload status: {}".format(upload_status_label))
                # logging purpose
                upload_response["response"][0]["scrub"]["file_enc_data"] = "removed because of space issues"
                self.log("Upload response (excluding file_enc_data) : {}".format(upload_response))
        self.te.write_te_results(self.outer_te_final_response)
