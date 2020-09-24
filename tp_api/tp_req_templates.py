import copy


# Common TE+TEX Upload request template
tp_appliance_upload_request_template = {
    "request": [{
        "protocol_version": "1.1",
        "api_key": "",
        "request_name": "UploadFile",
        "file_orig_name": "",
        "file_enc_data": ""
    }]
}


# "tex_options" template for upload
tex_options_template = {
    "scrub_method": 1,
    "scrubbed_parts_codes": [1018, 1019, 1021, 1025, 1026, 1034, 1137, 1139, 1141, 1142, 1143, 1150, 1151],
    "save_original_file_on_server": False
}


# "te_options" template for upload
te_options_template = {
    "file_name": "",
    "file_type": "",
    "is_base64": True,
    "features": ["te", "te_eb", "av"],
    "te": {
        "reports_version_number": 2,
        "reports": ["summary"],
        "version_info": True,
        "return_errors": True
    }
}


# TE Query request template
te_av_query_request_template = {
    "request": [{
        "protocol_version": "1.1",
        "api_key": "",
        "request_name": "QueryFile",
        "sha1": "",
        "features": ["te", "av"],
        "te": {
            "reports_version_number": 2,
            "reports": ["summary"],
            "version_info": True,
            "return_errors": True
        }
    }]
}


def get_te_av_tex_upload_request_template():
    """
    A copy must be made to any used template so changes will not affect it.
    :return the basic request template for uploading a file to be handled by TE, TEX, te_eb and AV.
    """
    req = copy.deepcopy(tp_appliance_upload_request_template)
    req['request'][0]['te_options'] = copy.deepcopy(te_options_template)
    req['request'][0]['scrub_options'] = copy.deepcopy(tex_options_template)
    return req


def get_te_av_query_request_template():
    """
    A copy must be made to any used template so changes will not affect it.
    :return the request template for querying a file by TE and AV
    """
    return copy.deepcopy(te_av_query_request_template)
