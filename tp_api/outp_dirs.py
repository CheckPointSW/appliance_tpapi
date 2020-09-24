import os.path
import time
import tp_log


def mkdir_force(curr_path):
    """create a directory if it doesn't exist"""
    if not os.path.exists(curr_path):
        os.mkdir(curr_path)


class OutputDirectories(object):
    """
    create the required output directories
    """
    def __init__(self, root_folder):
        date = time.strftime("%d_%m_%Y_%H_%M_%S")
        self.root_today_folder = root_folder + "/" + date
        tp_log.log_and_print("Current results directory is: {}".format(self.root_today_folder))
        self.tex_response_info = self.root_today_folder + "/" + "tex_response_info"
        self.tex_clean_files = self.root_today_folder + "/" + "tex_clean_files"
        self.te_response_info = self.root_today_folder + "/" + "te_response_info"
        self.te_reports = self.root_today_folder + "/" + "te_reports"
        self.av_response_info = self.root_today_folder + "/" + "av_response_info"
        self.create_directories()

    def create_directories(self):
        """
        1. create the general output folder by date
        Then, create its following sub folders:
        2. TEX response info
        3. TEX clean files
        4. TE response info
        5. TE reports
        6. AV response info
        """
        try:
            tp_log.log_and_print("Pre-processing: creating output subdirectories")
            mkdir_force(self.root_today_folder)
            mkdir_force(self.tex_response_info)
            mkdir_force(self.tex_clean_files)
            mkdir_force(self.te_response_info)
            mkdir_force(self.te_reports)
            mkdir_force(self.av_response_info)
        except Exception as E:
            tp_log.log_and_print("could not create output subdirectories, because: {}".format(E))
