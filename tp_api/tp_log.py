import logging
from logging.handlers import RotatingFileHandler


# ~~~~~~~~~~~~ logger ~~~~~~~~~~~~ #
logger = logging.getLogger('tp_api_log')


def set_log(output_path):
    logger.setLevel(logging.INFO)
    fh = RotatingFileHandler(output_path + '/tp_api.log', mode='a', maxBytes=5 * 2048 * 2048, backupCount=5,
                             encoding=None, delay=False)
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)


def log_and_print(msg):
    print(msg)
    logger.info(msg)


def log(msg):
    logger.info(msg)
