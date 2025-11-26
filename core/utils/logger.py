import logging
import os

LOG_FOLDER = "logs"
os.makedirs(LOG_FOLDER, exist_ok=True)

def get_logger(name="p2p_logger"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # avoid duplicate handlers
    if logger.handlers:
        return logger
    
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(name)s %(message)s"
    )
    
    #console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    #file handler
    fh = logging.FileHandler(os.path.join(LOG_FOLDER, "app.log"))
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    return logger

logger = get_logger()