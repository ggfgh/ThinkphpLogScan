from pocsuite3.lib.core.data import logger

def main():
    logger.error("error content")
    logger.debug("debug content")
    logger.info("info content")
    logger.critical("critical content")
    logger.warning("warning content")
    logger.info("Successfully found!!")
    logger.debug("debut content!!!")

if __name__ == "__main__":
    main()