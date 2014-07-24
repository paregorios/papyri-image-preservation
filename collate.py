#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
collate DLTS and DC3 lists of papyrological images
"""

import argparse
from functools import wraps
import logging
import os
import re
import sys
import traceback

DEFAULTLOGLEVEL = logging.WARNING

REXJP2 = re.compile("\.jp2$")

def arglogger(func):
    """
    decorator to log argument calls to functions
    """
    @wraps(func)
    def inner(*args, **kwargs): 
        logger = logging.getLogger(func.__name__)
        logger.debug("called with arguments: %s, %s" % (args, kwargs))
        return func(*args, **kwargs) 
    return inner    


@arglogger
def main (args):
    """
    main functions
    """
    logger = logging.getLogger(sys._getframe().f_code.co_name)

    logger.debug("reading DLTS list: '%s'" % args.filename_dlts)
    f = open(args.filename_dlts, 'r')
    data_dlts = f.readlines()
    f.close()
    logger.debug("read %s lines" % len(data_dlts))
    logger.debug("chomping lines in DLTS list")
    data_dlts = [d.rstrip() for d in data_dlts]

    logger.debug("reading DC3 list: '%s'" % args.filename_dc3)
    f = open(args.filename_dc3, 'r')
    data_dc3 = f.readlines()
    f.close()
    logger.debug("read %s lines" % len(data_dlts))
    logger.debug("chomping lines in DC3 list")
    data_dc3 = [d.rstrip() for d in data_dc3]

    logger.debug("removing filename extensions from DC data")
    logger.debug("first item before replace: '%s'" % data_dc3[0])
    data_dc3 = [REXJP2.sub('', d) for d in data_dc3]
    logger.debug("first item after replace: '%s'" % data_dc3[0])




if __name__ == "__main__":
    log_level = DEFAULTLOGLEVEL
    log_level_name = logging.getLevelName(log_level)
    logging.basicConfig(level=log_level)

    try:
        parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument ("-l", "--loglevel", type=str, help="desired logging level (case-insensitive string: DEBUG, INFO, WARNING, ERROR" )
        parser.add_argument ("-v", "--verbose", action="store_true", default=False, help="verbose output (logging level == INFO")
        parser.add_argument ("-vv", "--veryverbose", action="store_true", default=False, help="very verbose output (logging level == DEBUG")
        parser.add_argument('filename_dc3', type=str, help="filename with path for the DC3 list of files")
        parser.add_argument('filename_dlts', type=str, help="filename with path for the DLTS list of files")
        args = parser.parse_args()
        if args.loglevel is not None:
            args_log_level = re.sub('\s+', '', args.loglevel.strip().upper())
            try:
                log_level = getattr(logging, args_log_level)
            except AttributeError:
                logging.error("command line option to set log_level failed because '%s' is not a valid level name; using %s" % (args_log_level, log_level_name))
        if args.veryverbose:
            log_level = logging.DEBUG
        elif args.verbose:
            log_level = logging.INFO
        log_level_name = logging.getLevelName(log_level)
        logging.getLogger().setLevel(log_level)
        if log_level != DEFAULTLOGLEVEL:
            logging.warning("logging level changed to %s via command line option" % log_level_name)
        else:
            logging.info("using default logging level: %s" % log_level_name)
        logging.debug("command line: '%s'" % ' '.join(sys.argv))
        main(args)
        sys.exit(0)
    except KeyboardInterrupt, e: # Ctrl-C
        raise e
    except SystemExit, e: # sys.exit()
        raise e
    except Exception, e:
        print "ERROR, UNEXPECTED EXCEPTION"
        print str(e)
        traceback.print_exc()
        os._exit(1)
