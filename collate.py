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
REXDLTSFN = re.compile("[^/]+\.[a-zA-Z]{3,4}$")
REXDLTSEXT = re.compile("\.[^\.]{3,}$")

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

    logger.debug("capturing filenames from DLTS data")
    logger.debug("list length before replace: %s" % len(data_dlts))
    logger.debug("first item before replace: '%s'" % data_dlts[0])
    results = []
    for d in data_dlts:
        m = REXDLTSFN.search(d)
        if m:
            results.append(m.group())
        else:
            logger.warning("failed to match a filename in DLTS line '%s': IGNORED!" % d)
    data_dlts = results
    logger.debug("list length after replace: %s" % len(data_dlts))
    logger.debug("first item after replace: '%s'" % data_dlts[0])

    logger.debug("removing filename extensions from DLTS data")
    logger.debug("list length before replace: %s" % len(data_dlts))
    logger.debug("first item before replace: '%s'" % data_dlts[0])
    data_dlts = [REXDLTSEXT.sub('', d) for d in data_dlts]
    logger.debug("list length after replace: %s" % len(data_dlts))
    logger.debug("first item after replace: '%s'" % data_dlts[0])

    logger.debug("normalizing DC3 list")
    logger.debug("DC3 list contains %s filenames before normalization" % len(data_dc3))
    data_dc3 = list(set(data_dc3))
    logger.debug("DC3 list contains %s filenames after normalization" % len(data_dc3))

    logger.debug("normalizing DLTS list")
    logger.debug("DLTS list contains %s filenames before normalization" % len(data_dlts))
    data_dlts = list(set(data_dlts))
    logger.debug("DLTS list contains %s filenames after normalization" % len(data_dlts))

    # loop through DC3 lists looking for a match in DLTS
    dlts_missing = 0
    dlts_matching = 0
    outlines = []
    for d_dc3 in data_dc3:
        logger.debug("Looking for dc3 filename '%s' in DLTS data" % d_dc3)
        results = [d for d in data_dlts if d_dc3 == d]
        if len(results) == 0:
            dlts_missing = dlts_missing + 1
        else:
            dlts_matching = dlts_matching + 1
        if len(results) == 0 and args.misses:
            outlines.append("dc3 name missing in dlts: '%s'" % d_dc3)
        elif len(results) == 1 and args.matches:
            outlines.append("dc3 name matched in dlts: '%s'" % d_dc3)
        elif len(results) > 1:
            logger.warning("'%s' was matched %s times in DLTS; expected 1" % (d_dc3, len(results)))
    logger.info("In DLTS there are %s matching and %s missing filenames" % (dlts_matching, dlts_missing))

    # loop through DLTS lists looking for a match in DC3
    dc3_missing = 0
    dc3_matching = 0
    for d_dlts in data_dlts:
        logger.debug("Looking for dlts filename '%s' in dc3 data" % d_dc3)
        results = [d for d in data_dc3 if d_dlts == d]
        if len(results) == 0:
            dc3_missing = dc3_missing + 1
        else:
            dc3_matching = dc3_matching + 1
        if len(results) == 0 and args.misses:
            outlines.append("dlts name missing in dc3: '%s'" % d_dlts)
        elif len(results) == 1 and args.matches:
            outlines.append("dlts name matched in dc3: '%s'" % d_dlts)
        elif len(results) > 1:
            logger.warning("'%s' was matched %s times in DC3; expected 1" % (d_dlts, len(results)))
    logger.info("In DC3 there are %s matching and %s missing filenames" % (dc3_matching, dc3_missing))

    outlines = sorted(outlines)
    for line in outlines:
        print line




if __name__ == "__main__":
    log_level = DEFAULTLOGLEVEL
    log_level_name = logging.getLevelName(log_level)
    logging.basicConfig(level=log_level)

    try:
        parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument ("-l", "--loglevel", type=str, help="desired logging level (case-insensitive string: DEBUG, INFO, WARNING, ERROR" )
        parser.add_argument ("-v", "--verbose", action="store_true", default=False, help="verbose output (logging level == INFO")
        parser.add_argument ("-vv", "--veryverbose", action="store_true", default=False, help="very verbose output (logging level == DEBUG")
        parser.add_argument ("--matches", action="store_true", default=False, help="output only the matches")
        parser.add_argument ("--misses", action="store_true", default=True, help="output only filenames that don't match")
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
        if args.misses and args.matches:
            args.misses = False
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
