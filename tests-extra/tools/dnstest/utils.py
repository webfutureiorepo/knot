#!/usr/bin/env python3

import enum
import inspect
import os
import re
import time

from dnstest.context import Context

SEP = "------------------------------------"

class Proto(enum.Enum):
    UDP = 0
    TCP = 1
    TLS = 2
    QUIC = 3

class Skip(Exception):
    """Exception for skipping current case."""
    pass

class Failed(Exception):
    """Exception for serious error."""
    pass

def prepare_dir(path):
    try:
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            raise Exception("Can't create directory '%s'" % path)

def test_info():
    '''Get current test case name'''

    info = ""
    frames = inspect.getouterframes(inspect.currentframe())
    for frame in frames:
        frame_dir = os.path.normpath(os.path.dirname(frame[1]))
        if Context().test_dir in frame_dir:
            if len(info) > 0:
                info += "<-%i" % frame[2]
            else:
                info = "%s#%i" % (frame_dir, frame[2])
    parts = info.split("/")

    if len(parts) > 1:
        return parts[-2] + "/" + parts[-1]
    else:
        return "dnstest"

def ssearch(s, pattern):
    found = re.search(pattern, s)
    if found is None:
        return None
    else:
        return found.groups()[0]

def fsearch(fname, pattern, pattern2=None):
    with open(fname) as f:
        for line in f:
            if pattern in line and (pattern2 is None or pattern2 in line):
                return True
    return False

def fsearch_count(fname, pattern):
    count = 0
    with open(fname) as f:
        for line in f:
            if pattern in line:
                count += 1
    return count

def check_log(text):
    '''Log message header'''

    msg = "(%s) %s (%s)\n" % (time.strftime("%H:%M:%S"), str(text), test_info())
    Context().case_log.write(msg)
    Context().case_log.flush()

def detail_log(text):
    '''Log message body'''

    msg = "%s\n" % text
    Context().case_log.write(msg)
    Context().case_log.flush()

def set_err(msg):
    '''Set error state'''

    Context().err = True
    if not Context().err_msg:
        Context().err_msg = msg

def isset(value, name):
    '''Check if value is True'''

    if not value:
        set_err("IS SET \'%s\'" % name)
        check_log("ERROR: IS SET \'%s\'" % name)
        detail_log(SEP)
        return True
    return False

def compare(value, expected, name):
    '''Compare two values'''

    if value != expected:
        set_err("COMPARE \'%s\'" % name)
        check_log("ERROR: COMPARE \'%s\'" % name)
        detail_log("  (%s) != expected (%s)" % (value, expected))
        detail_log(SEP)
        return True
    return False

def compare_sections(section1, srv1name, section2, srv2name, name):
    '''Compare two message sections'''

    different = False

    for rrset in section1:
        if rrset not in section2:
            if not different:
                different = True
                set_err("COMPARE SECTION %s" % name)
                check_log("ERROR: COMPARE SECTION %s" % name)
            detail_log("!Extra rrset %s:" % srv1name)
            detail_log("  %s" % rrset)

    for rrset in section2:
        if rrset not in section1:
            if not different:
                different = True
                set_err("COMPARE SECTION %s" % name)
                check_log("ERROR: COMPARE SECTION %s" % name)
            detail_log("!Extra rrset %s:" % srv2name)
            detail_log("  %s" % rrset)

    if different:
        detail_log(SEP)
