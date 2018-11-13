#!/usr/bin/env python
#
# @descr    Checks max open files status for both system and per-process
#
# @author   Johan Hedberg <mail@johan.pp.se>
#

from argparse import ArgumentParser
from ctypes import CDLL, c_int32, c_ulong, c_void_p, Structure, POINTER, byref
from ctypes.util import find_library
from os import listdir
from psutil import pids
from resource import RLIMIT_NOFILE
from sys import exit

libc = CDLL(find_library("c"))
pid_t = c_int32
rlim_t = c_ulong


class rlimit(Structure):
    _fields_ = [('rlim_cur', rlim_t), ('rlim_max', rlim_t)]


# Nagios states
STATE_OK = 0
STATE_WARN = 1
STATE_CRIT = 2
STATE_UNKNOWN = 3

status_txt_mapper = {
    0: 'OK',
    1: 'WARNING',
    2: 'CRITICAL',
    3: 'UNKNOWN'
}

status = STATE_OK
status_str = ""
status_list = []

# Argument parsing
parser = ArgumentParser(description='Checks max open files status')
parser.add_argument('-c', metavar='<crit-percent>', required=False, default=90,
                    help='Percent of used filehandles to treat as critical')
parser.add_argument('-w', metavar='<warn-percent>', required=False, default=80,
                    help='Percent of used filehandles to treat as a warning')
args = parser.parse_args()


# Functions
def lsof(pid):
    try:
        path = "/proc/{}/fd".format(pid)
        fds = listdir(path)
        return len(fds)
    except OSError:
        return 0


# Getting system-wide limits
with open('/proc/sys/fs/file-nr') as f:
    (kern_openf, temp, kern_maxf) = f.read().rstrip().split("\t")
pc = round(float(kern_openf) / float(kern_maxf) * 100, 2)
if pc >= args.w and pc < args.c:
    status = STATE_WARN
    status_list.append("System-wide open files reached {}% of max ({})".format(pc, kern_maxf))
if pc >= args.c:
    status = STATE_CRIT


# Getting per pid limits
for pid in pids():
    pid_rlim = rlimit()
    libc.prlimit.argtypes = [pid_t, c_int32, c_void_p, POINTER(rlimit)]
    libc.prlimit(pid, RLIMIT_NOFILE, None, byref(pid_rlim))
    numf = lsof(pid)
    try:
        pc = round(float(numf) / float(pid_rlim.rlim_cur) * 100, 2)
    except ZeroDivisionError:
        pc = 0
    if pc >= args.w:
        try:
            with open('/proc/{}/comm'.format(pid)) as f:
                comm = f.read().strip()
        except OSError:
            comm = "Unknown"
        except IOError:
            comm = "Unknown"
    if pc >= args.c:
        status = STATE_CRIT
        status_list.append("PID {}({}) open files reached {}% of max ({})".format(pid, comm, pc, pid_rlim.rlim_cur))
    elif pc >= args.w:
        if status != STATE_CRIT:
            status = STATE_WARN
        status_list.append("PID {}({}) open files reached {}% of max ({})".format(pid, comm, pc, pid_rlim.rlim_cur))


# Exiting with proper status and message
if status == STATE_OK:
    status_str = "Both system-wide and per-process open files are well within their limits."
else:
    status_str = ", ".join(status_list)
status_str = "{}: {}".format(status_txt_mapper[status], status_str)
print status_str
exit(status)
