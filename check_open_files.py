#!/usr/bin/env python
#
# @descr    Checks max open files status for both system and per-process
#
# @author   Johan Hedberg <mail@johan.pp.se>
#

from argparse import ArgumentParser
from os import listdir
from sys import exit


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


def getlimit(pid):
    try:
        with open('/proc/{}/limits'.format(pid)) as f:
            content = f.readlines()
    except (IOError, OSError):
        return None
    for line in content:
        line = line.strip()
        if 'Max open files' in line:
            return line.split()[3]
    return None


def getpids():
    fds = listdir('/proc')
    ret = []
    for fd in fds:
        try:
            int(fd)
        except ValueError:
            continue
        ret.append(fd)
    return ret


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
for pid in getpids():
    pid_limit = getlimit(pid)
    if not pid_limit:  # Pid died during check execution
        continue
    numf = lsof(pid)
    try:
        pc = round(float(numf) / float(pid_limit) * 100, 2)
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
        status_list.append("PID {}({}) open files reached {}% of max ({})".format(pid, comm, pc, pid_limit))
    elif pc >= args.w:
        if status != STATE_CRIT:
            status = STATE_WARN
        status_list.append("PID {}({}) open files reached {}% of max ({})".format(pid, comm, pc, pid_limit))


# Exiting with proper status and message
if status == STATE_OK:
    status_str = "Both system-wide and per-process open files are well within their limits."
else:
    status_str = ", ".join(status_list)
status_str = "{}: {}".format(status_txt_mapper[status], status_str)
print status_str
exit(status)
