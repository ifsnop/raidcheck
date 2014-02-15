#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" monitord.py - Starts automatic SASS-C processes when new files are written."""

__author__ = "Diego Torres"
__copyright__ = "Copyright (C) 2014 Diego Torres <diego dot torres at gmail dot com>"

# Requires Python >= 2.7

import functools
import sys
import os
import statvfs                  # free space on partition
import time
import pprint
import datetime
import sys, getopt              # command line arguments
import ctypes
import platform                 # get_free_space_bytes()
import re                       # regexp
import stat                     # interface to stat.h (get filesize, owner...)
import errno                    # to fail stat with proper codes
from math import log            # format_size()
import sqlite3
import pyinotify

config = { 'db_file' : None,
    'recursive' : False,
    'watch_path' : './',
    'self': 'monitord.py'
    }

#cookie_dict = {}

class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        self.process(event)

    def process_IN_DELETE(self, event):
        self.process(event)

    def process_IN_MOVED_TO(self, event):
        #print 'in moved to'
        #pprint.pprint(event)
        self.process(event)

    def process_IN_MOVED_FROM(self, event):
        #print 'in moved from'
        #pprint.pprint(event)
        #cookie_dict[event.cookie] = event.path
        self.process(event)

    def process_IN_MOVE_SELF(self, event):
        self.process(event)

    def process_IN_CLOSE_WRITE(self, event):
        self.process(event)

    def process_IN_Q_OVERFLOW(self, event):
        print '{0} ! error overflow'\
            .format(format_time())
        return

    def process_default(self, event):
        #sys.stdout.write("=default=" + '\n' + format_time() + pprint.pformat(event) + '\n')
        return

    def process(self, event):
        #<Event dir=False mask=0x8 maskname=IN_CLOSE_WRITE name=q.qw11 path=/tmp/l pathname=/tmp/l/q.qw11 wd=4 >
        #sys.stdout.write("=process=" + format_time() + " " + pprint.pformat(event) + '\n')

        #return True
        file = {'nameext' : event.name,
                'path' : os.path.normpath(event.path),
                'pathnameext' : os.path.normpath(event.pathname),
                'name' : os.path.splitext(event.name)[0],
                'ext' : os.path.splitext(event.pathname)[1],
                'size' : -1,
                'event' : event.maskname,
                'dir' : event.dir
        }

        # only sometimes when maskname==IN_MOVED_TO
        if hasattr(event, 'src_pathname'):
            file['src'] = event.src_pathname

        try:
            filestat = os.stat(file['pathnameext'])
            file['size'] = filestat.st_size
        except OSError as e:
            # print e.strerror
            if e.errno != errno.ENOENT: # ignore file not found
                print "!!!!!!!!!!!!!!!!!!!!!!!!raised error!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                raise
            else:
                filestat = None
                #print "some file/dir was deleted, so no stat possible"

        time.sleep(2)
        print '{0} > filename({1}) filesize({2}) extension({3}) operation({4})'\
                .format(format_time(), file['nameext'], format_size(file['size']), \
                file['ext'], file['event'])

        #update_database(file)

        #if filestat is None:
        #    return False
        #if not stat.S_ISREG(filestat.st_mode):
        #    return False

        return True

def format_time():
    t = datetime.datetime.now()
    s = t.strftime('%Y-%m-%d %H:%M:%S.%f')
    tail = s[-7:]
    f = str('%0.3f' % round(float(tail),3))[2:]
    return '%s.%s' % (s[:-7], f)

def format_size(num):
    """Human friendly file size"""
    unit_list = zip(['B', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi'], [0, 0, 1, 2, 2, 2])
    if num > 1:
        exponent = min(int(log(num, 1024)), len(unit_list) - 1)
        quotient = float(num) / 1024**exponent
        unit, num_decimals = unit_list[exponent]
        format_string = '{:.%sf}{}' % (num_decimals)
        return format_string.format(quotient, unit)
    if num == 0 or num == 1:
        return str(num) + 'B'

def get_free_space_bytes(folder = './'):
    """ Return folder/drive free space (in bytes) """
    folder = str(folder)
    if platform.system() == 'Windows':
        free_bytes = ctypes.c_ulonglong(0)
        ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p(folder), None, None, ctypes.pointer(free_bytes))
        return free_bytes.value
    else:
        f = os.statvfs(folder)
        return f[statvfs.F_BAVAIL] * f[statvfs.F_FRSIZE]

def check_free_space(paths, free_bytes_limit):
    for path in paths:
        if get_free_space_bytes(path)<free_bytes_limit:
            return path
    return True

def sha1_file(filename):
    import hashlib
    with open(filename, 'rb') as f:
        return hashlib.sha1(f.read()).hexdigest()

def update_database(file):
    if config['db_file'] is None:
        return True

    if file['event'] == 'IN_DELETE_SELF': return True
    if file['event'][:9] == 'IN_CREATE': return True
    if file['event'][:9] == 'IN_DELETE' and file['dir']: return True
    #if file['event'][:9] == 'IN_CREATE' and file['dir']: return True

    time.sleep(2)

    print '{0} + file ({1}) with action ({2})'.format(format_time(), file['nameext'], file['event'])

    upathnameext = unicode(file['pathnameext'], sys.getfilesystemencoding())
    if 'src' in file:
        usrc = unicode(file['src'], sys.getfilesystemencoding())
    #else:
    #    file['event'] = 'IN_CLOSE_WRITE'

    if file['event'] == 'IN_MOVED_TO' and 'src' not in file:
        file['event'] = 'IN_CLOSE_WRITE'

    #sys.stdout.write(format_time() + pprint.pformat(file) + '\n')

    conn = sqlite3.connect(config['db_file'], detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    conn.commit()
    conn.close()
    return True

    if file['event'] == 'IN_CLOSE_WRITE':
        c.execute('''SELECT pathnameext, size, sha1, ts_create, ts_update, status
            FROM files WHERE pathnameext=?''', [upathnameext])
        row = c.fetchone()
        if row is None:
            print '{0} > adding({1})'.format(format_time(), file['pathnameext'])
            c.execute('''INSERT INTO files (pathnameext, size, ts_create, ts_update, status) VALUES
                (?,?,?,?,?)''', [upathnameext, file['size'], datetime.datetime.now(),
                datetime.datetime.now(), 'updated'])
        else:
            print '{0} > updating({1})'.format(format_time(), file['pathnameext'])
            c.execute('''UPDATE files SET status=?, ts_update=?
                WHERE pathnameext=?''', ['updated', datetime.datetime.now(), upathnameext])

    elif file['event'][:9] == 'IN_DELETE' or file['event'] == 'IN_MOVED_FROM':
        print '{0} > deleting({1})'.format(format_time(), file['pathnameext'])
        c.execute('''DELETE FROM files WHERE pathnameext=?''', [upathnameext])

    elif file['event'] == 'IN_MOVED_TO':
        c.execute('''SELECT pathnameext, size, sha1, ts_create, ts_update, status
            FROM files WHERE pathnameext=?''', [usrc])
        row = c.fetchone()
        if row is not None:
            print '{0} > renaming({1}=>{2})'.format(format_time(), file['src'], file['pathnameext'])
            c.execute('''UPDATE files SET status=?, ts_update=?, pathnameext=?
                WHERE pathnameext=?''', ['updated', datetime.datetime.now(), upathnameext, usrc])
        else:
            print '{0} > adding({1})'.format(format_time(), file['pathnameext'])
            c.execute('''INSERT INTO files (pathnameext, size, ts_create, ts_update, status) VALUES
                (?,?,?,?,?)''', [upathnameext, file['size'], datetime.datetime.now(),
                datetime.datetime.now(), 'updated'])

    elif file['event'] == 'IN_MOVED_TO|IN_ISDIR':
        #print "renaming lots of files len(" + str(len(usrc)) + ") str(" + usrc + ")"
        #print "SELECT pathnameext, size, sha1, ts_create, ts_update, status FROM files WHERE SUBSTR(pathnameext, 0," + str(len(usrc)+2) + ")='" + usrc + "/'"
        c.execute('''SELECT pathnameext, size, sha1, ts_create, ts_update, status
            FROM files WHERE SUBSTR(pathnameext, 0, ?)=?''', [len(usrc)+2, usrc + '/'])
        rows = c.fetchall()
        for row in rows:
            #print "renamed dir, update inside files dir(" + usrc + ') upathnameext(' + upathnameext + ') row(' + row['pathnameext'] + ') len(usrc)=' + str(len(usrc)) + '\n'
            newname =  upathnameext +  '/' + row['pathnameext'][len(usrc)+1:]
            #print ">" + newname + '<\n'
            print '{0} > renaming({1}=>{2})'.format(format_time(), row['pathnameext'], newname)
            c.execute('''UPDATE files SET status=?, ts_update=?, pathnameext=?
                WHERE pathnameext=?''', ['updated', datetime.datetime.now(), newname, row['pathnameext']])

    #elif file['event'] == 'IN_CREATE':
    #    print "new directory, nothing to do..."

    conn.commit()
    conn.close()

def main(argv):
    def usage():
        print 'usage: ', argv[0], '[-h|--help]'
        print '                 [-r|--recursive]'
        print '                 -w|--watch-path <path>'
        print
        print 'Starts automatic filesystm monitoring'
        print
        print ' -d, --db-file            sqlite path to store sha1 signatures'
        print '                          default to \'' + str(config['db_file']) + '\''
        print ' -r, --recursive          descent into subdirectories'
        print '                          defaults to', str(config['recursive'])
        print ' -w, --watch-path <path>  where to look for new files'
        print '                          defaults to \'' + config['watch_path'] + '\''

    try:
        opts, args = getopt.getopt(argv[1:], 'hd:rw:', ['help',
            'db-file=', 'recursive', 'watch-path='])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt,arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit()
        elif opt in ('-r', '--recursive'):
            config['recursive'] = True
        elif opt in ('-d', '--db-file'):
            config['db_file'] = arg
        elif opt in ('-w', '--watch-path'):
            config['watch_path'] = os.path.abspath(arg)

    config['self'] = argv[0]

    print '{0} > {1} init'.format(format_time(), config['self'])
    print '{0} > options: db-file({1})'.format(format_time(), config['db_file'])
    print '{0} > options: recursive({1})'.format(format_time(), config['recursive'])
    print '{0} > options: watch-path({1}) free_bytes({2})'.format(format_time(), config['watch_path'], format_size(get_free_space_bytes(config['watch_path'])))

    if config['db_file'] is not None:
        print '{0} > update phase 1'.format(format_time())
        conn = sqlite3.connect(config['db_file'], detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='files'")
        if c.fetchone()[0] != 1:
            c.execute('''CREATE TABLE files
                (pathnameext text, size integer, sha1 text, ts_create timestamp,
                ts_update timestamp, status text, UNIQUE (pathnameext))''')

        print '{0} > update phase 2'.format(format_time())
        for root, dirs, files in os.walk(config['watch_path'], topdown=True):
            for name in files:
                pathnameext = os.path.join(root, name)
                upathnameext = unicode(pathnameext, sys.getfilesystemencoding())
                size = -1
                try:
                    filestat = os.stat(pathnameext)
                    size = filestat.st_size
                except OSError as e:
                    print e.strerror
                    if e.errno != errno.ENOENT: # ignore file not found
                        raise
                    #else:
                        #print "some file/dir was deleted, so no stat possible"
                if size == -1:
                    break

                #print pathnameext + ":" + str(size)
                c.execute('''SELECT pathnameext, size FROM files WHERE pathnameext=?''', [upathnameext])
                row = c.fetchone()
                if row is None:
                    print '{0} > adding({1})'.format(format_time(), pathnameext)
                    c.execute('''INSERT INTO files (pathnameext, size, ts_create, ts_update, status) VALUES
                        (?,?,?,?,?)''', [upathnameext, size, datetime.datetime.now(),
                        datetime.datetime.now(), 'updated'])
                elif row['size'] != size:
                    print '{0} > updating({1})'.format(format_time(), pathnameext)
                    c.execute('''UPDATE files SET status=?, ts_update=?, size=?
                        WHERE pathnameext=?''', ['updated', datetime.datetime.now(), size, upathnameext])

        print '{0} > update phase 3'.format(format_time())
        uwatch_path = unicode(config['watch_path'], sys.getfilesystemencoding())
        c.execute('''SELECT pathnameext, size, sha1, ts_create, ts_update, status
            FROM files WHERE SUBSTR(pathnameext, 0, ?)=?''', [len(uwatch_path)+2, uwatch_path + '/'])
        rows = c.fetchall()
        for row in rows:
            #print row['pathnameext']
            #"renamed dir, update inside files dir(" + usrc + ') upathnameext(' + upathnameext + ') row(' + row['pathnameext'] + ') len(usrc)=' + str(len(usrc)) + '\n'
            #newname =  upathnameext +  '/' + row['pathnameext'][len(usrc)+1:]
            size = -1
            try:
                filestat = os.stat(row['pathnameext'])
                size = filestat.st_size
            except OSError as e:
                pass
                #if e.errno != errno.ENOENT: # ignore file not found
                #    raise
                #else:
                #    print "some file/dir was deleted, so no stat possible"

            pathnameext = unicode(row['pathnameext']).encode('utf8')
            upathnameext = row['pathnameext']

            if size == -1:
                #delete from database
                print '{0} > deleting({1})'.format(format_time(), pathnameext)
                c.execute('''DELETE FROM files WHERE pathnameext=?''', [upathnameext])
            # comprobar size!!!!
            elif size != row['size']:
                print '{0} > updating({1})'.format(format_time(), pathnameext)
                c.execute('''UPDATE files SET status=?, ts_update=?, size=?
                    WHERE pathnameext=?''', ['updated', datetime.datetime.now(), size, upathnameext])

        conn.commit()
        conn.close()

    #sys.exit()

    wm = pyinotify.WatchManager()
    notifier = pyinotify.Notifier(wm, EventHandler())
    wm.add_watch(config['watch_path'],
        pyinotify.ALL_EVENTS,
        #pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MOVED_TO | pyinotify.IN_MOVED_FROM |
        #pyinotify.IN_DELETE | pyinotify.IN_DELETE_SELF | pyinotify.IN_CREATE | pyinotify.IN_Q_OVERFLOW |
        #pyinotify.IN_MOVE_SELF,
        rec=config['recursive'], auto_add=config['recursive'])
    #on_loop_func = functools.partial(on_loop, counter=Counter())
    try:
        # disabled callback counter from example, not needed
        #notifier.loop(daemonize=False, callback=on_loop_func,
        #    pid_file="/var/run/{config['self']}", stdout='/tmp/stdout.txt')
        notifier.loop(daemonize=False, callback=None,
            pid_file="/var/run/{config['self']}", stdout='/tmp/stdout.txt')

    except pyinotify.NotifierError, err:
        print >> sys.stderr, err

    return

if __name__ == "__main__":
    main(sys.argv)

"""
# using shell commands, getting output
from subprocess import PIPE, Popen

def free_volume(filename):
    #Find amount of disk space available to the current user (in bytes)
    #   on the file system containing filename.
    stats = Popen(["df", "-Pk", filename], stdout=PIPE).communicate()[0]
    return int(stats.splitlines()[1].split()[3]) * 1024

http://stackoverflow.com/questions/89228/calling-an-external-command-in-python

from subprocess import call
call(["ls", "-l"])

The advantage of subprocess vs system is that it is more flexible (you can get the stdout, stderr, the "real" status code, better error handling, etc...). I think os.system is deprecated, too, or will be:

http://docs.python.org/library/subprocess.html#replacing-older-functions-with-the-subprocess-module

For quick/dirty/one time scripts, os.system is enough, though.

"""
"""
class Counter(object):
    def __init__(self):
        self.count = 0
    def plusone(self):
        self.count += 1
"""
"""
def on_loop(notifier, counter):
    # Dummy function called after each event loop
    if counter.count > 49:
        # Loops 49 times then exits.
        sys.stdout.write("Exit\n")
        notifier.stop()
        sys.exit(0)
    else:
    sys.stdout.write("Loop %d\n" % counter.count)
    counter.plusone()
    time.sleep(2)
"""