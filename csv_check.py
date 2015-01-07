#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" csv_import.py - Load a csv file to a sqlite db."""

__author__ = "Diego Torres"
__copyright__ = "Copyright (C) 2015 Diego Torres <diego dot torres at gmail dot com>"

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
import csv
from Queue import Queue
import threading
import contextlib
import collections
from contextlib import contextmanager
from collections import defaultdict
import zlib

config = { 'db_file' : None,
    'recursive' : False,
    'csv_path' : './',
    'self': None,
    'database': None,
    'vacuum': False,
    'queue' : Queue(),
    'salir' : False,
    'ready' : False,
    'timeout_status' : 600,
    'consistent_start' : True,
    'nice'  : True
}

class crc32(object):
    name = 'crc32'
    digest_size = 4
    block_size = 1

    def __init__(self, arg=''):
        self.__digest = 0
        self.update(arg)

    def copy(self):
        copy = super(self.__class__, self).__new__(__class__)
        copy.__digest = self.__digest
        return copy

    def digest(self):
        return self.__digest

    def hexdigest(self):
        return '{:08x}'.format(self.__digest)

    def update(self, arg):
        self.__digest = zlib.crc32(arg, self.__digest) & 0xffffffff

# Now you can define hashlib.crc32 = crc32
import hashlib
hashlib.crc32 = crc32
hashlib.algorithms += ('crc32',) # Python 2.7

def crc(fileName):
    prev = 0
    for eachLine in open(fileName,"rb"):
        prev = zlib.crc32(eachLine, prev)
    return "%08X"%(prev & 0xFFFFFFFF)

# Python 3.2: hashlib.algorithms_available.add('crc32')

class Transaction(object):
    """A context manager for safe, concurrent access to the database.
    All SQL commands should be executed through a transaction.
    """
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        """Begin a transaction. This transaction may be created while
        another is active in a different thread.
        """
        with self.db._tx_stack() as stack:
            first = not stack
            stack.append(self)
        if first:
            # Beginning a "root" transaction, which corresponds to an
            # SQLite transaction.
            self.db._db_lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Complete a transaction. This must be the most recently
        entered but not yet exited transaction. If it is the last active
        transaction, the database updates are committed.
        """
        with self.db._tx_stack() as stack:
            assert stack.pop() is self
            empty = not stack
        if empty:
            # Ending a "root" transaction. End the SQLite transaction.
            self.db._connection().commit()
            self.db._db_lock.release()

    def query(self, statement, subvals=(), debug=False):
        """Execute an SQL statement with substitution values and return
        a list of rows from the database.
        """
        if debug:
            print statement, subvals
        cursor = self.db._connection().execute(statement, subvals)
        return cursor.fetchall()

    def mutate(self, statement, subvals=()):
        """Execute an SQL statement with substitution values and return
        the row ID of the last affected row.
        """
        cursor = self.db._connection().execute(statement, subvals)
        return cursor.lastrowid

    def script(self, statements):
        """Execute a string containing multiple SQL statements."""
        self.db._connection().executescript(statements)


class Database(object):
    #"""A container for Model objects that wraps an SQLite database as
    #the backend.
    #"""
    #_models = ()
    #"""The Model subclasses representing tables in this database.
    #"""

    def __init__(self, path, timeout = 3):
        self.path = path

        self._connections = {}
        self._tx_stacks = defaultdict(list)

        self._timeout = timeout

        # A lock to protect the _connections and _tx_stacks maps, which
        # both map thread IDs to private resources.
        self._shared_map_lock = threading.Lock()

        # A lock to protect access to the database itself. SQLite does
        # allow multiple threads to access the database at the same
        # time, but many users were experiencing crashes related to this
        # capability: where SQLite was compiled without HAVE_USLEEP, its
        # backoff algorithm in the case of contention was causing
        # whole-second sleeps (!) that would trigger its internal
        # timeout. Using this lock ensures only one SQLite transaction
        # is active at a time.
        self._db_lock = threading.Lock()

        # Set up database schema.
        #for model_cls in self._models:
        #    self._make_table(model_cls._table, model_cls._fields)
        #    self._make_attribute_table(model_cls._flex_table)

    # Primitive access control: connections and transactions.

    def _connection(self):
        """Get a SQLite connection object to the underlying database.
        One connection object is created per thread.
        """
        thread_id = threading.current_thread().ident
        with self._shared_map_lock:
            if thread_id in self._connections:
                return self._connections[thread_id]
            else:
                # Make a new connection.
                conn = sqlite3.connect(
                    self.path,
                    self._timeout,
                )

                # Access SELECT results like dictionaries.
                conn.row_factory = sqlite3.Row

                conn.text_factory = str

                self._connections[thread_id] = conn
                return conn

    @contextlib.contextmanager
    def _tx_stack(self):
        """A context manager providing access to the current thread's
        transaction stack. The context manager synchronizes access to
        the stack map. Transactions should never migrate across threads.
        """
        thread_id = threading.current_thread().ident
        with self._shared_map_lock:
            yield self._tx_stacks[thread_id]

    def transaction(self):
        """Get a :class:`Transaction` object for interacting directly
        with the underlying SQLite database.
        """
        return Transaction(self)

def format_time():
    t = datetime.datetime.now()
    s = t.strftime('%Y-%m-%d %H:%M:%S.%f')
    tail = s[-7:]
    f = str('%0.3f' % round(float(tail),3))[2:]
    return '%s.%s' % (s[:-7], f)

def format_size(num):
    """Human friendly file size"""
    if num is None:
        num = 0
        #return None
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

def calculate_speed(size, time):
    if time>0:
        speed = format_size(size/time)
    else:
        speed = "NaN"
    return speed + "/s"

def hash_file(filename):
    ret = {}
    try:
        import hashlib
        with open(filename, 'rb') as f:
            time_start = time.time()
            ret['hash'] = hashlib.sha1(f.read()).hexdigest()
            ret['time'] = time.time() - time_start
            return ret
    except (OSError, IOError) as e:
        return None
    return None

def main(argv):
    def usage():
        print 'usage: ', argv[0], '[-h|--help]'
        print '    -d|--db-file <file>'
        print '    [-r|--recursive]'
        print '    [-p--path <path>]'
        print
        print 'Starts file checking with database'
        print
        print ' -d, --db-file <file>     sqlite path to store csv, required'
        print '                          default to \'' + str(config['db_file']) + '\''
        print ' -r, --recursive          descent into subdirectories, optional'
        print '                          defaults to', str(config['recursive'])
        print ' -p, --path <path>        where to look for csv, optional'
        print '                          defaults to \'' + config['csv_path'] + '\''

    try:
        opts, args = getopt.getopt(argv[1:], 'hd:rp:', ['help',
            'db-file=', 'recursive', 'path='])
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
        elif opt in ('-p', '--path'):
            config['path'] = os.path.abspath(arg)
            if not os.path.isdir(config['path']):
                print '{0} > specified path({1}) does not exists'.format(format_time(), config['path'])
                usage()
                sys.exit(2)

    config['self'] = argv[0]

    print '{0} > {1} init'.format(format_time(), config['self'])
    print '{0} > options: db-file({1})'.format(format_time(), config['db_file'])
    print '{0} > options: recursive({1})'.format(format_time(), config['recursive'])
    print '{0} > options: path({1}) free_bytes({2})'.format(format_time(), config['path'], format_size(get_free_space_bytes(config['path'])))

    if config['db_file'] is None:
        usage()
        sys.exit()

    config['database'] = Database(config['db_file'])
    transaction = Transaction(config['database'])

#Ellie20_extra.jpg,220794,60C27237,\2004-02\Ellie - Hot Sand 2\,
#450x340.jpg,78588,C04A50F0,\2011-09-27 - (za9220) - AXX Pledges Get it Up the Ass\,
#/ctcp valen !PSRequestCSV BBHHVID*
#tx.query("CREATE TABLE csvs "
#                "(filename text, size integer, crc32 text, path text, csv_name text)")

    with config['database'].transaction() as tx:
        rows = tx.query("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='csvs'")
        if rows[0][0] != 1:
            print '{0} > no csv inserted in db'.format(format_time())
            sys.exit(2)

        for root, dirs, files in os.walk(config['path'], topdown=True):
            for filename in files:
                pathname = os.path.join(root, filename)
                name,ext = os.path.splitext(pathname)
                s = os.stat(pathname)
                size = s.st_size
                #print pathname,s.st_size
                rows = tx.query("SELECT path, filename, crc32, csv_name FROM csvs WHERE size=?", [size])
                if not rows:
                    #print filename
                    continue

                for row in rows:
                    #print '{0} > found candidate file({1}) as file_in_csv({2}) size({3}) in csv({4})'.format(
                    #    format_time(), pathname, row['filename'], size, row['csv_name'])
                    crc32 = crc(pathname)
                    if crc32 == row['crc32']:
                        print '{0} > found file({1}) as file_in_csv({2}) crc32({3}) in csv({4})'.format(
                            format_time(), pathname, row['filename'], crc32, row['csv_name'])
                        print 'IFS {0} {1}'.format(row['csv_name'], pathname)
                    else:
                        if size>5000000:
                            print 'IFQ {0} {1} {2} "{3}{4}" {5}'.format(
                                row['csv_name'], crc32, size, row['path'], row['filename'],
                                pathname)


    return True

if __name__ == "__main__":
    main(sys.argv)
