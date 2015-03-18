#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" monitord.py - Hashes files using inotify events."""

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
import pyinotify
from Queue import Queue
import threading
import contextlib
import collections
from contextlib import contextmanager
from collections import defaultdict
import resource
import shutil
import signal
import bz2

config = { 'db_file' : None,
    'recursive' : False,
    'watch_path' : [],          # list of watched paths
    'wd' :  {},                 # dict of watched descriptors
    'self': None,
    'database': None,
    'vacuum': False,
    'queue' : Queue(),
    'salir' : False,
    'ready' : False,
    'timeout_status' : 600,
    'consistent_start' : True,
    'max_grouped_events' : 9,   # starting in 0
    'nice'  : False             # sleep 0.1s between hashes
}


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

    # Schema setup and migration.

    #def _make_table(self, table, fields):
    #    """Set up the schema of the database. `fields` is a mapping
    #    from field names to `Type`s. Columns are added if necessary.
    #    """
    #    # Get current schema.
    #    with self.transaction() as tx:
    #        rows = tx.query('PRAGMA table_info(%s)' % table)
    #    current_fields = set([row[1] for row in rows])
    #
    #    field_names = set(fields.keys())
    #    if current_fields.issuperset(field_names):
    #        # Table exists and has all the required columns.
    #        return
    #
    #    if not current_fields:
    #        # No table exists.
    #        columns = []
    #        for name, typ in fields.items():
    #            columns.append('{0} {1}'.format(name, typ.sql))
    #        setup_sql = 'CREATE TABLE {0} ({1});\n'.format(table,
    #                                                       ', '.join(columns))
    #
    #    else:
    #        # Table exists does not match the field set.
    #        setup_sql = ''
    #        for name, typ in fields.items():
    #            if name in current_fields:
    #                continue
    #            setup_sql += 'ALTER TABLE {0} ADD COLUMN {1} {2};\n'.format(
    #                table, name, typ.sql
    #            )
    #
    #    with self.transaction() as tx:
    #        tx.script(setup_sql)
    #
    #def _make_attribute_table(self, flex_table):
    #    """Create a table and associated index for flexible attributes
    #    for the given entity (if they don't exist).
    #    """
    #    with self.transaction() as tx:
    #        tx.script("""
    #            CREATE TABLE IF NOT EXISTS {0} (
    #                id INTEGER PRIMARY KEY,
    #                entity_id INTEGER,
    #                key TEXT,
    #                value TEXT,
    #                UNIQUE(entity_id, key) ON CONFLICT REPLACE);
    #            CREATE INDEX IF NOT EXISTS {0}_by_entity
    #                ON {0} (entity_id);
    #            """.format(flex_table))
    #
    # Querying.
    #
    #def _fetch(self, model_cls, query=None, sort=None):
    #    """Fetch the objects of type `model_cls` matching the given
    #    query. The query may be given as a string, string sequence, a
    #    Query object, or None (to fetch everything). `sort` is an
    #    `Sort` object.
    #    """
    #    query = query or TrueQuery()  # A null query.
    #    sort = sort or NullSort()  # Unsorted.
    #    where, subvals = query.clause()
    #    order_by = sort.order_clause()
    #
    #    sql = ("SELECT * FROM {0} WHERE {1} {2}").format(
    #        model_cls._table,
    #        where or '1',
    #        "ORDER BY {0}".format(order_by) if order_by else '',
    #    )
    #
    #    with self.transaction() as tx:
    #        rows = tx.query(sql, subvals)
    #
    #    return Results(
    #        model_cls, rows, self,
    #        None if where else query,  # Slow query component.
    #        sort if sort.is_slow() else None,  # Slow sort component.
    #    )
    #
    #def _get(self, model_cls, id):
    #    """Get a Model object by its id or None if the id does not
    #    exist.
    #    """
    #    return self._fetch(model_cls, MatchQuery('id', id)).get()

class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        self.process(event)

    def process_IN_DELETE(self, event):
        self.process(event)

    def process_IN_MOVED_TO(self, event):
        self.process(event)

    def process_IN_MOVED_FROM(self, event):
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

        f = {'nameext' : event.name,
                'path' : os.path.normpath(event.path),
                'pathnameext' : os.path.normpath(event.pathname),
                'name' : os.path.splitext(event.name)[0],
                'ext' : os.path.splitext(event.pathname)[1],
                'size' : None,
                'event' : event.maskname,
                'dir' : event.dir,
                'cookie': None,
                'src': None
        }

        # only sometimes when maskname==IN_MOVED_TO
        if hasattr(event, 'src_pathname'):
            f['src'] = event.src_pathname
        if hasattr(event, 'cookie'):
            f['cookie'] = event.cookie

        g = get_file_stat(f['pathnameext'])
        # even if g is None, event should be generated to detect file renaming

        # don't uncomment
        #if not g:
        #    return True

        f = dict(f.items() + g.items())

        #print '{0} > EP0 > file({1}) size({2}) with action({3}) src({4}) cookie({5})'.format(
        #        format_time(), f['pathnameext'], format_size(f['size']),
        #        f['event'], f['src'], f['cookie'])

        config['queue'].put(f)
        return True

def get_file_stat(file):

    f = dict()

    try:
        s = os.stat(file)
        f['size'] = s.st_size
        try:
            f['atime'] = str(datetime.datetime.fromtimestamp(s.st_atime))
        except ValueError as e:
            print '{0} error formating time of file({1}) atime({2:.3f})'.format(
                format_time(), file, s.st_atime)
            f['atime'] = 0
            #sys.exit(2)
        try:
            f['mtime'] = str(datetime.datetime.fromtimestamp(s.st_mtime))
        except ValueError as e:
            print '{0} error formating time of file({1}) mtime({2:.3f})'.format(
                format_time(), file, s.st_mtime)
            f['mtime'] = 0
        try:
            f['ctime'] = str(datetime.datetime.fromtimestamp(s.st_ctime))
        except ValueError as e:
            print '{0} error formating time of file({1}) ctime({2:.3f})'.format(
                format_time(), file, s.st_ctime)
            f['ctime'] = 0

    except OSError as e:
        if e.errno == errno.ENOENT:
            #f = None
            #print '{0} file({1}) was deleted'.format(
            #    format_time(), file)
            return f
        else: # if error different from not found
            print '{0} unexpected error({1}) when stat\'ing file({2})'.format(
                format_time(), e.strerror, file)
            raise
    except Exception as e:
        print '{0} file({1}) raised and unhandled exception type({2}) args({3})'.format(
            format_time(), file, type(e), e.args)

    return f

def format_time():
    t = datetime.datetime.now()
    s = t.strftime('%Y-%m-%d %H:%M:%S.%f')
    tail = s[-7:]
    f = str('%0.3f' % round(float(tail),3))[2:]
    return '%s.%s|%s' % (s[:-7], f, threading.current_thread().name)

def format_time_file():
    t = datetime.datetime.now()
    s = t.strftime('%Y%m%d%H%M%S')
    return s

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
    if time>0: # and size>1000000:
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

class BGWorkerQueuer(threading.Thread):
    def __init__(self, config, name):
        threading.Thread.__init__(self, name = name)
        self.config = config
        print '{0} > bgworkerQueuer spawned'.format(format_time())

    def run(self):
        #while not self.config['ready']:
        #    time.sleep(1)
        #print '{0} > bgworkerQueuer ready'.format(format_time())
        while not self.config['salir']:
            #print '{0} > tic'.format(format_time())
            time0 = None
            i = 0
            while not self.config['queue'].empty():
                if time0 is None:
                    time0 = time.time()
                item = self.config['queue'].get()
                # only insert in database if file/dir was stated successfully
                #if item['size'] is not None:
                # removed files need to be updated from database and have no size
                self.update_database(item)
                i += 1
                if i>self.config['max_grouped_events']:
                    break
            if time0 is None:
                time.sleep(1)
            else :
                time1 = time.time() - time0
                print '{0} > processing {1} event(s) for {2:.2f} secs'.format(format_time(), i, time1)
                sys.stdout.flush()

        print '{0} > bgworkerQueuer ended'.format(format_time())
        sys.stdout.flush()
        return True

    def update_database(self, f):
        #print '{0} > EP1 > file({1}) size({2}) with action({3}) src({4}) cookie({5})'.format(
        #    format_time(), f['pathnameext'], format_size(f['size']),
        #    f['event'], f['src'], f['cookie'])

        if f['event'] == 'IN_MOVE_SELF': return True
        if f['event'] == 'IN_DELETE_SELF': return True
        if f['event'][:9] == 'IN_CREATE': return True
        if f['event'][:9] == 'IN_DELETE' and f['dir']: return True
        #if f['event'] == 'IN_MOVED_FROM': return True #move file outside watched dir
        #if f['event'] == 'IN_MOVED_FROM|IN_ISDIR' and f['cookie'] is not None: return True # necesario para rename dir, pero no funciona para mover fuera
        if f['event'] == 'IN_MOVED_TO' and f['src'] is None: f['event'] = 'IN_CLOSE_WRITE'

        #print '{0} > EP2 > file({1}) size({2}) with action({3}) src({4}) cookie({5})'.format(
        #    format_time(), f['pathnameext'], format_size(f['size']),
        #    f['event'], f['src'], f['cookie'])

        with self.config['database'].transaction() as tx:
            minverified = get_min_verified()
            #rows = tx.query("SELECT MIN(verified) AS min FROM files WHERE status=?",['hashed']);
            #if not rows:
            #    minverified = 0
            #else:
            #    minverified = rows[0]['min'];

            if f['event'] == 'IN_CLOSE_WRITE':

                if f['size'] is None:
                    print '{0} > event(A0) file({1}) has None size, see before, we should return now'.format(format_time(), f['pathnameext'])
                    return

                rows = tx.query("SELECT pathnameext, size, atime, mtime, ctime FROM files WHERE pathnameext=?", (f['pathnameext'],))
                if not rows:
                    print '{0} > event(A1) adding({1})'.format(format_time(), f['pathnameext'])
                    tx.query("INSERT INTO files (pathnameext, size, hash, atime, mtime, ctime, verified, ts_create, ts_update, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        [f['pathnameext'], f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                        datetime.datetime.now(), datetime.datetime.now(), 'created'])
                else:
                    row = rows[0] # duplicated code from stage3()
                    if f['size'] != row['size']:
                        print '{0} > event(B1) updating ({1}) because file was modified'.format(format_time(), row['pathnameext'])
                        tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                            (f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                            datetime.datetime.now(), 'created', row['pathnameext'],))
                        #config['consistent_start'] = False
                    elif f['mtime'] != row['mtime'] or f['ctime'] != row['ctime']:
                        if f['mtime'] != row['mtime'] and f['ctime'] != row['ctime']:
                            print '{0} > event(B2) updating with modified file({1})'.format(format_time(), row['pathnameext'])
                            tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                                (f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                                datetime.datetime.now(), 'created', row['pathnameext'],))
                            #config['consistent_start'] = False
                        elif f['mtime'] != row['mtime']:
                            #print '{0} > event(B3) (can\'t happen, ctime should be modified also) updating with modified file({1})'.format(format_time(), row['pathnameext'])
                            print '{0} > event(B3) (mtime only) updating with modified file({1})'.format(format_time(), pathnameext)
                            tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                                (f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                                datetime.datetime.now(), 'created', row['pathnameext'],))
                        elif f['ctime'] != row['ctime']:
                            print '{0} > event(B4) updating inode information from file({1})'.format(format_time(), row['pathnameext'])
                            tx.query("UPDATE files SET ctime=?, ts_update=? WHERE pathnameext=?",
                                [f['ctime'], datetime.datetime.now(), row['pathnameext']])

                    #tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                    #    [f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                    #    datetime.datetime.now(), 'created', f['pathnameext']])

            elif f['event'][:9] == 'IN_DELETE':
                print '{0} > event(C) deleting({1})'.format(format_time(), f['pathnameext'])
                tx.query("DELETE FROM files WHERE pathnameext=?", (f['pathnameext'],))
            elif f['event'] == 'IN_MOVED_FROM':
                print '{0} > event(I) temporary deleting({1})'.format(format_time(), f['pathnameext'])
                tx.query("UPDATE files SET status=?, ts_update=? WHERE pathnameext=? AND status=?",
                    ['deleted_hashed;' + str(f['cookie']), datetime.datetime.now(), f['pathnameext'], 'hashed'])
                tx.query("UPDATE files SET status=?, ts_update=? WHERE pathnameext=? AND status=?",
                    ['deleted_created;' + str(f['cookie']), datetime.datetime.now(), f['pathnameext'], 'created'])

            elif f['event'] == 'IN_MOVED_FROM|IN_ISDIR' and not f['src']: # directory was moved away from watched dir, delete all files inside directory from database
                dir_path = f['pathnameext'] + '/'
                print '{0} > event(D) deleting({1})'.format(format_time(), dir_path)
                rows = tx.query("SELECT COUNT(*) AS count FROM files WHERE SUBSTR(pathnameext, 0, ?)=?",
                    (len(dir_path)+1, dir_path,))
                print '{0} > temporary deleting ({1}) files from ({2})'.format(format_time(), rows[0]['count'], dir_path)
                #tx.query("DELETE FROM files WHERE SUBSTR(pathnameext, 0, ?)=?",
                    #(len(dir_path)+1, dir_path,))
                tx.query("UPDATE files SET status=?, ts_update=? WHERE SUBSTR(pathnameext, 0, ?)=? AND status=?",
                    ['deleted_hashed;' + str(f['cookie']), datetime.datetime.now(), len(dir_path)+1, dir_path, 'hashed'])
                tx.query("UPDATE files SET status=?, ts_update=? WHERE SUBSTR(pathnameext, 0, ?)=? AND status=?",
                    ['deleted_created;' + str(f['cookie']), datetime.datetime.now(), len(dir_path)+1, dir_path, 'created'])

            elif f['event'] == 'IN_MOVED_TO':
                rows = tx.query("SELECT pathnameext, size, hash, ts_create, ts_update, status FROM files WHERE pathnameext=? AND status LIKE ?",
                    [f['src'], 'deleted%;' + str(f['cookie'])])
                if rows:
                    print '{0} > event(E) renaming({1}=>{2})'.format(format_time(), f['src'], f['pathnameext'])
                    # delete destination from database, maybe we are overwriting
                    tx.query("DELETE FROM files WHERE pathnameext=?", (f['pathnameext'],))
                    # renames in samba usually change twice the ctime field, so lets get the more recent update
                    g = get_file_stat(f['pathnameext'])
                    if g:
                        newstatus = rows[0]['status'].split("_")[1].split(";")[0]
                        tx.query("UPDATE files SET atime=?, mtime=?, ctime=?, ts_update=?, pathnameext=?, status=? WHERE pathnameext=?",
                            (g['atime'], g['mtime'], g['ctime'], datetime.datetime.now(), f['pathnameext'], newstatus, f['src'],))
                    else:
                        print '{0} > event(E1) failed while renaming, file({1}) doesn\'t exist, ignoring'.format(format_time(), f['pathnameext'])
                        # write code to handle this failure, deleting f['src'] from db because there was no destination in rename

                else:
                    # moved and not in database, but check before
                    if f['size'] is None:
                        print '{0} > event(F0) file({1}) has None size, see before, we should return now'.format(format_time(), f['pathnameext'])
                        return

                    print '{0} > event(F) adding({1})'.format(format_time(), f['pathnameext'])
                    rows = tx.query("SELECT pathnameext, status FROM files WHERE pathnameext=?", [f['pathnameext']])
                    if rows:
                        #for row in rows:
                        #    print row['pathnameext'], row['status'], '\n'
                        #    #pprint.pprint(row)
                        tx.query("DELETE FROM files WHERE pathnameext=?", [f['pathnameext']])

                    tx.query("INSERT INTO files (pathnameext, size, hash, atime, mtime, ctime, verified, ts_create, ts_update, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (f['pathnameext'], f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified, datetime.datetime.now(), datetime.datetime.now(), 'created',))

            elif f['event'] == 'IN_MOVED_TO|IN_ISDIR':
                if f['src'] is not None: # directory renaming
                    print '{0} > event(G) renamed dir({1}=>{2})'.format(format_time(), f['src'], f['pathnameext'])
                    rows = tx.query("SELECT pathnameext, size, hash, ts_create, ts_update, status FROM files WHERE SUBSTR(pathnameext, 0, ?)=? AND status LIKE ?",
                        [len(f['src'])+2, f['src'] + '/','deleted_%;' + str(f['cookie'])])
                    for row in rows:
                        newname =  f['pathnameext'] +  '/' + row['pathnameext'][len(f['src'])+1:]
                        newstatus = row['status'].split("_")[1].split(";")[0]
                        print '{0} > renaming({1}=>{2})'.format(format_time(), row['pathnameext'], newname)
                        tx.query("UPDATE files SET ts_update=?, pathnameext=?, status=? WHERE pathnameext=?",
                            [datetime.datetime.now(), newname, newstatus, row['pathnameext']])
                else:
                    print '{0} > event(H) moved new dir({1}) inside watched tree'.format(format_time(), f['pathnameext'])
                    # update all files inside new dir!
                    for root, dirs, files in os.walk(f['pathnameext'], topdown=True):
                        for name in files:
                            pathnameext = os.path.join(root, name)
                            f = get_file_stat(pathnameext)
                            if f:
                                rows = tx.query("SELECT pathnameext, size, atime, mtime, ctime, verified, ts_create, ts_update FROM files WHERE pathnameext=?",
                                    (pathnameext,))
                                if not rows:
                                    print "{0} > event(H1) adding({1})".format(format_time(), pathnameext)
                                    tx.query("INSERT INTO files (pathnameext, size, hash, atime, mtime, ctime, verified, ts_create, ts_update, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                        (pathnameext, f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                                        datetime.datetime.now(), datetime.datetime.now(), 'created',))
                                elif rows[0]['size'] != f['size'] or rows[0]['mtime'] != f['mtime'] or rows[0]['ctime'] != f['ctime']:
                                    # when moving a directory from outside watched tree, if dest dir exists, then an event
                                    # of move is raised for each file, not for the dir. we could never arrive here.
                                    print "{0} > event(H2) updating({1}) [should never happen!]".format(format_time(), pathnameext)
                                    tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                                        (f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified, datetime.datetime.now(), 'created', pathnameext,))
                            else:
                                print "{0} > event(H3) file({1}) doesn\'t exist, ignoring".format(format_time(), pathnameext)

        return

class BGWorkerHasher(threading.Thread):

    def __init__(self, config, name):
        threading.Thread.__init__(self, name = name)
        self.config = config
        print '{0} > bgworkerHasher spawned'.format(format_time())

    def run(self):
        while not self.config['salir']:
            pathnameext = self.get_file();
            if pathnameext is not None:
                #print '{0} > found hash candidate({1})'.format(format_time(), repr(pathnameext))
                #print '{0} > found hash candidate({1})'.format(format_time(), pathnameext)
                hash = hash_file(pathnameext)
                if hash is None:
                    print '{0} > couldn\'t calculate hash for file({1}), file no longer available'.format(format_time(), pathnameext)
                    remove_from_db(pathnameext)
                    #tx.query("DELETE FROM files WHERE pathnameext=?", [pathnameext])
                else:
                    #print '{0} > ({1}) => hash({2})'.format(format_time(), pathnameext, hash)
                    self.store_hash(pathnameext, hash)
                    if self.config['nice']:
                        time.sleep(0.1)
                sys.stdout.flush()
            else:
                time.sleep(1)

        print '{0} > bgworkerHasher ended'.format(format_time())
        sys.stdout.flush()
        return True

    def get_file(self):
        with self.config['database'].transaction() as tx:
            rows = tx.query('''SELECT pathnameext, size, hash, ts_create, ts_update, status
                FROM files WHERE status=? ORDER BY RANDOM() LIMIT 1''', ['created'])
            if rows:
                #print '{0} > found hashing candidate ({1})'.format(format_time(), rows[0]['pathnameext'])
                pathnameext = rows[0]['pathnameext']
                #pathnameext = pathnameext.encode('UTF-8')
            else:
                #print '{0} > database already processed'.format(format_time())
                pathnameext = None
        return pathnameext

    def store_hash(self, pathnameext, hash):
        with self.config['database'].transaction() as tx:
            rows = tx.query('''SELECT pathnameext, size, hash, ts_create, ts_update, status
                FROM files WHERE pathnameext=? AND status=? LIMIT 1''', [pathnameext, 'created'])
            #row = c.fetchone()
            if not rows:
                print '{0} > file({1}) is no longer available in database'.format(format_time(), pathnameext)
            else:
                tx.query('''UPDATE files SET hash=?, status=?, ts_update=? WHERE pathnameext=? AND status=?''',
                    [hash['hash'], 'hashed', datetime.datetime.now(), pathnameext, 'created'])
                print '{0} > stored file({1}) with hash({2}) in ({3})'.format(format_time(),
                    pathnameext, hash['hash'], calculate_speed(rows[0]['size'], hash['time']))
        return

class BGWorkerVerifier(threading.Thread):

    def __init__(self, config, name):
        threading.Thread.__init__(self, name = name)
        self.config = config
        print '{0} > bgworkerVerifier spawned'.format(format_time())

    def run(self):
        while not self.config['salir']:
            while not self.config['salir'] and self.config['ready']:
                pathnameext = self.get_file();
                if pathnameext is not None:
                    hash = hash_file(pathnameext)
                    if hash is None:
                        print '{0} > couldn\'t calculate hash for file({1}), file no longer available'.format(format_time(), pathnameext)
                        # remove file from database, because can't be accessed
                        remove_from_db(pathnameext)
                    else:
                        self.verify_hash(pathnameext, hash)
                        sys.stdout.flush()
                    for i in range(60):
                        if self.config['salir']:
                            break
                        else:
                            time.sleep(1)
                else:
                    time.sleep(1)
            if not self.config['salir']:
                time.sleep(1)

        print '{0} > bgworkerVerifier ended'.format(format_time())
        sys.stdout.flush()
        return True

    def get_file(self):
        with self.config['database'].transaction() as tx:
            rows = tx.query("SELECT pathnameext FROM files WHERE status=? AND verified<=(SELECT MIN(verified) FROM files) AND hash IS NOT NULL ORDER BY RANDOM() LIMIT 1",
                ['hashed']);
                #"SELECT pathnameext, size, hash, ts_create, ts_update, status FROM files WHERE status=? ORDER BY verified, ts_update LIMIT 1", ['hashed'])
                #"SELECT pathnameext FROM files WHERE status=? GROUP BY pathnameext HAVING verified<=MIN(verified) ORDER BY RANDOM() LIMIT 1",
            if rows:
                pathnameext = rows[0]['pathnameext']
                #print '{0} > found verifying candidate ({1})'.format(format_time(), pathnameext)
            else:
                pathnameext = None
        return pathnameext

    def verify_hash(self, pathnameext, hash):
        with self.config['database'].transaction() as tx:
            rows = tx.query('''SELECT pathnameext, size, hash, ts_create, ts_update, status
                FROM files WHERE pathnameext=? AND status=? LIMIT 1''', [pathnameext, 'hashed'])
            if not rows:
                print '{0} > file({1}) is no longer available in database'.format(format_time(), pathnameext)
            else:
                if rows[0]['hash'] == hash['hash']:
                    tx.query('''UPDATE files SET verified=verified+1,ts_update=? WHERE pathnameext=? AND status=?''',
                        [datetime.datetime.now(), pathnameext, 'hashed'])
                    print '{0} > verified file({1}) with hash({2}) at ({3})'.format(format_time(),
                        pathnameext, hash['hash'], calculate_speed(rows[0]['size'], hash['time']))
                else:
                    print '{0} > not verified file({1}) with dbhash({2}) hash({3}) at ({4})'.format(
                        format_time(), pathnameext, rows[0]['hash'], hash['hash'],
                        calculate_speed(rows[0]['size'], hash['time']))
                    self.config['salir'] = True
        return
"""
    def remove_from_db(self, pathnameext):

        with config['database'].transaction() as tx:
            #print '{0} > searching for deletion ({1})'.format(format_time(), pathnameext)
            rows = tx.query("SELECT pathnameext FROM files WHERE pathnameext=?",
                (pathnameext,))
            if rows:
                print '{0} > deleting({1}) from database'.format(format_time(), pathnameext)
                tx.query("DELETE FROM files WHERE pathnameext=?",
                    (pathnameext,))
        return
"""

class BGWorkerStatus(threading.Thread):

    def __init__(self, config, name):
        threading.Thread.__init__(self, name = name)
        self.config = config
        self.created = None
        self.hashed = None
        self.verified = None
        self.deleted = None
        print '{0} > bgworkerStatus spawned'.format(format_time())

    def run(self):
        while not self.config['salir']:
            with self.config['database'].transaction() as tx:
                """ purge files marked as deleted during a in_moved_from event
                because it is impossible to differentiate between a rename and a move """
                rowsd = tx.query("SELECT COUNT(*) as count, SUM(size) as size FROM files WHERE status LIKE ? AND ts_update < ?",
                    ['deleted_%', datetime.datetime.now() - datetime.timedelta(hours=1)])
                deleted = rowsd[0]['count']
                if deleted>0:
                    tx.query("DELETE FROM files WHERE status LIKE ? AND ts_update < ?",
                        ['deleted_%', datetime.datetime.now() - datetime.timedelta(minutes=1)])

                minverified = get_min_verified()
                #rows = tx.query("SELECT MIN(verified) AS min FROM files WHERE status=?",['hashed']);
                #minverified = rows[0]['min'];

                """ fix hashed files without hash, should never happen """
                rows = tx.query("SELECT COUNT(*) as count FROM files WHERE hash IS NULL AND status=?", ['hashed'])
                if rows[0]['count'] > 0:
                    print "{0} > fixing {1} file(s) hashed without hash".format(format_time(), rows[0]['count'])
                    tx.query("UPDATE files SET hash = NULL, status=?, verified=?, ts_update=? WHERE hash IS NULL AND status=?",
                        ['created', minverified, datetime.datetime.now(), 'hashed'])
                    minverified = get_min_verified()

                rowsc = tx.query("SELECT COUNT(*) as count, SUM(size) as size FROM files WHERE status=?", ('created',))
                rowsh = tx.query("SELECT COUNT(*) as count, SUM(size) as size FROM files WHERE status=?", ('hashed',))
                rowsv = tx.query("SELECT COUNT(*) as count FROM files WHERE status=? AND verified=?",
                    ['hashed', minverified])
                created = rowsc[0]['count'] #[row[0] for row in rows1]
                hashed = rowsh[0]['count'] #[row[0] for row in rows2]
                verified = rowsv[0]['count']

                maxverified = get_max_verified()
                #rows = tx.query("SELECT MIN(verified) AS min FROM files WHERE status=?",['hashed']);
                #minverified = rows[0]['min']
                #rows = tx.query("SELECT MAX(verified) AS max FROM files WHERE status=?",['hashed']);
                #maxverified = rows[0]['max']

                if hashed != self.hashed or created != self.created or verified != self.verified or deleted != self.deleted:
                    print "{0} > approximate queue size {1}".format(format_time(), config['queue'].qsize())
                    print "{0} > {1} files deleted using {2} have been purged".format(
                        format_time(), deleted, format_size(rowsd[0]['size']))
                    print "{0} > {1} files created using {2}".format(
                        format_time(), created, format_size(rowsc[0]['size']))
                    print "{0} > {1} files hashed using {2}".format(
                        format_time(), hashed, format_size(rowsh[0]['size']))
                    print "{0} > {1}/{2} files pending verification until next round min/max ratio ({3}/{4})".format(
                        format_time(),  verified+created, hashed, minverified, maxverified)
                    self.hashed = hashed
                    self.created = created
                    self.verified = verified
                    self.deleted = deleted
            sys.stdout.flush()
            if (self.created == 0): # don't start verifing files until there are files to verify
                self.config['ready'] = True
            else:
                self.config['ready'] = False
            for i in range(self.config['timeout_status']):
                if self.config['salir']:
                    break
                else:
                    time.sleep(1)

        print "{0} > bgworkerStatus ended".format(format_time())
        sys.stdout.flush()
        return True

def stage1():
    print "{0} > update phase 1 (check for table, purge deleted files)".format(format_time())
    with config['database'].transaction() as tx:
        rows = tx.query("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='files'")
        if rows[0][0] != 1:
            tx.query("CREATE TABLE files "
                "(pathnameext text, size integer, hash text, atime timestamp, "
                "mtime timestamp, ctime timestamp, verified integer, ts_create timestamp, "
                "ts_update timestamp, status text, UNIQUE (pathnameext))")
        tx.query("DELETE FROM files WHERE status LIKE ?", ['deleted%'])
    return True

def get_min_verified():
    with config['database'].transaction() as tx:
        rows = tx.query("SELECT MIN(verified) AS min FROM files WHERE status=?",['hashed']);
        if not rows or rows[0]['min'] is None:
            verified = 0
        else:
            verified = rows[0]['min']
    return verified

def get_max_verified():
    with config['database'].transaction() as tx:
        rows = tx.query("SELECT MAX(verified) AS max FROM files WHERE status=?",['hashed']);
        if not rows or rows[0]['max'] is None:
            verified = 0
        else:
            verified = rows[0]['max']
    return verified

def stage2():
    print "{0} > update phase 2 (correct db from watch dir change)".format(format_time())
    query = []
    where = []
    for path in config['watch_path']:
        query.append(len(path)+2)
        query.append(path + '/')
        where.append("SUBSTR(pathnameext, 0, ?)!=?")
    where = ' AND '.join(where)

    with config['database'].transaction() as tx:
        rows = tx.query("SELECT COUNT(*) FROM files WHERE " + where, query)
        #delete = [row[0] for row in rows]
        #print rows[0][0]
        if rows[0][0]!=0:
            print '{0} > deleting from db the files that are not in fs because of watch dir change({1})'.format(format_time(), rows[0][0])
            rows = tx.query("DELETE FROM files WHERE " + where, query)
            config['vacuum'] = True
    return True

def stage3():
    print "{0} > update phase 3 (check for files in fs not in db)".format(format_time())
    with config['database'].transaction() as tx:
        minverified = get_min_verified()
        for path in config['watch_path']:
            for root, dirs, files in os.walk(path, topdown=True):
                for name in files:
                    pathnameext = os.path.join(root, name)
                    f = get_file_stat(pathnameext)
                    if f:
                        rows = tx.query("SELECT pathnameext, size, atime, mtime, ctime, verified, ts_create, ts_update FROM files WHERE pathnameext=?",
                            (pathnameext,))
                        if not rows:
                            print "{0} > adding({1})".format(format_time(), pathnameext)
                            tx.query("INSERT INTO files (pathnameext, size, hash, atime, mtime, ctime, verified, ts_create, ts_update, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                (pathnameext, f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                                datetime.datetime.now(), datetime.datetime.now(), 'created',))
                            config['consistent_start'] = False
                        else:
                            row = rows[0]
                            if f['size'] != row['size']:
                                print '{0} > updating with modified file({1})'.format(format_time(), pathnameext)
                                tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                                    (f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                                    datetime.datetime.now(), 'created', row['pathnameext'],))
                                config['consistent_start'] = False
                            elif f['mtime'] != row['mtime'] or f['ctime'] != row['ctime']:
                                if f['mtime'] != row['mtime'] and f['ctime'] != row['ctime']:
                                    print '{0} > updating with modified file({1})'.format(format_time(), pathnameext)
                                    tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                                        (f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                                        datetime.datetime.now(), 'created', row['pathnameext'],))
                                    config['consistent_start'] = False
                                elif f['mtime'] != row['mtime']:
                                    #print '{0} > event(B3) (can\'t happen, ctime should be modified also) updating with modified file({1})'.format(format_time(), row['pathnameext'])
                                    print '{0} > (mtime only) updating with modified file({1})'.format(format_time(), pathnameext)
                                    tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                                        (f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                                        datetime.datetime.now(), 'created', row['pathnameext'],))
                                    config['consistent_start'] = False
                                elif f['ctime'] != row['ctime']:
                                    print '{0} > updating inode information from file({1})'.format(format_time(), pathnameext)
                                    tx.query("UPDATE files SET ctime=?, ts_update=? WHERE pathnameext=?",
                                        [f['ctime'], datetime.datetime.now(), row['pathnameext']])
                    else:
                        print '{0} > file({1}) can\'t be found, ignoring'.format(format_time(), pathnameext)

    return True

def stage4():
    print '{0} > update phase 4 (check for files in db not in fs)'.format(format_time())
    #uwatch_path = unicode(config['watch_path'], sys.getfilesystemencoding())
    with config['database'].transaction() as tx:
        minverified = get_min_verified()
        for path in config['watch_path']:
            rows = tx.query("SELECT pathnameext, size, hash, atime, mtime, ctime, verified, ts_create, ts_update, status FROM files WHERE SUBSTR(pathnameext, 0, ?)=?",
                [len(path) + 2, path + '/'])
            for row in rows:
                f = get_file_stat(row['pathnameext'])
                if not 'size' in f: # realmente cont "not f:" también debería funcionar
                    #print '{0} > deleting({1})'.format(format_time(), row['pathnameext'])
                    remove_from_db(row['pathnameext'])
                    #tx.query("DELETE FROM files WHERE pathnameext=?", (row['pathnameext'],))
                    config['vacuum'] = True
                    config['consistent_start'] = False
                elif f['size'] != row['size']:
                    print '{0} > updating with modified file({1})'.format(format_time(), pathnameext)
                    tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                        (f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                        datetime.datetime.now(), 'created', row['pathnameext'],))
                    config['consistent_start'] = False
                elif f['mtime'] != row['mtime'] or f['ctime'] != row['ctime']:
                    if f['mtime'] != row['mtime'] and f['ctime'] != row['ctime']:
                        print '{0} > updating with modified file({1})'.format(format_time(), row['pathnameext'])
                        tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                            (f['size'], None, f['atime'], f['mtime'], f['ctime'], minverified,
                            datetime.datetime.now(), 'created', row['pathnameext'],))
                        config['consistent_start'] = False
                    elif f['mtime'] != row['mtime']:
                        print '{0} > (can\'t happen, ctime should me modified also) updating with modified file({1})'.format(format_time(), row['pathnameext'])
                    elif f['ctime'] != row['ctime']:
                        print '{0} > updating inode information from file({1})'.format(format_time(), row['pathnameext'])
                        tx.query("UPDATE files SET ctime=?, ts_update=? WHERE pathnameext=?",
                            [f['ctime'], datetime.datetime.now(), row['pathnameext']])

        #rows = tx.query("SELECT COUNT(*) FROM files WHERE SUBSTR(pathnameext, 0, ?)!=?",
        #    [len(config['watch_path']) + 2, config['watch_path'] + '/'])
        ##delete = [row[0] for row in rows]
        #if (rows[0][0]!=0):
        #    print '{0} > deleting from db not in fs because of watch dir change({1})'.format(format_time(), rows[0][0])
        #    rows = tx.query("DELETE FROM files WHERE SUBSTR(pathnameext, 0, ?)!=?",
        #        [len(config['watch_path']) + 2, config['watch_path'] + '/'])
        #    config['vacuum'] = True

        if (config['vacuum']):
            tx.query("VACUUM");
            config['consistent_start'] = False

    return

def remove_from_db(pathnameext):
    with config['database'].transaction() as tx:
        #print '{0} > searching for deletion ({1})'.format(format_time(), pathnameext)
        rows = tx.query("SELECT pathnameext FROM files WHERE pathnameext=?", [pathnameext])
        if rows:
            print '{0} > deleting({1}) from database'.format(format_time(), pathnameext)
            tx.query("DELETE FROM files WHERE pathnameext=?", [pathnameext])
    return

def signal_handler(signal, frame):
        print('You Killed!')
        config['salir'] = True

def compress_file(comp_obj, source_file, dest_file):
    source = file(source_file, "r")
    dest = file(dest_file, "w")
    block = source.read(2048*2048)
    while block:
        c_block = comp_obj.compress(block)
        dest.write(c_block)
        block = source.read(2048*2048)
    c_block= comp_obj.flush()
    dest.write(c_block)
    source.close()
    dest.close()
    os.remove(source_file)
    return True

def main(argv):
    def usage():
        print 'usage: ', argv[0]
        print '    [-h|--help]'
        print '    -d|--db-file <file>'
        print '    [-r|--recursive]'
        print '    -w|--watch-path <path>'
        print
        print 'Starts automatic filesystem monitoring'
        print
        print '    -d, --db-file            sqlite path to store hash(sha1) signatures, required'
        print '                             default to \'' + str(config['db_file']) + '\''
        print '    -r, --recursive          descent into subdirectories, optional'
        print '                             defaults to', str(config['recursive'])
        print '    -w, --watch-path <path>  where to look for new files, optional'
        print '                             accepts several path, repeat as desired'

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
            if not os.path.isdir(os.path.abspath(arg)):
                print '{0} > specified path({1}) does not exists'.format(format_time(), os.path.abspath(arg))
                usage()
                sys.exit(2)
            config['watch_path'].append(os.path.abspath(arg))

    config['self'] = argv[0]

    if config['db_file'] is None:
        usage()
        sys.exit()

    if config['watch_path'] is None:
        usage()
        sys.exit()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    threading.current_thread().setName('m')

    print '{0} > {1} init'.format(format_time(), config['self'])
    print '{0} > options: db-file({1})'.format(format_time(), config['db_file'])
    print '{0} > options: recursive({1})'.format(format_time(), config['recursive'])

    resource.setrlimit(resource.RLIMIT_NOFILE, (16384, 16384))

    print '{0} > max open files configured to soft,hard{1}'.format(
        format_time(), (resource.getrlimit(resource.RLIMIT_NOFILE)))

    config['database'] = Database(config['db_file'])
    transaction = Transaction(config['database'])

    sys.stdout.flush()

    pyinotify.log.setLevel(50)
    wm = pyinotify.WatchManager()
    notifier = pyinotify.Notifier(wm, EventHandler(), timeout=10*1000)
    mask = pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MOVED_TO | pyinotify.IN_MOVED_FROM |\
        pyinotify.IN_DELETE | pyinotify.IN_DELETE_SELF | pyinotify.IN_CREATE | pyinotify.IN_Q_OVERFLOW |\
        pyinotify.IN_MOVE_SELF
    # |\
    #mask = pyinotify.ALL_EVENTS

    for path in config['watch_path']:
        print '{0} > options: watch-path({1}) free_bytes({2})'.format(format_time(), path, format_size(get_free_space_bytes(path)))

    config['wd'] = wm.add_watch(config['watch_path'],
        mask,
        rec=config['recursive'],
        auto_add=config['recursive'])
        #on_loop_func = functools.partial(on_loop, counter=Counter())

    abort = False
    for key in config['wd']:
        if config['wd'][key] == -1:
            print '{0} > couldn\'t open path({1})'.format(format_time(), key)
            abort = True

    if abort:
        print '{0} > error creating watches, maybe you should try:'.format(format_time())
        print 'sysctl -n -w fs.inotify.max_user_watches=16384'
        sys.exit(-1);

    stage1()
    sys.stdout.flush()

    backup_timestamp = "~" + format_time_file()
    shutil.copyfile(config['db_file'], config['db_file'] + backup_timestamp)

    stage2()
    sys.stdout.flush()

    thread_BGWorkerQueuer1 = BGWorkerQueuer(config, "q")
    thread_BGWorkerQueuer1.start()

    stage3()
    sys.stdout.flush()
    stage4()
    sys.stdout.flush()

    if not config['consistent_start']:
        print '{0} > database was not in a consistent state, fixed'.format(format_time())
        ret = compress_file(bz2.BZ2Compressor(), config['db_file'] + backup_timestamp, config['db_file'] + backup_timestamp + ".bz2");
        if ret == True:
            print '{0} > database backup writen as {1}'.format(format_time(), config['db_file'] + backup_timestamp + ".bz2")
    else:
        os.remove(config['db_file'] + backup_timestamp)

    #thread_BGWorkerQueuer2 = BGWorkerQueuer(config, "q2")
    #thread_BGWorkerQueuer2.start()
    #thread_BGWorkerQueuer3 = BGWorkerQueuer(config, "q3")
    #thread_BGWorkerQueuer3.start()

    thread_BGWorkerHasher = BGWorkerHasher(config, "h")
    thread_BGWorkerHasher.start()
    thread_BGWorkerStatus = BGWorkerStatus(config, "s")
    thread_BGWorkerStatus.start()
    thread_BGWorkerVerifier = BGWorkerVerifier(config, "v")
    thread_BGWorkerVerifier.start()

    try:
        while not config['salir']:
            notifier.process_events()
            while notifier.check_events():  #loop in case more events appear while we are processing
                notifier.read_events()
                notifier.process_events()
            #print '{0} > toc'.format(format_time())
        # disabled callback counter from example, not needed
        #notifier.loop(daemonize=False, callback=on_loop_func,
        #    pid_file="/var/run/{config['self']}", stdout='/tmp/stdout.txt')
        #notifier.loop(daemonize=False, callback=None,
        #    pid_file="/var/run/{config['self']}", stdout='/tmp/stdout.txt')

    except pyinotify.NotifierError, err:
        print >> sys.stderr, err
    except KeyboardInterrupt:
        print '{0} > waiting for all threads to end'.format(format_time())
        config['salir'] = True
        #notifier.stop()
        #sys.exit(0)

    notifier.stop()

    sys.stdout.flush()

    thread_BGWorkerQueuer1.join()
    ##thread_BGWorkerQueuer2.join()
    ##thread_BGWorkerQueuer3.join()
    thread_BGWorkerHasher.join()
    thread_BGWorkerStatus.join()
    thread_BGWorkerVerifier.join()

    sys.stdout.flush()

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

