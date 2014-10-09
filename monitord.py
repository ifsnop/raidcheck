#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" monitord.py - Hashes files using inotify events."""

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
from Queue import Queue
import threading
import contextlib
import collections
from contextlib import contextmanager
from collections import defaultdict

config = { 'db_file' : None,
    'recursive' : False,
    'watch_path' : './',
    'self': None,
    'database': None,
    'vacuum': False
}

q = Queue()
salir = [False]

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
                    #beets.config['timeout'].as_number(),
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
                'size' : -1,
                'event' : event.maskname,
                'dir' : event.dir
        }

        # only sometimes when maskname==IN_MOVED_TO
        if hasattr(event, 'src_pathname'):
            f['src'] = event.src_pathname

        g = get_file_stat(f['pathnameext'])
        f = dict(f.items() + g.items())

        #print '{0} o file ({1}) size ({2}) with action ({3})'.format(
        #        format_time(), f['nameext'], format_size(f['size']), f['event'])

        q.put(f)
        return True

def get_file_stat(file):

    f = dict()
    f['size'] = -1

    try:
        s = os.stat(file)
        f['size'] = s.st_size
        f['atime'] = str(datetime.datetime.fromtimestamp(s.st_atime))
        f['mtime'] = str(datetime.datetime.fromtimestamp(s.st_mtime))
        f['ctime'] = str(datetime.datetime.fromtimestamp(s.st_ctime))
    except OSError as e:
        # print e.strerror
        if e.errno != errno.ENOENT: # ignore file not found
            print "!!!!!!!!!!!!!!!!!!!!!!!!raised error!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            raise
        #else:
        #    f = None
            #print "some file/dir was deleted, so no stat possible"

    return f

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
    try:
        import hashlib
        with open(filename, 'rb') as f:
            return hashlib.sha1(f.read()).hexdigest()
    except (OSError, IOError) as e:
        return None
    return None

class BGWorkerQueuer(threading.Thread):
    def __init__(self, queue, salir, database):
        threading.Thread.__init__(self)
        self.queue = queue
        self.salir = salir
        self.database = database
        print '{0} > bgworkerQueuer spawned'.format(format_time())

    def run(self):
        while not self.salir[0]:
            #print '{0} > tic'.format(format_time())
            while not self.queue.empty():
                item = self.queue.get()
                self.update_database(item)
            time.sleep(1)
        print '{0} > bgworkerQueuer ended'.format(format_time())
        return True

    def update_database(self, f):
        src = None

        if f['event'] == 'IN_DELETE_SELF': return True
        if f['event'][:9] == 'IN_CREATE': return True
        if f['event'][:9] == 'IN_DELETE' and f['dir']: return True
        if f['event'] == 'IN_MOVED_FROM': return True

        #print '{0} i1 file ({1}) size ({2}) with action ({3})'.format(
        #    format_time(), f['nameext'], format_size(f['size']), f['event'])

        if 'src' in f:
            src = f['src']

        if f['event'] == 'IN_MOVED_TO' and 'src' not in f:
            f['event'] = 'IN_CLOSE_WRITE'

        #print '{0} i2 file ({1}) size ({2}) with action ({3})'.format(
        #    format_time(), f['nameext'], format_size(f['size']), f['event'])

        with self.database.transaction() as tx:

            if f['event'] == 'IN_CLOSE_WRITE':
                rows = tx.query("SELECT pathnameext FROM files WHERE pathnameext=?", (f['pathnameext'],))
                if not rows:
                    print '{0} > adding({1})'.format(format_time(), f['pathnameext'])
                    tx.query("INSERT INTO files (pathnameext, size, hash, atime, mtime, ctime, ts_create, ts_update, status) VALUES (?,?,?,?,?,?,?,?,?)",
                        (f['pathnameext'], f['size'], None, f['atime'], f['mtime'], f['ctime'], datetime.datetime.now(), datetime.datetime.now(), 'created',))
                else:
                    print '{0} > updating({1})'.format(format_time(), f['pathnameext'])
                    tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, ts_update=?, status=? WHERE pathnameext=?",
                    (f['size'], None, f['atime'], f['mtime'], f['ctime'], datetime.datetime.now(), 'created', f['pathnameext'],))

            elif f['event'][:9] == 'IN_DELETE': #or f['event'] == 'IN_MOVED_FROM':
                print '{0} > deleting({1})'.format(format_time(), f['pathnameext'])
                tx.query("DELETE FROM files WHERE pathnameext=?", (f['pathnameext'],))

            elif f['event'] == 'IN_MOVED_TO':
                rows = tx.query("SELECT pathnameext, size, hash, ts_create, ts_update, status FROM files WHERE pathnameext=?",
                    (f['src'],))
                if rows:
                    print '{0} > renaming({1}=>{2})'.format(format_time(), f['src'], f['pathnameext'])
                    tx.query("DELETE FROM files WHERE pathnameext=?", (f['pathnameext'],))
                    tx.query("UPDATE files SET atime=?, mtime=?, ctime=?, ts_update=?, pathnameext=? WHERE pathnameext=?",
                        (f['atime'], f['mtime'], f['ctime'], datetime.datetime.now(), f['pathnameext'], f['src'],))
                else:
                    print '{0} > adding({1})'.format(format_time(), f['pathnameext'])
                    tx.query("INSERT INTO files (pathnameext, size, hash, atime, mtime, ctime, ts_create, ts_update, status) VALUES (?,?,?,?,?,?,?,?,?)",
                        (f['pathnameext'], f['size'], None, f['atime'], f['mtime'], f['ctime'], datetime.datetime.now(), datetime.datetime.now(), 'created',))

            elif f['event'] == 'IN_MOVED_TO|IN_ISDIR':
                rows = tx.query("SELECT pathnameext, size, hash, ts_create, ts_update, status FROM files WHERE SUBSTR(pathnameext, 0, ?)=?",
                    (len(src)+2, src + '/',))
                for row in rows:
                    #print "renamed dir, update inside files dir(" + usrc + ') upathnameext(' + upathnameext + ') row(' + row['pathnameext'] + ') len(usrc)=' + str(len(usrc)) + '\n'
                    newname =  f['pathnameext'] +  '/' + row['pathnameext'][len(src)+1:]
                    #print ">" + newname + '<\n'
                    print '{0} > renaming({1}=>{2})'.format(format_time(), row['pathnameext'], newname)
                    tx.query("UPDATE files SET ts_update=?, pathnameext=? WHERE pathnameext=?",
                        (datetime.datetime.now(), newname, row['pathnameext'],))

#                    print "{0} > adding({1})".format(format_time(), pathnameext)
#                    tx.query("INSERT INTO files (pathnameext, size, hash, atime, mtime, ctime, ts_create, ts_update, status) VALUES (?,?,?,?,?,?,?,?,?)",
#                        (pathnameext, f['size'], None, f['atime'], f['mtime'], f['ctime'],
#                        datetime.datetime.now(), datetime.datetime.now(), 'created',))
#                elif rows[0]['size'] != f['size'] or rows[0]['mtime'] != f['mtime'] or rows[0]['ctime'] != f['ctime']:
#                    print "{0} > updating({1})".format(format_time(), pathnameext)






            #elif file['event'] == 'IN_CREATE':
            #    print "new directory, nothing to do..."

class BGWorkerHasher(threading.Thread):

    def __init__(self, salir, database):
        threading.Thread.__init__(self)
        self.salir = salir
        self.database = database
        print '{0} > bgworkerHasher spawned'.format(format_time())

    def run(self):
        while not self.salir[0]:
            pathnameext = self.get_file();
            if pathnameext is not None:
                #print '{0} > found hash candidate({1})'.format(format_time(), repr(pathnameext))
                #print '{0} > found hash candidate({1})'.format(format_time(), pathnameext)
                hash = sha1_file(pathnameext)
                #print '{0} > ({1}) => hash({2})'.format(format_time(), pathnameext, hash)
                self.store_hash(pathnameext, hash)
            else:
                time.sleep(1)
        print '{0} > bgworkerHasher ended'.format(format_time())
        return True

    def get_file(self):
        with self.database.transaction() as tx:
            rows = tx.query('''SELECT pathnameext, size, hash, ts_create, ts_update, status
                FROM files WHERE status=? ORDER BY RANDOM() LIMIT 1''', ['created'])
            if rows:
                #print '{0} > found hashing candidate ({1})'.format(format_time(), row['pathnameext'])
                pathnameext = rows[0]['pathnameext']
                #pathnameext = pathnameext.encode('UTF-8')
                #print pathnameext
            else:
                #print '{0} > database already processed'.format(format_time())
                pathnameext = None

            #conn.commit()
            #conn.close()
            return pathnameext

    def store_hash(self, pathnameext, hash):
        #conn = sqlite3.connect(config['db_file'], detect_types=sqlite3.PARSE_DECLTYPES)
        #conn.row_factory = sqlite3.Row
        #c = conn.cursor()
        with self.database.transaction() as tx:

            rows = tx.query('''SELECT pathnameext, size, hash, ts_create, ts_update, status
                FROM files WHERE pathnameext=? AND status=? LIMIT 1''', [pathnameext, 'created'])
            #row = c.fetchone()
            if not rows:
                print '{0} > file({1}) is no longer available in database'.format(format_time(), pathnameext)
            else:
                tx.query('''UPDATE files SET hash=?, status=? WHERE pathnameext=? AND status=?''',
                [hash, 'hashed', pathnameext, 'created'])
                print '{0} > stored file({1}) with hash({2})'.format(format_time(), pathnameext, hash)

        #conn.commit()
        #conn.close()
        return

class BGWorkerStatus(threading.Thread):

    def __init__(self, salir, database):
        threading.Thread.__init__(self)
        self.salir = salir
        self.database = database
        self.created = -1
        self.hashed = -1
        print '{0} > bgworkerStatus spawned'.format(format_time())

    def run(self):
        while not self.salir[0]:
            with self.database.transaction() as tx:
                rowsc = tx.query("SELECT COUNT(*) as count, SUM(size) as size FROM files WHERE status=?", ('created',))
                rowsh = tx.query("SELECT COUNT(*) as count, SUM(size) as size FROM files WHERE status=?", ('hashed',))
                created = rowsc[0]['count'] #[row[0] for row in rows1]
                hashed = rowsh[0]['count'] #[row[0] for row in rows2]
                if hashed != self.hashed or created != self.created:
                    print "{0} > {1} created using {2}/{3} hashed using {4}".format(
                        format_time(), created, format_size(rowsc[0]['size']),
                        hashed, format_size(rowsh[0]['size']))
                    self.hashed = hashed
                    self.created = created
            time.sleep(10)
        print "{0} > bgworkerStatus ended".format(format_time())
        return True

def stage1():

    print "{0} > update phase 1 (check for table)".format(format_time())
    with config['database'].transaction() as tx:
        rows = tx.query("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='files'")
        if rows[0][0] != 1:
            tx.query("CREATE TABLE files "
                "(pathnameext text, size integer, hash text, atime timestamp, "
                "mtime timestamp, ctime timestamp, verified integer, ts_create timestamp, "
                "ts_update timestamp, status text, UNIQUE (pathnameext))")
    return True

def stage2():

    print "{0} > update phase 2 (check for files in fs not in db)".format(format_time())
    with config['database'].transaction() as tx:
        for root, dirs, files in os.walk(config['watch_path'], topdown=True):
            for name in files:
                pathnameext = os.path.join(root, name)
                f = get_file_stat(pathnameext)
                rows = tx.query("SELECT pathnameext, size, atime, mtime, ctime, verified, ts_create, ts_update FROM files WHERE pathnameext=?",
                    (pathnameext,))
                if not rows:
                    print "{0} > adding({1})".format(format_time(), pathnameext)
                    tx.query("INSERT INTO files (pathnameext, size, hash, atime, mtime, ctime, verified, ts_create, ts_update, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (pathnameext, f['size'], None, f['atime'], f['mtime'], f['ctime'], 0,
                        datetime.datetime.now(), datetime.datetime.now(), 'created',))
                elif rows[0]['size'] != f['size'] or rows[0]['mtime'] != f['mtime'] or rows[0]['ctime'] != f['ctime']:
                    print "{0} > updating({1})".format(format_time(), pathnameext)
                    tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                        (f['size'], None, f['atime'], f['mtime'], f['ctime'], 0, datetime.datetime.now(), 'created', pathnameext,))

    return True

def stage3():
    print '{0} > update phase 3 (check for files in db not in fs)'.format(format_time())

    #uwatch_path = unicode(config['watch_path'], sys.getfilesystemencoding())
    #watch_path = config['watch_path']
    #"renamed dir, update inside files dir(" + usrc + ') upathnameext(' + upathnameext + ') row(' + row['pathnameext'] + ') len(usrc)=' + str(len(usrc)) + '\n'
    #newname =  upathnameext +  '/' + row['pathnameext'][len(usrc)+1:]
    with config['database'].transaction() as tx:
        rows = tx.query("SELECT pathnameext, size, hash, atime, mtime, ctime, verified, ts_create, ts_update, status FROM files WHERE SUBSTR(pathnameext, 0, ?)=?",
            [len(config['watch_path']) + 2, config['watch_path'] + '/'])
        for row in rows:
            f = get_file_stat(row['pathnameext'])
            if f['size'] == -1:
                print '{0} > deleting({1})'.format(format_time(), row['pathnameext'])
                tx.query("DELETE FROM files WHERE pathnameext=?",
                    (row['pathnameext'],))
                config['vacuum'] = True
            elif f['size'] != row['size'] or f['mtime'] != row['mtime'] or f['ctime'] != row['ctime']:
                print '{0} > updating({1})'.format(format_time(), pathnameext)
                tx.query("UPDATE files SET size=?, hash=?, atime=?, mtime=?, ctime=?, verified=?, ts_update=?, status=? WHERE pathnameext=?",
                    (f['size'], None, f['atime'], f['mtime'], f['ctime'], 0,
                    datetime.datetime.now(), 'created', row['pathnameext'],))
                config['vacuum'] = True
        rows = tx.query("SELECT COUNT(*) FROM files WHERE SUBSTR(pathnameext, 0, ?)!=?",
            [len(config['watch_path']) + 2, config['watch_path'] + '/'])
        #delete = [row[0] for row in rows]
        if (rows[0][0]!=0):
            print '{0} > deleting in db not in fs because of watch dir change({1})'.format(format_time(), rows[0][0])
            rows = tx.query("DELETE FROM files WHERE SUBSTR(pathnameext, 0, ?)!=?",
                [len(config['watch_path']) + 2, config['watch_path'] + '/'])
            config['vacuum'] = True
        if (config['vacuum']):
            tx.query("VACUUM");

    return

def main(argv):
    def usage():
        print 'usage: ', argv[0], '[-h|--help]'
        print '                 [-r|--recursive]'
        print '                 -w|--watch-path <path>'
        print
        print 'Starts automatic filesystem monitoring'
        print
        print ' -d, --db-file            sqlite path to store hash(sha1) signatures'
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

    if config['db_file'] is None:
        usage()
        sys.exit()

    config['database'] = Database(config['db_file'])
    transaction = Transaction(config['database'])

    stage1()
    stage2()
    stage3()

    #sys.exit()

    thread_BGWorkerQueuer = BGWorkerQueuer(q, salir, config['database'])
    thread_BGWorkerQueuer.start()

    thread_BGWorkerHasher = BGWorkerHasher(salir, config['database'])
    thread_BGWorkerHasher.start()

    thread_BGWorkerStatus = BGWorkerStatus(salir, config['database'])
    thread_BGWorkerStatus.start()

    wm = pyinotify.WatchManager()
    notifier = pyinotify.Notifier(wm, EventHandler(), timeout=10*1000)
    mask = pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MOVED_TO | pyinotify.IN_MOVED_FROM |\
        pyinotify.IN_DELETE | pyinotify.IN_DELETE_SELF | pyinotify.IN_CREATE | pyinotify.IN_Q_OVERFLOW |\
        pyinotify.IN_MOVE_SELF
        #pyinotify.ALL_EVENTS
    wm.add_watch(config['watch_path'],
        mask,
        rec=config['recursive'],
        auto_add=config['recursive'])
    #on_loop_func = functools.partial(on_loop, counter=Counter())

    #salir[0] = False
    #thread_BGWorker.join()

    try:
        while True:
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
        salir[0] = True
        notifier.stop()
        sys.exit(0)

    notifier.stop()
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

