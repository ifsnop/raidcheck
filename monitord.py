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
    'self': 'monitord.py'
    }

q = Queue()

salir = [False]

database = None

transaction = None

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

    def query(self, statement, subvals=()):
        """Execute an SQL statement with substitution values and return
        a list of rows from the database.
        """
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
    """A container for Model objects that wraps an SQLite database as
    the backend.
    """
    _models = ()
    """The Model subclasses representing tables in this database.
    """

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
        for model_cls in self._models:
            self._make_table(model_cls._table, model_cls._fields)
            self._make_attribute_table(model_cls._flex_table)

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

    def _make_table(self, table, fields):
        """Set up the schema of the database. `fields` is a mapping
        from field names to `Type`s. Columns are added if necessary.
        """
        # Get current schema.
        with self.transaction() as tx:
            rows = tx.query('PRAGMA table_info(%s)' % table)
        current_fields = set([row[1] for row in rows])

        field_names = set(fields.keys())
        if current_fields.issuperset(field_names):
            # Table exists and has all the required columns.
            return

        if not current_fields:
            # No table exists.
            columns = []
            for name, typ in fields.items():
                columns.append('{0} {1}'.format(name, typ.sql))
            setup_sql = 'CREATE TABLE {0} ({1});\n'.format(table,
                                                           ', '.join(columns))

        else:
            # Table exists does not match the field set.
            setup_sql = ''
            for name, typ in fields.items():
                if name in current_fields:
                    continue
                setup_sql += 'ALTER TABLE {0} ADD COLUMN {1} {2};\n'.format(
                    table, name, typ.sql
                )

        with self.transaction() as tx:
            tx.script(setup_sql)

    def _make_attribute_table(self, flex_table):
        """Create a table and associated index for flexible attributes
        for the given entity (if they don't exist).
        """
        with self.transaction() as tx:
            tx.script("""
                CREATE TABLE IF NOT EXISTS {0} (
                    id INTEGER PRIMARY KEY,
                    entity_id INTEGER,
                    key TEXT,
                    value TEXT,
                    UNIQUE(entity_id, key) ON CONFLICT REPLACE);
                CREATE INDEX IF NOT EXISTS {0}_by_entity
                    ON {0} (entity_id);
                """.format(flex_table))

    # Querying.

    def _fetch(self, model_cls, query=None, sort=None):
        """Fetch the objects of type `model_cls` matching the given
        query. The query may be given as a string, string sequence, a
        Query object, or None (to fetch everything). `sort` is an
        `Sort` object.
        """
        query = query or TrueQuery()  # A null query.
        sort = sort or NullSort()  # Unsorted.
        where, subvals = query.clause()
        order_by = sort.order_clause()

        sql = ("SELECT * FROM {0} WHERE {1} {2}").format(
            model_cls._table,
            where or '1',
            "ORDER BY {0}".format(order_by) if order_by else '',
        )

        with self.transaction() as tx:
            rows = tx.query(sql, subvals)

        return Results(
            model_cls, rows, self,
            None if where else query,  # Slow query component.
            sort if sort.is_slow() else None,  # Slow sort component.
        )

    def _get(self, model_cls, id):
        """Get a Model object by its id or None if the id does not
        exist.
        """
        return self._fetch(model_cls, MatchQuery('id', id)).get()




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

        print '{0} o file ({1}) size ({2}) with action ({3})'.format(
                format_time(),
                file['nameext'],
                format_size(file['size']),
                file['event'])

        q.put(file)
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

    def update_database(self, file):
        if config['db_file'] is None:
            return True

        if file['event'] == 'IN_DELETE_SELF': return True
        if file['event'][:9] == 'IN_CREATE': return True
        if file['event'][:9] == 'IN_DELETE' and file['dir']: return True
        #if file['event'][:9] == 'IN_CREATE' and file['dir']: return True

        print '{0} i file ({1}) size ({2}) with action ({3})'.format(
            format_time(),
            file['nameext'],
            format_size(file['size']),
            file['event'])

        upathnameext = unicode(file['pathnameext'], sys.getfilesystemencoding())
        if 'src' in file:
            usrc = unicode(file['src'], sys.getfilesystemencoding())
        #else:
        #    file['event'] = 'IN_CLOSE_WRITE'

        if file['event'] == 'IN_MOVED_TO' and 'src' not in file:
            file['event'] = 'IN_CLOSE_WRITE'

        #sys.stdout.write(format_time() + pprint.pformat(file) + '\n')
        #print database

        with self.database.transaction() as tx:

            if file['event'] == 'IN_CLOSE_WRITE':
                rows = tx.query('''SELECT pathnameext, size, sha1, ts_create, ts_update, status
                    FROM files WHERE pathnameext=?''', [upathnameext])
                if not rows:
                    print '{0} > adding({1})'.format(format_time(), file['pathnameext'])
                    tx.query('''INSERT INTO files (pathnameext, size, ts_create, ts_update, status) VALUES
                        (?,?,?,?,?)''', [upathnameext, file['size'], datetime.datetime.now(),
                        datetime.datetime.now(), 'created'])
                else:
                    print '{0} > updating({1})'.format(format_time(), file['pathnameext'])
                    tx.query('''UPDATE files SET status=?, ts_update=?, size=?
                        WHERE pathnameext=?''', ['created', datetime.datetime.now(), file['size'], upathnameext])

            elif file['event'][:9] == 'IN_DELETE' or file['event'] == 'IN_MOVED_FROM':
                print '{0} > deleting({1})'.format(format_time(), file['pathnameext'])
                tx.query('''DELETE FROM files WHERE pathnameext=?''', [upathnameext])

            elif file['event'] == 'IN_MOVED_TO':
                rows = tx.query('''SELECT pathnameext, size, sha1, ts_create, ts_update, status
                    FROM files WHERE pathnameext=?''', [usrc])
                if not rows:
                    print '{0} > renaming({1}=>{2})'.format(format_time(), file['src'], file['pathnameext'])
                    tx.query('''UPDATE files SET status=?, ts_update=?, pathnameext=?
                        WHERE pathnameext=?''', ['created', datetime.datetime.now(), upathnameext, usrc])
                else:
                    print '{0} > adding({1})'.format(format_time(), file['pathnameext'])
                    tx.query('''INSERT INTO files (pathnameext, size, ts_create, ts_update, status) VALUES
                        (?,?,?,?,?)''', [upathnameext, file['size'], datetime.datetime.now(),
                        datetime.datetime.now(), 'created'])

            elif file['event'] == 'IN_MOVED_TO|IN_ISDIR':
                #print "renaming lots of files len(" + str(len(usrc)) + ") str(" + usrc + ")"
                #print "SELECT pathnameext, size, sha1, ts_create, ts_update, status FROM files WHERE SUBSTR(pathnameext, 0," + str(len(usrc)+2) + ")='" + usrc + "/'"
                rows = tx.query('''SELECT pathnameext, size, sha1, ts_create, ts_update, status
                    FROM files WHERE SUBSTR(pathnameext, 0, ?)=?''', [len(usrc)+2, usrc + '/'])
                for row in rows:
                    #print "renamed dir, update inside files dir(" + usrc + ') upathnameext(' + upathnameext + ') row(' + row['pathnameext'] + ') len(usrc)=' + str(len(usrc)) + '\n'
                    newname =  upathnameext +  '/' + row['pathnameext'][len(usrc)+1:]
                    #print ">" + newname + '<\n'
                    print '{0} > renaming({1}=>{2})'.format(format_time(), row['pathnameext'], newname)
                    tx.query('''UPDATE files SET status=?, ts_update=?, pathnameext=?
                        WHERE pathnameext=?''', ['created', datetime.datetime.now(), newname, row['pathnameext']])

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
            if config['db_file'] is not None:
                pathnameext = self.get_file();
                if pathnameext is not None:
                    #print '{0} > found hash candidate({1})'.format(format_time(), pathnameext)
                    hash = sha1_file(pathnameext)
                    #print '{0} > ({1}) => hash({2})'.format(format_time(), pathnameext, sha1_file(pathnameext))
                    self.store_hash(pathnameext, hash)
                else:
                    time.sleep(1)
        print '{0} > bgworkerHasher ended'.format(format_time())
        return True

    def get_file(self):
        with self.database.transaction() as tx:
            rows = tx.query('''SELECT pathnameext, size, sha1, ts_create, ts_update, status
                FROM files WHERE status=? ORDER BY RANDOM() LIMIT 1''', ['created'])
            if rows:
                #print '{0} > found hashing candidate ({1})'.format(format_time(), row['pathnameext'])
                pathnameext = rows[0]['pathnameext']
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

            rows = tx.query('''SELECT pathnameext, size, sha1, ts_create, ts_update, status
                FROM files WHERE pathnameext=? AND status=? LIMIT 1''', [pathnameext, 'created'])
            #row = c.fetchone()
            if not rows:
                print '{0} > file({1}) is no longer available in database'.format(format_time(), pathnameext)
            else:
                tx.query('''UPDATE files SET sha1=?, status=? WHERE pathnameext=? AND status=?''',
                [hash, 'updated', pathnameext, 'created'])
                print '{0} > stored file({1}) hash({2})'.format(format_time(), pathnameext, hash)

        #conn.commit()
        #conn.close()
        return

def main(argv):
    def usage():
        print 'usage: ', argv[0], '[-h|--help]'
        print '                 [-r|--recursive]'
        print '                 -w|--watch-path <path>'
        print
        print 'Starts automatic filesystem monitoring'
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

        database = Database(config['db_file'])
        transaction = Transaction(database)

        print '{0} > update phase 1 (check for table)'.format(format_time())
        #conn = sqlite3.connect(config['db_file'], detect_types=sqlite3.PARSE_DECLTYPES)
        #conn.row_factory = sqlite3.Row
        #c = conn.cursor()
        #c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='files'")
        #if c.fetchone()[0] != 1:
        #    c.execute('''CREATE TABLE files
        #        (pathnameext text, size integer, sha1 text, ts_create timestamp,
        #        ts_update timestamp, status text, UNIQUE (pathnameext))''')
        with database.transaction() as tx:
            rows = tx.query("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='files'")
            if rows[0][0] != 1:
                tx.query('''CREATE TABLE files
                (pathnameext text, size integer, sha1 text, ts_create timestamp,
                ts_update timestamp, status text, UNIQUE (pathnameext))''')


            rows1 = tx.query('SELECT * FROM files WHERE status=?', ('created',))
            rows2 = tx.query('SELECT * FROM files WHERE status=?', ('updated',))

            created = [row[0] for row in rows1]
            updated = [row[0] for row in rows2]

            print '{0} > created({1})'.format(format_time(), created)
            print '{0} > updated({1})'.format(format_time(), updated)


            print '{0} > update phase 2 (check for files in fs not in db)'.format(format_time())
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
                    #c.execute('''SELECT pathnameext, size FROM files WHERE pathnameext=?''', [upathnameext])
                    #row = c.fetchone()
                    rows = tx.query('''SELECT pathnameext, size FROM files WHERE pathnameext=?''', [upathnameext])
                    #if row is None:
                    #    print '{0} > adding({1})'.format(format_time(), pathnameext)
                    #    c.execute('''INSERT INTO files (pathnameext, size, ts_create, ts_update, status) VALUES
                    #        (?,?,?,?,?)''', [upathnameext, size, datetime.datetime.now(),
                    #        datetime.datetime.now(), 'created'])
                    #elif row['size'] != size:
                    #    print '{0} > updating({1})'.format(format_time(), pathnameext)
                    #    c.execute('''UPDATE files SET status=?, ts_update=?, size=?
                    #        WHERE pathnameext=?''', ['created', datetime.datetime.now(), size, upathnameext])
                    if not rows:
                        print '{0} > adding({1})'.format(format_time(), pathnameext)
                        tx.query('''INSERT INTO files (pathnameext, size, ts_create, ts_update, status) VALUES
                            (?,?,?,?,?)''', [upathnameext, size, datetime.datetime.now(),
                            datetime.datetime.now(), 'created'])
                    elif rows[0]['size'] != size:
                        print '{0} > updating({1})'.format(format_time(), pathnameext)
                        tx.query('''UPDATE files SET status=?, ts_update=?, size=?
                            WHERE pathnameext=?''', ['created', datetime.datetime.now(), size, upathnameext])

            print '{0} > update phase 3 (check for files in db not in fs)'.format(format_time())
            uwatch_path = unicode(config['watch_path'], sys.getfilesystemencoding())
            #c.execute('''SELECT pathnameext, size, sha1, ts_create, ts_update, status
            #    FROM files WHERE SUBSTR(pathnameext, 0, ?)=?''', [len(uwatch_path)+2, uwatch_path + '/'])
            #rows = c.fetchall()
            #for row in rows:
            #print row['pathnameext']
            #"renamed dir, update inside files dir(" + usrc + ') upathnameext(' + upathnameext + ') row(' + row['pathnameext'] + ') len(usrc)=' + str(len(usrc)) + '\n'
            #newname =  upathnameext +  '/' + row['pathnameext'][len(usrc)+1:]
            rows = tx.query('''SELECT pathnameext, size, sha1, ts_create, ts_update, status
                FROM files WHERE SUBSTR(pathnameext, 0, ?)=?''', [len(uwatch_path)+2, uwatch_path + '/'])
            for row in rows:
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
                    tx.query('''DELETE FROM files WHERE pathnameext=?''', [upathnameext])
                # comprobar size!!!!
                elif size != row['size']:
                    print '{0} > updating({1})'.format(format_time(), pathnameext)
                    tx.query('''UPDATE files SET status=?, ts_update=?, size=?
                        WHERE pathnameext=?''', ['created', datetime.datetime.now(), size, upathnameext])

        #conn.commit()
        #conn.close()

    #sys.exit()

    thread_BGWorkerQueuer = BGWorkerQueuer(q, salir, database)
    thread_BGWorkerQueuer.start()

    thread_BGWorkerHasher = BGWorkerHasher(salir, database)
    thread_BGWorkerHasher.start()

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

