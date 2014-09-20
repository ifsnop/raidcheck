raidcheck
=========

Most disk, disk controller and higher-level systems are subject to a small
degree of unrecoverable failure. With ever-growing disk capacities, file
sizes, and increases in the amount of data stored on a disk, the likelihood
of the occurrence of data decay and other forms of uncorrected and
undetected data corruption increases.

Higher-level software systems may be employed to mitigate the risk of such
underlying failures by increasing redundancy and implementing integrity
checking and self-repairing algorithms. The ZFS file system was designed
to address many of these data corruption issues. The Btrfs file system
also includes data protection and recovery mechanisms, and so does ReFS.

raidcheck updates a database with files + hashes. Periodically checks them,
to see if someone is corrupted. It is useful in a raid environment, where
silent file corruption can occur.

monitord.py       Monitors file updates (creation, deletion, etc) and
                  updates a sqlite3 database.

FAQ
======

Getting the message "No space left on device (ENOSPC)" when adding a new
watch.
From https://github.com/seb-m/pyinotify/wiki/Frequently-Asked-Questions

You must have reached your quota of watches, type:

~~~
sysctl -n fs.inotify.max_user_watches
~~~

to read your current limit and type:

~~~
sysctl -n -w fs.inotify.max_user_watches=16384
~~~

to increase it to 16384.

TODO
======

Fix accesing sqlite from multiple threads by switching to SQLAlchemy

Exception in thread Thread-2:
Traceback (most recent call last):
  File "/usr/lib/python2.7/threading.py", line 552, in __bootstrap_inner
    self.run()
  File "./monitord.py", line 262, in run
    pathnameext = self.get_file();
  File "./monitord.py", line 278, in get_file
    FROM files WHERE status=? ORDER BY RANDOM() LIMIT 1''', ['created'])
OperationalError: database is locked

