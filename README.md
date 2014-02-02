raidcheck
=========

daemons to check file integrity. useful in a raid environment, where
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
