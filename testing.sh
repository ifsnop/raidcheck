rm /tmp/q.q 2> /dev/null
touch /tmp/q.q
sleep 1
echo 1
echo .dump | sqlite3 db.sqlite | grep INSERT
rm /tmp/q.q
sleep 1
echo nada
echo .dump | sqlite3 db.sqlite | grep INSERT
touch /q.q
mv /q.q /tmp/q.q
sleep 1
echo 1
echo .dump | sqlite3 db.sqlite | grep INSERT
mv /tmp/q.q /
sleep 1
echo nada
echo .dump | sqlite3 db.sqlite | grep INSERT
rm /q.q

touch /tmp/q.q2
mv /tmp/q.q2 /tmp/q.q
sleep 1
echo 1
echo .dump | sqlite3 db.sqlite | grep INSERT
rm /tmp/q.q

mkdir /tmp/q
echo created /tmp/q DIR
echo .dump | sqlite3 db.sqlite
mv /tmp/q /tmp/q2
sleep 1
echo 0 moved to /tmp/q2
echo .dump | sqlite3 db.sqlite

touch /tmp/q2/q
sleep 1
echo create /tmp/q2/q
echo .dump | sqlite3 db.sqlite

rm -rf /tmp/q2
echo 9 deleted /tmp/q2
sleep 1
echo .dump | sqlite3 db.sqlite
