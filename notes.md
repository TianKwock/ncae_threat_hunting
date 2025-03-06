# Threat Hunting

## File System Analysis

Common targets: /tmp , /var/tmp , /dev/shm

```
find / -user <user> -type f 2>/dev/null
find / -group <group> 2>/dev/null
find / -type f -cmin -5 2>/dev/null
```

`exiftool <file>` to analyze metadata 

`md5sum <file>` or `sha256sum <file>` to analyze checksums

`ls -l` for modify timestamp, `ls -lc` for change timestamp, and `ls -lu` for access timestamp, or `stat <file>` for all of them

`cat /etc/passwd | grep ":0:"` 

`groups <user>` to list all groups that a user belongs to

`getent group <group>` to list all users in a group 

`last` can be used to examine user logins and sessions, it reads /var/log/wtmp

`lastb` tracks failed login attempts by reading /var/log/btmp 

`lastlog` provides info on a user's most recent login, reading /var/log/lastlog

`who` or `who -u` to see users currently logged into system
