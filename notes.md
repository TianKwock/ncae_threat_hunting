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

`sudo cat /etc/sudoers` to check sudoers file, to edit, do `visudo`

`ls -la /home/*/.ssh` to check for bad authorized_keys permissions?

`strings <file>` to extract strings

`sudo debsums -e -s` will report modified/corrupted files

`find / -perm -u=s -type f 2>/dev/null | grep -e "python" -e "var"` searches for files with the SUID bit, optionally add the grep part to limit the search to common sus things 

`sudo cat /home/<user>/.bash_history | grep -C 3 "python"` if suspicious of a user, alternatively just look at their history without the grep part 

### Rootkits 

Check Rootkit
`sudo chkrootkit` is good for a first-pass, but be aware it does not perform an in-dept analysis 

Rootkit Hunter
`rkhunter --update` -> `sudo rkhunter -c -sk` will give a more comprehensive assessment of the system. '-c' is to run a full system check, and '-sk' is to skip keypresses

`cat /var/log/rkhunter.log | grep "Warning"` can be run after the scan to focus on things that rkhunter found sus, be sure to capitalize 'Warning'

## Process Analysis

`ps -eFH | less` will select all processes (-e), return in extra full format (-F), and show the process hierarchy (-H)

`sudo lsof -p <PID>` can be useful for connecting dots if you find something sus in the output of the previous command

`pstree -p -s <PID>` can be used to identify the origin of sus processes

`top -d 5 -c -u <user>` will show processes relating to a user that updates dynamically
every 5 seconds


