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

`sudo cat /home/<user>/.bash_history | grep -C 3 "python"` run if suspicious of a user, alternatively just look at their history without the grep part 

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

### Cronjobs

Users can have their crontab file stored in the /var/spool/cron/crontabs directory, while /etc/crontab governs system-wide cronjobs. 

`cat /etc/crontab` to check out the system-wide cronjobs

`ls /etc/cron.hourly` , `ls /etc/cron.daily` , `ls /etc/cron.weekly` , `ls /etc/cron.monthly` , `ls /etc/cron.d` are all worth taking a look at, especially hourly, daily, and additional (cron.d)

`sudo ls -la /var/spool/cron/crontabs` will give a good idea of what's going on with the users

`sudo crontab -l | grep -v "#"` this may be slightly redundant i'm not 100% sure but its concise and may be a good replacement for the one where you ls a bunch of directories

`sudo bash -c 'for user in $(cut -f1 -d: /etc/passwd); do entries=$(crontab -u $user -l 2>/dev/null | grep -v "^#"); if [ -n "$entries" ]; then echo "$user: Crontab entry found!"; echo "$entries"; echo; fi; done'` this command will loop through users on the system and identify if they have any user-level cronjobs 

Cron execution logs are stored in either /var/log/syslog (Debian) or /var/log/cron (RHEL / CentOS). To investigate them effectively, try the following commands:

`sudo grep cron /var/log/syslog | grep -E 'failed|error|fatal'` to check for failed job executions

`sudo grep cron /var/log/syslog | grep -i '<user>'` for sus users 

`pspy64` can be useful for monitoring processes without needing root privileges in real-time

### Services

`sudo systemctl list-units --all --type=service --state=running` will show currently running services 

`sudo systemctl status <service>` and `cat /etc/systemd/system/<service>` if you find a sus service; look at status, main PID, and CGroup in the first command

`sudo journalctl -f -u <service>` will shows service logs. -f for real-time and -u to specify the service 

### Autostart Scripts

System-wide: Typically start when OS boots. /etc/init.d/ , /etc/rc.d/ , /etc/systemd/system/

User-speficic: Typically executed when a user logs in. ~/.config/autostart/ , ~/.config/

`ls -a /home/*/.config/autostart` can give you a good idea of what's going on with the users

Other places to snoop around in: ~/.bash_history , ~/.ssh , ~/.profile , /etc/update-motd.d/ , /usr/lib/update-notifier/

## Linux Priv Esc 

`uname -a` or `cat /proc/version` can give details about the system

