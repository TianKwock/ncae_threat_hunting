# Threat Hunting

## File System Analysis

Common targets: /tmp , /var/tmp , /dev/shm

```
find / -user <user> -type f 2>/dev/null
find / -group <group> 2>/dev/null
find / -type f -cmin -5 2>/dev/null
```

`exiftool <file>` to analyze metadata 
