# Pre-run Linux script to intentionnaly make some implementations to need remediations

chmod 664 /etc/passwd
chmod 664 /etc/shadow
chmod 664 /etc/fstab
chmod 664 /etc/group

groupadd badgroup 
chown root:badgroup /etc/group
chown root:badgroup /etc/shadow

