from huepy import bold, red, green, yellow
from subprocess import Popen, PIPE
from csv import writer
from time import time
from sys import exit


# dummy log_file variable
log_file = ''


"""
benchmark structure
for b in benchmark_*:
    b[0] = recommendation id number
    b[1] = Scored (1) [OR] Not Scored (0)
    b[2] = Server      Profile  -> Level 1 (1) [OR] Level 2 (2) [OR] N/A (0)
    b[3] = Workstation Profile  -> Level 1 (1) [OR] Level 2 (2) [OR] N/A (0)
    b[4] = explanation
"""
benchmark_ind = [
    ['1.1.1.1', 1, 1, 1, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 1, 1, 1, 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.3', 1, 1, 1, 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.4', 1, 1, 1, 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.5', 1, 1, 1, 'Ensure mounting of hfsplus filesystems is disabled'],
    ['1.1.1.6', 1, 1, 1, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.7', 1, 1, 1, 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.1.8', 0, 2, 2, 'Ensure mounting of FAT filesystems is limited'],
    ['1.1.2', 1, 1, 1, 'Ensure /tmp is configured'],
    ['1.1.3', 1, 1, 1, 'Ensure nodev option set on /tmp partition'],
    ['1.1.4', 1, 1, 1, 'Ensure nosuid option set on /tmp partition'],
    ['1.1.5', 1, 1, 1, 'Ensure noexec option set on /tmp partition'],
    ['1.1.6', 1, 2, 2, 'Ensure separate partition exists for /var'],
    ['1.1.7', 1, 2, 2, 'Ensure separate partition exists for /var/tmp'],
    ['1.1.8', 1, 1, 1, 'Ensure nodev option set on /var/tmp partition'],
    ['1.1.9', 1, 1, 1, 'Ensure nosuid option set on /var/tmp partition'],
    ['1.1.10', 1, 1, 1, 'Ensure noexec option set on /var/tmp partition'],
    ['1.1.11', 1, 2, 2, 'Ensure separate partition exists for /var/log'],
    ['1.1.12', 1, 2, 2, 'Ensure separate partition exists for /var/log/audit'],
    ['1.1.13', 1, 2, 2, 'Ensure separate partition exists for /home'],
    ['1.1.14', 1, 1, 1, 'Ensure nodev option set on /home partition'],
    ['1.1.15', 1, 1, 1, 'Ensure nodev option set on /dev/shm partition'],
    ['1.1.16', 1, 1, 1, 'Ensure nosuid option set on /dev/shm partition'],
    ['1.1.17', 1, 1, 1, 'Ensure noexec option set on /dev/shm partition'],
    ['1.1.18', 0, 1, 1, 'Ensure nodev option set on removable media partitions'],
    ['1.1.19', 0, 1, 1, 'Ensure nosuid option set on removable media partitions'],
    ['1.1.20', 0, 1, 1, 'Ensure noexec option set on removable media partitions'],
    ['1.1.21', 1, 1, 1, 'Ensure sticky bit is set on all world-writable directories'],
    ['1.1.22', 1, 1, 2, 'Disable Automounting'],
    ['1.1.23', 1, 1, 2, 'Disable USB Storage'],
    ['1.2.1', 0, 1, 1,
        'Ensure package manager repositories are configured (distro specific)'],
    ['1.2.2', 0, 1, 1, 'Ensure GPG keys are configured (distro specific)'],
    ['1.3.1', 1, 1, 1, 'Ensure AIDE is installed (distro specific)'],
    ['1.3.2', 1, 1, 1, 'Ensure filesystem integrity is regularly checked'],
    ['1.4.1', 1, 1, 1,
        'Ensure permissions on bootloader config are configured (bootloader specific)'],
    ['1.4.2', 1, 1, 1,
        'Ensure bootloader password is set (bootloader specific)'],
    ['1.4.3', 1, 1, 1, 'Ensure authentication required for single user mode'],
    ['1.4.4', 0, 1, 1,
        'Ensure interactive boot is not enabled (bootloader specific)'],
    ['1.5.1', 1, 1, 1, 'Ensure core dumps are restricted'],
    ['1.5.2', 1, 1, 1, 'Ensure XD/NX support is enabled'],
    ['1.5.3', 1, 1, 1,
        'Ensure address space layout randomization (ASLR) is enabled'],
    ['1.5.4', 1, 1, 1, 'Ensure prelink is disabled (distro specific)'],
    ['1.6.1.1', 1, 2, 2,
        'Ensure SELinux or AppArmor are installed (distro specific)'],
    ['1.6.2.1', 1, 2, 2, 'Ensure SELinux is not disabled in bootloader configuration'],
    ['1.6.2.2', 1, 2, 2, 'Ensure the SELinux state is enforcing'],
    ['1.6.2.3', 1, 2, 2, 'Ensure SELinux policy is configured'],
    ['1.6.2.4', 1, 2, 0,
        'Ensure SETroubleshoot is not installed (distro specific)'],
    ['1.6.2.5', 1, 2, 2,
        'Ensure the MCS Translation Service (mcstrans) is not installed (distro specific)'],
    ['1.6.2.6', 1, 2, 2, 'Ensure no unconfined daemons exist'],
    ['1.6.3.1', 1, 2, 2, 'Ensure AppArmor is not disabled in bootloader configuration'],
    ['1.6.3.2', 1, 2, 2, 'Ensure all AppArmor Profiles are enforcing'],
    ['1.7.1.1', 1, 1, 1, 'Ensure message of the day is configured properly'],
    ['1.7.1.2', 1, 1, 1, 'Ensure local login warning banner is configured properly'],
    ['1.7.1.3', 1, 1, 1, 'Ensure remote login warning banner is configured properly'],
    ['1.7.1.4', 1, 1, 1, 'Ensure permissions on /etc/motd are configured'],
    ['1.7.1.5', 1, 1, 1, 'Ensure permissions on /etc/issue are configured'],
    ['1.7.1.6', 1, 1, 1, 'Ensure permissions on /etc/issue.net are configured'],
    ['1.7.2', 1, 1, 1, 'Ensure GDM login banner is configured'],
    ['1.8', 0, 1, 1,
        'Ensure updates, patches, and additional security software are installed (distro specific)'],
    ['2.1.1', 1, 1, 1, 'Ensure chargen services are not enabled'],
    ['2.1.2', 1, 1, 1, 'Ensure daytime services are not enabled'],
    ['2.1.3', 1, 1, 1, 'Ensure discard services are not enabled'],
    ['2.1.4', 1, 1, 1, 'Ensure echo services are not enabled'],
    ['2.1.5', 1, 1, 1, 'Ensure time services are not enabled'],
    ['2.1.6', 1, 1, 1, 'Ensure rsh server is not enabled'],
    ['2.1.7', 1, 1, 1, 'Ensure talk server is not enabled'],
    ['2.1.8', 1, 1, 1, 'Ensure telnet server is not enabled'],
    ['2.1.9', 1, 1, 1, 'Ensure tftp server is not enabled'],
    ['2.1.10', 1, 1, 1, 'Ensure xinetd is not enabled'],
    ['2.2.1.1', 0, 1, 1,
        'Ensure time synchronization is in use (distro specific)'],
    ['2.2.1.2', 1, 1, 1, 'Ensure ntp is configured'],
    ['2.2.1.3', 1, 1, 1, 'Ensure chrony is configured'],
    ['2.2.1.4', 1, 1, 1, 'Ensure systemd-timesyncd is configured'],
    ['2.2.2', 1, 1, 0,
        'Ensure X Window System is not installed (distro specific)'],
    ['2.2.3', 1, 1, 1, 'Ensure Avahi Server is not enabled'],
    ['2.2.4', 1, 1, 2, 'Ensure CUPS is not enabled'],
    ['2.2.5', 1, 1, 1, 'Ensure DHCP Server is not enabled'],
    ['2.2.6', 1, 1, 1, 'Ensure LDAP server is not enabled'],
    ['2.2.7', 1, 1, 1, 'Ensure NFS and RPC are not enabled'],
    ['2.2.8', 1, 1, 1, 'Ensure DNS Server is not enabled'],
    ['2.2.9', 1, 1, 1, 'Ensure FTP Server is not enabled'],
    ['2.2.10', 1, 1, 1, 'Ensure HTTP server is not enabled'],
    ['2.2.11', 1, 1, 1, 'Ensure IMAP and POP3 server is not enabled'],
    ['2.2.12', 1, 1, 1, 'Ensure Samba is not enabled'],
    ['2.2.13', 1, 1, 1, 'Ensure HTTP Proxy Server is not enabled'],
    ['2.2.14', 1, 1, 1, 'Ensure SNMP Server is not enabled'],
    ['2.2.15', 1, 1, 1, 'Ensure mail transfer agent is configured for local-only mode'],
    ['2.2.16', 1, 1, 1, 'Ensure rsync service is not enabled'],
    ['2.2.17', 1, 1, 1, 'Ensure NIS Server is not enabled'],
    ['2.3.1', 1, 1, 1, 'Ensure NIS Client is not installed (distro specific)'],
    ['2.3.2', 1, 1, 1, 'Ensure rsh client is not installed (distro specific)'],
    ['2.3.3', 1, 1, 1,
        'Ensure talk client is not installed (distro specific)'],
    ['2.3.4', 1, 1, 1,
        'Ensure telnet client is not installed (distro specific)'],
    ['2.3.5', 1, 1, 1,
        'Ensure LDAP client is not installed (distro specific)'],
    ['3.1.1', 1, 1, 1, 'Ensure IP forwarding is disabled'],
    ['3.1.2', 1, 1, 1, 'Ensure packet redirect sending is disabled'],
    ['3.2.1', 1, 1, 1, 'Ensure source routed packets are not accepted'],
    ['3.2.2', 1, 1, 1, 'Ensure ICMP redirects are not accepted'],
    ['3.2.3', 1, 1, 1, 'Ensure secure ICMP redirects are not accepted'],
    ['3.2.4', 1, 1, 1, 'Ensure suspicious packets are logged'],
    ['3.2.5', 1, 1, 1, 'Ensure broadcast ICMP requests are ignored'],
    ['3.2.6', 1, 1, 1, 'Ensure bogus ICMP responses are ignored'],
    ['3.2.7', 1, 1, 1, 'Ensure Reverse Path Filtering is enabled'],
    ['3.2.8', 1, 1, 1, 'Ensure TCP SYN Cookies is enabled'],
    ['3.2.9', 1, 1, 1, 'Ensure IPv6 router advertisements are not accepted'],
    ['3.3.1', 0, 1, 1, 'Ensure TCP Wrappers is installed (distro specific)'],
    ['3.3.2', 0, 1, 1, 'Ensure /etc/hosts.allow is configured'],
    ['3.3.3', 0, 1, 1, 'Ensure /etc/hosts.deny is configured'],
    ['3.3.4', 1, 1, 1, 'Ensure permissions on /etc/hosts.allow are configured'],
    ['3.3.5', 1, 1, 1, 'Ensure permissions on /etc/hosts.deny are configured'],
    ['3.4.1', 1, 2, 2, 'Ensure DCCP is disabled'],
    ['3.4.2', 1, 2, 2, 'Ensure SCTP is disabled'],
    ['3.4.3', 1, 2, 2, 'Ensure RDS is disabled'],
    ['3.4.4', 1, 2, 2, 'Ensure TIPC is disabled'],
    ['3.5.1.1', 1, 1, 1, 'Ensure IPv6 default deny firewall policy'],
    ['3.5.1.2', 1, 1, 1, 'Ensure IPv6 loopback traffic is configured'],
    ['3.5.1.3', 0, 1, 1, 'Ensure IPv6 outbound and established connections are configured'],
    ['3.5.1.4', 0, 1, 1, 'Ensure IPv6 firewall rules exist for all open ports'],
    ['3.5.2.1', 1, 1, 1, 'Ensure default deny firewall policy'],
    ['3.5.2.2', 1, 1, 1, 'Ensure loopback traffic is configured'],
    ['3.5.2.3', 0, 1, 1, 'Ensure outbound and established connections are configured'],
    ['3.5.2.4', 1, 1, 1, 'Ensure firewall rules exist for all open ports'],
    ['3.5.3', 1, 1, 1, 'Ensure iptables is installed (distro specific)'],
    ['3.6', 0, 1, 2, 'Ensure wireless interfaces are disabled'],
    ['3.7', 0, 2, 2, 'Disable IPv6'],
    ['4.1.1.1', 1, 2, 2, 'Ensure audit log storage size is configured'],
    ['4.1.1.2', 1, 2, 2, 'Ensure system is disabled when audit logs are full'],
    ['4.1.1.3', 1, 2, 2, 'Ensure audit logs are not automatically deleted'],
    ['4.1.2', 1, 2, 2, 'Ensure auditd is installed (distro specific)'],
    ['4.1.3', 1, 2, 2, 'Ensure auditd service is enabled'],
    ['4.1.4', 1, 2, 2,
        'Ensure auditing for processes that start prior to auditd is enabled (bootloader specific)'],
    ['4.1.5', 1, 2, 2, 'Ensure events that modify date and time information are collected'],
    ['4.1.6', 1, 2, 2, 'Ensure events that modify user/group information are collected'],
    ['4.1.7', 1, 2, 2, "Ensure events that modify the system's network environment are collected"],
    ['4.1.8', 1, 2, 2, "Ensure events that modify the system's Mandatory Access Controls are collected"],
    ['4.1.9', 1, 2, 2, 'Ensure login and logout events are collected'],
    ['4.1.10', 1, 2, 2, 'Ensure session initiation information is collected'],
    ['4.1.11', 1, 2, 2, 'Ensure discretionary access control permission modification events are collected'],
    ['4.1.12', 1, 2, 2, 'Ensure unsuccessful unauthorized file access attempts are collected'],
    ['4.1.13', 1, 2, 2, 'Ensure use of privileged commands is collected'],
    ['4.1.14', 1, 2, 2, 'Ensure successful file system mounts are collected'],
    ['4.1.15', 1, 2, 2, 'Ensure file deletion events by users are collected'],
    ['4.1.16', 1, 2, 2,
        'Ensure changes to system administration scope (sudoers) is collected'],
    ['4.1.17', 1, 2, 2,
        'Ensure system administrator actions (sudolog) are collected'],
    ['4.1.18', 1, 2, 2, 'Ensure kernel module loading and unloading is collected'],
    ['4.1.19', 1, 2, 2, 'Ensure the audit configuration is immutable'],
    ['4.2.1.1', 1, 1, 1, 'Ensure rsyslog is installed (distro specific)'],
    ['4.2.1.2', 1, 1, 1, 'Ensure rsyslog Service is enabled'],
    ['4.2.1.3', 0, 1, 1, 'Ensure logging is configured'],
    ['4.2.1.4', 1, 1, 1, 'Ensure rsyslog default file permissions configured'],
    ['4.2.1.5', 1, 1, 1, 'Ensure rsyslog is configured to send logs to a remote log host'],
    ['4.2.1.6', 0, 1, 1,
        'Ensure remote rsyslog messages are only accepted on designated log hosts'],
    ['4.2.2.1', 1, 1, 1, 'Ensure journald is configured to send logs to rsyslog'],
    ['4.2.2.2', 1, 1, 1, 'Ensure journald is configured to compress large log files'],
    ['4.2.2.3', 1, 1, 1, 'Ensure journald is configured to write logfiles to persistent disk'],
    ['4.2.3', 1, 1, 1, 'Ensure permissions on all logfiles are configured'],
    ['4.3', 0, 1, 1, 'Ensure logrotate is configured'],
    ['5.1.1', 1, 1, 1, 'Ensure cron daemon is enabled'],
    ['5.1.2', 1, 1, 1, 'Ensure permissions on /etc/crontab are configured'],
    ['5.1.3', 1, 1, 1, 'Ensure permissions on /etc/cron.hourly are configured'],
    ['5.1.4', 1, 1, 1, 'Ensure permissions on /etc/cron.daily are configured'],
    ['5.1.5', 1, 1, 1, 'Ensure permissions on /etc/cron.weekly are configured'],
    ['5.1.6', 1, 1, 1, 'Ensure permissions on /etc/cron.monthly are configured'],
    ['5.1.7', 1, 1, 1, 'Ensure permissions on /etc/cron.d are configured'],
    ['5.1.8', 1, 1, 1, 'Ensure at/cron is restricted to authorized users'],
    ['5.2.1', 1, 1, 1, 'Ensure permissions on /etc/ssh/sshd_config are configured'],
    ['5.2.2', 1, 1, 1, 'Ensure permissions on SSH private host key files are configured'],
    ['5.2.3', 1, 1, 1, 'Ensure permissions on SSH public host key files are configured'],
    ['5.2.4', 1, 1, 1, 'Ensure SSH Protocol is set to 2'],
    ['5.2.5', 1, 1, 1, 'Ensure SSH LogLevel is appropriate'],
    ['5.2.6', 1, 2, 1, 'Ensure SSH X11 forwarding is disabled'],
    ['5.2.7', 1, 1, 1, 'Ensure SSH MaxAuthTries is set to 4 or less'],
    ['5.2.8', 1, 1, 1, 'Ensure SSH IgnoreRhosts is enabled'],
    ['5.2.9', 1, 1, 1, 'Ensure SSH HostbasedAuthentication is disabled'],
    ['5.2.10', 1, 1, 1, 'Ensure SSH root login is disabled'],
    ['5.2.11', 1, 1, 1, 'Ensure SSH PermitEmptyPasswords is disabled'],
    ['5.2.12', 1, 1, 1, 'Ensure SSH PermitUserEnvironment is disabled'],
    ['5.2.13', 1, 1, 1, 'Ensure only strong Ciphers are used'],
    ['5.2.14', 1, 1, 1, 'Ensure only strong MAC algorithms are used'],
    ['5.2.15', 1, 1, 1, 'Ensure only strong Key Exchange algorithms are used'],
    ['5.2.16', 1, 1, 1, 'Ensure SSH Idle Timeout Interval is configured'],
    ['5.2.17', 1, 1, 1, 'Ensure SSH LoginGraceTime is set to one minute or less'],
    ['5.2.18', 1, 1, 1, 'Ensure SSH access is limited'],
    ['5.2.19', 1, 1, 1, 'Ensure SSH warning banner is configured'],
    ['5.2.20', 1, 1, 1, 'Ensure SSH PAM is enabled'],
    ['5.2.21', 1, 2, 2, 'Ensure SSH AllowTcpForwarding is disabled'],
    ['5.2.22', 1, 1, 1, 'Ensure SSH MaxStartups is configured'],
    ['5.2.23', 1, 1, 1, 'Ensure SSH MaxSessions is set to 4 or less'],
    ['5.3.1', 1, 1, 1, 'Ensure password creation requirements are configured'],
    ['5.3.2', 0, 1, 1, 'Ensure lockout for failed password attempts is configured'],
    ['5.3.3', 0, 1, 1, 'Ensure password reuse is limited'],
    ['5.3.4', 0, 1, 1, 'Ensure password hashing algorithm is SHA-512'],
    ['5.4.1.1', 1, 1, 1, 'Ensure password expiration is 365 days or less'],
    ['5.4.1.2', 1, 1, 1, 'Ensure minimum days between password changes is 7 or more'],
    ['5.4.1.3', 1, 1, 1, 'Ensure password expiration warning days is 7 or more'],
    ['5.4.1.4', 1, 1, 1, 'Ensure inactive password lock is 30 days or less'],
    ['5.4.1.5', 1, 1, 1, 'Ensure all users last password change date is in the past'],
    ['5.4.2', 1, 1, 1, 'Ensure system accounts are secured'],
    ['5.4.3', 1, 1, 1, 'Ensure default group for the root account is GID 0'],
    ['5.4.4', 1, 1, 1, 'Ensure default user umask is 027 or more restrictive'],
    ['5.4.5', 1, 2, 2, 'Ensure default user shell timeout is 900 seconds or less'],
    ['5.5', 0, 1, 1, 'Ensure root login is restricted to system console'],
    ['5.6', 1, 1, 1, 'Ensure access to the su command is restricted'],
    ['6.1.1', 0, 2, 2, 'Audit system file permissions (distro specific)'],
    ['6.1.2', 1, 1, 1, 'Ensure permissions on /etc/passwd are configured'],
    ['6.1.3', 1, 1, 1, 'Ensure permissions on /etc/shadow are configured'],
    ['6.1.4', 1, 1, 1, 'Ensure permissions on /etc/group are configured'],
    ['6.1.5', 1, 1, 1, 'Ensure permissions on /etc/gshadow are configured'],
    ['6.1.6', 1, 1, 1, 'Ensure permissions on /etc/passwd- are configured'],
    ['6.1.7', 1, 1, 1, 'Ensure permissions on /etc/shadow- are configured'],
    ['6.1.8', 1, 1, 1, 'Ensure permissions on /etc/group- are configured'],
    ['6.1.9', 1, 1, 1, 'Ensure permissions on /etc/gshadow- are configured'],
    ['6.1.10', 1, 1, 1, 'Ensure no world writable files exist'],
    ['6.1.11', 1, 1, 1, 'Ensure no unowned files or directories exist'],
    ['6.1.12', 1, 1, 1, 'Ensure no ungrouped files or directories exist'],
    ['6.1.13', 0, 1, 1, 'Audit SUID executables'],
    ['6.1.14', 0, 1, 1, 'Audit SGID executables'],
    ['6.2.1', 1, 1, 1, 'Ensure password fields are not empty'],
    ['6.2.2', 1, 1, 1, 'Ensure no legacy "+" entries exist in /etc/passwd'],
    ['6.2.3', 1, 1, 1, 'Ensure no legacy "+" entries exist in /etc/shadow'],
    ['6.2.4', 1, 1, 1, 'Ensure no legacy "+" entries exist in /etc/group'],
    ['6.2.5', 1, 1, 1, 'Ensure root is the only UID 0 account'],
    ['6.2.6', 1, 1, 1, 'Ensure root PATH Integrity'],
    ['6.2.7', 1, 1, 1, "Ensure all users' home directories exist"],
    ['6.2.8', 1, 1, 1, "Ensure users' home directories permissions are 750 or more restrictive"],
    ['6.2.9', 1, 1, 1, 'Ensure users own their home directories'],
    ['6.2.10', 1, 1, 1, "Ensure users' dot files are not group or world writable"],
    ['6.2.11', 1, 1, 1, 'Ensure no users have .forward files'],
    ['6.2.12', 1, 1, 1, 'Ensure no users have .netrc files'],
    ['6.2.13', 1, 1, 1, "Ensure users' .netrc Files are not group or world accessible"],
    ['6.2.14', 1, 1, 1, 'Ensure no users have .rhosts files'],
    ['6.2.15', 1, 1, 1, 'Ensure all groups in /etc/passwd exist in /etc/group'],
    ['6.2.16', 1, 1, 1, 'Ensure no duplicate UIDs exist'],
    ['6.2.17', 1, 1, 1, 'Ensure no duplicate GIDs exist'],
    ['6.2.18', 1, 1, 1, 'Ensure no duplicate user names exist'],
    ['6.2.19', 1, 1, 1, 'Ensure no duplicate group names exist'],
    ['6.2.20', 1, 1, 1, 'Ensure shadow group is empty'],
]
benchmark_cen = [
    ['1.1.1.1', 1, 1, 1, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 0, 2, 2, 'Ensure mounting of vFAT filesystems is limited'],
    ['1.1.1.3', 1, 1, 1, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.4', 1, 1, 1, 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.2', 1, 1, 1, 'Ensure /tmp is configured'],
    ['1.1.3', 1, 1, 1, 'Ensure nodev option set on /tmp partition'],
    ['1.1.4', 1, 1, 1, 'Ensure nosuid option set on /tmp partition'],
    ['1.1.5', 1, 1, 1, 'Ensure noexec option set on /tmp partition'],
    ['1.1.6', 1, 2, 2, 'Ensure separate partition exists for /var'],
    ['1.1.7', 1, 2, 2, 'Ensure separate partition exists for /var/tmp'],
    ['1.1.8', 1, 1, 1, 'Ensure nodev option set on /var/tmp partition'],
    ['1.1.9', 1, 1, 1, 'Ensure nosuid option set on /var/tmp partition'],
    ['1.1.10', 1, 1, 1, 'Ensure noexec option set on /var/tmp partition'],
    ['1.1.11', 1, 2, 2, 'Ensure separate partition exists for /var/log'],
    ['1.1.12', 1, 2, 2, 'Ensure separate partition exists for /var/log/audit'],
    ['1.1.13', 1, 2, 2, 'Ensure separate partition exists for /home'],
    ['1.1.14', 1, 1, 1, 'Ensure nodev option set on /home partition'],
    ['1.1.15', 1, 1, 1, 'Ensure nodev option set on /dev/shm partition'],
    ['1.1.16', 1, 1, 1, 'Ensure nosuid option set on /dev/shm partition'],
    ['1.1.17', 1, 1, 1, 'Ensure noexec option set on /dev/shm partition'],
    ['1.1.21', 1, 1, 1, 'Ensure sticky bit is set on all world-writable directories'],
    ['1.1.22', 1, 1, 2, 'Disable Automounting'],
    ['1.1.23', 1, 1, 2, 'Disable USB Storage'],
]
benchmark_deb = [
    ['1.1.1.1', 1, 1, 1, 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.2', 1, 1, 1, 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.3', 1, 1, 1, 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.4', 1, 1, 1, 'Ensure mounting of hfsplus filesystems is disabled'],
    ['1.1.1.5', 1, 1, 1, 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.2', 1, 1, 1, 'Ensure /tmp is configured'],
    ['1.1.3', 1, 1, 1, 'Ensure nodev option set on /tmp partition'],
    ['1.1.4', 1, 1, 1, 'Ensure nosuid option set on /tmp partition'],
    ['1.1.5', 1, 1, 1, 'Ensure noexec option set on /tmp partition'],
    ['1.1.6', 1, 2, 2, 'Ensure separate partition exists for /var'],
    ['1.1.7', 1, 2, 2, 'Ensure separate partition exists for /var/tmp'],
    ['1.1.8', 1, 1, 1, 'Ensure nodev option set on /var/tmp partition'],
    ['1.1.9', 1, 1, 1, 'Ensure nosuid option set on /var/tmp partition'],
    ['1.1.10', 1, 1, 1, 'Ensure noexec option set on /var/tmp partition'],
    ['1.1.11', 1, 2, 2, 'Ensure separate partition exists for /var/log'],
    ['1.1.12', 1, 2, 2, 'Ensure separate partition exists for /var/log/audit'],
    ['1.1.13', 1, 2, 2, 'Ensure separate partition exists for /home'],
    ['1.1.14', 1, 1, 1, 'Ensure nodev option set on /home partition'],
    ['1.1.15', 1, 1, 1, 'Ensure nodev option set on /dev/shm partition'],
    ['1.1.16', 1, 1, 1, 'Ensure nosuid option set on /dev/shm partition'],
    ['1.1.17', 1, 1, 1, 'Ensure noexec option set on /dev/shm partition'],
    ['1.1.18', 0, 1, 1, 'Ensure nodev option set on removable media partitions'],
    ['1.1.19', 0, 1, 1, 'Ensure nosuid option set on removable media partitions'],
    ['1.1.20', 0, 1, 1, 'Ensure noexec option set on removable media partitions'],
    ['1.1.21', 1, 1, 1, 'Ensure sticky bit is set on all world-writable directories'],
    ['1.1.22', 1, 1, 2, 'Disable Automounting'],
    ['1.2.1', 0, 1, 1,
        'Ensure package manager repositories are configured'],
    ['1.2.2', 0, 1, 1, 'Ensure GPG keys are configured'],
    ['1.3.1', 1, 1, 1, 'Ensure AIDE is installed'],
    ['1.3.2', 1, 1, 1, 'Ensure filesystem integrity is regularly checked'],
    ['1.4.1', 1, 1, 1,
        'Ensure permissions on bootloader config are configured (bootloader specific)'],
    ['1.4.2', 1, 1, 1,
        'Ensure bootloader password is set (bootloader specific)'],
    ['1.4.3', 1, 1, 1, 'Ensure authentication required for single user mode'],
    ['1.5.1', 1, 1, 1, 'Ensure core dumps are restricted'],
    ['1.5.2', 0, 1, 1, 'Ensure XD/NX support is enabled'],
    ['1.5.3', 1, 1, 1,
        'Ensure address space layout randomization (ASLR) is enabled'],
    ['1.5.4', 1, 1, 1, 'Ensure prelink is disabled'],
    ['1.6.1.1', 1, 2, 2, 'Ensure SELinux is enabled in bootloader configuration'],
    ['1.6.1.2', 1, 2, 2, 'Ensure the SELinux state is enforcing'],
    ['1.6.1.3', 1, 2, 2, 'Ensure SELinux policy is configured'],
    ['1.6.1.4', 1, 2, 2, 'Ensure no unconfined daemons exist'],
    ['1.6.2.1', 1, 2, 2, 'Ensure AppArmor is enabled in the bootloader configuration'],
    ['1.6.2.2', 1, 2, 2, 'Ensure all AppArmor Profiles are enforcing'],
    ['1.6.3', 1, 2, 2, 'Ensure SELinux or AppArmor are installed'],
    ['1.7.1.1', 1, 1, 1, 'Ensure message of the day is configured properly'],
    ['1.7.1.2', 1, 1, 1, 'Ensure local login warning banner is configured properly'],
    ['1.7.1.3', 1, 1, 1, 'Ensure remote login warning banner is configured properly'],
    ['1.7.1.4', 1, 1, 1, 'Ensure permissions on /etc/motd are configured'],
    ['1.7.1.5', 1, 1, 1, 'Ensure permissions on /etc/issue are configured'],
    ['1.7.1.6', 1, 1, 1, 'Ensure permissions on /etc/issue.net are configured'],
    ['1.7.2', 1, 1, 1, 'Ensure GDM login banner is configured'],
    ['1.8', 0, 1, 1,
        'Ensure updates, patches, and additional security software are installed'],
    ['2.1.1', 1, 1, 1, 'Ensure xinetd is not installed'],
    ['2.1.2', 1, 1, 1, 'Ensure openbsd-inetd is not installed'],
    ['2.2.1.1', 0, 1, 1,
        'Ensure time synchronization is in use'],
    ['2.2.1.2', 1, 1, 1, 'Ensure ntp is configured'],
    ['2.2.1.3', 1, 1, 1, 'Ensure chrony is configured'],
    ['2.2.2', 1, 1, 0,
        'Ensure X Window System is not installed'],
    ['2.2.3', 1, 1, 1, 'Ensure Avahi Server is not enabled'],
    ['2.2.4', 1, 1, 2, 'Ensure CUPS is not enabled'],
    ['2.2.5', 1, 1, 1, 'Ensure DHCP Server is not enabled'],
    ['2.2.6', 1, 1, 1, 'Ensure LDAP server is not enabled'],
    ['2.2.7', 1, 1, 1, 'Ensure NFS and RPC are not enabled'],
    ['2.2.8', 1, 1, 1, 'Ensure DNS Server is not enabled'],
    ['2.2.9', 1, 1, 1, 'Ensure FTP Server is not enabled'],
    ['2.2.10', 1, 1, 1, 'Ensure HTTP server is not enabled'],
    ['2.2.11', 1, 1, 1, 'Ensure IMAP and POP3 server is not enabled'],
    ['2.2.12', 1, 1, 1, 'Ensure Samba is not enabled'],
    ['2.2.13', 1, 1, 1, 'Ensure HTTP Proxy Server is not enabled'],
    ['2.2.14', 1, 1, 1, 'Ensure SNMP Server is not enabled'],
    ['2.2.15', 1, 1, 1, 'Ensure mail transfer agent is configured for local-only mode'],
    ['2.2.16', 1, 1, 1, 'Ensure rsync service is not enabled'],
    ['2.2.17', 1, 1, 1, 'Ensure NIS Server is not enabled'],
    ['2.3.1', 1, 1, 1, 'Ensure NIS Client is not installed'],
    ['2.3.2', 1, 1, 1, 'Ensure rsh client is not installed'],
    ['2.3.3', 1, 1, 1,
        'Ensure talk client is not installed'],
    ['2.3.4', 1, 1, 1,
        'Ensure telnet client is not installed'],
    ['2.3.5', 1, 1, 1,
        'Ensure LDAP client is not installed'],
    ['3.1.1', 1, 1, 1, 'Ensure IP forwarding is disabled'],
    ['3.1.2', 1, 1, 1, 'Ensure packet redirect sending is disabled'],
    ['3.2.1', 1, 1, 1, 'Ensure source routed packets are not accepted'],
    ['3.2.2', 1, 1, 1, 'Ensure ICMP redirects are not accepted'],
    ['3.2.3', 1, 1, 1, 'Ensure secure ICMP redirects are not accepted'],
    ['3.2.4', 1, 1, 1, 'Ensure suspicious packets are logged'],
    ['3.2.5', 1, 1, 1, 'Ensure broadcast ICMP requests are ignored'],
    ['3.2.6', 1, 1, 1, 'Ensure bogus ICMP responses are ignored'],
    ['3.2.7', 1, 1, 1, 'Ensure Reverse Path Filtering is enabled'],
    ['3.2.8', 1, 1, 1, 'Ensure TCP SYN Cookies is enabled'],
    ['3.2.9', 1, 1, 1, 'Ensure IPv6 router advertisements are not accepted'],
    ['3.3.1', 1, 1, 1, 'Ensure TCP Wrappers is installed'],
    ['3.3.2', 0, 1, 1, 'Ensure /etc/hosts.allow is configured'],
    ['3.3.3', 0, 1, 1, 'Ensure /etc/hosts.deny is configured'],
    ['3.3.4', 1, 1, 1, 'Ensure permissions on /etc/hosts.allow are configured'],
    ['3.3.5', 1, 1, 1, 'Ensure permissions on /etc/hosts.deny are configured'],
    ['3.4.1', 0, 1, 1, 'Ensure DCCP is disabled'],
    ['3.4.2', 0, 1, 1, 'Ensure SCTP is disabled'],
    ['3.4.3', 0, 1, 1, 'Ensure RDS is disabled'],
    ['3.4.4', 0, 1, 1, 'Ensure TIPC is disabled'],
    ['3.5.1.1', 1, 1, 1, 'Ensure default deny firewall policy'],
    ['3.5.1.2', 1, 1, 1, 'Ensure loopback traffic is configured'],
    ['3.5.1.3', 0, 1, 1, 'Ensure outbound and established connections are configured'],
    ['3.5.1.4', 1, 1, 1, 'Ensure firewall rules exist for all open ports'],
    ['3.5.2.1', 1, 1, 1, 'Ensure IPv6 default deny firewall policy'],
    ['3.5.2.2', 1, 1, 1, 'Ensure IPv6 loopback traffic is configured'],
    ['3.5.2.3', 0, 1, 1, 'Ensure IPv6 outbound and established connections are configured'],
    ['3.5.2.4', 0, 1, 1, 'Ensure IPv6 firewall rules exist for all open ports'],
    ['3.5.3', 1, 1, 1, 'Ensure iptables is installed'],
    ['3.6', 0, 1, 2, 'Ensure wireless interfaces are disabled'],
    ['3.7', 0, 2, 2, 'Disable IPv6'],
    ['4.1.1.1', 0, 2, 2, 'Ensure audit log storage size is configured'],
    ['4.1.1.2', 1, 2, 2, 'Ensure system is disabled when audit logs are full'],
    ['4.1.1.3', 1, 2, 2, 'Ensure audit logs are not automatically deleted'],
    ['4.1.2', 1, 2, 2, 'Ensure auditd service is enabled'],
    ['4.1.3', 1, 2, 2,
        'Ensure auditing for processes that start prior to auditd is enabled (bootloader specific)'],
    ['4.1.4', 1, 2, 2, 'Ensure events that modify date and time information are collected'],
    ['4.1.5', 1, 2, 2, 'Ensure events that modify user/group information are collected'],
    ['4.1.6', 1, 2, 2, "Ensure events that modify the system's network environment are collected"],
    ['4.1.7', 1, 2, 2, "Ensure events that modify the system's Mandatory Access Controls are collected"],
    ['4.1.8', 1, 2, 2, 'Ensure login and logout events are collected'],
    ['4.1.9', 1, 2, 2, 'Ensure session initiation information is collected'],
    ['4.1.10', 1, 2, 2, 'Ensure discretionary access control permission modification events are collected'],
    ['4.1.11', 1, 2, 2, 'Ensure unsuccessful unauthorized file access attempts are collected'],
    ['4.1.12', 1, 2, 2, 'Ensure use of privileged commands is collected'],
    ['4.1.13', 1, 2, 2, 'Ensure successful file system mounts are collected'],
    ['4.1.14', 1, 2, 2, 'Ensure file deletion events by users are collected'],
    ['4.1.15', 1, 2, 2,
        'Ensure changes to system administration scope (sudoers) is collected'],
    ['4.1.16', 1, 2, 2,
        'Ensure system administrator actions (sudolog) are collected'],
    ['4.1.17', 1, 2, 2, 'Ensure kernel module loading and unloading is collected'],
    ['4.1.18', 1, 2, 2, 'Ensure the audit configuration is immutable'],
    ['4.2.1.1', 1, 1, 1, 'Ensure rsyslog Service is enabled'],
    ['4.2.1.2', 0, 1, 1, 'Ensure logging is configured'],
    ['4.2.1.3', 1, 1, 1, 'Ensure rsyslog default file permissions configured'],
    ['4.2.1.4', 1, 1, 1, 'Ensure rsyslog is configured to send logs to a remote log host'],
    ['4.2.1.5', 0, 1, 1,
        'Ensure remote rsyslog messages are only accepted on designated log hosts'],
    ['4.2.2.1', 1, 1, 1, 'Ensure syslog-ng service is enabled'],
    ['4.2.2.2', 0, 1, 1, 'Ensure logging is configured'],
    ['4.2.2.3', 1, 1, 1, 'Ensure syslog-ng default file permissions configured'],
    ['4.2.2.4', 0, 1, 1, 'Ensure syslog-ng is configured to send logs to a remote log host'],
    ['4.2.2.5', 0, 1, 1,
        'Ensure remote syslog-ng messages are only accepted on designated log hosts'],
    ['4.2.3', 1, 1, 1, 'Ensure rsyslog or syslog-ng is installed'],
    ['4.2.4', 1, 1, 1, 'Ensure permissions on all logfiles are configured'],
    ['4.3', 0, 1, 1, 'Ensure logrotate is configured'],
    ['5.1.1', 1, 1, 1, 'Ensure cron daemon is enabled'],
    ['5.1.2', 1, 1, 1, 'Ensure permissions on /etc/crontab are configured'],
    ['5.1.3', 1, 1, 1, 'Ensure permissions on /etc/cron.hourly are configured'],
    ['5.1.4', 1, 1, 1, 'Ensure permissions on /etc/cron.daily are configured'],
    ['5.1.5', 1, 1, 1, 'Ensure permissions on /etc/cron.weekly are configured'],
    ['5.1.6', 1, 1, 1, 'Ensure permissions on /etc/cron.monthly are configured'],
    ['5.1.7', 1, 1, 1, 'Ensure permissions on /etc/cron.d are configured'],
    ['5.1.8', 1, 1, 1, 'Ensure at/cron is restricted to authorized users'],
    ['5.2.1', 1, 1, 1, 'Ensure permissions on /etc/ssh/sshd_config are configured'],
    ['5.2.2', 1, 1, 1, 'Ensure permissions on SSH private host key files are configured'],
    ['5.2.3', 1, 1, 1, 'Ensure permissions on SSH public host key files are configured'],
    ['5.2.4', 1, 1, 1, 'Ensure SSH Protocol is set to 2'],
    ['5.2.5', 1, 1, 1, 'Ensure SSH LogLevel is appropriate'],
    ['5.2.6', 1, 2, 1, 'Ensure SSH X11 forwarding is disabled'],
    ['5.2.7', 1, 1, 1, 'Ensure SSH MaxAuthTries is set to 4 or less'],
    ['5.2.8', 1, 1, 1, 'Ensure SSH IgnoreRhosts is enabled'],
    ['5.2.9', 1, 1, 1, 'Ensure SSH HostbasedAuthentication is disabled'],
    ['5.2.10', 1, 1, 1, 'Ensure SSH root login is disabled'],
    ['5.2.11', 1, 1, 1, 'Ensure SSH PermitEmptyPasswords is disabled'],
    ['5.2.12', 1, 1, 1, 'Ensure SSH PermitUserEnvironment is disabled'],
    ['5.2.13', 1, 1, 1, 'Ensure only strong Ciphers are used'],
    ['5.2.14', 1, 1, 1, 'Ensure only strong MAC algorithms are used'],
    ['5.2.15', 1, 1, 1, 'Ensure only strong Key Exchange algorithms are used'],
    ['5.2.16', 1, 1, 1, 'Ensure SSH Idle Timeout Interval is configured'],
    ['5.2.17', 1, 1, 1, 'Ensure SSH LoginGraceTime is set to one minute or less'],
    ['5.2.18', 1, 1, 1, 'Ensure SSH access is limited'],
    ['5.2.19', 1, 1, 1, 'Ensure SSH warning banner is configured'],
    ['5.3.1', 1, 1, 1, 'Ensure password creation requirements are configured'],
    ['5.3.2', 1, 1, 1, 'Ensure lockout for failed password attempts is configured'],
    ['5.3.3', 1, 1, 1, 'Ensure password reuse is limited'],
    ['5.3.4', 1, 1, 1, 'Ensure password hashing algorithm is SHA-512'],
    ['5.4.1.1', 1, 1, 1, 'Ensure password expiration is 365 days or less'],
    ['5.4.1.2', 1, 1, 1, 'Ensure minimum days between password changes is 7 or more'],
    ['5.4.1.3', 1, 1, 1, 'Ensure password expiration warning days is 7 or more'],
    ['5.4.1.4', 1, 1, 1, 'Ensure inactive password lock is 30 days or less'],
    ['5.4.1.5', 1, 1, 1, 'Ensure all users last password change date is in the past'],
    ['5.4.2', 1, 1, 1, 'Ensure system accounts are non-login'],
    ['5.4.3', 1, 1, 1, 'Ensure default group for the root account is GID 0'],
    ['5.4.4', 1, 1, 1, 'Ensure default user umask is 027 or more restrictive'],
    ['5.4.5', 1, 2, 2, 'Ensure default user shell timeout is 900 seconds or less'],
    ['5.5', 0, 1, 1, 'Ensure root login is restricted to system console'],
    ['5.6', 1, 1, 1, 'Ensure access to the su command is restricted'],
    ['6.1.1', 0, 2, 2, 'Audit system file permissions'],
    ['6.1.2', 1, 1, 1, 'Ensure permissions on /etc/gshadow are configured'],
    ['6.1.3', 1, 1, 1, 'Ensure permissions on /etc/shadow- are configured'],
    ['6.1.4', 1, 1, 1, 'Ensure permissions on /etc/gshadow- are configured'],
    ['6.1.5', 1, 1, 1, 'Ensure permissions on /etc/passwd are configured'],
    ['6.1.6', 1, 1, 1, 'Ensure permissions on /etc/shadow are configured'],
    ['6.1.7', 1, 1, 1, 'Ensure permissions on /etc/group are configured'],
    ['6.1.8', 1, 1, 1, 'Ensure permissions on /etc/passwd- are configured'],
    ['6.1.9', 1, 1, 1, 'Ensure permissions on /etc/group- are configured'],
    ['6.1.10', 1, 1, 1, 'Ensure no world writable files exist'],
    ['6.1.11', 1, 1, 1, 'Ensure no unowned files or directories exist'],
    ['6.1.12', 1, 1, 1, 'Ensure no ungrouped files or directories exist'],
    ['6.1.13', 0, 1, 1, 'Audit SUID executables'],
    ['6.1.14', 0, 1, 1, 'Audit SGID executables'],
    ['6.2.1', 1, 1, 1, 'Ensure password fields are not empty'],
    ['6.2.2', 1, 1, 1, 'Ensure no legacy "+" entries exist in /etc/passwd'],
    ['6.2.3', 1, 1, 1, 'Ensure no legacy "+" entries exist in /etc/shadow'],
    ['6.2.4', 1, 1, 1, 'Ensure no legacy "+" entries exist in /etc/group'],
    ['6.2.5', 1, 1, 1, 'Ensure root is the only UID 0 account'],
    ['6.2.6', 1, 1, 1, 'Ensure root PATH Integrity'],
    ['6.2.7', 1, 1, 1, "Ensure all users' home directories exist"],
    ['6.2.8', 1, 1, 1, "Ensure users' home directories permissions are 750 or more restrictive"],
    ['6.2.9', 1, 1, 1, 'Ensure users own their home directories'],
    ['6.2.10', 1, 1, 1, "Ensure users' dot files are not group or world writable"],
    ['6.2.11', 1, 1, 1, 'Ensure no users have .forward files'],
    ['6.2.12', 1, 1, 1, 'Ensure no users have .netrc files'],
    ['6.2.13', 1, 1, 1, "Ensure users' .netrc Files are not group or world accessible"],
    ['6.2.14', 1, 1, 1, 'Ensure no users have .rhosts files'],
    ['6.2.15', 1, 1, 1, 'Ensure all groups in /etc/passwd exist in /etc/group'],
    ['6.2.16', 1, 1, 1, 'Ensure no duplicate UIDs exist'],
    ['6.2.17', 1, 1, 1, 'Ensure no duplicate GIDs exist'],
    ['6.2.18', 1, 1, 1, 'Ensure no duplicate user names exist'],
    ['6.2.19', 1, 1, 1, 'Ensure no duplicate group names exist'],
    ['6.2.20', 1, 1, 1, 'Ensure shadow group is empty'],
]
benchmark_fed = [
    ['1.1.1.1', 1, 1, 1, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 0, 2, 2, 'Ensure mounting of vFAT filesystems is limited'],
    ['1.1.1.3', 1, 1, 1, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.4', 1, 1, 1, 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.2', 1, 1, 1, 'Ensure /tmp is configured'],
    ['1.1.3', 1, 1, 1, 'Ensure nodev option set on /tmp partition'],
    ['1.1.4', 1, 1, 1, 'Ensure nosuid option set on /tmp partition'],
    ['1.1.5', 1, 1, 1, 'Ensure noexec option set on /tmp partition'],
    ['1.1.6', 1, 2, 2, 'Ensure separate partition exists for /var'],
    ['1.1.7', 1, 2, 2, 'Ensure separate partition exists for /var/tmp'],
    ['1.1.8', 1, 1, 1, 'Ensure nodev option set on /var/tmp partition'],
    ['1.1.9', 1, 1, 1, 'Ensure nosuid option set on /var/tmp partition'],
    ['1.1.10', 1, 1, 1, 'Ensure noexec option set on /var/tmp partition'],
    ['1.1.11', 1, 2, 2, 'Ensure separate partition exists for /var/log'],
    ['1.1.12', 1, 2, 2, 'Ensure separate partition exists for /var/log/audit'],
    ['1.1.13', 1, 2, 2, 'Ensure separate partition exists for /home'],
    ['1.1.14', 1, 1, 1, 'Ensure nodev option set on /home partition'],
    ['1.1.15', 1, 1, 1, 'Ensure nodev option set on /dev/shm partition'],
    ['1.1.16', 1, 1, 1, 'Ensure nosuid option set on /dev/shm partition'],
    ['1.1.17', 1, 1, 1, 'Ensure noexec option set on /dev/shm partition'],
    ['1.1.21', 1, 1, 1, 'Ensure sticky bit is set on all world-writable directories'],
    ['1.1.22', 1, 1, 2, 'Disable Automounting'],
    ['1.1.23', 1, 1, 2, 'Disable USB Storage'],
]
benchmark_red = [
    ['1.1.1.1', 1, 1, 1, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 0, 2, 2, 'Ensure mounting of vFAT filesystems is limited'],
    ['1.1.1.3', 1, 1, 1, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.4', 1, 1, 1, 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.2', 1, 1, 1, 'Ensure /tmp is configured'],
    ['1.1.3', 1, 1, 1, 'Ensure nodev option set on /tmp partition'],
    ['1.1.4', 1, 1, 1, 'Ensure nosuid option set on /tmp partition'],
    ['1.1.5', 1, 1, 1, 'Ensure noexec option set on /tmp partition'],
    ['1.1.6', 1, 2, 2, 'Ensure separate partition exists for /var'],
    ['1.1.7', 1, 2, 2, 'Ensure separate partition exists for /var/tmp'],
    ['1.1.8', 1, 1, 1, 'Ensure nodev option set on /var/tmp partition'],
    ['1.1.9', 1, 1, 1, 'Ensure nosuid option set on /var/tmp partition'],
    ['1.1.10', 1, 1, 1, 'Ensure noexec option set on /var/tmp partition'],
    ['1.1.11', 1, 2, 2, 'Ensure separate partition exists for /var/log'],
    ['1.1.12', 1, 2, 2, 'Ensure separate partition exists for /var/log/audit'],
    ['1.1.13', 1, 2, 2, 'Ensure separate partition exists for /home'],
    ['1.1.14', 1, 1, 1, 'Ensure nodev option set on /home partition'],
    ['1.1.15', 1, 1, 1, 'Ensure nodev option set on /dev/shm partition'],
    ['1.1.16', 1, 1, 1, 'Ensure nosuid option set on /dev/shm partition'],
    ['1.1.17', 1, 1, 1, 'Ensure noexec option set on /dev/shm partition'],
    ['1.1.21', 1, 1, 1, 'Ensure sticky bit is set on all world-writable directories'],
    ['1.1.22', 1, 1, 2, 'Disable Automounting'],
    ['1.1.23', 1, 1, 2, 'Disable USB Storage'],
]
benchmark_sus = [
    ['1.1.1.1', 1, 1, 1, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 1, 1, 1, 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.3', 1, 1, 1, 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.4', 1, 1, 1, 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.5', 1, 1, 1, 'Ensure mounting of hfsplus filesystems is disabled'],
    ['1.1.1.6', 1, 1, 1, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.7', 1, 1, 1, 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.1.8', 1, 2, 2, 'Ensure mounting of FAT filesystems is disabled'],
    ['1.1.2', 1, 2, 2, 'Ensure /tmp is configured'],
    ['1.1.3', 1, 1, 1, 'Ensure nodev option set on /tmp partition'],
    ['1.1.4', 1, 1, 1, 'Ensure nosuid option set on /tmp partition'],
    ['1.1.5', 1, 1, 1, 'Ensure noexec option set on /tmp partition'],
    ['1.1.6', 1, 2, 2, 'Ensure separate partition exists for /var'],
    ['1.1.7', 1, 2, 2, 'Ensure separate partition exists for /var/tmp'],
    ['1.1.8', 1, 1, 1, 'Ensure nodev option set on /var/tmp partition'],
    ['1.1.9', 1, 1, 1, 'Ensure nosuid option set on /var/tmp partition'],
    ['1.1.10', 1, 1, 1, 'Ensure noexec option set on /var/tmp partition'],
    ['1.1.11', 1, 2, 2, 'Ensure separate partition exists for /var/log'],
    ['1.1.12', 1, 2, 2, 'Ensure separate partition exists for /var/log/audit'],
    ['1.1.13', 1, 2, 2, 'Ensure separate partition exists for /home'],
    ['1.1.14', 1, 1, 1, 'Ensure nodev option set on /home partition'],
    ['1.1.15', 1, 1, 1, 'Ensure nodev option set on /dev/shm partition'],
    ['1.1.16', 1, 1, 1, 'Ensure nosuid option set on /dev/shm partition'],
    ['1.1.17', 1, 1, 1, 'Ensure noexec option set on /dev/shm partition'],
    ['1.1.21', 1, 1, 1, 'Ensure sticky bit is set on all world-writable directories'],
    ['1.1.22', 1, 1, 2, 'Disable Automounting'],
]
benchmark_ubu = [
    ['1.1.1.1', 1, 1, 1, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 1, 1, 1, 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.3', 1, 1, 1, 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.4', 1, 1, 1, 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.5', 1, 1, 1, 'Ensure mounting of hfsplus filesystems is disabled'],
    ['1.1.1.6', 1, 1, 1, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.7', 1, 1, 1, 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.1.8', 0, 2, 2, 'Ensure mounting of FAT filesystems is limited'],
    ['1.1.2', 1, 1, 1, 'Ensure /tmp is configured'],
    ['1.1.3', 1, 1, 1, 'Ensure nodev option set on /tmp partition'],
    ['1.1.4', 1, 1, 1, 'Ensure nosuid option set on /tmp partition'],
    ['1.1.5', 1, 1, 1, 'Ensure noexec option set on /tmp partition'],
    ['1.1.6', 1, 2, 2, 'Ensure separate partition exists for /var'],
    ['1.1.7', 1, 2, 2, 'Ensure separate partition exists for /var/tmp'],
    ['1.1.8', 1, 1, 1, 'Ensure nodev option set on /var/tmp partition'],
    ['1.1.9', 1, 1, 1, 'Ensure nosuid option set on /var/tmp partition'],
    ['1.1.10', 1, 1, 1, 'Ensure noexec option set on /var/tmp partition'],
    ['1.1.11', 1, 2, 2, 'Ensure separate partition exists for /var/log'],
    ['1.1.12', 1, 2, 2, 'Ensure separate partition exists for /var/log/audit'],
    ['1.1.13', 1, 2, 2, 'Ensure separate partition exists for /home'],
    ['1.1.14', 1, 1, 1, 'Ensure nodev option set on /home partition'],
    ['1.1.15', 1, 1, 1, 'Ensure nodev option set on /dev/shm partition'],
    ['1.1.16', 1, 1, 1, 'Ensure nosuid option set on /dev/shm partition'],
    ['1.1.17', 1, 1, 1, 'Ensure noexec option set on /dev/shm partition'],
    ['1.1.21', 1, 1, 1, 'Ensure sticky bit is set on all world-writable directories'],
    ['1.1.22', 1, 1, 2, 'Disable Automounting'],
    ['1.1.23', 1, 1, 2, 'Disable USB Storage'],
    ['1.2.1', 0, 1, 1,
        'Ensure package manager repositories are configured'],
    ['1.2.2', 0, 1, 1, 'Ensure GPG keys are configured'],
    ['1.3.1', 1, 1, 1, 'Ensure sudo is installed'],
    ['1.3.2', 1, 1, 1, 'Ensure sudo commands use pty'],
    ['1.3.3', 1, 1, 1, 'Ensure sudo log file exists'],
    ['1.4.1', 1, 1, 1, 'Ensure AIDE is installed'],
    ['1.4.2', 1, 1, 1, 'Ensure filesystem integrity is regularly checked'],
    ['1.5.1', 1, 1, 1,
        'Ensure permissions on bootloader config are configured (bootloader specific)'],
    ['1.5.2', 1, 1, 1,
        'Ensure bootloader password is set (bootloader specific)'],
    ['1.5.3', 1, 1, 1, 'Ensure authentication required for single user mode'],
    ['1.5.4', 0, 1, 1,
        'Ensure interactive boot is not enabled (bootloader specific)'],
    ['1.6.1', 1, 1, 1, 'Ensure XD/NX support is enabled'],
    ['1.6.2', 1, 1, 1,
        'Ensure address space layout randomization (ASLR) is enabled'],
    ['1.6.3', 1, 1, 1, 'Ensure prelink is disabled'],
    ['1.6.4', 1, 1, 1, 'Ensure core dumps are restricted'],
    ['1.7.1.1', 1, 1, 1, 'Ensure AppArmor is installed'],
    ['1.7.1.2', 1, 1, 1, 'Ensure AppArmor is enabled in the bootloader configuration'],
    ['1.7.1.3', 1, 1, 1, 'Ensure all AppArmor Profiles are in enforce or complain mode'],
    ['1.7.1.4', 1, 2, 2, 'Ensure all AppArmor Profiles are enforcing'],
    ['1.8.1.1', 1, 1, 1, 'Ensure message of the day is configured properly'],
    ['1.8.1.2', 1, 1, 1, 'Ensure local login warning banner is configured properly'],
    ['1.8.1.3', 1, 1, 1, 'Ensure remote login warning banner is configured properly'],
    ['1.8.1.4', 1, 1, 1, 'Ensure permissions on /etc/motd are configured'],
    ['1.8.1.5', 1, 1, 1, 'Ensure permissions on /etc/issue are configured'],
    ['1.8.1.6', 1, 1, 1, 'Ensure permissions on /etc/issue.net are configured'],
    ['1.8.2', 1, 1, 1, 'Ensure GDM login banner is configured'],
    ['1.9', 0, 1, 1,
        'Ensure updates, patches, and additional security software are installed'],
    ['2.1.1', 1, 1, 1, 'Ensure xinetd is not installed'],
    ['2.1.2', 1, 1, 1, 'Ensure openbsd-inetd is not installed'],
    ['2.2.1.1', 1, 1, 1,
        'Ensure time synchronization is in use'],
    ['2.2.1.2', 0, 1, 1, 'Ensure systemd-timesyncd is configured'],
    ['2.2.1.3', 1, 1, 1, 'Ensure chrony is configured'],
    ['2.2.1.4', 1, 1, 1, 'Ensure ntp is configured'],
    ['2.2.2', 1, 1, 0,
        'Ensure X Window System is not installed'],
    ['2.2.3', 1, 1, 1, 'Ensure Avahi Server is not enabled'],
    ['2.2.4', 1, 1, 2, 'Ensure CUPS is not enabled'],
    ['2.2.5', 1, 1, 1, 'Ensure DHCP Server is not enabled'],
    ['2.2.6', 1, 1, 1, 'Ensure LDAP server is not enabled'],
    ['2.2.7', 1, 1, 1, 'Ensure NFS and RPC are not enabled'],
    ['2.2.8', 1, 1, 1, 'Ensure DNS Server is not enabled'],
    ['2.2.9', 1, 1, 1, 'Ensure FTP Server is not enabled'],
    ['2.2.10', 1, 1, 1, 'Ensure HTTP server is not enabled'],
    ['2.2.11', 1, 1, 1, 'Ensure email services are not enabled'],
    ['2.2.12', 1, 1, 1, 'Ensure Samba is not enabled'],
    ['2.2.13', 1, 1, 1, 'Ensure HTTP Proxy Server is not enabled'],
    ['2.2.14', 1, 1, 1, 'Ensure SNMP Server is not enabled'],
    ['2.2.15', 1, 1, 1, 'Ensure mail transfer agent is configured for local-only mode'],
    ['2.2.16', 1, 1, 1, 'Ensure rsync service is not enabled'],
    ['2.2.17', 1, 1, 1, 'Ensure NIS Server is not enabled'],
    ['2.3.1', 1, 1, 1, 'Ensure NIS Client is not installed'],
    ['2.3.2', 1, 1, 1, 'Ensure rsh client is not installed'],
    ['2.3.3', 1, 1, 1,
        'Ensure talk client is not installed'],
    ['2.3.4', 1, 1, 1,
        'Ensure telnet client is not installed'],
    ['2.3.5', 1, 1, 1,
        'Ensure LDAP client is not installed'],
    ['3.1.1', 1, 1, 1, 'Ensure packet redirect sending is disabled'],
    ['3.1.2', 1, 1, 1, 'Ensure IP forwarding is disabled'],
    ['3.2.1', 1, 1, 1, 'Ensure source routed packets are not accepted'],
    ['3.2.2', 1, 1, 1, 'Ensure ICMP redirects are not accepted'],
    ['3.2.3', 1, 1, 1, 'Ensure secure ICMP redirects are not accepted'],
    ['3.2.4', 1, 1, 1, 'Ensure suspicious packets are logged'],
    ['3.2.5', 1, 1, 1, 'Ensure broadcast ICMP requests are ignored'],
    ['3.2.6', 1, 1, 1, 'Ensure bogus ICMP responses are ignored'],
    ['3.2.7', 1, 1, 1, 'Ensure Reverse Path Filtering is enabled'],
    ['3.2.8', 1, 1, 1, 'Ensure TCP SYN Cookies is enabled'],
    ['3.2.9', 1, 1, 1, 'Ensure IPv6 router advertisements are not accepted'],
    ['3.3.1', 1, 1, 1, 'Ensure TCP Wrappers is installed'],
    ['3.3.2', 0, 1, 1, 'Ensure /etc/hosts.allow is configured'],
    ['3.3.3', 0, 1, 1, 'Ensure /etc/hosts.deny is configured'],
    ['3.3.4', 1, 1, 1, 'Ensure permissions on /etc/hosts.allow are configured'],
    ['3.3.5', 1, 1, 1, 'Ensure permissions on /etc/hosts.deny are configured'],
    ['3.4.1', 1, 2, 2, 'Ensure DCCP is disabled'],
    ['3.4.2', 1, 2, 2, 'Ensure SCTP is disabled'],
    ['3.4.3', 1, 2, 2, 'Ensure RDS is disabled'],
    ['3.4.4', 1, 2, 2, 'Ensure TIPC is disabled'],
    ['3.5.1.1', 1, 1, 1, 'Ensure a Firewall package is installed'],
    ['3.5.2.1', 1, 1, 1, 'Ensure ufw service is enabled'],
    ['3.5.2.2', 1, 1, 1, 'Ensure default deny firewall policy'],
    ['3.5.2.3', 1, 1, 1, 'Ensure loopback traffic is configured'],
    ['3.5.2.4', 0, 1, 1, 'Ensure outbound connections are configured'],
    ['3.5.2.5', 0, 1, 1, 'Ensure firewall rules exist for all open ports'],
    ['3.5.3.1', 0, 1, 1, 'Ensure iptables are flushed'],
    ['3.5.3.2', 1, 1, 1, 'Ensure a table exists'],
    ['3.5.3.3', 1, 1, 1, 'Ensure base chains exist'],
    ['3.5.3.4', 1, 1, 1, 'Ensure loopback traffic is configured'],
    ['3.5.3.5', 0, 1, 1, 'Ensure outbound and established connections are configured'],
    ['3.5.3.6', 1, 1, 1, 'Ensure default deny firewall policy'],
    ['3.5.3.7', 1, 1, 1, 'Ensure nftables service is enabled'],
    ['3.5.3.8', 1, 1, 1, 'Ensure nftables rules are permanent'],
    ['3.5.4.1.1', 1, 1, 1, 'Ensure default deny firewall policy'],
    ['3.5.4.1.2', 1, 1, 1, 'Ensure loopback traffic is configured'],
    ['3.5.4.1.3', 0, 1, 1, 'Ensure outbound and established connections are configured'],
    ['3.5.4.1.4', 1, 1, 1, 'Ensure firewall rules exist for all open ports'],
    ['3.5.4.2.1', 1, 1, 1, 'Ensure IPv6 default deny firewall policy'],
    ['3.5.4.2.2', 1, 1, 1, 'Ensure IPv6 loopback traffic is configured'],
    ['3.5.4.2.3', 0, 1, 1, 'Ensure IPv6 outbound and established connections are configured'],
    ['3.5.4.2.4', 0, 1, 1, 'Ensure IPv6 firewall rules exist for all open ports'],
    ['3.6', 0, 1, 2, 'Ensure wireless interfaces are disabled'],
    ['3.7', 0, 2, 2, 'Disable IPv6'],
    ['4.1.1.1', 1, 2, 2, 'Ensure auditd is installed'],
    ['4.1.1.2', 1, 2, 2, 'Ensure auditd service is enabled'],
    ['4.1.1.3', 1, 2, 2,
        'Ensure auditing for processes that start prior to auditd is enabled (bootloader specific)'],
    ['4.1.1.4', 1, 2, 2, 'Ensure audit_backlog_limit is sufficient'],
    ['4.1.2.1', 1, 2, 2, 'Ensure audit log storage size is configured'],
    ['4.1.2.2', 1, 2, 2, 'Ensure audit logs are not automatically deleted'],
    ['4.1.2.3', 1, 2, 2, 'Ensure system is disabled when audit logs are full'],
    ['4.1.3', 1, 2, 2, 'Ensure events that modify date and time information are collected'],
    ['4.1.4', 1, 2, 2, 'Ensure events that modify user/group information are collected'],
    ['4.1.5', 1, 2, 2, "Ensure events that modify the system's network environment are collected"],
    ['4.1.6', 1, 2, 2, "Ensure events that modify the system's Mandatory Access Controls are collected"],
    ['4.1.7', 1, 2, 2, 'Ensure login and logout events are collected'],
    ['4.1.8', 1, 2, 2, 'Ensure session initiation information is collected'],
    ['4.1.9', 1, 2, 2, 'Ensure discretionary access control permission modification events are collected'],
    ['4.1.10', 1, 2, 2, 'Ensure unsuccessful unauthorized file access attempts are collected'],
    ['4.1.11', 1, 2, 2, 'Ensure use of privileged commands is collected'],
    ['4.1.12', 1, 2, 2, 'Ensure successful file system mounts are collected'],
    ['4.1.13', 1, 2, 2, 'Ensure file deletion events by users are collected'],
    ['4.1.14', 1, 2, 2,
        'Ensure changes to system administration scope (sudoers) is collected'],
    ['4.1.15', 1, 2, 2,
        'Ensure system administrator actions (sudolog) are collected'],
    ['4.1.16', 1, 2, 2, 'Ensure kernel module loading and unloading is collected'],
    ['4.1.17', 1, 2, 2, 'Ensure the audit configuration is immutable'],
    ['4.2.1.1', 1, 1, 1, 'Ensure rsyslog is installed'],
    ['4.2.1.2', 1, 1, 1, 'Ensure rsyslog Service is enabled'],
    ['4.2.1.3', 0, 1, 1, 'Ensure logging is configured'],
    ['4.2.1.4', 1, 1, 1, 'Ensure rsyslog default file permissions configured'],
    ['4.2.1.5', 1, 1, 1, 'Ensure rsyslog is configured to send logs to a remote log host'],
    ['4.2.1.6', 0, 1, 1,
        'Ensure remote rsyslog messages are only accepted on designated log hosts'],
    ['4.2.2.1', 1, 1, 1, 'Ensure journald is configured to send logs to rsyslog'],
    ['4.2.2.2', 1, 1, 1, 'Ensure journald is configured to compress large log files'],
    ['4.2.2.3', 1, 1, 1, 'Ensure journald is configured to write logfiles to persistent disk'],
    ['4.2.3', 1, 1, 1, 'Ensure permissions on all logfiles are configured'],
    ['4.3', 0, 1, 1, 'Ensure logrotate is configured'],
    ['5.1.1', 1, 1, 1, 'Ensure cron daemon is enabled'],
    ['5.1.2', 1, 1, 1, 'Ensure permissions on /etc/crontab are configured'],
    ['5.1.3', 1, 1, 1, 'Ensure permissions on /etc/cron.hourly are configured'],
    ['5.1.4', 1, 1, 1, 'Ensure permissions on /etc/cron.daily are configured'],
    ['5.1.5', 1, 1, 1, 'Ensure permissions on /etc/cron.weekly are configured'],
    ['5.1.6', 1, 1, 1, 'Ensure permissions on /etc/cron.monthly are configured'],
    ['5.1.7', 1, 1, 1, 'Ensure permissions on /etc/cron.d are configured'],
    ['5.1.8', 1, 1, 1, 'Ensure at/cron is restricted to authorized users'],
    ['5.2.1', 1, 1, 1, 'Ensure permissions on /etc/ssh/sshd_config are configured'],
    ['5.2.2', 1, 1, 1, 'Ensure permissions on SSH private host key files are configured'],
    ['5.2.3', 1, 1, 1, 'Ensure permissions on SSH public host key files are configured'],
    ['5.2.4', 1, 1, 1, 'Ensure SSH Protocol is not set to 1'],
    ['5.2.5', 1, 1, 1, 'Ensure SSH LogLevel is appropriate'],
    ['5.2.6', 1, 2, 1, 'Ensure SSH X11 forwarding is disabled'],
    ['5.2.7', 1, 1, 1, 'Ensure SSH MaxAuthTries is set to 4 or less'],
    ['5.2.8', 1, 1, 1, 'Ensure SSH IgnoreRhosts is enabled'],
    ['5.2.9', 1, 1, 1, 'Ensure SSH HostbasedAuthentication is disabled'],
    ['5.2.10', 1, 1, 1, 'Ensure SSH root login is disabled'],
    ['5.2.11', 1, 1, 1, 'Ensure SSH PermitEmptyPasswords is disabled'],
    ['5.2.12', 1, 1, 1, 'Ensure SSH PermitUserEnvironment is disabled'],
    ['5.2.13', 1, 1, 1, 'Ensure only strong Ciphers are used'],
    ['5.2.14', 1, 1, 1, 'Ensure only strong MAC algorithms are used'],
    ['5.2.15', 1, 1, 1, 'Ensure only strong Key Exchange algorithms are used'],
    ['5.2.16', 1, 1, 1, 'Ensure SSH Idle Timeout Interval is configured'],
    ['5.2.17', 1, 1, 1, 'Ensure SSH LoginGraceTime is set to one minute or less'],
    ['5.2.18', 1, 1, 1, 'Ensure SSH access is limited'],
    ['5.2.19', 1, 1, 1, 'Ensure SSH warning banner is configured'],
    ['5.2.20', 1, 1, 1, 'Ensure SSH PAM is enabled'],
    ['5.2.21', 1, 2, 2, 'Ensure SSH AllowTcpForwarding is disabled'],
    ['5.2.22', 1, 1, 1, 'Ensure SSH MaxStartups is configured'],
    ['5.2.23', 1, 1, 1, 'Ensure SSH MaxSessions is set to 4 or less'],
    ['5.3.1', 1, 1, 1, 'Ensure password creation requirements are configured'],
    ['5.3.2', 1, 1, 1, 'Ensure lockout for failed password attempts is configured'],
    ['5.3.3', 1, 1, 1, 'Ensure password reuse is limited'],
    ['5.3.4', 1, 1, 1, 'Ensure password hashing algorithm is SHA-512'],
    ['5.4.1.1', 1, 1, 1, 'Ensure password expiration is 365 days or less'],
    ['5.4.1.2', 1, 1, 1, 'Ensure minimum days between password changes is 7 or more'],
    ['5.4.1.3', 1, 1, 1, 'Ensure password expiration warning days is 7 or more'],
    ['5.4.1.4', 1, 1, 1, 'Ensure inactive password lock is 30 days or less'],
    ['5.4.1.5', 1, 1, 1, 'Ensure all users last password change date is in the past'],
    ['5.4.2', 1, 1, 1, 'Ensure system accounts are secured'],
    ['5.4.3', 1, 1, 1, 'Ensure default group for the root account is GID 0'],
    ['5.4.4', 1, 1, 1, 'Ensure default user umask is 027 or more restrictive'],
    ['5.4.5', 1, 1, 1, 'Ensure default user shell timeout is 900 seconds or less'],
    ['5.5', 0, 1, 1, 'Ensure root login is restricted to system console'],
    ['5.6', 1, 1, 1, 'Ensure access to the su command is restricted'],
    ['6.1.1', 0, 2, 2, 'Audit system file permissions'],
    ['6.1.2', 1, 1, 1, 'Ensure permissions on /etc/passwd are configured'],
    ['6.1.3', 1, 1, 1, 'Ensure permissions on /etc/gshadow- are configured'],
    ['6.1.4', 1, 1, 1, 'Ensure permissions on /etc/shadow are configured'],
    ['6.1.5', 1, 1, 1, 'Ensure permissions on /etc/group are configured'],
    ['6.1.6', 1, 1, 1, 'Ensure permissions on /etc/passwd- are configured'],
    ['6.1.7', 1, 1, 1, 'Ensure permissions on /etc/shadow- are configured'],
    ['6.1.8', 1, 1, 1, 'Ensure permissions on /etc/group- are configured'],
    ['6.1.9', 1, 1, 1, 'Ensure permissions on /etc/gshadow are configured'],
    ['6.1.10', 1, 1, 1, 'Ensure no world writable files exist'],
    ['6.1.11', 1, 1, 1, 'Ensure no unowned files or directories exist'],
    ['6.1.12', 1, 1, 1, 'Ensure no ungrouped files or directories exist'],
    ['6.1.13', 0, 1, 1, 'Audit SUID executables'],
    ['6.1.14', 0, 1, 1, 'Audit SGID executables'],
    ['6.2.1', 1, 1, 1, 'Ensure password fields are not empty'],
    ['6.2.2', 1, 1, 1, 'Ensure no legacy "+" entries exist in /etc/passwd'],
    ['6.2.3', 1, 1, 1, "Ensure all users' home directories exist"],
    ['6.2.4', 1, 1, 1, 'Ensure no legacy "+" entries exist in /etc/shadow'],
    ['6.2.5', 1, 1, 1, 'Ensure no legacy "+" entries exist in /etc/group'],
    ['6.2.6', 1, 1, 1, 'Ensure root is the only UID 0 account'],
    ['6.2.7', 1, 1, 1, 'Ensure root PATH Integrity'],
    ['6.2.8', 1, 1, 1, "Ensure users' home directories permissions are 750 or more restrictive"],
    ['6.2.9', 1, 1, 1, 'Ensure users own their home directories'],
    ['6.2.10', 1, 1, 1, "Ensure users' dot files are not group or world writable"],
    ['6.2.11', 1, 1, 1, 'Ensure no users have .forward files'],
    ['6.2.12', 1, 1, 1, 'Ensure no users have .netrc files'],
    ['6.2.13', 1, 1, 1, "Ensure users' .netrc Files are not group or world accessible"],
    ['6.2.14', 1, 1, 1, 'Ensure no users have .rhosts files'],
    ['6.2.15', 1, 1, 1, 'Ensure all groups in /etc/passwd exist in /etc/group'],
    ['6.2.16', 1, 1, 1, 'Ensure no duplicate UIDs exist'],
    ['6.2.17', 1, 1, 1, 'Ensure no duplicate GIDs exist'],
    ['6.2.18', 1, 1, 1, 'Ensure no duplicate user names exist'],
    ['6.2.19', 1, 1, 1, 'Ensure no duplicate group names exist'],
    ['6.2.20', 1, 1, 1, 'Ensure shadow group is empty'],
]


def print_success(r, x, p, len): print(bold(green('{:<11}{:<{width}}{:>5}'.format(
    r, x, p, width=len-16))))


def print_fail(r, x, p, len): print(bold(red('{:<11}{:<{width}}{:>5}'.format(
    r, x, p, width=len-16))))


def print_neutral(r, x, p, len): print(bold(yellow('{:<11}{:<{width}}{:>5}'.format(
    r, x, p, width=len-16))))


# function to execute the check
def check(execute):
    global log_file
    write_log = open(log_file + str(time()) + '.SeBAz.log', 'a')
    write_log.write('Start:\t\t' + str(time()) +
                    '\nCommand:\t' + execute + '\nOutput:\n')
    execute = Popen(execute, stdin=PIPE, stdout=PIPE, stderr=PIPE,
                    shell=True, executable='/bin/bash').communicate()
    execute = [e.decode('utf-8') for e in execute]
    write_log.writelines(execute)
    write_log.write('\nEnd:\t\t' + str(time()))
    write_log.close()
    return execute


"""
Definitions of Functions that perform independent checks against benchmarks
return_value[0] = result
return_value[1] = PASS/FAIL/CHEK
return_value[2] = success/error message
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_ind():
    return_value = list()
    success, error = check('modprobe -n -v cramfs')
    if 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep cramfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('cramfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('cramfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('cramfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_2_ind():
    return_value = list()
    success, error = check('modprobe -n -v freevxfs')
    if 'insmod' in success:
        return_value.append('freevxfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep freevxfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('freevxfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('freevxfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('freevxfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_3_ind():
    return_value = list()
    success, error = check('modprobe -n -v jffs2')
    if 'insmod' in success:
        return_value.append('jffs2 can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep jffs2')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('jffs2 cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('jffs2 is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('jffs2 mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_4_ind():
    return_value = list()
    success, error = check('modprobe -n -v hfs')
    if 'insmod' in success:
        return_value.append('hfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep hfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('hfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('hfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('hfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_5_ind():
    return_value = list()
    success, error = check('modprobe -n -v hfsplus')
    if 'insmod' in success:
        return_value.append('hfsplus can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep hfsplus')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('hfsplus cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('hfsplus is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('hfsplus mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_6_ind():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'insmod' in success:
        return_value.append('squashfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep squashfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('squashfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('squashfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('squashfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_7_ind():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep udf')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('udf cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('udf is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('udf mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_8_ind():
    return_value = list()
    success, error = check('grep -i vfat /etc/fstab')
    if success:
        return_value.append('vfat is mounted')
        return_value.append('CHEK')
        return_value.append(success)
    else:
        success, error = check('modprobe -n -v vfat')
        if 'insmod' in success:
            return_value.append('vfat can be mounted')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            result_success = success
            result_error = error
            success, error = check('lsmod | grep vfat')
            if 'install /bin/true' in result_success or 'not found in directory' in result_error:
                if not success:
                    return_value.append('vfat cannot be mounted')
                    return_value.append('PASS')
                    return_value.append(
                        result_success if result_success else result_error)
                else:
                    return_value.append('vfat is mounted')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success if result_success else result_error + '\n' + success)
            else:
                return_value.append('vfat mount status undetermined')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_2_ind():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_value.append('/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('/tmp is not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_3_ind():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything\n" + success)
        else:
            return_value.append('nodev is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' returned the following\n" + return_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nodev is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_4_ind():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything\n" + success)
        else:
            return_value.append('nosuid is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid returned\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nosuid is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_5_ind():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything\n" + success)
        else:
            return_value.append('noexec is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec returned the following\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('noexec is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_6_ind():
    return_value = list()
    success, error = check("mount | grep -E '\s/var\s'")
    if success:
        return_value.append('/var is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep -E '\s/var\s' did not return any result")
    return return_value


def _1_1_7_ind():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        return_value.append('/var/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/tmp is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/tmp did not return any result")
    return return_value


def _1_1_8_ind():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_ind():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nodev is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_ind():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_11_ind():
    return_value = list()
    success, error = check('mount | grep /var/log')
    if success:
        return_value.append('/var/log is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/log did not return any result")
    return return_value


def _1_1_12_ind():
    return_value = list()
    success, error = check('mount | grep /var/log/audit')
    if success:
        return_value.append('/var/log/audit is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log/audit is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep /var/log/audit did not return any result")
    return return_value


def _1_1_13_ind():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        return_value.append('/home is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/home is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /home did not return any result")
    return return_value


def _1_1_14_ind():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        success, error = check("mount | grep -E '\s/home\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /home')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /home')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append(
            "/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_ind():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_ind():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_ind():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_18_ind():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nodev = [drive for drive in success.splitlines()
                 if 'nodev' not in drive]
        if not nodev:
            return_value.append('nodev is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nodev is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nodev" set\n'
            for n in nodev:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_19_ind():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nosuid = [drive for drive in success.splitlines()
                  if 'nosuid' not in drive]
        if not nosuid:
            return_value.append('nosuid is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nosuid is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nosuid" set\n'
            for n in nosuid:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_20_ind():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        noexec = [drive for drive in success.splitlines()
                  if 'noexec' not in drive]
        if not noexec:
            return_value.append('noexec is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('noexec is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "noexec" set\n'
            for n in noexec:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_21_ind():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append(
            "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append(
            'The following directories does not have their sticky bit set\n' + success)
    return return_value


def _1_1_22_ind():
    return_value = list()
    success, error = check('systemctl is-enabled autofs | grep enabled')
    if error:
        return_value.append('automounting could not be checked')
        return_value.append('PASS')
        return_value.append(error)
    else:
        if 'enabled' in success:
            return_value.append('automounting is enabled')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            return_value.append('automounting is disabled')
            return_value.append('PASS')
            return_value.append(success)
    return return_value


def _1_1_23_ind():
    return_value = list()
    success, error = check('modprobe -n -v usb-storage')
    if 'insmod' in success:
        return_value.append('usb-storage can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep usb-storage')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('usb-storage cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('usb-storage is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('usb-storage mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


# distro specific
def _1_2_1_ind():
    return_value = list()
    return_value.append('package configuration not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('apt-cache policy')
    if success:
        return_value.append('check configuration of repos')
        return_value.append('CHEK')
        return_value.append(
            'The following are the configuration of the package manager repositories\n' + success)
    else:
        return_value.append('package configuration not checked')
        return_value.append('CHEK')
        return_value.append(
            'apt-cache policy did not return anything\n' + error)
    return return_value


# distro specific
def _1_2_2_ind():
    return_value = list()
    return_value.append('GPG keys source not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('apt-key list')
    if success:
        return_value.append('check GPG keys source')
        return_value.append('CHEK')
        return_value.append(
            'The following are the configuration of the GPG keys\n' + success)
    else:
        return_value.append('GPG keys not checked')
        return_value.append('CHEK')
        return_value.append(
            'apt-key list did not return any keys\n' + error)
    return return_value


# distro specific
def _1_3_1_ind():
    return_value = list()
    return_value.append('AIDE not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s aide')
    if success:
        return_value.append('AIDE is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('AIDE is not installed')
        return_value.append('FAIL')
        return_value.append('dpkg -s aide returned\n' + error)
    return return_value


def _1_3_2_ind():
    return_value = list()
    success, error = check('crontab -u root -l | grep aide')
    if success:
        result = success
        success, error = check('grep -r aide /etc/cron.* /etc/crontab')
        if success:
            result += '\nThe following cron jobs are scheduled\n' + success
            return_value.append('file integrity is checked')
            return_value.append('PASS')
            return_value.append(result)
        else:
            result += '\nNo cron jobs are scheduled for AIDE\n' + error
            return_value.append('file integrity is not checked')
            return_value.append('FAIL')
            return_value.append(result)
    else:
        return_value.append('No AIDE cron jobs scheduled')
        return_value.append('FAIL')
        return_value.append(
            'grep -r aide /etc/cron.* /etc/crontab returned the following\n' + success + '\n' + error)
    return return_value


# bootloader specific
def _1_4_1_ind():
    return_value = list()
    success, error = check('stat /boot/grub*/grub.cfg | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0400/-r--------)' in success:
                return_value.append('bootloader permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('bootloader permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('bootloader invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('grub config not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /boot/grub*/grub.cfg | grep Access returned\n' + success + '\n' + error)
    return return_value


# bootloader specific
def _1_4_2_ind():
    return_value = list()
    success, error = check('grep "^\s*password" /boot/grub/menu.lst')
    if success:
        return_value.append('bootloader password is set')
        return_value.append('PASS')
        return_value.append(success)
    else:
        success, error = check('grep "^\s*password" /boot/grub/grub.cfg')
        if success:
            return_value.append('bootloader password is set')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('bootloader password not checked')
            return_value.append('CHEK')
            return_value.append(error)
    return return_value


def _1_4_3_ind():
    return_value = list()
    success, error = check('grep ^root:[*\!]: /etc/shadow')
    if success:
        return_value.append('auth required for single user mode')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('auth not required for single user mode')
        return_value.append('FAIL')
        return_value.append(
            'grep ^root:[*\!]: /etc/shadow returned the following\n' + error)
    return return_value


# bootloader specific
def _1_4_4_ind():
    return_value = list()
    success, error = check(
        'grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot')
    if 'PROMPT_FOR_CONFIRM="no"' in success:
        return_value.append('interactive boot disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('interactive boot not checked')
        return_value.append('CHEK')
        return_value.append(
            'grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot returned the following\n' + success + '\n' + error)
    return return_value


def _1_5_1_ind():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check(
        'grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check('sysctl fs.suid_dumpable')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check(
        'grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    if len(result_success.splitlines()) == 6:
        return_value.append('core dumps are restricted')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('core dumps not restricted')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success +
                            '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


def _1_5_2_ind():
    return_value = list()
    success, error = check("journalctl | grep 'protection: active'")
    if success:
        return_value.append('XD/NX support is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        result_error = error
        success, error = check(
            "[[ -n $(grep noexec[0-9]*=off /proc/cmdline) || -z $(grep -E -i ' (pae|nx) ' /proc/cpuinfo) || -n $(grep '\sNX\s.*\sprotection:\s' /var/log/dmesg | grep -v active) ]] && echo \"NX Protection is not active\"")
        if not success:
            return_value.append('XD/NX support is enabled')
            return_value.append('PASS')
            return_value.append(error)
        else:
            return_value.append('XD/NX not enabled')
            return_value.append('FAIL')
            return_value.append(result_error + '\n' + success + '\n' + error)
    return return_value


def _1_5_3_ind():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('sysctl kernel.randomize_va_space')
    if '2' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    success, error = check(
        'grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*')
    if '2' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    if len(result_success.splitlines()) == 4:
        return_value.append('ASLR enabled')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('ASLR not enabled')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success +
                            '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


# distro specific
def _1_5_4_ind():
    return_value = list()
    return_value.append('prelink not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s prelink')
    if not success:
        return_value.append('prelink is not installed')
        return_value.append('PASS')
        return_value.append(error)
    else:
        return_value.append('prelink is installed')
        return_value.append('FAIL')
        return_value.append('dpkg -s prelink returned\n' + success)
    return return_value


# distro specific
def _1_6_1_1_ind():
    return_value = list()
    return_value.append('SELinux or AppArmor not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s libselinux1')
    if success:
        return_value.append('SELinux is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        result_error = error + '\n'
        success, error = check('dpkg -s apparmor')
        if success:
            return_value.append('AppArmor is installed')
            return_value.append('PASS')
            return_value.append(success)
        else:
            result_error += error
            return_value.append('SELinux and AppArmor is not installed')
            return_value.append('FAIL')
            return_value.append(result_error)
    return return_value


def _1_6_2_1_ind():
    return_value = list()
    success, error = check('grep "^\s*kernel" /boot/grub/menu.lst')
    if success:
        if 'selinux=0' not in success and 'enforcing=0' not in success:
            return_value.append('SELinux not disabled boot-config')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SELinux disabled boot-config')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        result_error = error + '\n'
        success, error = check('grep "^\s*linux" /boot/grub2/grub.cfg')
        if success:
            if 'selinux=0' not in success and 'enforcing=0' not in success:
                return_value.append('SELinux not disabled boot-config')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('SELinux disabled boot-config')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('SELinux not checked')
            return_value.append('CHEK')
            return_value.append(result_error + error)
    return return_value


def _1_6_2_2_ind():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('grep SELINUX=enforcing /etc/selinux/config')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check('sestatus')
    if 'SELinux status: enabled' in success and 'Current mode: enforcing' in success and 'Mode from config file: enforcing' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    if len(result_success.splitlines()) == 4:
        return_value.append('SELinux state is enforcing')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('SELinux state is not enforcing')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success +
                            '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


def _1_6_2_3_ind():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('grep SELINUXTYPE= /etc/selinux/config')
    if 'SELINUXTYPE=targeted' in success or 'SELINUXTYPE=mls' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    success, error = check('sestatus')
    if 'Policy from config file: targeted' in success or 'Policy from config file: mls' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    if len(result_success.splitlines()) == 4:
        return_value.append('SELinux policy is configured')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('SELinux policy is not configured')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success +
                            '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


# distro specific
def _1_6_2_4_ind():
    return_value = list()
    return_value.append('SETroubleshoot not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s setroubleshoot')
    if not success:
        return_value.append('SETroubleshoot is not installed')
        return_value.append('PASS')
        return_value.append(error)
    else:
        return_value.append('SETroubleshoot is installed')
        return_value.append('FAIL')
        return_value.append('dpkg -s setroubleshoot returned\n' + success)
    return return_value


# distro specific
def _1_6_2_5_ind():
    return_value = list()
    return_value.append('mcstrans not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s mcstrans')
    if not success:
        return_value.append('mcstrans is not installed')
        return_value.append('PASS')
        return_value.append(error)
    else:
        return_value.append('mcstrans is installed')
        return_value.append('FAIL')
        return_value.append('dpkg -s mcstrans returned\n' + success)
    return return_value


def _1_6_2_6_ind():
    return_value = list()
    success, error = check(
        "ps -eZ | grep -E \"initrc\" | grep -E -v -w \"tr|ps|grep|bash|awk\" | tr ':' ' ' | awk '{ print $NF }'")
    if not success:
        return_value.append('no unconfined daemons exist')
        return_value.append('PASS')
        return_value.append(
            "ps -eZ | grep -E \"initrc\" | grep -E -v -w \"tr|ps|grep|bash|awk\" | tr ':' ' ' | awk '{ print $NF }' returned nothing")
    else:
        return_value.append('unconfined daemons exist')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


def _1_6_3_1_ind():
    return_value = list()
    success, error = check('grep "^\s*kernel" /boot/grub/menu.lst')
    if success:
        if 'apparmor=0' not in success:
            return_value.append('AppArmor not disabled boot-config')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SELinux disabled boot-config')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        result_error = error + '\n'
        success, error = check('grep "^\s*linux" /boot/grub/menu.lst')
        if success:
            if 'apparmor=0' not in success:
                return_value.append('AppArmor not disabled boot-config')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('AppArmor disabled boot-config')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('AppArmor not checked')
            return_value.append('CHEK')
            return_value.append(result_error + error)
    return return_value


def _1_6_3_2_ind():
    return_value = list()
    success, error = check('apparmor_status')
    if success:
        loaded_profiles = [
            p for p in success.splitlines() if 'profiles are loaded.' in p]
        complain_profiles = [p for p in success.splitlines(
        ) if 'profiles are in complain mode.' in p]
        unconfined_process = [
            p for p in success.splitlines() if 'processes are unconfined' in p]
        if loaded_profiles and not loaded_profiles[0].startswith('0'):
            if complain_profiles and complain_profiles[0].startswith('0'):
                if unconfined_process and unconfined_process[0].startswith('0'):
                    return_value.append('all AppArmor Profiles are enforcing')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append('AppArmor processes are confined')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('AppArmor profiles are in complain mode')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('No AppArmor profiles are loaded')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('AppArmor status not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_7_1_1_ind():
    return_value = list()
    success, error = check('cat /etc/motd')
    if success:
        result_success = success
        success, error = check(
            "grep -E -i \"(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/motd")
        if not success:
            return_value.append('motd is configured properly')
            return_value.append('PASS')
            return_value.append(
                'check if the message of the day matches site policy\n' + result_success)
        else:
            return_value.append('motd contains sensitive information')
            return_value.append('FAIL')
            return_value.append(
                'Following OS [or] patch level information were found in the message of the day\n' + result_success)
    else:
        return_value.append('no message of the day')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _1_7_1_2_ind():
    return_value = list()
    success, error = check('cat /etc/issue')
    if success:
        result_success = success
        success, error = check(
            "grep -E -i \"(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue")
        if not success:
            return_value.append('login banner configured properly')
            return_value.append('PASS')
            return_value.append(
                'check if the local login warning banner matches site policy\n' + result_success)
        else:
            return_value.append('login banner contains sensitive info')
            return_value.append('FAIL')
            return_value.append(
                'Following OS [or] patch level information were found in the local login banner\n' + result_success)
    else:
        return_value.append('no local login warning banner')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _1_7_1_3_ind():
    return_value = list()
    success, error = check('cat /etc/issue.net')
    if success:
        result_success = success
        success, error = check(
            "grep -E -i \"(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue.net")
        if not success:
            return_value.append('remote login banner configured properly')
            return_value.append('PASS')
            return_value.append(
                'check if the remote login warning banner matches site policy\n' + result_success)
        else:
            return_value.append('remote banner contains sensitive info')
            return_value.append('FAIL')
            return_value.append(
                'Following OS [or] patch level information were found in the remote login banner\n' + result_success)
    else:
        return_value.append('no remote login warning banner')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _1_7_1_4_ind():
    return_value = list()
    success, error = check('stat /etc/motd | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/motd permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/motd permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/motd invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/motd not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/motd | grep Access did not return anything\n' + error)
    return return_value


def _1_7_1_5_ind():
    return_value = list()
    success, error = check('stat /etc/issue | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/issue permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/issue permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/issue invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/issue not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/issue | grep Access did not return anything\n' + error)
    return return_value


def _1_7_1_6_ind():
    return_value = list()
    success, error = check('stat /etc/issue.net | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/issue.net permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/issue.net permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/issue.net invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/issue.net not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/issue.net | grep Access did not return anything\n' + error)
    return return_value


def _1_7_2_ind():
    return_value = list()
    success, error = check('cat /etc/gdm3/greeter.dconf-defaults')
    if success:
        result_success = success
        success, error = check(
            'cat /etc/gdm3/greeter.dconf-defaults | grep banner-message-')
        if success:
            if 'banner-message-enable=true' in success and not success.splitlines()[0].startswith('#'):
                if "banner-message-text='" in success and not success.splitlines()[1].startswith('#'):
                    return_value.append('GDM login banner is configured')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('no GDM login banner message')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('GDM banner message not enabled')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('GDM login banner not configured')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('GDM not found')
        return_value.append('CHEK')
        return_value.append(
            'cat /etc/gdm3/greeter.dconf-defaults did not return anything\n' + error)
    return return_value


# distro specific
def _1_8_ind():
    return_value = list()
    return_value.append('software not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('apt-get -s upgrade')
    if success:
        if '0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.' in success:
            return_value.append('software installed properly')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('software packages need checking')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('software state not checked')
        return_value.append('CHEK')
        return_value.append(
            'apt-get -s upgrade did not return anything\n' + error)
    return return_value


def _2_1_1_ind():
    return_value = list()
    success, error = check('grep -R "^chargen" /etc/inetd.*')
    if success:
        return_value.append('chargen services are enabled')
        return_value.append('FAIL')
        return_value.append(
            'grep -R "^chargen" /etc/inetd.* returned the following\n' + success)
    else:
        return_value.append('chargen is not present')
        return_value.append('PASS')
        return_value.append(
            'grep -R "^chargen" /etc/inetd.* returned the following\n' + error)
    return return_value


def _2_1_2_ind():
    return_value = list()
    success, error = check('grep -R "^daytime" /etc/inetd.*')
    if success:
        return_value.append('daytime services are enabled')
        return_value.append('FAIL')
        return_value.append(
            'grep -R "^daytime" /etc/inetd.* returned the following\n' + success)
    else:
        return_value.append('daytime is not present')
        return_value.append('PASS')
        return_value.append(
            'grep -R "^daytime" /etc/inetd.* returned the following\n' + error)
    return return_value


def _2_1_3_ind():
    return_value = list()
    success, error = check('grep -R "^discard" /etc/inetd.*')
    if success:
        return_value.append('discard services are enabled')
        return_value.append('FAIL')
        return_value.append(
            'grep -R "^discard" /etc/inetd.* returned the following\n' + success)
    else:
        return_value.append('discard is not present')
        return_value.append('PASS')
        return_value.append(
            'grep -R "^discard" /etc/inetd.* returned the following\n' + error)
    return return_value


def _2_1_4_ind():
    return_value = list()
    success, error = check('grep -R "^echo"/etc/inetd.*')
    if success:
        return_value.append('echo services are enabled')
        return_value.append('FAIL')
        return_value.append(
            'grep -R "^echo" /etc/inetd.* returned the following\n' + success)
    else:
        return_value.append('echo is not present')
        return_value.append('PASS')
        return_value.append(
            'grep -R "^echo" /etc/inetd.* returned the following\n' + error)
    return return_value


def _2_1_5_ind():
    return_value = list()
    success, error = check('grep -R "^time" /etc/inetd.*')
    if success:
        return_value.append('time services are enabled')
        return_value.append('FAIL')
        return_value.append(
            'grep -R "^time" /etc/inetd.* returned the following\n' + success)
    else:
        return_value.append('time is not present')
        return_value.append('PASS')
        return_value.append(
            'grep -R "^time" /etc/inetd.* returned the following\n' + error)
    return return_value


def _2_1_6_ind():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('grep -R "^shell" /etc/inetd.*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check('grep -R "^login" /etc/inetd.*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check('grep -R "^exec" /etc/inetd.*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    if len(result_success):
        return_value.append('rsh services are enabled')
        return_value.append('FAIL')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('rsh services not present')
        return_value.append('PASS')
        return_value.append(result_success + '\n' + result_error)
    return return_value


def _2_1_7_ind():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('grep -R "^talk" /etc/inetd.*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check('grep -R "^ntalk" /etc/inetd.*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    if len(result_success):
        return_value.append('talk server is enabled')
        return_value.append('FAIL')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('talk server not present')
        return_value.append('PASS')
        return_value.append(result_success + '\n' + result_error)
    return return_value


def _2_1_8_ind():
    return_value = list()
    success, error = check('grep -R "^telnet" /etc/inetd.*')
    if success:
        return_value.append('telnet server is enabled')
        return_value.append('FAIL')
        return_value.append(
            'grep -R "^telnet" /etc/inetd.* returned the following\n' + success)
    else:
        return_value.append('telnet server not present')
        return_value.append('PASS')
        return_value.append(
            'grep -R "^telnet" /etc/inetd.* returned the following\n' + error)
    return return_value


def _2_1_9_ind():
    return_value = list()
    success, error = check('grep -R "^tftp" /etc/inetd.*')
    if success:
        return_value.append('tftp server is enabled')
        return_value.append('FAIL')
        return_value.append(
            'grep -R "^tftp" /etc/inetd.* returned the following\n' + success)
    else:
        return_value.append('tftp server not present')
        return_value.append('PASS')
        return_value.append(
            'grep -R "^tftp" /etc/inetd.* returned the following\n' + error)
    return return_value


def _2_1_10_ind():
    return_value = list()
    success, error = check('systemctl is-enabled xinetd')
    if success:
        if 'enabled' in success:
            return_value.append('xinetd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled xinetd returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep xinetd')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('xinetd is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('xinetd is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep xinetd returned the following\n' + success)
            else:
                return_value.append('xinetd is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('xinetd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled xinetd returned the following\n' + error)
    return return_value


# distro specific
def _2_2_1_1_ind():
    return_value = list()
    return_value.append('time sync not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s ntp')
    if 'Status: install ok installed' in success:
        return_value.append('ntp is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        result_error = success + '\n' + error
        success, error = check('dpkg -s chrony')
        if 'Status: install ok installed' in success:
            return_value.append('chrony is installed')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('time sync not used')
            return_value.append('FAIL')
            return_value.append(result_error + '\n' + success + '\n' + error)
    return return_value


def _2_2_1_2_ind():
    return_value = list()
    success, error = check('grep "^restrict" /etc/ntp.conf | grep default')
    if success:
        ntp_restrict = ['kod', 'nomodify', 'notrap', 'nopeer', 'noquery']
        if all(r in s for r in ntp_restrict for s in success.splitlines()):
            result_success = success
            success, error = check('grep -E "^(server|pool)" /etc/ntp.conf')
            if success:
                result_success += '\nVerify remote server configurations\n' + success
                success, error = check('grep "^OPTIONS" /etc/sysconfig/ntpd')
                if 'OPTIONS="-u ntp:ntp"' in success:
                    return_value.append('ntp is configured')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    result_error = success + '\n' + error
                    success, error = check(
                        'grep "^NTPD_OPTIONS" /etc/sysconfig/ntp')
                    if 'OPTIONS="-u ntp:ntp"' in success:
                        return_value.append('ntp is configured')
                        return_value.append('PASS')
                        return_value.append(result_success + '\n' + success)
                    else:
                        result_error += success + '\n' + error
                        success, error = check(
                            'grep "RUNASUSER=ntp" /etc/init.d/ntp')
                        if success:
                            return_value.append('ntp is configured')
                            return_value.append('PASS')
                            return_value.append(
                                result_success + '\n' + success)
                        else:
                            return_value.append(
                                'ntp user configuration not found')
                            return_value.append('FAIL')
                            return_value.append('Following were found configured\n' + result_success +
                                                '\nFollowing are misconfigured\n' + result_error + '\n' + error)
            else:
                return_value.append('remote server misconfigured')
                return_value.append('FAIL')
                return_value.append(
                    'grep -E "^(server|pool)" /etc/ntp.conf returned the following\n' + error)
        else:
            return_value.append('ntp options misconfigured')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('ntp not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _2_2_1_3_ind():
    return_value = list()
    success, error = check('grep -E "^(server|pool)" /etc/chrony.conf')
    if success:
        result_success = 'Verify remote server configurations\n' + success
        success, error = check('ps -ef | grep chronyd')
        if success:
            if any(s.startswith('chrony') for s in success):
                return_value.append('chrony is configured')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + success)
            else:
                return_value.append('chrony not first field of chronyd')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + success)
        else:
            return_value.append('no chrony processes found')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('remote server not configured')
        return_value.append('FAIL')
        return_value.append(
            'grep -E "^(server|pool)" /etc/chrony.conf returned the following\n' + error)
    return return_value


def _2_2_1_4_ind():
    return_value = list()
    success, error = check('systemctl is-enabled systemd-timesyncd.service')
    if 'enabled' in success:
        result_success = success
        success, error = check('cat /etc/systemd/timesyncd.conf')
        if success:
            result_success += '\nEnsure that the NTP servers, NTP FallbackNTP servers, and RootDistanceMaxSec listed are in accordance with local policy\n' + success
            success, error = check('timedatectl status')
            if success:
                return_value.append('system clock is synchronized')
                return_value.append('PASS')
                return_value.append(result_success + '\nCheck\n' + success)
            else:
                return_value.append('system clock not synchronized')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('no timesync daemon found')
            return_value.append('FAIL')
            return_value.append(
                result_success + '\ncat /etc/systemd/timesyncd.conf returned the following\n' + error)
    else:
        return_value.append('systemd-timesyncd is misconfigured')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


# distro specific
def _2_2_2_ind():
    return_value = list()
    return_value.append('X Window System not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -l xserver-xorg*')
    if success:
        return_value.append('X Window System installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('X Window System not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_2_3_ind():
    return_value = list()
    success, error = check('systemctl is-enabled avahi-daemon')
    if success:
        if 'enabled' in success:
            return_value.append('avahi-daemon is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled avahi-daemon returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep avahi-daemon')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('avahi-daemon is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('avahi-daemon is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep avahi-daemon returned the following\n' + success)
            else:
                return_value.append('avahi-daemon is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('avahi-daemon not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled avahi-daemon returned the following\n' + error)
    return return_value


def _2_2_4_ind():
    return_value = list()
    success, error = check('systemctl is-enabled cups')
    if success:
        if 'enabled' in success:
            return_value.append('cups is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled cups returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep cups')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('cups is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('cups is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep cups returned the following\n' + success)
            else:
                return_value.append('cups is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('cups not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled cups returned the following\n' + error)
    return return_value


def _2_2_5_ind():
    return_value = list()
    success, error = check('systemctl is-enabled dhcpd')
    if success:
        if 'enabled' in success:
            return_value.append('dhcpd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled dhcpd returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep dhcpd')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('dhcpd is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('dhcpd is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep dhcpd returned the following\n' + success)
            else:
                return_value.append('dhcpd is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('dhcpd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled dhcpd returned the following\n' + error)
    return return_value


def _2_2_6_ind():
    return_value = list()
    success, error = check('systemctl is-enabled slapd')
    if success:
        if 'enabled' in success:
            return_value.append('slapd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled slapd returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep slapd')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('slapd is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('slapd is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep slapd returned the following\n' + success)
            else:
                return_value.append('slapd is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('slapd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled slapd returned the following\n' + error)
    return return_value


def _2_2_7_ind():
    return_value = list()
    nfs_enabled = True
    success, error = check('systemctl is-enabled nfs')
    if success:
        if 'enabled' in success:
            return_value.append('nfs is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled nfs returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep nfs')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    nfs_enabled = False
                    result_success += '\n' + success
                else:
                    return_value.append('nfs is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep nfs returned the following\n' + success)
            else:
                nfs_enabled = False
                result_success += '\n' + error
    else:
        nfs_enabled = False
        result_success = 'systemctl is-enabled nfs returned the following\n' + error
    if not nfs_enabled:
        success, error = check('systemctl is-enabled rpcbind')
        if success:
            if 'enabled' in success:
                return_value.append('rpcbind is enabled')
                return_value.append('FAIL')
                return_value.append(
                    result_success + '\nsystemctl is-enabled rpcbind returned the following\n' + success)
            else:
                result_success += '\n' + success
                success, error = check('ls /etc/rc*.d | grep rpcbind')
                if success:
                    if not any(s for s in success.splitlines() if s.startswith('S')):
                        return_value.append('nfs and rpcbind are disabled')
                        return_value.append('PASS')
                        return_value.append(result_success + '\n' + success)
                    else:
                        return_value.append('rpcbind is enabled')
                        return_value.append('FAIL')
                        return_value.append(
                            result_success + '\nls /etc/rc*.d | grep rpcbind returned the following\n' + success)
                else:
                    return_value.append('nfs and rpcbind are disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + error)
        else:
            return_value.append('npc and rpcbind are disabled')
            return_value.append('PASS')
            return_value.append(
                result_success + '\nsystemctl is-enabled rpcbind returned the following\n' + error)
    return return_value


def _2_2_8_ind():
    return_value = list()
    success, error = check('systemctl is-enabled named')
    if success:
        if 'enabled' in success:
            return_value.append('named is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled named returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep named')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('named is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('named is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep named returned the following\n' + success)
            else:
                return_value.append('named is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('named not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled named returned the following\n' + error)
    return return_value


def _2_2_9_ind():
    return_value = list()
    success, error = check('systemctl is-enabled vsftpd')
    if success:
        if 'enabled' in success:
            return_value.append('vsftpd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled vsftpd returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep vsftpd')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('vsftpd is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('vsftpd is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep vsftpd returned the following\n' + success)
            else:
                return_value.append('vsftpd is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('vsftpd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled vsftpd returned the following\n' + error)
    return return_value


def _2_2_10_ind():
    return_value = list()
    success, error = check('systemctl is-enabled httpd')
    if success:
        if 'enabled' in success:
            return_value.append('httpd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled httpd returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep httpd')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('httpd is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('httpd is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep httpd returned the following\n' + success)
            else:
                return_value.append('httpd is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('httpd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled httpd returned the following\n' + error)
    return return_value


def _2_2_11_ind():
    return_value = list()
    success, error = check('systemctl is-enabled dovecot')
    if success:
        if 'enabled' in success:
            return_value.append('dovecot is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled dovecot returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep dovecot')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('dovecot is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('dovecot is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep dovecot returned the following\n' + success)
            else:
                return_value.append('dovecot is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('dovecot not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled dovecot returned the following\n' + error)
    return return_value


def _2_2_12_ind():
    return_value = list()
    success, error = check('systemctl is-enabled smb')
    if success:
        if 'enabled' in success:
            return_value.append('smb is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled smb returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep smb')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('smb is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('smb is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep smb returned the following\n' + success)
            else:
                return_value.append('smb is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('smb not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled smb returned the following\n' + error)
    return return_value


def _2_2_13_ind():
    return_value = list()
    success, error = check('systemctl is-enabled squid')
    if success:
        if 'enabled' in success:
            return_value.append('squid is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled squid returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep squid')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('squid is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('squid is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep squid returned the following\n' + success)
            else:
                return_value.append('squid is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('squid not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled squid returned the following\n' + error)
    return return_value


def _2_2_14_ind():
    return_value = list()
    success, error = check('systemctl is-enabled snmpd')
    if success:
        if 'enabled' in success:
            return_value.append('snmpd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled snmpd returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep snmpd')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('snmpd is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('snmpd is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep snmpd returned the following\n' + success)
            else:
                return_value.append('snmpd is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('snmpd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled snmpd returned the following\n' + error)
    return return_value


def _2_2_15_ind():
    return_value = list()
    success, error = check(
        "ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'")
    if not success:
        return_value.append('mta is local only')
        return_value.append('PASS')
        return_value.append(
            "ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s' returned the following\n" + error)
    else:
        return_value.append('mta is not local only')
        return_value.append('FAIL')
        return_value.append(
            "ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s' returned the following\n" + success)
    return return_value


def _2_2_16_ind():
    return_value = list()
    success, error = check('systemctl is-enabled rsyncd')
    if success:
        if 'enabled' in success:
            return_value.append('rsyncd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled rsyncd returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep rsyncd')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('rsyncd is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('rsyncd is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep rsyncd returned the following\n' + success)
            else:
                return_value.append('rsyncd is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('rsyncd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled rsyncd returned the following\n' + error)
    return return_value


def _2_2_17_ind():
    return_value = list()
    success, error = check('systemctl is-enabled ypserv')
    if success:
        if 'enabled' in success:
            return_value.append('ypserv is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled ypserv returned the following\n' + success)
        else:
            result_success = success
            success, error = check('ls /etc/rc*.d | grep ypserv')
            if success:
                if not any(s for s in success.splitlines() if s.startswith('S')):
                    return_value.append('ypserv is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('ypsesrv is enabled')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep ypserv returned the following\n' + success)
            else:
                return_value.append('ypserv is disabled')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + error)
    else:
        return_value.append('ypserv not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled ypserv returned the following\n' + error)
    return return_value


# distro specific
def _2_3_1_ind():
    return_value = list()
    return_value.append('NIS Client not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s ypbind')
    if 'Status: install ok installed' in success:
        return_value.append('NIS Client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('NIS Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


# distro specific
def _2_3_2_ind():
    return_value = list()
    return_value.append('rsh Client not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s rsh')
    if 'Status: install ok installed' in success:
        return_value.append('rsh client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('rsh Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


# distro specific
def _2_3_3_ind():
    return_value = list()
    return_value.append('talk Client not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s talk')
    if 'Status: install ok installed' in success:
        return_value.append('talk client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('talk Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


# distro specific
def _2_3_4_ind():
    return_value = list()
    return_value.append('telnet Client not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s telnet')
    if 'Status: install ok installed' in success:
        return_value.append('telnet client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('telnet Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


# distro specific
def _2_3_5_ind():
    return_value = list()
    return_value.append('LDAP Client not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s openldap-clients')
    if error:
        result_error = error
        success, error = check('dpkg -s openldap2-client')
        if error:
            result_error += '\n' + error
            success, error = check('dpkg -s ldap-utils')
            if error:
                return_value.append('LDAP Client not installed')
                return_value.append('PASS')
                return_value.append(result_error + '\n' + error)
            else:
                return_value.append('ldap-utils installed')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('openldap2-client installed')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('openldap-clients installed')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


def _3_1_1_ind():
    return_value = list()
    success, error = check('sysctl net.ipv4.ip_forward')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv6.conf.all.forwarding')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv6\.conf\.all\.forwarding" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv6 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                    return_value.append('IP forwarding disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv6 forwards packets')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv6 forwards packets')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 forwards packets')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 forwards packets')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_1_2_ind():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.send_redirects')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.send_redirects')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('packet redirect sending is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 redirects default packets')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 redirects default packets')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 redirects all packets')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 redirects all packets')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_1_ind():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.accept_source_route')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.accept_source_route')
            if success.endswith('0\n'):
                result_success += success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    result_success += success + '\n'
                    success, error = check(
                        'sysctl net.ipv6.conf.all.accept_source_route')
                    if success.endswith('0\n'):
                        result_success = success + '\n'
                        success, error = check(
                            'grep "net\.ipv6\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
                        ipv6 = [s.split(':')[1] for s in success.splitlines()]
                        if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                            result_success += success + '\n'
                            success, error = check(
                                'sysctl net.ipv6.conf.default.accept_source_route')
                            if success.endswith('0\n'):
                                result_success += success + '\n'
                                success, error = check(
                                    'grep "net\.ipv6\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
                                ipv6 = [s.split(':')[1]
                                        for s in success.splitlines()]
                                if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                                    return_value.append(
                                        'source routed packets are not accepted')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                                else:
                                    return_value.append(
                                        'ipv6 accepts default source packets')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                            else:
                                return_value.append(
                                    'ipv6 accepts default source packets')
                                return_value.append('FAIL')
                                return_value.append(result_success + success)
                        else:
                            return_value.append(
                                'ipv6 accepts all source packets')
                            return_value.append('FAIL')
                            return_value.append(result_success + success)
                    else:
                        return_value.append('ipv6 accepts all source packets')
                        return_value.append('FAIL')
                        return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 accepts default source packets')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 accepts default source packets')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 accepts all source packets')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 accepts all source packets')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_2_ind():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.accept_redirects')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.accept_redirects')
            if success.endswith('0\n'):
                result_success += success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    result_success += success + '\n'
                    success, error = check(
                        'sysctl net.ipv6.conf.all.accept_redirects')
                    if success.endswith('0\n'):
                        result_success = success + '\n'
                        success, error = check(
                            'grep "net\.ipv6\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                        ipv6 = [s.split(':')[1] for s in success.splitlines()]
                        if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                            result_success += success + '\n'
                            success, error = check(
                                'sysctl net.ipv6.conf.default.accept_redirects')
                            if success.endswith('0\n'):
                                result_success += success + '\n'
                                success, error = check(
                                    'grep "net\.ipv6\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                                ipv6 = [s.split(':')[1]
                                        for s in success.splitlines()]
                                if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                                    return_value.append(
                                        'ICMP redirects not accepted')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                                else:
                                    return_value.append(
                                        'ipv6 accepts default redirects')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                            else:
                                return_value.append(
                                    'ipv6 accepts default redirects')
                                return_value.append('FAIL')
                                return_value.append(result_success + success)
                        else:
                            return_value.append('ipv6 accepts all redirects')
                            return_value.append('FAIL')
                            return_value.append(result_success + success)
                    else:
                        return_value.append('ipv6 accepts all redirects')
                        return_value.append('FAIL')
                        return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 accepts default redirects')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 accepts default redirects')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 accepts all redirects')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 accepts all redirects')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_3_ind():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.secure_redirects')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.secure_redirects')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('secure ICMP redirects not accepted')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 redirects default secure ICMP')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 redirects default secure ICMP')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 redirects all secure ICMP')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 redirects all secure ICMP')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_4_ind():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.log_martians')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv4.conf.default.log_martians')
            if success.endswith('1\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('suspicious packets are logged')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 default packets not logged')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 default packets not logged')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 all packets not logged')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 all packets not logged')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_5_ind():
    return_value = list()
    success, error = check('sysctl net.ipv4.icmp_echo_ignore_broadcasts')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            return_value.append('broadcast ICMP requests ignored')
            return_value.append('PASS')
            return_value.append(result_success + success)
        else:
            return_value.append('ipv4 broadcasts not ignored')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 broadcasts not ignored')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_6_ind():
    return_value = list()
    success, error = check('sysctl net.ipv4.icmp_ignore_bogus_error_responses')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            return_value.append('bogus ICMP responses ignored')
            return_value.append('PASS')
            return_value.append(result_success + success)
        else:
            return_value.append('ipv4 bogus responses not ignored')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 bogus responses not ignored')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_7_ind():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.rp_filter')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv4.conf.default.rp_filter')
            if success.endswith('1\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('Reverse Path Filtering enabled')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 default rp filtering disabled')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 default rp filtering disabled')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 all rp filtering disabled')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 all rp filtering disabled')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_8_ind():
    return_value = list()
    success, error = check('sysctl net.ipv4.tcp_syncookies')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            return_value.append('TCP SYN Cookies enabled')
            return_value.append('PASS')
            return_value.append(result_success + success)
        else:
            return_value.append('ipv4 tcp syncookies disabled')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 tcp syncookies disabled')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_9_ind():
    return_value = list()
    success, error = check('sysctl net.ipv6.conf.all.accept_ra')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv6 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv6.conf.default.accept_ra')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                    return_value.append('IPv6 router advert not accepted')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv6 default ra accepted')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv6 default ra accepted')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv6 all ra accepted')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv6 all ra accepted')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


# distro specific
def _3_3_1_ind():
    return_value = list()
    return_value.append('TCP Wrappers not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s tcpd')
    if 'Status: install ok installed' in success:
        return_value.append('TCP Wrappers installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('TCP Wrappers not installed')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_3_2_ind():
    return_value = list()
    success, error = check('cat /etc/hosts.allow')
    if not all(s.startswith('#') or not s for s in success.splitlines()):
        return_value.append('/etc/hosts.allow configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/etc/hosts.allow not configured')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_3_3_ind():
    return_value = list()
    success, error = check('cat /etc/hosts.deny')
    if 'ALL: ALL' in success:
        return_value.append('/etc/hosts.deny configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/etc/hosts.deny not configured')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_3_4_ind():
    return_value = list()
    success, error = check('stat /etc/hosts.allow | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/hosts.allow permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/hosts.allow permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/hosts.allow invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/hosts.allow not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/hosts.allow | grep Access did not return anything\n' + error)
    return return_value


def _3_3_5_ind():
    return_value = list()
    success, error = check('stat /etc/hosts.deny | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/hosts.deny permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/hosts.deny permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/hosts.deny invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/hosts.deny not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/hosts.deny | grep Access did not return anything\n' + error)
    return return_value


def _3_4_1_ind():
    return_value = list()
    success, error = check('modprobe -n -v dccp')
    if 'insmod' in success:
        return_value.append('dccp can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep dccp')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('dccp cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('dccp is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('dccp mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_4_2_ind():
    return_value = list()
    success, error = check('modprobe -n -v sctp')
    if 'insmod' in success:
        return_value.append('sctp can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep sctp')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('sctp cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('sctp is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('sctp mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_4_3_ind():
    return_value = list()
    success, error = check('modprobe -n -v rds')
    if 'insmod' in success:
        return_value.append('rds can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep rds')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('rds cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('rds is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('rds mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_4_4_ind():
    return_value = list()
    success, error = check('modprobe -n -v tipc')
    if 'insmod' in success:
        return_value.append('tipc can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep tipc')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('tipc cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('tipc is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('tipc mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_5_1_1_ind():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('ip6tables -L | grep Chain')
    if success:
        if all('policy DROP' in s or 'policy REJECT' in s for s in success.splitlines()):
            return_value.append('IPv6 default deny policy')
            return_value.append('PASS')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
        else:
            return_value.append('IPv6 default no deny policy')
            return_value.append('FAIL')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
    else:
        if result_success:
            return_value.append('ipv6 used though disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_5_1_2_ind():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('ip6tables -L INPUT -v -n')
    if success:
        loopbacks = [s for s in success.splitlines()]
        flag = 1
        if len(loopbacks) > 2:
            flag = 0
            for i in range(2, len(loopbacks)):
                rule = loopbacks[i].split()
                if rule[2] == 'ACCEPT' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == 'lo':
                            if rule[-3] == '*':
                                if rule[-2] == '::/0':
                                    if rule[-1] == '::/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'IPv6 input accpet destination not ::/0')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + '\nFollowing uses ipv6\n' + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'IPv6 input accpet source not ::/0')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + '\nFollowing uses ipv6\n' + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'IPv6 input accpet out not *')
                                return_value.append('FAIL')
                                return_value.append(
                                    success + '\nFollowing uses ipv6\n' + result_success)
                                flag += 1
                                break
                        else:
                            return_value.append('IPv6 input accpet in not lo')
                            return_value.append('FAIL')
                            return_value.append(
                                success + '\nFollowing uses ipv6\n' + result_success)
                            flag += 1
                            break
                    else:
                        return_value.append('IPv6 input accept prot not all')
                        return_value.append('FAIL')
                        return_value.append(
                            success + '\nFollowing uses ipv6\n' + result_success)
                        flag += 1
                        break
                elif rule[2] == 'DROP' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == '*':
                            if rule[-3] == '*':
                                if rule[-2] == '::1':
                                    if rule[-1] == '::/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'IPv6 input drop destination not ::/0')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + '\nFollowing uses ipv6\n' + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'IPv6 input drop source not ::1')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + '\nFollowing uses ipv6\n' + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'IPv6 input drop out not *')
                                return_value.append('FAIL')
                                return_value.append(
                                    success + '\nFollowing uses ipv6\n' + result_success)
                                flag += 1
                                break
                        else:
                            return_value.append('IPv6 input drop in not *')
                            return_value.append('FAIL')
                            return_value.append(
                                success + '\nFollowing uses ipv6\n' + result_success)
                            flag += 1
                            break
                    else:
                        return_value.append('IPv6 input drop prot not all')
                        return_value.append('FAIL')
                        return_value.append(
                            success + '\nFollowing uses ipv6\n' + result_success)
                        flag += 1
                        break
        else:
            return_value.append('IPv6 input loopback no config')
            return_value.append('FAIL')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
        if not flag:
            result_success += '\nConfig of IPv6 Input table\n' + success + '\n'
            success, error = check('ip6tables -L OUTPUT -v -n')
            if success:
                loopbacks = [s for s in success.splitlines()]
                if len(loopbacks) > 2:
                    for i in range(2, len(loopbacks)):
                        rule = loopbacks[i].split()
                        if rule[2] == 'ACCEPT' and not flag:
                            if rule[3] == 'all':
                                if rule[-4] == '*':
                                    if rule[-3] == 'lo':
                                        if rule[-2] == '::/0':
                                            if rule[-1] == '::/0':
                                                return_value.append(
                                                    'IPv6 loopback traffic is configured')
                                                return_value.append('PASS')
                                                return_value.append(
                                                    success + '\nFollowing uses ipv6\n' + result_success)
                                            else:
                                                return_value.append(
                                                    'IPv6 output accpet destination not ::/0')
                                                return_value.append('FAIL')
                                                return_value.append(
                                                    success + '\nFollowing uses ipv6\n' + result_success)
                                                flag += 1
                                                break
                                        else:
                                            return_value.append(
                                                'IPv6 output accpet source not ::/0')
                                            return_value.append('FAIL')
                                            return_value.append(
                                                success + '\nFollowing uses ipv6\n' + result_success)
                                            flag += 1
                                            break
                                    else:
                                        return_value.append(
                                            'IPv6 output accpet out not lo')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + '\nFollowing uses ipv6\n' + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'IPv6 output accpet in not *')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + '\nFollowing uses ipv6\n' + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'IPv6 output accept prot not all')
                                return_value.append('FAIL')
                                return_value.append(
                                    success + '\nFollowing uses ipv6\n' + result_success)
                                flag += 1
                                break
                else:
                    return_value.append('IPv6 output loopback no config')
                    return_value.append('FAIL')
                    return_value.append(
                        success + '\nFollowing uses ipv6\n' + result_success)
            else:
                if result_success:
                    return_value.append(
                        'ipv6 enabled output loopback disabled')
                    return_value.append('FAIL')
                    return_value.append(
                        'The following have ipv6 enabled\n' + result_success)
                else:
                    return_value.append('ipv6 disabled')
                    return_value.append('PASS')
                    return_value.append(
                        'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    else:
        if result_success:
            return_value.append('ipv6 enabled input loopback disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_5_1_3_ind():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('ip6tables -L -v -n')
    if success:
        if len(success.splitlines()) > 8:
            return_value.append('IPv6 Table contains config')
            return_value.append('PASS')
            return_value.append('verify all rules for new outbound, and established connections match site policy\n' +
                                success + '\nFollowing uses ipv6\n' + result_success)
        else:
            return_value.append('IPv6 Table contains no config')
            return_value.append('FAIL')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
    else:
        if result_success:
            return_value.append('ipv6 used though disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_5_1_4_ind():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('ss -6tuln')
    if success:
        open_ports = [s.split()[0]
                      for s in success.splitlines() if s.split()[0] != 'Netid']
        if len(open_ports):
            result_success = success
            success, error = check('ip6tables -L INPUT -v -n')
            if success:
                rules = [s.split()[0] for s in success.splitlines() if s.split()[0] != 'Chain' and s.split()[
                    0] != 'pkts' and s.split()[2] not in ['ACCEPT', 'DROP', 'QUEUE', 'RETURN']]
                if all(o in rules for o in open_ports):
                    return_value.append('all open ports have firewall rule')
                    return_value.append('PASS')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\nIPv6 input table configuration\n' + success)
                else:
                    return_value.append('open ports no firewall rule')
                    return_value.append('FAIL')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\nIPv6 input table configuration\n' + success)
            else:
                return_value.append('IPv6 input Table not found')
                return_value.append('FAIL')
                return_value.append(
                    error + '\nFollowing open ports were found\n' + result_success)
        else:
            return_value.append('no open ports found')
            return_value.append('PASS')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
    else:
        if result_success:
            return_value.append('ipv6 used though disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_5_2_1_ind():
    return_value = list()
    success, error = check('iptables -w -L | grep Chain')
    if success:
        if all('policy DROP' in s or 'policy REJECT' in s for s in success.splitlines()):
            return_value.append('default deny firewall policy')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('no default deny firewall')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('firewall policy not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_2_2_ind():
    return_value = list()
    success, error = check('iptables -w -L INPUT -v -n')
    if success:
        loopbacks = [s for s in success.splitlines()]
        flag = 1
        if len(loopbacks) > 2:
            flag = 0
            for i in range(2, len(loopbacks)):
                rule = loopbacks[i].split()
                if rule[2] == 'ACCEPT' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == 'lo':
                            if rule[-3] == '*':
                                if rule[-2] == '0.0.0.0/0':
                                    if rule[-1] == '0.0.0.0/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'fw input accpet destination not 0.0.0.0/0')
                                        return_value.append('FAIL')
                                        return_value.append(success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'fw input accpet source not 0.0.0.0/0')
                                    return_value.append('FAIL')
                                    return_value.append(success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'fw input accpet out not *')
                                return_value.append('FAIL')
                                return_value.append(success)
                                flag += 1
                                break
                        else:
                            return_value.append('fw input accpet in not lo')
                            return_value.append('FAIL')
                            return_value.append(success)
                            flag += 1
                            break
                    else:
                        return_value.append('fw input accept prot not all')
                        return_value.append('FAIL')
                        return_value.append(success)
                        flag += 1
                        break
                elif rule[2] == 'DROP' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == '*':
                            if rule[-3] == '*':
                                if rule[-2] == '127.0.0.0/8':
                                    if rule[-1] == '0.0.0.0/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'fw input drop destination not 0.0.0.0/0')
                                        return_value.append('FAIL')
                                        return_value.append(success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'fw input drop source not 127.0.0.0/8')
                                    return_value.append('FAIL')
                                    return_value.append(success)
                                    flag += 1
                                    break
                            else:
                                return_value.append('fw input drop out not *')
                                return_value.append('FAIL')
                                return_value.append(success)
                                flag += 1
                                break
                        else:
                            return_value.append('fw input drop in not *')
                            return_value.append('FAIL')
                            return_value.append(success)
                            flag += 1
                            break
                    else:
                        return_value.append('fw input drop prot not all')
                        return_value.append('FAIL')
                        return_value.append(success)
                        flag += 1
                        break
        else:
            return_value.append('fw input loopback no config')
            return_value.append('FAIL')
            return_value.append(success)
        if not flag:
            result_success = '\nConfig of firewall Input table\n' + success + '\n'
            success, error = check('iptables -w -L OUTPUT -v -n')
            if success:
                loopbacks = [s for s in success.splitlines()]
                if len(loopbacks) > 2:
                    for i in range(2, len(loopbacks)):
                        rule = loopbacks[i].split()
                        if rule[2] == 'ACCEPT' and not flag:
                            if rule[3] == 'all':
                                if rule[-4] == '*':
                                    if rule[-3] == 'lo':
                                        if rule[-2] == '0.0.0.0/0':
                                            if rule[-1] == '0.0.0.0/0':
                                                return_value.append(
                                                    'firewall loopback traffic configured')
                                                return_value.append('PASS')
                                                return_value.append(
                                                    success + result_success)
                                            else:
                                                return_value.append(
                                                    'fw output accpet destination not 0.0.0.0/0')
                                                return_value.append('FAIL')
                                                return_value.append(
                                                    success + result_success)
                                                flag += 1
                                                break
                                        else:
                                            return_value.append(
                                                'fw output accpet source not 0.0.0.0/0')
                                            return_value.append('FAIL')
                                            return_value.append(
                                                success + result_success)
                                            flag += 1
                                            break
                                    else:
                                        return_value.append(
                                            'fw output accpet out not lo')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'fw output accpet in not *')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'fw output accept prot not all')
                                return_value.append('FAIL')
                                return_value.append(success + result_success)
                                flag += 1
                                break
                else:
                    return_value.append('fw output loopback no config')
                    return_value.append('FAIL')
                    return_value.append(success + result_success)
            else:
                return_value.append('firewall output loopback not found')
                return_value.append('FAIL')
                return_value.append(error)
    else:
        return_value.append('firewall input loopback not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_2_3_ind():
    return_value = list()
    success, error = check('iptables -w -L -v -n')
    if success:
        if len(success.splitlines()) > 8:
            return_value.append('iptables contains config')
            return_value.append('PASS')
            return_value.append(
                'verify all rules for new outbound, and established connections match site policy\n' + success)
        else:
            return_value.append('iptables contains no config')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('iptables not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_2_4_ind():
    return_value = list()
    success, error = check('ss -4tuln')
    if success:
        open_ports = [s.split()[0]
                      for s in success.splitlines() if s.split()[0] != 'Netid']
        if len(open_ports):
            result_success = success
            success, error = check('iptables -w -L INPUT -v -n')
            if success:
                rules = [s.split()[0] for s in success.splitlines() if s.split()[0] != 'Chain' and s.split()[
                    0] != 'pkts' and s.split()[2] not in ['ACCEPT', 'DROP', 'QUEUE', 'RETURN']]
                if all(o in rules for o in open_ports):
                    return_value.append('all open ports have firewall rule')
                    return_value.append('PASS')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\niptables input configuration\n' + success)
                else:
                    return_value.append('open ports no firewall rule')
                    return_value.append('FAIL')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\niptables input configuration\n' + success)
            else:
                return_value.append('iptables input not found')
                return_value.append('FAIL')
                return_value.append(
                    error + '\nFollowing open ports were found\n' + result_success)
        else:
            return_value.append('no open ports found')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('no open ports found')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


# distro specific
def _3_5_3_ind():
    return_value = list()
    return_value.append('iptables not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s iptables')
    if 'Status: install ok installed' in success:
        return_value.append('iptables installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('iptables not installed')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_6_ind():
    return_value = list()
    success, error = check('iwconfig')
    if success:
        result_success = success
        success, error = check('ip link show up')
        if success:
            active_wlan = [s for s in success.splitlines() if 'wlan' in s.split()[
                1]]
            if not active_wlan:
                return_value.append('wireless interfaces inactive')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + success)
            else:
                return_value.append('wireless interfaces active')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + success)
        else:
            return_value.append('ip link status unkown')
            return_value.append('CHEK')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('wireless interfaces disabled')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _3_7_ind():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disabled=1')
    if success:
        return_value.append('IPv6 enabled')
        return_value.append('FAIL')
        return_value.append('The following use IPv6\n' + success)
    else:
        return_value.append('IPv6 disabled')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _4_1_1_1_ind():
    return_value = list()
    success, error = check(
        'grep max_log_file /etc/audit/auditd.conf')
    if success:
        return_value.append('audit log storage size is configured')
        return_value.append('PASS')
        return_value.append(
            'Ensure output is in compliance with site policy\n' + success)
    else:
        return_value.append('audit log storage size not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_1_1_2_ind():
    return_value = list()
    success, error = check(
        'grep space_left_action /etc/audit/auditd.conf')
    if success:
        result_success = success + '\n'
        success, error = check('grep action_mail_acct /etc/audit/auditd.conf')
        if success:
            result_success = success + '\n'
            success, error = check(
                'grep admin_space_left_action /etc/audit/auditd.conf')
            if success:
                return_value.append('system disabled when audit logs full')
                return_value.append('PASS')
                return_value.append(result_success + success)
            else:
                return_value.append('admin_space_left_action not set')
                return_value.append('FAIL')
                return_value.append(
                    'grep admin_space_left_action /etc/audit/auditd.conf returned the following\n' + error)
        else:
            return_value.append('action_mail_acct not set')
            return_value.append('FAIL')
            return_value.append(
                'grep action_mail_acct /etc/audit/auditd.conf returned the following\n' + error)
    else:
        return_value.append('system not disabled when audit logs full')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_1_1_3_ind():
    return_value = list()
    success, error = check(
        'grep max_log_file_action /etc/audit/auditd.conf')
    if success:
        if 'max_log_file_action = keep_logs' in success:
            return_value.append('audit logs not automatically deleted')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('audit logs automatically deleted')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('audit log file action not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


# distro specific
def _4_1_2_ind():
    return_value = list()
    return_value.append('autitd not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s auditd audispd-plugins')
    if all('Status: install ok installed' in s for s in success.splitlines()):
        return_value.append('auditd is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('auditd not installed')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_1_3_ind():
    return_value = list()
    success, error = check('systemctl is-enabled auditd')
    if 'enabled' in success:
        result_success = success
        success, error = check('ls /etc/rc*.d | grep auditd')
        if success:
            runlevel02 = [s for s in success.splitlines()
                          if s.startswith('S02')]
            runlevel03 = [s for s in success.splitlines()
                          if s.startswith('S03')]
            runlevel04 = [s for s in success.splitlines()
                          if s.startswith('S04')]
            runlevel05 = [s for s in success.splitlines()
                          if s.startswith('S05')]
            if runlevel02:
                if runlevel03:
                    if runlevel04:
                        if runlevel05:
                            return_value.append('auditd service is enabled')
                            return_value.append('PASS')
                            return_value.append(
                                result_success + '\n' + success)
                        else:
                            return_value.append(
                                'auditd runlevel S05 not found')
                            return_value.append('FAIL')
                            return_value.append(
                                result_success + '\nls /etc/rc*.d | grep auditd returned the following\n' + success)
                    else:
                        return_value.append('auditd runlevel S04 not found')
                        return_value.append('FAIL')
                        return_value.append(
                            result_success + '\nls /etc/rc*.d | grep auditd returned the following\n' + success)
                else:
                    return_value.append('auditd runlevel S03 not found')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep auditd returned the following\n' + success)
            else:
                return_value.append('auditd runlevel S02 not found')
                return_value.append('FAIL')
                return_value.append(
                    result_success + '\nls /etc/rc*.d | grep auditd returned the following\n' + success)
        else:
            return_value.append('auditd is disabled')
            return_value.append('FAIL')
            return_value.append(
                result_success + '\nls /etc/rc*.d | grep auditd returned the following\n' + error)
    else:
        return_value.append('auditd not found')
        return_value.append('FAIL')
        return_value.append(
            'systemctl is-enabled auditd returned the following\n' + error)
    return return_value


# bootloader specific
def _4_1_4_ind():
    return_value = list()
    success, error = check('grep "^\s*linux" /boot/grub*/grub.cfg')
    if success:
        if all('audit=1' in s for s in success.splitlines()):
            return_value.append('processes prior to auditd audited')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('processes prior to auditd not audited')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        result_error = error + '\n'
        success, error = check('grep "^\s*kernel" /boot/grub/menu.lst')
        if success:
            if all('audit=1' in s for s in success.splitlines()):
                return_value.append('processes prior to auditd audited')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('processes prior to auditd not audited')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('process prior to auditd not found')
            return_value.append('CHEK')
            return_value.append(result_error + '\n' + error)
    return return_value


def _4_1_5_ind():
    return_value = list()
    success, error = check('grep time-change /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep time-change')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change' in result_success or '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' in result_success:
            if '-a always,exit -F arch=b64 -S clock_settime -k time-change' in result_success or '-a always,exit -F arch=b32 -S clock_settime -k time-change' in result_success:
                if '-w /etc/localtime -p wa -k time-change' in result_success:
                    return_value.append('events modifying date and time coll')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('localtime time-change not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('clock_settime not collected')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('adjtimex and settimeofday not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('events modifying date and time not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_6_ind():
    return_value = list()
    success, error = check('grep identity /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep identity')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /etc/group -p wa -k identity' in result_success:
            if '-w /etc/passwd -p wa -k identity' in result_success:
                if '-w /etc/gshadow -p wa -k identity' in result_success:
                    if '-w /etc/shadow -p wa -k identity' in result_success:
                        if '-w /etc/security/opasswd -p wa -k identity' in result_success:
                            return_value.append(
                                'events modifying u/g info collected')
                            return_value.append('PASS')
                            return_value.append(result_success)
                        else:
                            return_value.append(
                                'opasswd identity events not coll')
                            return_value.append('FAIL')
                            return_value.append(result_success)
                    else:
                        return_value.append('shadow identity events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('gshadow identity events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('passwd identity events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('group identity events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('events modifying u/g info not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_7_ind():
    return_value = list()
    success, error = check('grep system-locale /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grepsystem-locale')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale' in result_success or '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' in result_success:
            if '-w /etc/issue -p wa -k system-locale' in result_success:
                if '-w /etc/issue.net -p wa -k system-locale' in result_success:
                    if '-w /etc/hosts -p wa -k system-locale' in result_success:
                        if '-w /etc/sysconfig/network -p wa -k system-locale' in result_success:
                            return_value.append(
                                "events modifying system's n/w env coll")
                            return_value.append('PASS')
                            return_value.append(result_success)
                        else:
                            return_value.append(
                                'network system-locale events not coll')
                            return_value.append('FAIL')
                            return_value.append(result_success)
                    else:
                        return_value.append(
                            'hosts system-locale events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append(
                        'issue.net system-locale events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('issue system-locale events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('system-locale name change not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append("events modifying system's n/w env not coll")
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_8_ind():
    return_value = list()
    success, error = check('grep MAC-policy /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep MAC-policy')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /etc/selinux/ -p wa -k MAC-policy' in result_success or '-w /etc/apparmor/ -p wa -k MAC-policy' in result_success:
            if '-w /usr/share/selinux/ -p wa -k MAC-policy' in result_success or '-w /etc/apparmor.d/ -p wa -k MAC-policy' in result_success:
                return_value.append("events modifying system's MAC coll")
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('dir MAC-policy events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('etc MAC-policy events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append("events modifying system's MAC not coll")
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_9_ind():
    return_value = list()
    success, error = check('grep logins /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep logins')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /var/log/faillog -p wa -k logins' in result_success:
            if '-w /var/log/lastlog -p wa -k logins' in result_success:
                if '-w /var/log/tallylog -p wa -k logins' in result_success:
                    return_value.append(
                        'login and logout events are collected')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('tallylog logins events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('lastlog logins events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('faillog logins events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('login and logout events not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_10_ind():
    return_value = list()
    success, error = check(
        "grep -E '(session|logins)' /etc/audit/rules.d/*.rules")
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check("auditctl -l | grep -E '(session|logins)'")
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /var/run/utmp -p wa -k session' in result_success:
            if '-w /var/log/wtmp -p wa -k logins' in result_success:
                if '-w /var/log/btmp -p wa -k logins' in result_success:
                    return_value.append('session initiation info is collected')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('btmp logins events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('wtmp logins events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('utmp session events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('session initiation info not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_11_ind():
    return_value = list()
    success, error = check('grep perm_mod /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep perm_mod')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod' in result_success:
            if '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod' in result_success:
                if '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod' in result_success:
                    if '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=-1 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=-1 -k perm_mod' in result_success:
                        if '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=-1 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=-1 -k perm_mod' in result_success:
                            if '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=-1 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=-1 -k perm_mod' in result_success:
                                return_value.append(
                                    'access control mod events collected')
                                return_value.append('PASS')
                                return_value.append(result_success)
                            else:
                                return_value.append(
                                    'setxattr auditctl events not coll')
                                return_value.append('FAIL')
                                return_value.append(result_success)
                        else:
                            return_value.append(
                                'chown auditctl events not coll')
                            return_value.append('FAIL')
                            return_value.append(result_success)
                    else:
                        return_value.append('chmod auditctl events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('setxattr *.rules events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('chown *.rules events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('chmod *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('access control mod events not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_12_ind():
    return_value = list()
    success, error = check('grep access /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep access')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access' in result_success:
            if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access' in result_success:
                if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=-1 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=-1 -k access' in result_success:
                    if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=-1 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=-1 -k access' in result_success:
                        return_value.append(
                            'unauthorized file access collected')
                        return_value.append('PASS')
                        return_value.append(result_success)
                    else:
                        return_value.append('EPERM auditctl events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('EACCES auditctl events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('EPERM *.rules events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('EACCES *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('unauthorized file access not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_13_ind():
    return_value = list()
    success, error = check('mount | grep -e "/dev/sd"')
    partitions = [s.split()[0] for s in success.splitlines()]
    if len(partitions):
        result_success = 'Following partitions were found\n' + success
        flag = 0
        for p in partitions:
            success, error = check(
                "find " + p + " -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \"-a always,exit -F path=\" $1 \" -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged\" }'")
            result_success += success if success else error + \
                '\nABOVE was found on ' + p + '\n'
            flag += 1 if success else 0
        if not flag:
            return_value.append('privileged commands not collected')
            return_value.append('FAIL')
            return_value.append(result_success)
        else:
            return_value.append('privileged commands collected')
            return_value.append('PASS')
            return_value.append(
                'Verify all resulting lines are a .rules file in /etc/audit/rules.d/ and the output of auditctl -l AND .rules file output should be auid!=-1 not auid!=4294967295\n' + result_success)
    else:
        return_value.append('no partitions found')
        return_value.append('CHEK')
        return_value.append(success + error)
    return return_value


def _4_1_14_ind():
    return_value = list()
    success, error = check('grep mounts /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep mounts')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts' in result_success or '-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts' in result_success:
            if '-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=-1 -k mounts' in result_success or '-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=-1 -k mounts' in result_success:
                return_value.append('successful fs mounts collected')
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('mount auditctl events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('mount *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('successful fs mounts not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_15_ind():
    return_value = list()
    success, error = check('grep delete /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep delete')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete' in result_success or '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete' in result_success:
            if '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=-1 -k delete' in result_success or '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=-1 -k delete' in result_success:
                return_value.append('user file deletion events collected')
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('unlink, rename auditctl events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('unlink, rename *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('user file deletion events not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_16_ind():
    return_value = list()
    success, error = check('grep scope /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep scope')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /etc/sudoers -p wa -k scope' in result_success:
            if '-w /etc/sudoers.d/ -p wa -k scope' in result_success:
                return_value.append('changes to sudoers collected')
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('directory scope events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('sudoers scope events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('changes to sudoers not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_17_ind():
    return_value = list()
    success, error = check('grep actions /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep actions')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /var/log/sudo.log -p wa -k actions' in result_success:
            return_value.append('sudolog collected')
            return_value.append('PASS')
            return_value.append(result_success)
        else:
            return_value.append('sudo.log actions events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('sudolog not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_18_ind():
    return_value = list()
    success, error = check('grep modules /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep modules')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b32 -S init_module -S delete_module -k modules' in result_success or '-a always,exit -F arch=b64 -S init_module -S delete_module-k modules' in result_success:
            if '-w /sbin/insmod -p x -k modules' in result_success:
                if '-w /sbin/rmmod -p x -k modules' in result_success:
                    if '-w /sbin/modprobe -p x -k modules' in result_success:
                        return_value.append('kernel module monitored')
                        return_value.append('PASS')
                        return_value.append(result_success)
                    else:
                        return_value.append('modprobe modules events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('rmmod modules events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('insmod modules events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('modules *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('kernel module not monitored')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_19_ind():
    return_value = list()
    success, error = check(
        'grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1')
    if '-e 2' in success:
        return_value.append('audit configuration immutable')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('audit configuration is mutable')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _4_2_1_1_ind():
    return_value = list()
    return_value.append('rsyslog not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('dpkg -s rsyslog')
    if 'Status: install ok installed' in success:
        return_value.append('rsyslog is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('rsyslog not installed')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_1_2_ind():
    return_value = list()
    success, error = check('systemctl is-enabled rsyslog')
    if 'enabled' in success:
        result_success = success
        success, error = check('ls /etc/rc*.d | grep rsyslog')
        if success:
            runlevel02 = [s for s in success.splitlines()
                          if s.startswith('S02')]
            runlevel03 = [s for s in success.splitlines()
                          if s.startswith('S03')]
            runlevel04 = [s for s in success.splitlines()
                          if s.startswith('S04')]
            runlevel05 = [s for s in success.splitlines()
                          if s.startswith('S05')]
            if runlevel02:
                if runlevel03:
                    if runlevel04:
                        if runlevel05:
                            return_value.append('rsyslog service is enabled')
                            return_value.append('PASS')
                            return_value.append(
                                result_success + '\n' + success)
                        else:
                            return_value.append(
                                'rsyslog runlevel S05 not found')
                            return_value.append('FAIL')
                            return_value.append(
                                result_success + '\nls /etc/rc*.d | grep rsyslog returned the following\n' + success)
                    else:
                        return_value.append('rsyslog runlevel S04 not found')
                        return_value.append('FAIL')
                        return_value.append(
                            result_success + '\nls /etc/rc*.d | grep rsyslog returned the following\n' + success)
                else:
                    return_value.append('rsyslog runlevel S03 not found')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep rsyslog returned the following\n' + success)
            else:
                return_value.append('rsyslog runlevel S02 not found')
                return_value.append('FAIL')
                return_value.append(
                    result_success + '\nls /etc/rc*.d | grep rsyslog returned the following\n' + success)
        else:
            return_value.append('rsyslog is disabled')
            return_value.append('FAIL')
            return_value.append(
                result_success + '\nls /etc/rc*.d | grep rsyslog returned the following\n' + error)
    else:
        return_value.append('rsyslog not found')
        return_value.append('FAIL')
        return_value.append(
            'systemctl is-enabled rsyslog returned the following\n' + error)
    return return_value


def _4_2_1_3_ind():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('cat /etc/rsyslog.conf')
    if success:
        result_success += 'Review the contents of rsyslog.conf\n' + success
    else:
        result_error += error
    success, error = check('cat /etc/rsyslog.d/*.conf')
    if success:
        result_success += 'Review the contents of rsyslog.d/*.conf\n' + success
    else:
        result_error += error
    success, error = check('ls -l /var/log/')
    if success:
        result_success += 'verify that the log files are logging information\n' + success
    else:
        result_error += error
    if len(result_success):
        return_value.append('logging is configured')
        return_value.append('CHEK')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('logging not configured')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_2_1_4_ind():
    return_value = list()
    success, error = check(
        'grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf')
    if success:
        allowed_perms = ['0640', '0600', '0440', '0400', '0240', '0200']
        perms = [s.split(':')[1].split()[1] for s in success.splitlines()]
        if all(p in allowed_perms for p in perms):
            return_value.append('rsyslog file permissions configured')
            return_value.append('PASS')
            return_value.append(success + '\n' + error)
        else:
            return_value.append('rsyslog file permissions not configured')
            return_value.append('PASS')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('rsyslog file permissions not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_1_5_ind():
    return_value = list()
    success, error = check(
        'grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf')
    if success:
        return_value.append('rsyslog sends logs to remote log host')
        return_value.append('PASS')
        return_value.append(
            'verify that logs are sent to central log host\n' + success + '\n' + error)
    else:
        return_value.append('rsyslog does not sends logs')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_1_6_ind():
    return_value = list()
    success, error = check(
        "grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check(
        "grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
    result_success = success if success else ''
    result_error = error if error else ''
    if len(result_success):
        return_value.append('rsyslog messages accepted designated')
        return_value.append('PASS')
        return_value.append(
            'verify the resulting lines are uncommented on designated log hosts and commented or removed on all others\n' + result_success + '\n' + result_error)
    else:
        return_value.append('rsyslog messages not config')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_2_2_1_ind():
    return_value = list()
    success, error = check(
        'grep -e ForwardToSyslog /etc/systemd/journald.conf')
    if success:
        if 'ForwardToSyslog=yes' in success and not success.startswith('#'):
            return_value.append('journald sends logs to rsyslog')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('journald does not send logs to rsyslog')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('journald not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_2_2_ind():
    return_value = list()
    success, error = check('grep -e Compress /etc/systemd/journald.conf')
    if success:
        if 'Compress=yes' in success and not success.startswith('#'):
            return_value.append('jjournald compresses large log files')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('journald not compress large log files')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('journald not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_2_3_ind():
    return_value = list()
    success, error = check('grep -e Storage /etc/systemd/journald.conf')
    if success:
        if 'Storage=persistent' in success and not success.startswith('#'):
            return_value.append('journald writes logfiles to persistent disk')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('journald does not write logfiles')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('journald not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_3_ind():
    return_value = list()
    success, error = check('find /var/log -type f -ls')
    if success:
        logs = [s.split()[2][-6:] for s in success.splitlines()]
        if all(l in ['r-----', '------'] for l in logs):
            return_value.append('all logfiles permissions configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('logfiles permissions not configured')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('logfiles permissions not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_3_ind():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('cat /etc/logrotate.conf')
    if success:
        result_success += 'verify logs in logrotate.conf are rotated according to site policy\n' + success
    else:
        result_error += error
    success, error = check('cat /etc/logrotate.d/*')
    if success:
        result_success += 'verify logs in logrotate directory are rotated according to site policy\n' + success
    else:
        result_error += error
    if len(result_success):
        return_value.append('lograte is configured')
        return_value.append('CHEK')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('lograte not configured')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _5_1_1_ind():
    return_value = list()
    success, error = check('systemctl is-enabled crond')
    if 'enabled' in success:
        result_success = success
        success, error = check('ls /etc/rc*.d | grep crond')
        if success:
            runlevel02 = [s for s in success.splitlines()
                          if s.startswith('S02')]
            runlevel03 = [s for s in success.splitlines()
                          if s.startswith('S03')]
            runlevel04 = [s for s in success.splitlines()
                          if s.startswith('S04')]
            runlevel05 = [s for s in success.splitlines()
                          if s.startswith('S05')]
            if runlevel02:
                if runlevel03:
                    if runlevel04:
                        if runlevel05:
                            return_value.append('cron daemon is enabled')
                            return_value.append('PASS')
                            return_value.append(
                                result_success + '\n' + success)
                        else:
                            return_value.append(
                                'cron daemon runlevel S05 not found')
                            return_value.append('FAIL')
                            return_value.append(
                                result_success + '\nls /etc/rc*.d | grep crond returned the following\n' + success)
                    else:
                        return_value.append(
                            'cron daemon runlevel S04 not found')
                        return_value.append('FAIL')
                        return_value.append(
                            result_success + '\nls /etc/rc*.d | grep crond returned the following\n' + success)
                else:
                    return_value.append('cron daemon runlevel S03 not found')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\nls /etc/rc*.d | grep crond returned the following\n' + success)
            else:
                return_value.append('cron daemon runlevel S02 not found')
                return_value.append('FAIL')
                return_value.append(
                    result_success + '\nls /etc/rc*.d | grep crond returned the following\n' + success)
        else:
            return_value.append('cron daemon is disabled')
            return_value.append('FAIL')
            return_value.append(
                result_success + '\nls /etc/rc*.d | grep crond returned the following\n' + error)
    else:
        return_value.append('cron daemon not found')
        return_value.append('FAIL')
        return_value.append(
            'systemctl is-enabled crond returned the following\n' + error)
    return return_value


def _5_1_2_ind():
    return_value = list()
    success, error = check('stat /etc/crontab')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/crontab configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/crontab not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/crontab not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/crontab returned the following\n' + error)
    return return_value


def _5_1_3_ind():
    return_value = list()
    success, error = check('stat /etc/cron.hourly')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.hourly configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.hourly not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.hourly not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.hourly returned the following\n' + error)
    return return_value


def _5_1_4_ind():
    return_value = list()
    success, error = check('stat /etc/cron.daily')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.daily configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.daily not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.daily not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.daily returned the following\n' + error)
    return return_value


def _5_1_5_ind():
    return_value = list()
    success, error = check('stat /etc/cron.weekly')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.weekly configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.weekly not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.weekly not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.weekly returned the following\n' + error)
    return return_value


def _5_1_6_ind():
    return_value = list()
    success, error = check('stat /etc/cron.monthly')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.monthly configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.monthly not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.monthly not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.monthly returned the following\n' + error)
    return return_value


def _5_1_7_ind():
    return_value = list()
    success, error = check('stat /etc/cron.d')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.d configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.d not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.d not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.d returned the following\n' + error)
    return return_value


def _5_1_8_ind():
    return_value = list()
    success, error = check('stat /etc/cron.deny')
    if 'No such file or directory' in error:
        result_error = error
        success, error = check('stat /etc/at.deny')
        if 'No such file or directory' in error:
            result_error += error
            success, error = check('stat /etc/cron.allow')
            if success:
                go_perm = success.splitlines()[0].split()[1][-7:-1]
                if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
                    result_success = success
                    success, error = check('stat /etc/at.allow')
                    if success:
                        go_perm = success.splitlines()[0].split()[1][-7:-1]
                        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
                            return_value.append(
                                'at/cron restricted to authorized users')
                            return_value.append('PASS')
                            return_value.append(
                                result_error + '\n' + result_success + '\n' + success)
                        else:
                            return_value.append('/etc/at.allow not configured')
                            return_value.append('FAIL')
                            return_value.append(
                                result_error + '\n' + result_success + '\n' + success + '\n' + error)
                    else:
                        return_value.append('/etc/at.allow not found')
                        return_value.append('FAIL')
                        return_value.append(result_error + '\n' + result_success +
                                            '\nstat /etc/at.allow returned the following\n' + error)
                else:
                    return_value.append('/etc/cron.allow not configured')
                    return_value.append('FAIL')
                    return_value.append(result_error + '\n' + result_success +
                                        '\nstat /etc/at.allow returned the following\n' + success)
            else:
                return_value.append('/etc/cron.allow not found')
                return_value.append('FAIL')
                return_value.append(
                    result_error + '\nstat /etc/at.allow returned the following\n' + error)
        else:
            return_value.append('/etc/at.deny exists')
            return_value.append('FAIL')
            return_value.append(
                result_error + '\nstat /etc/at.deny returned the following\n' + error)
    else:
        return_value.append('/etc/cron.deny exists')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.deny returned the following\n' + error)
    return return_value


def _5_2_1_ind():
    return_value = list()
    success, error = check('stat /etc/ssh/sshd_config')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/ssh/sshd_config configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on sshd_config not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/ssh/sshd_config not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/ssh/sshd_config returned the following\n' + error)
    return return_value


def _5_2_2_ind():
    return_value = list()
    success, error = check(
        "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;")
    if success:
        result_success = success
        success, error = check(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | grep \"Access: (\"")
        if all(s.split()[1][-7:-1] == '------' and 'Uid: (    0/    root)   Gid: (    0/    root)' in s for s in success.splitlines()):
            return_value.append('SSH private host keys perms config')
            return_value.append('PASS')
            return_value.append(result_success)
        else:
            return_value.append('SSH private host keys perms not config')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('SSH private host keys not found')
        return_value.append('FAIL')
        return_value.append(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;\n" + error)
    return return_value


def _5_2_3_ind():
    return_value = list()
    success, error = check(
        "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;")
    if success:
        result_success = success
        success, error = check(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \; | grep \"Access: (\"")
        if all(s.split()[1][-7:-1] in ['------', 'r--r--', 'r-----', '---r--'] and 'Uid: (    0/    root)   Gid: (    0/    root)' in s for s in success.splitlines()):
            return_value.append('SSH public host keys perms config')
            return_value.append('PASS')
            return_value.append(result_success)
        else:
            return_value.append('SSH public host keys perms not config')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('SSH public host keys not found')
        return_value.append('FAIL')
        return_value.append(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;\n" + error)
    return return_value


def _5_2_4_ind():
    return_value = list()
    success, error = check('grep ^Protocol /etc/ssh/sshd_config')
    if 'Protocol 2' in success:
        return_value.append('SSH Protocol set to 2')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH Protocol not 2')
        return_value.append('FAIL')
        return_value.append(
            'grep ^Protocol /etc/ssh/sshd_config returned the following\n' + success + error)
    return return_value


def _5_2_5_ind():
    return_value = list()
    success, error = check('sshd -T | grep loglevel')
    if 'LogLevel VERBOSE' in success or 'loglevel INFO' in success:
        return_value.append('SSH LogLevel is appropriate')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH LogLevel not appropriate')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep loglevel returned the following\n' + success + error)
    return return_value


def _5_2_6_ind():
    return_value = list()
    success, error = check('sshd -T | grep x11forwarding')
    if 'X11Forwarding no' in success:
        return_value.append('SSH X11 forwarding is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH X11 forwarding not disabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep x11forwarding returned the following\n' + success + error)
    return return_value


def _5_2_7_ind():
    return_value = list()
    success, error = check('sshd -T | grep maxauthtries')
    if success:
        tries = success.split()[1]
        if int(tries) <= 4:
            return_value.append('SSH MaxAuthTries is set to ' + tries)
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SSH MaxAuthTries is more than 4')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('SSH MaxAuthTries not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep maxauthtries returned the following\n' + error)
    return return_value


def _5_2_8_ind():
    return_value = list()
    success, error = check('sshd -T | grep ignorerhosts')
    if 'IgnoreRhosts yes' in success:
        return_value.append('SSH IgnoreRhosts is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH IgnoreRhosts is disabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep ignorerhosts returned the following\n' + success + error)
    return return_value


def _5_2_9_ind():
    return_value = list()
    success, error = check('sshd -T | grep hostbasedauthentication')
    if 'HostbasedAuthentication no' in success:
        return_value.append('SSH HBA is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH HBA is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep hostbasedauthentication returned the following\n' + success + error)
    return return_value


def _5_2_10_ind():
    return_value = list()
    success, error = check('sshd -T | grep permitrootlogin')
    if 'PermitRootLogin no' in success:
        return_value.append('SSH root login is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH root login is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep permitrootlogin returned the following\n' + success + error)
    return return_value


def _5_2_11_ind():
    return_value = list()
    success, error = check('sshd -T | grep permitemptypasswords')
    if 'PermitEmptyPasswords no' in success:
        return_value.append('SSH PermitEmptyPasswords is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH PermitEmptyPasswords is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep permitemptypasswords returned the following\n' + success + error)
    return return_value


def _5_2_12_ind():
    return_value = list()
    success, error = check('sshd -T | grep permituserenvironment')
    if 'PermitUserEnvironment no' in success:
        return_value.append('SSH PermitUserEnvironment is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH PermitUserEnvironment is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep permituserenvironment returned the following\n' + success + error)
    return return_value


def _5_2_13_ind():
    return_value = list()
    success, error = check('sshd -T | grep ciphers')
    weak_cyphers = ['3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour',
                    'arcfour128', 'arcfour256', 'blowfish-cbc', 'cast128-cbc', 'rijndael-cbc@lysator.liu.se']
    if success and not any(s in weak_cyphers for s in success.splitlines()):
        return_value.append('SSH only strong Ciphers are used')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH strong Ciphers not used')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep ciphers returned the following\n' + success + error)
    return return_value


def _5_2_14_ind():
    return_value = list()
    success, error = check('sshd -T | grep -i "MACs"')
    weak_mac = ['hmac-md5', 'hmac-md5-96', 'hmac-ripemd160', 'hmac-sha1', 'hmac-sha1-96', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-md5-etm@openssh.com',
                'hmac-md5-96-etm@openssh.com', 'hmac-ripemd160-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'hmac-sha1-96-etm@openssh.com', 'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com']
    if success and not any(s in weak_mac for s in success.splitlines()):
        return_value.append('SSH only strong MAC algorithms are used')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH strong MAC algorithms not used')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep -i "MACs" returned the following\n' + success + error)
    return return_value


def _5_2_15_ind():
    return_value = list()
    success, error = check('sshd -T | grep kexalgorithms')
    weak_keys = ['diffie-hellman-group1-sha1',
                 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1']
    if success and not any(s in weak_keys for s in success.splitlines()):
        return_value.append('SSH only strong Key Exchange algorithms are used')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH strong Key Exchange algorithms not used')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep kexalgorithms returned the following\n' + success + error)
    return return_value


def _5_2_16_ind():
    return_value = list()
    success, error = check('sshd -T | grep clientaliveinterval')
    if success:
        result_success = success
        alive = success.split()[1]
        if 1 <= int(alive) <= 300:
            success, error = check('sshd -T | grep clientalivecountmax')
            if success:
                count = success.split()[1]
                if int(count) <= 3:
                    return_value.append('SSH Idle Timeout Interval configured')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('SSH ClientAliveCountMax more than 3')
                    return_value.append('FAIL')
                    return_value.append(result_success + '\n' + success)
            else:
                return_value.append('SSH ClientAliveCountMax not found')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('SSH ClientAliveInterval more than 300')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('SSH ClientAliveInterval not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep clientaliveinterval returned the following\n' + error)
    return return_value


def _5_2_17_ind():
    return_value = list()
    success, error = check('sshd -T | grep logingracetime')
    if success:
        grace = success.split()[1]
        if 1 <= int(grace) <= 60:
            return_value.append('SSH LoginGraceTime is ' + grace)
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SSH LoginGraceTime more than 60')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('SSH LoginGraceTime not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep logingracetime returned the following\n' + error)
    return return_value


def _5_2_18_ind():
    return_value = list()
    success, error = check('sshd -T | grep allowusers')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('sshd -T | grep allowgroups')
    result_success += success if success else ''
    result_error += error if error else ''
    success, error = check('sshd -T | grep denyusers')
    result_success += success if success else ''
    result_error += error if error else ''
    success, error = check('sshd -T | grep denygroups')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        return_value.append('SSH access is limited')
        return_value.append('PASS')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('SSH access is not limited')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _5_2_19_ind():
    return_value = list()
    success, error = check('sshd -T | grep banner')
    if 'Banner /etc/issue.net' in success:
        return_value.append('SSH warning banner is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH warning banner is not configured')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep banner returned the following\n' + success + error)
    return return_value


def _5_2_20_ind():
    return_value = list()
    success, error = check('sshd -T | grep -i usepam')
    if 'usepam yes' in success:
        return_value.append('SSH PAM is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH PAM is disabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep usepam returned the following\n' + success + error)
    return return_value


def _5_2_21_ind():
    return_value = list()
    success, error = check('sshd -T | grep -i allowtcpforwarding')
    if 'AllowTcpForwarding no' in success:
        return_value.append('SSH AllowTcpForwarding is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH AllowTcpForwarding is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep -i allowtcpforwarding returned the following\n' + success + error)
    return return_value


def _5_2_22_ind():
    return_value = list()
    success, error = check('sshd -T | grep -i maxstartups')
    if success:
        if 'maxstartups 10:30:60' in success:
            return_value.append('SSH MaxStartups is configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SSH MaxStartups is configured')
            return_value.append('CHEK')
            return_value.append(
                'verify that output of MaxStartups matches site policy\n' + success + error)
    else:
        return_value.append('SSH MaxStartups not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep -i maxstartups returned the following\n' + error)
    return return_value


def _5_2_23_ind():
    return_value = list()
    success, error = check('sshd -T | grep -i maxsessions')
    if success:
        sessions = success.split()[1]
        if int(sessions) <= 4:
            return_value.append('SSH MaxSessions is set to ' + sessions)
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SSH MaxSessions is set to ' + sessions)
            return_value.append('CHEK')
            return_value.append(
                'verify that output of MaxSessions matches site policy\n' + success + error)
    else:
        return_value.append('SSH MaxSessions not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep -i maxsessions returned the following\n' + error)
    return return_value


def _5_3_1_ind():
    return_value = list()
    success, error = check(
        'cat /etc/pam.d/common-password | grep -E "password required pam_cracklib.so"')
    result_success = success if success else ''
    result_error = error
    success, error = check(
        'cat /etc/pam.d/common-password | grep -E "password requisite pam_pwquality.so"')
    result_success += success if success else ''
    result_error += error
    success, error = check(
        'cat /etc/pam.d/system-auth | grep -E "password required pam_cracklib.so"')
    result_success += success if success else ''
    result_error += error
    success, error = check(
        'cat /etc/pam.d/system-auth | grep -E "password requisite pam_pwquality.so"')
    result_success += success if success else ''
    result_error += error
    success, error = check('cat /etc/security/pwquality.conf')
    result_success += success if success else ''
    result_error += error
    if len(result_success):
        return_value.append('password creation req configured')
        return_value.append('CHEK')
        return_value.append(
            'Verify password creation requirements conform to organization policy and minlen is 14 or more\n' + result_success + '\n' + result_error)
    else:
        return_value.append('password creation req not found')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _5_3_2_ind():
    return_value = list()
    success, error = check('cat /etc/pam.d/common-auth')
    result_success = success if success else ''
    result_error = error
    success, error = check('cat /etc/pam.d/system-auth')
    result_success += success if success else ''
    result_error += error
    success, error = check('cat /etc/pam.d/password-auth')
    result_success += success if success else ''
    result_error += error
    if len(result_success):
        return_value.append('failed password lockout configured')
        return_value.append('CHEK')
        return_value.append(
            'Verify password lockouts are configured and pam_faillock.so lines should surround a pam_unix.so\n' + result_success + '\n' + result_error)
    else:
        return_value.append('failed password lockout not configured')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _5_3_3_ind():
    return_value = list()
    success, error = check('cat /etc/pam.d/common-password | grep remember=')
    result_success = success if success else ''
    result_error = error
    success, error = check('cat /etc/pam.d/system-auth | grep remember=')
    result_success += success if success else ''
    result_error += error
    if len(result_success):
        return_value.append('password reuse is limited')
        return_value.append('CHEK')
        return_value.append(
            'Verify remembered password history is 5or more\n' + result_success + '\n' + result_error)
    else:
        return_value.append('password reuse not limited')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _5_3_4_ind():
    return_value = list()
    success, error = check('cat /etc/pam.d/common-password | grep sha512')
    result_success = success if success else ''
    result_error = error
    success, error = check('cat /etc/pam.d/system-auth | grep sha512')
    result_success += success if success else ''
    result_error += error
    success, error = check('cat /etc/pam.d/password-auth | grep sha512')
    result_success += success if success else ''
    result_error += error
    if len(result_success):
        return_value.append('password hashing algorithm is SHA-512')
        return_value.append('CHEK')
        return_value.append(
            'ensure the sha512 option is included in all results\n' + result_success + '\n' + result_error)
    else:
        return_value.append('password hashing algorithm not SHA-512')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _5_4_1_1_ind():
    return_value = list()
    success, error = check('grep PASS_MAX_DAYS /etc/login.defs')
    days = [d[1].split()[0] for d in [s.split() for s in success.splitlines(
    ) if not s.startswith('#')] if d[1].split()[0].lstrip('-').isdigit()]
    if days:
        if int(days[0]) <= 365 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                "grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,5")
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) <= 365 and int(d) != -1 for d in days):
                    return_value.append(
                        'password expiration less than 365 days')
                    return_value.append('PASS')
                    return_value.append('verify PASS_MAX_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MAX_DAYS\n' + success)
                else:
                    return_value.append('user password expiration gt 365 days')
                    return_value.append('FAIL')
                    return_value.append('verify PASS_MAX_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MAX_DAYS\n' + success)
            else:
                return_value.append('users password expiration not found')
                return_value.append('FAIL')
                return_value.append('verify PASS_MAX_DAYS conforms to site policy\n' +
                                    result_success + '\nUsers PASS_MAX_DAYS\n' + success)
        else:
            return_value.append('password expiration not 365 days or less')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('password expiration not found')
        return_value.append('FAIL')
        return_value.append(
            'grep PASS_MAX_DAYS /etc/login.defs returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_2_ind():
    return_value = list()
    success, error = check('grep PASS_MIN_DAYS /etc/login.defs')
    days = [d[1].split()[0] for d in [s.split() for s in success.splitlines(
    ) if not s.startswith('#')] if d[1].split()[0].lstrip('-').isdigit()]
    if days:
        if int(days[0]) >= 7 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                'grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4')
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) >= 7 and int(d) != -1 for d in days):
                    return_value.append('password changes gt 7 days')
                    return_value.append('PASS')
                    return_value.append('verify PASS_MIN_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MIN_DAYS\n' + success)
                else:
                    return_value.append('user password changes lt 7 days')
                    return_value.append('FAIL')
                    return_value.append('verify PASS_MIN_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MIN_DAYS\n' + success)
            else:
                return_value.append('users password changes days not found')
                return_value.append('FAIL')
                return_value.append('verify PASS_MIN_DAYS conforms to site policy\n' +
                                    result_success + '\nUsers PASS_MIN_DAYS\n' + success)
        else:
            return_value.append('password changes not 7 days or more')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('password changes days not found')
        return_value.append('FAIL')
        return_value.append(
            'grep PASS_MIN_DAYS /etc/login.defs returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_3_ind():
    return_value = list()
    success, error = check('grep PASS_WARN_AGE /etc/login.defs')
    days = [d[1].split()[0] for d in [s.split() for s in success.splitlines(
    ) if not s.startswith('#')] if d[1].split()[0].lstrip('-').isdigit()]
    if days:
        if int(days[0]) >= 7 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                'grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,6')
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) >= 7 and int(d) != -1 for d in days):
                    return_value.append('password change warning gt 7 days')
                    return_value.append('PASS')
                    return_value.append('verify PASS_WARN_AGE conforms to site policy\n' +
                                        result_success + '\nUsers PASS_WARN_AGE\n' + success)
                else:
                    return_value.append(
                        'user password change warning lt 7 days')
                    return_value.append('FAIL')
                    return_value.append('verify PASS_WARN_AGE conforms to site policy\n' +
                                        result_success + '\nUsers PASS_WARN_AGE\n' + success)
            else:
                return_value.append('users password warn not found')
                return_value.append('FAIL')
                return_value.append('verify PASS_WARN_AGE conforms to site policy\n' +
                                    result_success + '\nUsers PASS_WARN_AGE\n' + success)
        else:
            return_value.append('password expiration warning lt 7 days')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('password expiration warning not found')
        return_value.append('FAIL')
        return_value.append(
            'grep PASS_WARN_AGE /etc/login.defs returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_4_ind():
    return_value = list()
    success, error = check('useradd -D | grep INACTIVE')
    days = [d for d in [s.split('=')[1] for s in success.splitlines(
    ) if not s.startswith('#')] if d.lstrip('-').isdigit()]
    if days:
        if int(days[0]) <= 30 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                'grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7')
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) <= 30 and int(d) != -1 for d in days):
                    return_value.append(
                        'inactive password lock less than 30 days')
                    return_value.append('PASS')
                    return_value.append('verify INACTIVE conforms to site policy\n' +
                                        result_success + '\nUsers INACTIVE\n' + success)
                else:
                    return_value.append('user password lock more than 30 days')
                    return_value.append('FAIL')
                    return_value.append('verify INACTIVE conforms to site policy\n' +
                                        result_success + '\nUsers INACTIVE\n' + success)
            else:
                return_value.append('users password lock not found')
                return_value.append('FAIL')
                return_value.append('verify INACTIVE conforms to site policy\n' +
                                    result_success + '\nUsers INACTIVE\n' + success)
        else:
            return_value.append('inactive password lock more than 30 days')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('inactive password lock not found')
        return_value.append('FAIL')
        return_value.append(
            'useradd -D | grep INACTIVE returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_5_ind():
    return_value = list()
    success, error = check(
        "for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo \"$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)\"; done")
    if not success:
        return_value.append('last password change date in past')
        return_value.append('PASS')
        return_value.append(
            "for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo \"$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)\"; done\nreturned the following\n" + error)
    else:
        return_value.append('last password change date not in past')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


def _5_4_2_ind():
    return_value = list()
    success, error = check(
        'awk -F: \'($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<\'"$(awk \'/^\s*UID_MIN/{print $2}\' /etc/login.defs)"\' && $7!="\'"$(which nologin)"\'" && $7!="/bin/false") {print}\' /etc/passwd')
    if not success:
        result_error = error
        success, error = check(
            'awk -F: \'($1!="root" && $1!~/^\+/ && $3<\'"$(awk \'/^\s*UID_MIN/{print $2}\' /etc/login.defs)"\') {print $1}\' /etc/passwd | xargs -I \'{}\' sudo passwd -S \'{}\' | awk \'($2!="L" && $2!="LK") {print $1}\'')
        if not success:
            return_value.append('system accounts are secured')
            return_value.append('PASS')
            return_value.append(result_error + '\n' + error)
        else:
            return_value.append('irregular user provides shell')
            return_value.append('FAIL')
            return_value.append(result_error + '\n' + success)
    else:
        return_value.append('nologin shell not set in password file')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


def _5_4_3_ind():
    return_value = list()
    success, error = check('grep "^root:" /etc/passwd | cut -f4 -d:')
    if '0' in success:
        return_value.append('root account GID is 0')
        return_value.append('PASS')
        return_value.append(
            'grep "^root:" /etc/passwd | cut -f4 -d: returned\n' + success)
    else:
        return_value.append('root account GID not 0')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _5_4_4_ind():
    return_value = list()
    success, error = check('grep "umask" /etc/bashrc')
    if success:
        umask_permissions = ['22', '23', '27',
                             '32', '33', '37', '72', '73', '77']
        if any(u in success for u in umask_permissions):
            result_success = success
            success, error = check('grep "umask" /etc/profile')
            if success:
                if any(u in success for u in umask_permissions):
                    result_success += success
                    success, error = check('grep "umask" /etc/profile.d/*.sh')
                    if success:
                        if all(any(u in s for u in umask_permissions) for s in success.splitlines()):
                            return_value.append(
                                'default user umask is restrictive')
                            return_value.append('PASS')
                            return_value.append(
                                result_success + '\n' + success)
                        else:
                            return_value.append(
                                'profile.d/*.sh umask not less than 027')
                            return_value.append('FAIL')
                            return_value.append(success)
                    else:
                        return_value.append(
                            'umask not found in profile.d/*.sh')
                        return_value.append('FAIL')
                        return_value.append(result_success + '\n' + error)
                else:
                    return_value.append(
                        'profile umask not restrictive than 027')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('umask not found in profile')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('bashrc umask not 027 or more restrictive')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('umask not found in bashrc')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _5_4_5_ind():
    return_value = list()
    success, error = check('grep "^TMOUT" /etc/bashrc')
    if success:
        if all(s.strip('=')[1].lstrip('-').isdigit() and int(s.strip('=')[1]) != -1 and int(s.strip('=')[1]) <= 900 for s in success.splitlines()):
            result_success = success
            success, error = check('grep "^TMOUT" /etc/profile')
            if success:
                if all(s.strip('=')[1].lstrip('-').isdigit() and int(s.strip('=')[1]) != -1 and int(s.strip('=')[1]) <= 900 for s in success.splitlines()):
                    return_value.append('user shell timeout is lt 900 sec')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('profile shell timeout not lt 900 sec')
                    return_value.append('FAIL')
                    return_value.append(result_success + '\n' + success)
            else:
                return_value.append('shell timeout not in profile')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('bashrc shell timeout not lt 900 sec')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('shell timeout not in bashrc')
        return_value.append('FAIL')
        return_value.append(
            'grep "^TMOUT" /etc/bashrc returned the following\n' + error)
    return return_value


def _5_5_ind():
    return_value = list()
    success, error = check('cat /etc/securetty')
    if success:
        return_value.append('root login is restricted to system')
        return_value.append('PASS')
        return_value.append(
            'check if following are valid terminals that may be logged in directly as root\n' + success)
    else:
        return_value.append('root login not restricted to system')
        return_value.append('FAIL')
        return_value.append(
            'cat /etc/securetty returned the following\n' + error)
    return return_value


def _5_6_ind():
    return_value = list()
    success, error = check('grep pam_wheel.so /etc/pam.d/su')
    if success:
        if any('auth       required   pam_wheel.so use_uid' in s and not s.startswith('#') for s in success.splitlines()):
            result_success = success
            success, error = check('grep wheel /etc/group')
            if success:
                if all(s.startswith('wheel:x:10:root,') for s in success.splitlines()):
                    return_value.append('access to su command is restricted')
                    return_value.append('PASS')
                    return_value.append(
                        result_success + '\nverify users in wheel group match site policy\n' + success)
                else:
                    return_value.append('access to su command not restricted')
                    return_value.append('FAIL')
                    return_value.append(result_success + '\n' + success)
            else:
                return_value.append('access to su command not restricted')
                return_value.append('FAIL')
                return_value.append(
                    result_success + '\ngrep wheel /etc/group returned the following\n' + error)
        else:
            return_value.append('access to su command not restricted')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('access to su command not restricted')
        return_value.append('FAIL')
        return_value.append(
            'grep pam_wheel.so /etc/pam.d/su returned the following\n' + error)
    return return_value


# distro specific
def _6_1_1_ind():
    return_value = list()
    return_value.append('system file perms not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    global log_file
    write_log = log_file.split(
        '_SeBAz_logs/')[0] + '.system_file_permissions.SeBAz.log'
    success, error = check('dpkg --verify > ' + write_log)
    return_value.append('Audit system file permissions')
    return_value.append('CHEK')
    return_value.append('Verify the contents of ' +
                        write_log.split('/')[-1] + '\n' + success + '\n' + error)
    return return_value


def _6_1_2_ind():
    return_value = list()
    success, error = check('stat /etc/passwd | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/passwd permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/passwd permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/passwd invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/passwd not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/passwd | grep Access did not return anything\n' + error)
    return return_value


def _6_1_3_ind():
    return_value = list()
    success, error = check('stat /etc/shadow | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith(('0/    root)', 'shadow)')):
                allowed_access = ['(0640/-rw-r-----)', '(0600/-rw-------)',
                                  '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/shadow permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/shadow permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/shadow invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/shadow invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/shadow not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/shadow | grep Access did not return anything\n' + error)
    return return_value


def _6_1_4_ind():
    return_value = list()
    success, error = check('stat /etc/group | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/group permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/group permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/group invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/group not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/group | grep Access did not return anything\n' + error)
    return return_value


def _6_1_5_ind():
    return_value = list()
    success, error = check('stat /etc/gshadow | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith(('0/    root)', 'shadow)')):
                allowed_access = [
                    '(0640/-rw-r-----)', '(0600/-rw-------)', '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/gshadow permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/gshadow permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/gshadow invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/gshadow invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/gshadow not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/gshadow | grep Access did not return anything\n' + error)
    return return_value


def _6_1_6_ind():
    return_value = list()
    success, error = check('stat /etc/passwd- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            allowed_access = ['(0600/-rw-------)', '(0400/-r--------)']
            if any(a in success for a in allowed_access):
                return_value.append('/etc/passwd- permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/passwd- permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/passwd- invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/passwd- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/passwd- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_7_ind():
    return_value = list()
    success, error = check('stat /etc/shadow- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith(('0/    root)', 'shadow)')):
                allowed_access = [
                    '(0640/-rw-r-----)', '(0600/-rw-------)', '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/shadow- permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/shadow- permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/shadow- invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/shadow- invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/shadow- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/shadow- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_8_ind():
    return_value = list()
    success, error = check('stat /etc/group- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            allowed_access = ['(0644/-rw-r--r--)', '(0640/-rw-r-----)', '(0600/-rw-------)',
                              '(0444/-r--r--r--)', '(0440/-r--r-----)', '(0400/-r--------)']
            if any(a in success for a in allowed_access):
                return_value.append('/etc/group- permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/group- permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/group- invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/group- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/group- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_9_ind():
    return_value = list()
    success, error = check('stat /etc/gshadow- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith(('0/    root)', 'shadow)')):
                allowed_access = [
                    '(0640/-rw-r-----)', '(0600/-rw-------)', '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/gshadow- permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/gshadow- permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/gshadow- invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/gshadow- invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/gshadow- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/gshadow- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_10_ind():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check(
                    'find ' + p + ' -xdev -type f -perm -0002')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('world writable files does not exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 confirms that all world writable directories have the sticky variable set\n" + result_error)
            else:
                return_value.append('world writable files exist in partitions')
                return_value.append('FAIL')
                return_value.append(
                    'The following world writable files exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('world writable files does not exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 confirms that all world writable directories have the sticky variable set\n" + result_error + '\n' + error)
    else:
        return_value.append('world writable files exist')
        return_value.append('FAIL')
        return_value.append(
            'The following world writable files exist\n' + success)
    return return_value


def _6_1_11_ind():
    return_value = list()
    success, error = check(
        "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check('find ' + p + ' -xdev -nouser')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('no unowned files or directories exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser confirms that no unowned files or directories exist\n" + result_error)
            else:
                return_value.append('unowned files or directories exist')
                return_value.append('FAIL')
                return_value.append(
                    'The following unowned files or directories exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('no unowned files or directories exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser confirms that no unowned files or directories exist\n" + result_error + '\n' + error)
    else:
        return_value.append('unowned files or directories exist')
        return_value.append('FAIL')
        return_value.append(
            'The following unowned files or directories exist\n' + success)
    return return_value


def _6_1_12_ind():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check('find ' + p + ' -xdev -nogroup')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('no ungrouped files or directories exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup confirms that no ungrouped files or directories exist\n" + result_error)
            else:
                return_value.append('ungrouped files or directories exist')
                return_value.append('FAIL')
                return_value.append(
                    'The following ungrouped files or directories exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('no ungrouped files or directories exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup confirms that no ungrouped files or directories exist\n" + result_error + '\n' + error)
    else:
        return_value.append('ungrouped files or directories exist')
        return_value.append('FAIL')
        return_value.append(
            'The following ungrouped files or directories exist\n' + success)
    return return_value


def _6_1_13_ind():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check(
                    'find ' + p + ' -xdev -type f -perm -4000')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('SUID executables does not exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 confirms that SUID executables does not exist\n" + result_error)
            else:
                return_value.append('SUID executables found')
                return_value.append('FAIL')
                return_value.append(
                    'The following SUID executables exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('SUID executables does not exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 confirms that SUID executables does not exist\n" + result_error + '\n' + error)
    else:
        return_value.append('SUID executables found')
        return_value.append('FAIL')
        return_value.append(
            'The following SUID executables exist\n' + success)
    return return_value


def _6_1_14_ind():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check(
                    'find ' + p + ' -xdev -type f -perm -2000')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('SGID executables does not exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 confirms that SGID executables does not exist\n" + result_error)
            else:
                return_value.append('SGID executables found')
                return_value.append('FAIL')
                return_value.append(
                    'The following SGID executables exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('SGID executables does not exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 confirms that SGID executables does not exist\n" + result_error + '\n' + error)
    else:
        return_value.append('SGID executables found')
        return_value.append('FAIL')
        return_value.append(
            'The following SGID executables exist\n' + success)
    return return_value


def _6_2_1_ind():
    return_value = list()
    success, error = check(
        "awk -F: '($2 == \"\" ) { print $1 \" does not have a password \"}' /etc/shadow")
    if not success:
        return_value.append('password fields are not empty')
        return_value.append('PASS')
        return_value.append(
            "awk -F: '($2 == \"\" ) { print $1 \" does not have a password \"}' /etc/shadow returned the following\n" + error)
    else:
        return_value.append('password fields are empty')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have empty password fields\n' + success)
    return return_value


def _6_2_2_ind():
    return_value = list()
    success, error = check("grep '^\+:' /etc/passwd")
    if not success:
        return_value.append('no legacy "+" entries exist in /etc/passwd')
        return_value.append('PASS')
        return_value.append(
            "grep '^\+:' /etc/passwd returned the following\n" + error)
    else:
        return_value.append('legacy "+" entries exist in /etc/passwd')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have legacy "+" entries in /etc/passwd\n' + success)
    return return_value


def _6_2_3_ind():
    return_value = list()
    success, error = check("grep '^\+:' /etc/shadow")
    if not success:
        return_value.append('no legacy "+" entries exist in /etc/shadow')
        return_value.append('PASS')
        return_value.append(
            "grep '^\+:' /etc/shadow returned the following\n" + error)
    else:
        return_value.append('legacy "+" entries exist in /etc/shadow')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have legacy "+" entries in /etc/shadow\n' + success)
    return return_value


def _6_2_4_ind():
    return_value = list()
    success, error = check("grep '^\+:' /etc/group")
    if not success:
        return_value.append('no legacy "+" entries exist in /etc/group')
        return_value.append('PASS')
        return_value.append(
            "grep '^\+:' /etc/group returned the following\n" + error)
    else:
        return_value.append('legacy "+" entries exist in /etc/group')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have legacy "+" entries in /etc/group\n' + success)
    return return_value


def _6_2_5_ind():
    return_value = list()
    success, error = check("awk -F: '($3 == 0) { print $1 }' /etc/passwd")
    if success:
        if 'root\n' == success:
            return_value.append('root is the only UID 0 account')
            return_value.append('PASS')
            return_value.append(
                "awk -F: '($3 == 0) { print $1 }' /etc/passwd returned the following\n" + success)
        else:
            return_value.append('root is not the only UID 0 account')
            return_value.append('FAIL')
            return_value.append(
                "awk -F: '($3 == 0) { print $1 }' /etc/passwd returned the following UID 0 accounts\n" + success)
    else:
        return_value.append('no UID 0 account found')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _6_2_6_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_6.sh')
    check('sudo cat ' + script + ' > ./root_path_integrity.sh')
    check('chmod +x ./root_path_integrity.sh')
    success, error = check('./root_path_integrity.sh')
    if not success:
        return_value.append('root PATH Integrity maintained')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_6.sh returned the following\n' + error)
    else:
        return_value.append('writable dir in root\'s executable path')
        return_value.append('FAIL')
        return_value.append(
            'The following writable directories were found in root\'s executable path\n' + success)
    check('rm ./root_path_integrity.sh')
    return return_value


def _6_2_7_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_7.sh')
    check('sudo cat ' + script + ' > ./home_directories.sh')
    check('chmod +x ./home_directories.sh')
    success, error = check('./home_directories.sh')
    if not success:
        return_value.append('all users\' home directories exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_7.sh returned the following\n' + error)
    else:
        return_value.append('users without home directory')
        return_value.append('FAIL')
        return_value.append(
            'The following users are without home directory\n' + success)
    check('rm ./home_directories.sh')
    return return_value


def _6_2_8_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_8.sh')
    check('sudo cat ' + script + ' > ./home_directory_permissions.sh')
    check('chmod +x ./home_directory_permissions.sh')
    success, error = check('./home_directory_permissions.sh')
    if not success:
        return_value.append('home directories permissions are gt 750')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_8.sh returned the following\n' + error)
    else:
        return_value.append('Group or world-writable home directories')
        return_value.append('FAIL')
        return_value.append(
            'The following users have Group or world-writable home directories\n' + success)
    check('rm ./home_directory_permissions.sh')
    return return_value


def _6_2_9_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_9.sh')
    check('sudo cat ' + script + ' > ./own_home_directory.sh')
    check('chmod +x ./own_home_directory.sh')
    success, error = check('./own_home_directory.sh')
    if not success:
        return_value.append('users own their home directories')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_9.sh returned the following\n' + error)
    else:
        return_value.append('user not owner of home directory')
        return_value.append('FAIL')
        return_value.append(
            'The following users are not the not owner of their home directories\n' + success)
    check('rm ./own_home_directory.sh')
    return return_value


def _6_2_10_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_10.sh')
    check('sudo cat ' + script + ' > ./user_dot_file.sh')
    check('chmod +x ./user_dot_file.sh')
    success, error = check('./user_dot_file.sh')
    if not success:
        return_value.append('users\' . files not group or world-writable')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_10.sh returned the following\n' + error)
    else:
        return_value.append('users\' . files group or world-writable')
        return_value.append('FAIL')
        return_value.append(
            'The following  users\' dot files are group or world writable\n' + success)
    check('rm ./user_dot_file.sh')
    return return_value


def _6_2_11_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_11.sh')
    check('sudo cat ' + script + ' > ./user_forward_file.sh')
    check('chmod +x ./user_forward_file.sh')
    success, error = check('./user_forward_file.sh')
    if not success:
        return_value.append('no users have .forward files')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_11.sh returned the following\n' + error)
    else:
        return_value.append('users have .forward files')
        return_value.append('FAIL')
        return_value.append(
            'The following users have .forward files\n' + success)
    check('rm ./user_forward_file.sh')
    return return_value


def _6_2_12_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_12.sh')
    check('sudo cat ' + script + ' > ./user_netrc_file.sh')
    check('chmod +x ./user_netrc_file.sh')
    success, error = check('./user_netrc_file.sh')
    if not success:
        return_value.append('no users have .netrc files')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_12.sh returned the following\n' + error)
    else:
        return_value.append('users have .netrc files')
        return_value.append('FAIL')
        return_value.append(
            'The following users have .netrc files\n' + success)
    check('rm ./user_netrc_file.sh')
    return return_value


def _6_2_13_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_13.sh')
    check('sudo cat ' + script + ' > ./user_netrc_writable.sh')
    check('chmod +x ./user_netrc_writable.sh')
    success, error = check('./user_netrc_writable.sh')
    if not success:
        return_value.append('users\' .netrc not group or world accessible')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_13.sh returned the following\n' + error)
    else:
        return_value.append('users\' .netrc group or world accessible')
        return_value.append('FAIL')
        return_value.append(
            'The following users\' .netrc Files are not group or world accessible\n' + success)
    check('rm ./user_netrc_writable.sh')
    return return_value


def _6_2_14_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_14.sh')
    check('sudo cat ' + script + ' > ./user_rhosts_file.sh')
    check('chmod +x ./user_rhosts_file.sh')
    success, error = check('./user_rhosts_file.sh')
    if not success:
        return_value.append('no users have .rhosts files')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_14.sh returned the following\n' + error)
    else:
        return_value.append('users have .rhosts files')
        return_value.append('FAIL')
        return_value.append(
            'The following users have .rhosts files\n' + success)
    check('rm ./user_rhosts_file.sh')
    return return_value


def _6_2_15_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_15.sh')
    check('sudo cat ' + script + ' > ./group_passwd.sh')
    check('chmod +x ./group_passwd.sh')
    success, error = check('./group_passwd.sh')
    if not success:
        return_value.append('all groups in passwd exist in group')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_15.sh returned the following\n' + error)
    else:
        return_value.append('groups in passwd don\'t exist in group')
        return_value.append('FAIL')
        return_value.append(
            'The following groups in /etc/passwd don\'t exist in /etc/group\n' + success)
    check('rm ./group_passwd.sh')
    return return_value


def _6_2_16_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_16.sh')
    check('sudo cat ' + script + ' > ./duplicate_uid.sh')
    check('chmod +x ./duplicate_uid.sh')
    success, error = check('./duplicate_uid.sh')
    if not success:
        return_value.append('no duplicate UIDs exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_16.sh returned the following\n' + error)
    else:
        return_value.append('duplicate UIDs exist')
        return_value.append('FAIL')
        return_value.append('The following duplicate UIDs exist\n' + success)
    check('rm ./duplicate_uid.sh')
    return return_value


def _6_2_17_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_17.sh')
    check('sudo cat ' + script + ' > ./duplicate_gid.sh')
    check('chmod +x ./duplicate_gid.sh')
    success, error = check('./duplicate_gid.sh')
    if not success:
        return_value.append('no duplicate GIDs exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_17.sh returned the following\n' + error)
    else:
        return_value.append('duplicate GIDs exist')
        return_value.append('FAIL')
        return_value.append('The following duplicate GIDs exist\n' + success)
    check('rm ./duplicate_gid.sh')
    return return_value


def _6_2_18_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_18.sh')
    check('sudo cat ' + script + ' > ./duplicate_user_name.sh')
    check('chmod +x ./duplicate_user_name.sh')
    success, error = check('./duplicate_user_name.sh')
    if not success:
        return_value.append('no duplicate user names exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_18.sh returned the following\n' + error)
    else:
        return_value.append('duplicate user names exist')
        return_value.append('FAIL')
        return_value.append(
            'The following duplicate user names exist\n' + success)
    check('rm ./duplicate_user_name.sh')
    return return_value


def _6_2_19_ind():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ind/6_2_19.sh')
    check('sudo cat ' + script + ' > ./duplicate_group_name.sh')
    check('chmod +x ./duplicate_group_name.sh')
    success, error = check('./duplicate_group_name.sh')
    if not success:
        return_value.append('no duplicate group names exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ind/6_2_19.sh returned the following\n' + error)
    else:
        return_value.append('duplicate group names exist')
        return_value.append('FAIL')
        return_value.append(
            'The following duplicate group names exist\n' + success)
    check('rm ./duplicate_group_name.sh')
    return return_value


def _6_2_20_ind():
    return_value = list()
    success, error = check('grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group')
    if not success:
        return_value.append('users not assigned to shadow group')
        return_value.append('PASS')
        return_value.append(
            'grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group returned the following\n' + error)
    else:
        result_success = ''
        result_error = ''
        for shadow_gid in success.splitlines():
            result = check("awk -F: '($4 == \"" + shadow_gid +
                           "\") { print }' /etc/passwd")
            result_success += result[0]
            result_error += result[1]
        if len(result_success):
            return_value.append('users not assigned to shadow group')
            return_value.append('PASS')
            return_value.append(
                'Following GIDs don\'t have entries in passwd\n' + success + '\n' + result_error)
        else:
            return_value.append(
                'users assigned to shadow group in /etc/passwd')
            return_value.append('FAIL')
            return_value.append('The following users are assigned to the shadow group in /etc/passwd\n' +
                                success + '\n' + result_success + '\n' + result_error + '\n' + error)
    return return_value


"""
Definitions of Functions that perform CentOS checks against benchmarks
return_value[0] = result
return_value[1] = PASS/FAIL/CHEK
return_value[2] = success/error message
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_cen():
    return_value = list()
    success, error = check('modprobe -n -v cramfs')
    if 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep cramfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('cramfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('cramfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('cramfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_2_cen():
    return_value = list()
    success, error = check("grep -E -i '\svfat\s' /etc/fstab")
    if success:
        return_value.append('vfat is mounted')
        return_value.append('CHEK')
        return_value.append(success)
    else:
        success, error = check('modprobe -n -v vfat')
        if 'insmod' in success:
            return_value.append('vfat can be mounted')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            result_success = success
            result_error = error
            success, error = check('lsmod | grep vfat')
            if 'install /bin/true' in result_success or 'not found in directory' in result_error:
                if not success:
                    return_value.append('vfat cannot be mounted')
                    return_value.append('PASS')
                    return_value.append(
                        result_success if result_success else result_error)
                else:
                    return_value.append('vfat is mounted')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success if result_success else result_error + '\n' + success)
            else:
                return_value.append('vfat mount status undetermined')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_3_cen():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'insmod' in success:
        return_value.append('squashfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep squashfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('squashfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('squashfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('squashfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_4_cen():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep udf')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('udf cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('udf is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('udf mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_2_cen():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_value.append('/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('/tmp is not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_3_cen():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything\n" + success)
        else:
            return_value.append('nodev is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' returned the following\n" + return_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nodev is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_4_cen():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything\n" + success)
        else:
            return_value.append('nosuid is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid returned\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nosuid is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_5_cen():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything\n" + success)
        else:
            return_value.append('noexec is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec returned the following\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('noexec is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_6_cen():
    return_value = list()
    success, error = check("mount | grep -E '\s/var\s'")
    if success:
        return_value.append('/var is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep -E '\s/var\s' did not return any result")
    return return_value


def _1_1_7_cen():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        return_value.append('/var/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/tmp is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/tmp did not return any result")
    return return_value


def _1_1_8_cen():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_cen():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_cen():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_11_cen():
    return_value = list()
    success, error = check('mount | grep /var/log')
    if success:
        return_value.append('/var/log is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/log did not return any result")
    return return_value


def _1_1_12_cen():
    return_value = list()
    success, error = check('mount | grep /var/log/audit')
    if success:
        return_value.append('/var/log/audit is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log/audit is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep /var/log/audit did not return any result")
    return return_value


def _1_1_13_cen():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        return_value.append('/home is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/home is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /home did not return any result")
    return return_value


def _1_1_14_cen():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        success, error = check("mount | grep -E '\s/home\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /home')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /home')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append(
            "/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_cen():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_cen():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_cen():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_18_cen():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nodev = [drive for drive in success.splitlines()
                 if 'nodev' not in drive]
        if not nodev:
            return_value.append('nodev is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nodev is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nodev" set\n'
            for n in nodev:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_19_cen():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nosuid = [drive for drive in success.splitlines()
                  if 'nosuid' not in drive]
        if not nosuid:
            return_value.append('nosuid is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nosuid is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nosuid" set\n'
            for n in nosuid:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_20_cen():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        noexec = [drive for drive in success.splitlines()
                  if 'noexec' not in drive]
        if not noexec:
            return_value.append('noexec is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('noexec is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "noexec" set\n'
            for n in noexec:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_21_cen():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append(
            "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append(
            'The following directories does not have their sticky bit set\n' + success)
    return return_value


def _1_1_22_cen():
    return_value = list()
    success, error = check('systemctl is-enabled autofs | grep enabled')
    if error:
        return_value.append('automounting could not be checked')
        return_value.append('CHEK')
        return_value.append(error)
    else:
        if 'enabled' in success:
            return_value.append('automounting is enabled')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            return_value.append('automounting is disabled')
            return_value.append('PASS')
            return_value.append(success)
    return return_value


def _1_1_23_cen():
    return_value = list()
    success, error = check('modprobe -n -v usb-storage')
    if 'insmod' in success:
        return_value.append('usb-storage can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep usb-storage')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('usb-storage cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('usb-storage is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('usb-storage mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


"""
Definitions of Functions that perform Debian checks against benchmarks
return_value[0] = result
return_value[1] = PASS/FAIL/CHEK
return_value[2] = success/error message
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_deb():
    return_value = list()
    success, error = check('modprobe -n -v freevxfs')
    if 'insmod' in success:
        return_value.append('freevxfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep freevxfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('freevxfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('freevxfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('freevxfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_2_deb():
    return_value = list()
    success, error = check('modprobe -n -v jffs2')
    if 'insmod' in success:
        return_value.append('jffs2 can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep jffs2')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('jffs2 cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('jffs2 is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('jffs2 mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_3_deb():
    return_value = list()
    success, error = check('modprobe -n -v hfs')
    if 'insmod' in success:
        return_value.append('hfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep hfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('hfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('hfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('hfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_4_deb():
    return_value = list()
    success, error = check('modprobe -n -v hfsplus')
    if 'insmod' in success:
        return_value.append('hfsplus can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep hfsplus')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('hfsplus cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('hfsplus is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('hfsplus mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_5_deb():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep udf')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('udf cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('udf is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('udf mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_2_deb():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_value.append('/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('/tmp is not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_3_deb():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything\n" + success)
        else:
            return_value.append('nodev is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' returned the following\n" + return_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nodev is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_4_deb():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything\n" + success)
        else:
            return_value.append('nosuid is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid returned\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nosuid is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_5_deb():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything\n" + success)
        else:
            return_value.append('noexec is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec returned the following\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('noexec is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_6_deb():
    return_value = list()
    success, error = check("mount | grep -E '\s/var\s'")
    if success:
        return_value.append('/var is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep -E '\s/var\s' did not return any result")
    return return_value


def _1_1_7_deb():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        return_value.append('/var/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/tmp is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/tmp did not return any result")
    return return_value


def _1_1_8_deb():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_deb():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_deb():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_11_deb():
    return_value = list()
    success, error = check('mount | grep /var/log')
    if success:
        return_value.append('/var/log is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/log did not return any result")
    return return_value


def _1_1_12_deb():
    return_value = list()
    success, error = check('mount | grep /var/log/audit')
    if success:
        return_value.append('/var/log/audit is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log/audit is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep /var/log/audit did not return any result")
    return return_value


def _1_1_13_deb():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        return_value.append('/home is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/home is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /home did not return any result")
    return return_value


def _1_1_14_deb():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        success, error = check("mount | grep -E '\s/home\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /home')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /home')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append(
            "/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_deb():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_deb():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_deb():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_18_deb():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nodev = [drive for drive in success.splitlines()
                 if 'nodev' not in drive]
        if not nodev:
            return_value.append('nodev is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nodev is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nodev" set\n'
            for n in nodev:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_19_deb():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nosuid = [drive for drive in success.splitlines()
                  if 'nosuid' not in drive]
        if not nosuid:
            return_value.append('nosuid is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nosuid is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nosuid" set\n'
            for n in nosuid:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_20_deb():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        noexec = [drive for drive in success.splitlines()
                  if 'noexec' not in drive]
        if not noexec:
            return_value.append('noexec is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('noexec is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "noexec" set\n'
            for n in noexec:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_21_deb():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append(
            "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append(
            'The following directories does not have their sticky bit set\n' + success)
    return return_value


def _1_1_22_deb():
    return_value = list()
    success, error = check('systemctl is-enabled autofs | grep enabled')
    if error:
        return_value.append('automounting could not be checked')
        return_value.append('CHEK')
        return_value.append(error)
    else:
        if 'enabled' in success:
            return_value.append('automounting is enabled')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            return_value.append('automounting is disabled')
            return_value.append('PASS')
            return_value.append(success)
    return return_value


def _1_2_1_deb():
    return_value = list()
    success, error = check('apt-cache policy')
    if success:
        return_value.append('check configuration of repos')
        return_value.append('CHEK')
        return_value.append(
            'The following are the configuration of the package manager repositories\n' + success)
    else:
        return_value.append('package configuration not checked')
        return_value.append('CHEK')
        return_value.append(
            'apt-cache policy did not return anything\n' + error)
    return return_value


def _1_2_2_deb():
    return_value = list()
    success, error = check('apt-key list')
    if success:
        return_value.append('check GPG keys source')
        return_value.append('CHEK')
        return_value.append(
            'The following are the configuration of the GPG keys\n' + success)
    else:
        return_value.append('GPG keys not checked')
        return_value.append('CHEK')
        return_value.append(
            'apt-key list did not return any keys\n' + error)
    return return_value


def _1_3_1_deb():
    return_value = list()
    success, error = check('dpkg -s aide')
    if success:
        return_value.append('AIDE is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('AIDE is not installed')
        return_value.append('FAIL')
        return_value.append('dpkg -s aide returned\n' + error)
    return return_value


def _1_3_2_deb():
    return_value = list()
    success, error = check('crontab -u root -l | grep aide')
    if success:
        result = success
        success, error = check('grep -r aide /etc/cron.* /etc/crontab')
        if success:
            result += '\nThe following cron jobs are scheduled\n' + success
            return_value.append('file integrity is checked')
            return_value.append('PASS')
            return_value.append(result)
        else:
            result += '\nNo cron jobs are scheduled for AIDE\n' + error
            return_value.append('file integrity is not checked')
            return_value.append('FAIL')
            return_value.append(result)
    else:
        return_value.append('No AIDE cron jobs scheduled')
        return_value.append('FAIL')
        return_value.append(
            'grep -r aide /etc/cron.* /etc/crontab returned the following\n' + success + '\n' + error)
    return return_value


# bootloader specific
def _1_4_1_deb():
    return_value = list()
    success, error = check('stat /boot/grub*/grub.cfg | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0400/-r--------)' in success:
                return_value.append('bootloader permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('bootloader permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('bootloader invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('grub config not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /boot/grub*/grub.cfg | grep Access returned\n' + success + '\n' + error)
    return return_value


# bootloader specific
def _1_4_2_deb():
    return_value = list()
    success, error = check('grep "^set superusers" /boot/grub/grub.cfg')
    if success:
        result_success = success
        success, error = check('grep "^password" /boot/grub/grub.cfg')
        if success:
            if all(s.startswith('password_pbkdf2') for s in success.splitlines()):
                return_value.append('bootloader password is set')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + success)
            else:
                return_value.append('bootloader pwd not password_pbkdf2')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + success)
        else:
            return_value.append('bootloader user pwd not found')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('bootloader superusers not found')
        return_value.append('FAIL')
        return_value.append(
            'grep "^set superusers" /boot/grub/grub.cfg returned\n' + error)
    return return_value


def _1_4_3_deb():
    return_value = list()
    success, error = check('grep ^root:[*\!]: /etc/shadow')
    if success:
        return_value.append('auth required for single user mode')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('auth not required for single user mode')
        return_value.append('FAIL')
        return_value.append(
            'grep ^root:[*\!]: /etc/shadow returned the following\n' + error)
    return return_value


def _1_5_1_deb():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check(
        'grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check('sysctl fs.suid_dumpable')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check(
        'grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    if len(result_success.splitlines()) == 6:
        return_value.append('core dumps are restricted')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('core dumps not restricted')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success +
                            '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


def _1_5_2_deb():
    return_value = list()
    success, error = check('dmesg | grep NX')
    if 'NX (Execute Disable) protection: active' in success:
        return_value.append('XD/NX support is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('XD/NX support is disabled')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _1_5_3_deb():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('sysctl kernel.randomize_va_space')
    if '2' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    success, error = check(
        'grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*')
    if '2' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    if len(result_success.splitlines()) == 4:
        return_value.append('ASLR enabled')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('ASLR not enabled')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success +
                            '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


def _1_5_4_deb():
    return_value = list()
    success, error = check('dpkg -s prelink')
    if not success:
        return_value.append('prelink is not installed')
        return_value.append('PASS')
        return_value.append(error)
    else:
        return_value.append('prelink is installed')
        return_value.append('FAIL')
        return_value.append('dpkg -s prelink returned\n' + success)
    return return_value


# bootloader specific
def _1_6_1_1_deb():
    return_value = list()
    success, error = check('grep "^\s*linux" /boot/grub/grub.cfg')
    if success:
        if 'selinux=1' in success and 'security=selinux' in success:
            return_value.append('SELinux enabled in boot-config')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SELinux disabled in boot-config')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('SELinux not checked')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _1_6_1_2_deb():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('grep SELINUX=enforcing /etc/selinux/config')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check('sestatus')
    if 'SELinux status: enabled' in success and 'Current mode: enforcing' in success and 'Mode from config file: enforcing' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    if len(result_success.splitlines()) == 4:
        return_value.append('SELinux state is enforcing')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('SELinux state is not enforcing')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success +
                            '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


def _1_6_1_3_deb():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('grep SELINUXTYPE= /etc/selinux/config')
    if 'SELINUXTYPE=default' in success or 'SELINUXTYPE=mls' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    success, error = check('sestatus')
    if 'Policy from config file: default' in success or 'Policy from config file: mls' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    if len(result_success.splitlines()) == 4:
        return_value.append('SELinux policy is configured')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('SELinux policy is not configured')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success +
                            '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


# distro specific
def _1_6_1_4_deb():
    return_value = list()
    success, error = check(
        "ps -eZ | egrep \"initrc\" | egrep -vw \"tr|ps|egrep|bash|awk\" | tr ':' ' ' | awk '{ print $NF }'")
    if not success:
        return_value.append('no unconfined daemons exist')
        return_value.append('PASS')
        return_value.append(
            "ps -eZ | egrep \"initrc\" | egrep -vw \"tr|ps|egrep|bash|awk\" | tr ':' ' ' | awk '{ print $NF }' returned nothing")
    else:
        return_value.append('unconfined daemons exist')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


# bootloader specific
def _1_6_2_1_deb():
    return_value = list()
    success, error = check('grep "^\s*linux" /boot/grub/grub.cfg')
    if success:
        if 'apparmor=1' in success and 'security=apparmor' in success:
            return_value.append('AppArmor enabled in boot-config')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('AppArmor disabled in boot-config')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('AppArmor not checked')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _1_6_2_2_deb():
    return_value = list()
    success, error = check('apparmor_status')
    if success:
        loaded_profiles = [
            p for p in success.splitlines() if 'profiles are loaded.' in p]
        complain_profiles = [p for p in success.splitlines(
        ) if 'profiles are in complain mode.' in p]
        unconfined_process = [
            p for p in success.splitlines() if 'processes are unconfined' in p]
        if loaded_profiles and not loaded_profiles[0].startswith('0'):
            if complain_profiles and complain_profiles[0].startswith('0'):
                if unconfined_process and unconfined_process[0].startswith('0'):
                    return_value.append('all AppArmor Profiles are enforcing')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append('AppArmor processes are confined')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('AppArmor profiles are in complain mode')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('No AppArmor profiles are loaded')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('AppArmor status not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_6_3_deb():
    return_value = list()
    success, error = check('dpkg -s selinux')
    if success:
        return_value.append('SELinux is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        result_error = error + '\n'
        success, error = check('dpkg -s apparmor')
        if success:
            return_value.append('AppArmor is installed')
            return_value.append('PASS')
            return_value.append(success)
        else:
            result_error += error
            return_value.append('SELinux and AppArmor is not installed')
            return_value.append('FAIL')
            return_value.append(result_error)
    return return_value


def _1_7_1_1_deb():
    return_value = list()
    success, error = check('cat /etc/motd')
    if success:
        result_success = success
        success, error = check(
            "egrep -i '(\\v|\\r|\\m|\\s|Debian)' /etc/motd")
        if not success:
            return_value.append('motd is configured properly')
            return_value.append('PASS')
            return_value.append(
                'check if the message of the day matches site policy\n' + result_success)
        else:
            return_value.append('motd contains sensitive information')
            return_value.append('FAIL')
            return_value.append(
                'Following OS [or] patch level information were found in the message of the day\n' + result_success)
    else:
        return_value.append('no message of the day')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _1_7_1_2_deb():
    return_value = list()
    success, error = check('cat /etc/issue')
    if success:
        result_success = success
        success, error = check(
            "egrep -i '(\\v|\\r|\\m|\\s|Debian)' /etc/issue")
        if not success:
            return_value.append('login banner configured properly')
            return_value.append('PASS')
            return_value.append(
                'check if the local login warning banner matches site policy\n' + result_success)
        else:
            return_value.append('login banner contains sensitive info')
            return_value.append('FAIL')
            return_value.append(
                'Following OS [or] patch level information were found in the local login banner\n' + result_success)
    else:
        return_value.append('no local login warning banner')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _1_7_1_3_deb():
    return_value = list()
    success, error = check('cat /etc/issue.net')
    if success:
        result_success = success
        success, error = check(
            "egrep -i '(\\v|\\r|\\m|\\s|Debian)' /etc/issue.net")
        if not success:
            return_value.append('remote login banner configured properly')
            return_value.append('PASS')
            return_value.append(
                'check if the remote login warning banner matches site policy\n' + result_success)
        else:
            return_value.append('remote banner contains sensitive info')
            return_value.append('FAIL')
            return_value.append(
                'Following OS [or] patch level information were found in the remote login banner\n' + result_success)
    else:
        return_value.append('no remote login warning banner')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _1_7_1_4_deb():
    return_value = list()
    success, error = check('stat /etc/motd | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/motd permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/motd permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/motd invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/motd not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/motd | grep Access did not return anything\n' + error)
    return return_value


def _1_7_1_5_deb():
    return_value = list()
    success, error = check('stat /etc/issue | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/issue permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/issue permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/issue invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/issue not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/issue | grep Access did not return anything\n' + error)
    return return_value


def _1_7_1_6_deb():
    return_value = list()
    success, error = check('stat /etc/issue.net | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/issue.net permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/issue.net permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/issue.net invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/issue.net not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/issue.net | grep Access did not return anything\n' + error)
    return return_value


def _1_7_2_deb():
    return_value = list()
    success, error = check('cat /etc/gdm3/greeter.dconf-defaults')
    if success:
        result_success = success
        success, error = check(
            'cat /etc/gdm3/greeter.dconf-defaults | grep banner-message-')
        if success:
            if 'banner-message-enable=true' in success and not success.splitlines()[0].startswith('#'):
                if "banner-message-text='" in success and not success.splitlines()[1].startswith('#'):
                    return_value.append('GDM login banner is configured')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('no GDM login banner message')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('GDM banner message not enabled')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('GDM login banner not configured')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('GDM not found')
        return_value.append('CHEK')
        return_value.append(
            'cat /etc/gdm3/greeter.dconf-defaults did not return anything\n' + error)
    return return_value


def _1_8_deb():
    return_value = list()
    success, error = check('apt-get -s upgrade')
    if success:
        if '0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.' in success:
            return_value.append('software installed properly')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('software packages need checking')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('software state not checked')
        return_value.append('CHEK')
        return_value.append(
            'apt-get -s upgrade did not return anything\n' + error)
    return return_value


def _2_1_1_deb():
    return_value = list()
    success, error = check('dpkg -s xinetd')
    if success:
        return_value.append('xinetd is installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('xinetd is not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_1_2_deb():
    return_value = list()
    success, error = check('dpkg -s openbsd-inetd')
    if success:
        return_value.append('openbsd-inetd is installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('openbsd-inetd is not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_2_1_1_deb():
    return_value = list()
    success, error = check('dpkg -s ntp')
    if 'Status: install ok installed' in success:
        return_value.append('ntp is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        result_error = success + '\n' + error
        success, error = check('dpkg -s chrony')
        if 'Status: install ok installed' in success:
            return_value.append('chrony is installed')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('time sync not used')
            return_value.append('FAIL')
            return_value.append(result_error + '\n' + success + '\n' + error)
    return return_value


def _2_2_1_2_deb():
    return_value = list()
    success, error = check('grep "^restrict" /etc/ntp.conf | grep default')
    if success:
        ntp_restrict = ['kod', 'nomodify', 'notrap', 'nopeer', 'noquery']
        if all(r in s for r in ntp_restrict for s in success.splitlines()):
            result_success = success
            success, error = check('egrep "^(server|pool)" /etc/ntp.conf')
            if success:
                result_success += '\nVerify remote server configurations\n' + success
                success, error = check('grep "RUNASUSER=ntp" /etc/init.d/ntp')
                if 'RUNASUSER=ntp' in success:
                    return_value.append('ntp is configured')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append(
                        'ntp not run as ntp user')
                    return_value.append('FAIL')
                    return_value.append('Following were found configured\n' + result_success +
                                        '\nFollowing are misconfigured\n' + success + '\n' + error)
            else:
                return_value.append('remote server misconfigured')
                return_value.append('FAIL')
                return_value.append(result_success +
                                    '\negrep "^(server|pool)" /etc/ntp.conf returned the following\n' + error)
        else:
            return_value.append('ntp options misconfigured')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('ntp not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _2_2_1_3_deb():
    return_value = list()
    success, error = check('egrep "^(server|pool)" /etc/chrony/chrony.conf')
    if success:
        return_value.append('chrony is configured')
        return_value.append('PASS')
        return_value.append(
            'Verify remote server is configured properly\n' + success)
    else:
        return_value.append('remote server not configured')
        return_value.append('FAIL')
        return_value.append(
            'egrep "^(server|pool)" /etc/chrony/chrony.conf returned the following\n' + error)
    return return_value


def _2_2_2_deb():
    return_value = list()
    success, error = check('dpkg -l xserver-xorg*')
    if success:
        return_value.append('X Window System installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('X Window System not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_2_3_deb():
    return_value = list()
    success, error = check('systemctl is-enabled avahi-daemon')
    if success:
        if 'enabled' in success:
            return_value.append('avahi-daemon is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled avahi-daemon returned the following\n' + success)
        else:
            return_value.append('avahi-daemon is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('avahi-daemon not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled avahi-daemon returned the following\n' + error)
    return return_value


def _2_2_4_deb():
    return_value = list()
    success, error = check('systemctl is-enabled cups')
    if success:
        if 'enabled' in success:
            return_value.append('cups is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled cups returned the following\n' + success)
        else:
            return_value.append('cups is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('cups not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled cups returned the following\n' + error)
    return return_value


def _2_2_5_deb():
    return_value = list()
    success, error = check('systemctl is-enabled isc-dhcp-server')
    if 'enabled' in success:
        return_value.append('dhcp server is enabled')
        return_value.append('FAIL')
        return_value.append(
            'systemctl is-enabled isc-dhcp-server returned the following\n' + success)
    else:
        result_success = success
        result_error = error
        success, error = check('systemctl is-enabled isc-dhcp-server6')
        if 'enabled' in success:
            return_value.append('dhcp server is enabled')
            return_value.append('FAIL')
            return_value.append(
                result_success + '\n' + result_error + '\nsystemctl is-enabled isc-dhcp-server6 returned the following\n' + success)
        else:
            return_value.append('dhcp server is disabled')
            return_value.append('PASS')
            return_value.append(result_success + '\n' +
                                result_error + '\n' + success + '\n' + error)
    return return_value


def _2_2_6_deb():
    return_value = list()
    success, error = check('systemctl is-enabled slapd')
    if success:
        if 'enabled' in success:
            return_value.append('slapd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled slapd returned the following\n' + success)
        else:
            return_value.append('slapd is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('slapd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled slapd returned the following\n' + error)
    return return_value


def _2_2_7_deb():
    return_value = list()
    success, error = check('systemctl is-enabled nfs-server')
    if 'enabled' in success:
        return_value.append('nfs server is enabled')
        return_value.append('FAIL')
        return_value.append(
            'systemctl is-enabled nfs-server returned the following\n' + success)
    else:
        result_success = success
        result_error = error
        success, error = check('systemctl is-enabled rpcbind')
        if 'enabled' in success:
            return_value.append('rpcbind is enabled')
            return_value.append('FAIL')
            return_value.append(
                result_success + '\n' + result_error + '\nsystemctl is-enabled rpcbind returned the following\n' + success)
        else:
            return_value.append('NFS and RPC are not enabled')
            return_value.append('PASS')
            return_value.append(result_success + '\n' +
                                result_error + '\n' + success + '\n' + error)
    return return_value


def _2_2_8_deb():
    return_value = list()
    success, error = check('systemctl is-enabled bind9')
    if success:
        if 'enabled' in success:
            return_value.append('bind9 is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled bind9 returned the following\n' + success)
        else:
            return_value.append('bind9 is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('bind9 not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled bind9 returned the following\n' + error)
    return return_value


def _2_2_9_deb():
    return_value = list()
    success, error = check('systemctl is-enabled vsftpd')
    if success:
        if 'enabled' in success:
            return_value.append('vsftpd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled vsftpd returned the following\n' + success)
        else:
            return_value.append('vsftpd is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('vsftpd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled vsftpd returned the following\n' + error)
    return return_value


def _2_2_10_deb():
    return_value = list()
    success, error = check('systemctl is-enabled apache2')
    if success:
        if 'enabled' in success:
            return_value.append('apache2 is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled apache2 returned the following\n' + success)
        else:
            return_value.append('apache2 is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('apache2 not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled apache2 returned the following\n' + error)
    return return_value


def _2_2_11_deb():
    return_value = list()
    success, error = check('systemctl is-enabled exim4')
    if success:
        if 'enabled' in success:
            return_value.append('exim4 is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled exim4 returned the following\n' + success)
        else:
            return_value.append('exim4 is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('exim4 not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled exim4 returned the following\n' + error)
    return return_value


def _2_2_12_deb():
    return_value = list()
    success, error = check('systemctl is-enabled smbd')
    if success:
        if 'enabled' in success:
            return_value.append('smbd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled smbd returned the following\n' + success)
        else:
            return_value.append('smbd is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('smbd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled smbd returned the following\n' + error)
    return return_value


def _2_2_13_deb():
    return_value = list()
    success, error = check('systemctl is-enabled squid')
    if success:
        if 'enabled' in success:
            return_value.append('squid is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled squid returned the following\n' + success)
        else:
            return_value.append('squid is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('squid not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled squid returned the following\n' + error)
    return return_value


def _2_2_14_deb():
    return_value = list()
    success, error = check('systemctl is-enabled snmpd')
    if success:
        if 'enabled' in success:
            return_value.append('snmpd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled snmpd returned the following\n' + success)
        else:
            return_value.append('snmpd is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('snmpd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled snmpd returned the following\n' + error)
    return return_value


def _2_2_15_deb():
    return_value = list()
    success, error = check('netstat -an | grep LIST | grep ":25[[:space:]]"')
    if success:
        if '127.0.0.1' not in success and '::1' not in success:
            return_value.append('mta is local only')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('mta listening on loopback')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('mta config not found')
        return_value.append('CHEK')
        return_value.append(
            'netstat -an | grep LIST | grep ":25[[:space:]]" returned the following\n' + error)
    return return_value


def _2_2_16_deb():
    return_value = list()
    success, error = check('systemctl is-enabled rsync')
    if success:
        if 'enabled' in success:
            return_value.append('rsync is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled rsync returned the following\n' + success)
        else:
            return_value.append('rsync is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('rsync not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled rsync returned the following\n' + error)
    return return_value


def _2_2_17_deb():
    return_value = list()
    success, error = check('systemctl is-enabled nis')
    if success:
        if 'enabled' in success:
            return_value.append('nis is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled nis returned the following\n' + success)
        else:
            return_value.append('nis is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('nis not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled nis returned the following\n' + error)
    return return_value


def _2_3_1_deb():
    return_value = list()
    success, error = check('dpkg -s nis')
    if 'Status: install ok installed' in success:
        return_value.append('NIS Client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('NIS Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_3_2_deb():
    return_value = list()
    success, error = check('dpkg -s rsh-client')
    if 'Status: install ok installed' in success:
        return_value.append('rsh client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('dpkg -s rsh-redone-client')
        if 'Status: install ok installed' in success:
            return_value.append('rsh redone client installed')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            return_value.append('rsh Client not installed')
            return_value.append('PASS')
            return_value.append(result_success + '\n' +
                                result_error + '\n' + success + '\n' + error)
    return return_value


def _2_3_3_deb():
    return_value = list()
    success, error = check('dpkg -s talk')
    if 'Status: install ok installed' in success:
        return_value.append('talk client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('talk Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_3_4_deb():
    return_value = list()
    success, error = check('dpkg -s telnet')
    if 'Status: install ok installed' in success:
        return_value.append('telnet client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('telnet Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_3_5_deb():
    return_value = list()
    success, error = check('dpkg -s ldap-utils')
    if 'Status: install ok installed' in success:
        return_value.append('ldap-utils client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('ldap-utils Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _3_1_1_deb():
    return_value = list()
    success, error = check('sysctl net.ipv4.ip_forward')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv6.conf.all.forwarding')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv6\.conf\.all\.forwarding" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv6 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                    return_value.append('IP forwarding disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv6 forwards packets')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv6 forwards packets')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 forwards packets')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 forwards packets')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_1_2_deb():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.send_redirects')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.send_redirects')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('packet redirect sending is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 redirects default packets')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 redirects default packets')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 redirects all packets')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 redirects all packets')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_1_deb():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.accept_source_route')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.accept_source_route')
            if success.endswith('0\n'):
                result_success += success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    result_success += success + '\n'
                    success, error = check(
                        'sysctl net.ipv6.conf.all.accept_source_route')
                    if success.endswith('0\n'):
                        result_success = success + '\n'
                        success, error = check(
                            'grep "net\.ipv6\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
                        ipv6 = [s.split(':')[1] for s in success.splitlines()]
                        if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                            result_success += success + '\n'
                            success, error = check(
                                'sysctl net.ipv6.conf.default.accept_source_route')
                            if success.endswith('0\n'):
                                result_success += success + '\n'
                                success, error = check(
                                    'grep "net\.ipv6\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
                                ipv6 = [s.split(':')[1]
                                        for s in success.splitlines()]
                                if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                                    return_value.append(
                                        'source routed packets are not accepted')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                                else:
                                    return_value.append(
                                        'ipv6 accepts default source packets')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                            else:
                                return_value.append(
                                    'ipv6 accepts default source packets')
                                return_value.append('FAIL')
                                return_value.append(result_success + success)
                        else:
                            return_value.append(
                                'ipv6 accepts all source packets')
                            return_value.append('FAIL')
                            return_value.append(result_success + success)
                    else:
                        return_value.append('ipv6 accepts all source packets')
                        return_value.append('FAIL')
                        return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 accepts default source packets')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 accepts default source packets')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 accepts all source packets')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 accepts all source packets')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_2_deb():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.accept_redirects')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.accept_redirects')
            if success.endswith('0\n'):
                result_success += success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    result_success += success + '\n'
                    success, error = check(
                        'sysctl net.ipv6.conf.all.accept_redirects')
                    if success.endswith('0\n'):
                        result_success = success + '\n'
                        success, error = check(
                            'grep "net\.ipv6\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                        ipv6 = [s.split(':')[1] for s in success.splitlines()]
                        if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                            result_success += success + '\n'
                            success, error = check(
                                'sysctl net.ipv6.conf.default.accept_redirects')
                            if success.endswith('0\n'):
                                result_success += success + '\n'
                                success, error = check(
                                    'grep "net\.ipv6\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                                ipv6 = [s.split(':')[1]
                                        for s in success.splitlines()]
                                if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                                    return_value.append(
                                        'ICMP redirects not accepted')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                                else:
                                    return_value.append(
                                        'ipv6 accepts default redirects')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                            else:
                                return_value.append(
                                    'ipv6 accepts default redirects')
                                return_value.append('FAIL')
                                return_value.append(result_success + success)
                        else:
                            return_value.append('ipv6 accepts all redirects')
                            return_value.append('FAIL')
                            return_value.append(result_success + success)
                    else:
                        return_value.append('ipv6 accepts all redirects')
                        return_value.append('FAIL')
                        return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 accepts default redirects')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 accepts default redirects')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 accepts all redirects')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 accepts all redirects')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_3_deb():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.secure_redirects')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.secure_redirects')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('secure ICMP redirects not accepted')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 redirects default secure ICMP')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 redirects default secure ICMP')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 redirects all secure ICMP')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 redirects all secure ICMP')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_4_deb():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.log_martians')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv4.conf.default.log_martians')
            if success.endswith('1\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('suspicious packets are logged')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 default packets not logged')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 default packets not logged')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 all packets not logged')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 all packets not logged')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_5_deb():
    return_value = list()
    success, error = check('sysctl net.ipv4.icmp_echo_ignore_broadcasts')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            return_value.append('broadcast ICMP requests ignored')
            return_value.append('PASS')
            return_value.append(result_success + success)
        else:
            return_value.append('ipv4 broadcasts not ignored')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 broadcasts not ignored')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_6_deb():
    return_value = list()
    success, error = check('sysctl net.ipv4.icmp_ignore_bogus_error_responses')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            return_value.append('bogus ICMP responses ignored')
            return_value.append('PASS')
            return_value.append(result_success + success)
        else:
            return_value.append('ipv4 bogus responses not ignored')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 bogus responses not ignored')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_7_deb():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.rp_filter')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv4.conf.default.rp_filter')
            if success.endswith('1\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('Reverse Path Filtering enabled')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 default rp filtering disabled')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 default rp filtering disabled')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 all rp filtering disabled')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 all rp filtering disabled')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_8_deb():
    return_value = list()
    success, error = check('sysctl net.ipv4.tcp_syncookies')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            return_value.append('TCP SYN Cookies enabled')
            return_value.append('PASS')
            return_value.append(result_success + success)
        else:
            return_value.append('ipv4 tcp syncookies disabled')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 tcp syncookies disabled')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_9_deb():
    return_value = list()
    success, error = check('sysctl net.ipv6.conf.all.accept_ra')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv6 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv6.conf.default.accept_ra')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                    return_value.append('IPv6 router advert not accepted')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv6 default ra accepted')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv6 default ra accepted')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv6 all ra accepted')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv6 all ra accepted')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_3_1_deb():
    return_value = list()
    success, error = check('dpkg -s tcpd')
    if 'Status: install ok installed' in success:
        return_value.append('TCP Wrappers installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('TCP Wrappers not installed')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_3_2_deb():
    return_value = list()
    success, error = check('cat /etc/hosts.allow')
    if not all(s.startswith('#') or not s for s in success.splitlines()):
        return_value.append('/etc/hosts.allow configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/etc/hosts.allow not configured')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_3_3_deb():
    return_value = list()
    success, error = check('cat /etc/hosts.deny')
    if 'ALL: ALL' in success:
        return_value.append('/etc/hosts.deny configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/etc/hosts.deny not configured')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_3_4_deb():
    return_value = list()
    success, error = check('stat /etc/hosts.allow | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/hosts.allow permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/hosts.allow permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/hosts.allow invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/hosts.allow not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/hosts.allow | grep Access did not return anything\n' + error)
    return return_value


def _3_3_5_deb():
    return_value = list()
    success, error = check('stat /etc/hosts.deny | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/hosts.deny permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/hosts.deny permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/hosts.deny invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/hosts.deny not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/hosts.deny | grep Access did not return anything\n' + error)
    return return_value


def _3_4_1_deb():
    return_value = list()
    success, error = check('modprobe -n -v dccp')
    if 'insmod' in success:
        return_value.append('dccp can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep dccp')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('dccp cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('dccp is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('dccp mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_4_2_deb():
    return_value = list()
    success, error = check('modprobe -n -v sctp')
    if 'insmod' in success:
        return_value.append('sctp can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep sctp')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('sctp cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('sctp is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('sctp mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_4_3_deb():
    return_value = list()
    success, error = check('modprobe -n -v rds')
    if 'insmod' in success:
        return_value.append('rds can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep rds')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('rds cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('rds is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('rds mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_4_4_deb():
    return_value = list()
    success, error = check('modprobe -n -v tipc')
    if 'insmod' in success:
        return_value.append('tipc can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep tipc')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('tipc cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('tipc is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('tipc mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_5_1_1_deb():
    return_value = list()
    success, error = check('iptables -w -L | grep Chain')
    if success:
        if all('policy DROP' in s or 'policy REJECT' in s for s in success.splitlines()):
            return_value.append('default deny firewall policy')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('no default deny firewall')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('firewall policy not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_1_2_deb():
    return_value = list()
    success, error = check('iptables -w -L INPUT -v -n')
    if success:
        loopbacks = [s for s in success.splitlines()]
        flag = 1
        if len(loopbacks) > 2:
            flag = 0
            for i in range(2, len(loopbacks)):
                rule = loopbacks[i].split()
                if rule[2] == 'ACCEPT' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == 'lo':
                            if rule[-3] == '*':
                                if rule[-2] == '0.0.0.0/0':
                                    if rule[-1] == '0.0.0.0/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'fw input accpet destination not 0.0.0.0/0')
                                        return_value.append('FAIL')
                                        return_value.append(success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'fw input accpet source not 0.0.0.0/0')
                                    return_value.append('FAIL')
                                    return_value.append(success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'fw input accpet out not *')
                                return_value.append('FAIL')
                                return_value.append(success)
                                flag += 1
                                break
                        else:
                            return_value.append('fw input accpet in not lo')
                            return_value.append('FAIL')
                            return_value.append(success)
                            flag += 1
                            break
                    else:
                        return_value.append('fw input accept prot not all')
                        return_value.append('FAIL')
                        return_value.append(success)
                        flag += 1
                        break
                elif rule[2] == 'DROP' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == '*':
                            if rule[-3] == '*':
                                if rule[-2] == '127.0.0.0/8':
                                    if rule[-1] == '0.0.0.0/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'fw input drop destination not 0.0.0.0/0')
                                        return_value.append('FAIL')
                                        return_value.append(success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'fw input drop source not 127.0.0.0/8')
                                    return_value.append('FAIL')
                                    return_value.append(success)
                                    flag += 1
                                    break
                            else:
                                return_value.append('fw input drop out not *')
                                return_value.append('FAIL')
                                return_value.append(success)
                                flag += 1
                                break
                        else:
                            return_value.append('fw input drop in not *')
                            return_value.append('FAIL')
                            return_value.append(success)
                            flag += 1
                            break
                    else:
                        return_value.append('fw input drop prot not all')
                        return_value.append('FAIL')
                        return_value.append(success)
                        flag += 1
                        break
        else:
            return_value.append('fw input loopback no config')
            return_value.append('FAIL')
            return_value.append(success)
        if not flag:
            result_success = '\nConfig of firewall Input table\n' + success + '\n'
            success, error = check('iptables -w -L OUTPUT -v -n')
            if success:
                loopbacks = [s for s in success.splitlines()]
                if len(loopbacks) > 2:
                    for i in range(2, len(loopbacks)):
                        rule = loopbacks[i].split()
                        if rule[2] == 'ACCEPT' and not flag:
                            if rule[3] == 'all':
                                if rule[-4] == '*':
                                    if rule[-3] == 'lo':
                                        if rule[-2] == '0.0.0.0/0':
                                            if rule[-1] == '0.0.0.0/0':
                                                return_value.append(
                                                    'firewall loopback traffic configured')
                                                return_value.append('PASS')
                                                return_value.append(
                                                    success + result_success)
                                            else:
                                                return_value.append(
                                                    'fw output accpet destination not 0.0.0.0/0')
                                                return_value.append('FAIL')
                                                return_value.append(
                                                    success + result_success)
                                                flag += 1
                                                break
                                        else:
                                            return_value.append(
                                                'fw output accpet source not 0.0.0.0/0')
                                            return_value.append('FAIL')
                                            return_value.append(
                                                success + result_success)
                                            flag += 1
                                            break
                                    else:
                                        return_value.append(
                                            'fw output accpet out not lo')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'fw output accpet in not *')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'fw output accept prot not all')
                                return_value.append('FAIL')
                                return_value.append(success + result_success)
                                flag += 1
                                break
                else:
                    return_value.append('fw output loopback no config')
                    return_value.append('FAIL')
                    return_value.append(success + result_success)
            else:
                return_value.append('firewall output loopback not found')
                return_value.append('FAIL')
                return_value.append(error)
    else:
        return_value.append('firewall input loopback not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_1_3_deb():
    return_value = list()
    success, error = check('iptables -w -L -v -n')
    if success:
        if len(success.splitlines()) > 8:
            return_value.append('iptables contains config')
            return_value.append('PASS')
            return_value.append(
                'verify all rules for new outbound, and established connections match site policy\n' + success)
        else:
            return_value.append('iptables contains no config')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('iptables not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_1_4_deb():
    return_value = list()
    success, error = check('netstat -ln')
    if success:
        open_ports = [s.split()[0]
                      for s in success.splitlines() if '6' not in s.split()[0] and s.split()[0] != 'Active' and s.split()[0] != 'Proto' and s.split()[0] != 'unix']
        if len(open_ports):
            result_success = success
            success, error = check('iptables -w -L INPUT -v -n')
            if success:
                rules = [s.split()[0] for s in success.splitlines() if s.split()[0] != 'Chain' and s.split()[
                    0] != 'pkts' and s.split()[2] not in ['ACCEPT', 'DROP', 'QUEUE', 'RETURN']]
                if all(o in rules for o in open_ports):
                    return_value.append('all open ports have firewall rule')
                    return_value.append('PASS')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\niptables input configuration\n' + success)
                else:
                    return_value.append('open ports no firewall rule')
                    return_value.append('FAIL')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\niptables input configuration\n' + success)
            else:
                return_value.append('iptables input not found')
                return_value.append('FAIL')
                return_value.append(
                    error + '\nFollowing open ports were found\n' + result_success)
        else:
            return_value.append('no open ports found')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('no open ports found')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _3_5_2_1_deb():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('ip6tables -L | grep Chain')
    if success:
        if all('policy DROP' in s or 'policy REJECT' in s for s in success.splitlines()):
            return_value.append('IPv6 default deny policy')
            return_value.append('PASS')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
        else:
            return_value.append('IPv6 default no deny policy')
            return_value.append('FAIL')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
    else:
        if result_success:
            return_value.append('ipv6 used though disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_5_2_2_deb():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('ip6tables -L INPUT -v -n')
    if success:
        loopbacks = [s for s in success.splitlines()]
        flag = 1
        if len(loopbacks) > 2:
            flag = 0
            for i in range(2, len(loopbacks)):
                rule = loopbacks[i].split()
                if rule[2] == 'ACCEPT' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == 'lo':
                            if rule[-3] == '*':
                                if rule[-2] == '::/0':
                                    if rule[-1] == '::/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'IPv6 input accpet destination not ::/0')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + '\nFollowing uses ipv6\n' + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'IPv6 input accpet source not ::/0')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + '\nFollowing uses ipv6\n' + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'IPv6 input accpet out not *')
                                return_value.append('FAIL')
                                return_value.append(
                                    success + '\nFollowing uses ipv6\n' + result_success)
                                flag += 1
                                break
                        else:
                            return_value.append('IPv6 input accpet in not lo')
                            return_value.append('FAIL')
                            return_value.append(
                                success + '\nFollowing uses ipv6\n' + result_success)
                            flag += 1
                            break
                    else:
                        return_value.append('IPv6 input accept prot not all')
                        return_value.append('FAIL')
                        return_value.append(
                            success + '\nFollowing uses ipv6\n' + result_success)
                        flag += 1
                        break
                elif rule[2] == 'DROP' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == '*':
                            if rule[-3] == '*':
                                if rule[-2] == '::1':
                                    if rule[-1] == '::/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'IPv6 input drop destination not ::/0')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + '\nFollowing uses ipv6\n' + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'IPv6 input drop source not ::1')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + '\nFollowing uses ipv6\n' + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'IPv6 input drop out not *')
                                return_value.append('FAIL')
                                return_value.append(
                                    success + '\nFollowing uses ipv6\n' + result_success)
                                flag += 1
                                break
                        else:
                            return_value.append('IPv6 input drop in not *')
                            return_value.append('FAIL')
                            return_value.append(
                                success + '\nFollowing uses ipv6\n' + result_success)
                            flag += 1
                            break
                    else:
                        return_value.append('IPv6 input drop prot not all')
                        return_value.append('FAIL')
                        return_value.append(
                            success + '\nFollowing uses ipv6\n' + result_success)
                        flag += 1
                        break
        else:
            return_value.append('IPv6 input loopback no config')
            return_value.append('FAIL')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
        if not flag:
            result_success += '\nConfig of IPv6 Input table\n' + success + '\n'
            success, error = check('ip6tables -L OUTPUT -v -n')
            if success:
                loopbacks = [s for s in success.splitlines()]
                if len(loopbacks) > 2:
                    for i in range(2, len(loopbacks)):
                        rule = loopbacks[i].split()
                        if rule[2] == 'ACCEPT' and not flag:
                            if rule[3] == 'all':
                                if rule[-4] == '*':
                                    if rule[-3] == 'lo':
                                        if rule[-2] == '::/0':
                                            if rule[-1] == '::/0':
                                                return_value.append(
                                                    'IPv6 loopback traffic is configured')
                                                return_value.append('PASS')
                                                return_value.append(
                                                    success + '\nFollowing uses ipv6\n' + result_success)
                                            else:
                                                return_value.append(
                                                    'IPv6 output accpet destination not ::/0')
                                                return_value.append('FAIL')
                                                return_value.append(
                                                    success + '\nFollowing uses ipv6\n' + result_success)
                                                flag += 1
                                                break
                                        else:
                                            return_value.append(
                                                'IPv6 output accpet source not ::/0')
                                            return_value.append('FAIL')
                                            return_value.append(
                                                success + '\nFollowing uses ipv6\n' + result_success)
                                            flag += 1
                                            break
                                    else:
                                        return_value.append(
                                            'IPv6 output accpet out not lo')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + '\nFollowing uses ipv6\n' + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'IPv6 output accpet in not *')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + '\nFollowing uses ipv6\n' + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'IPv6 output accept prot not all')
                                return_value.append('FAIL')
                                return_value.append(
                                    success + '\nFollowing uses ipv6\n' + result_success)
                                flag += 1
                                break
                else:
                    return_value.append('IPv6 output loopback no config')
                    return_value.append('FAIL')
                    return_value.append(
                        success + '\nFollowing uses ipv6\n' + result_success)
            else:
                if result_success:
                    return_value.append(
                        'ipv6 enabled output loopback disabled')
                    return_value.append('FAIL')
                    return_value.append(
                        'The following have ipv6 enabled\n' + result_success)
                else:
                    return_value.append('ipv6 disabled')
                    return_value.append('PASS')
                    return_value.append(
                        'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    else:
        if result_success:
            return_value.append('ipv6 enabled input loopback disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_5_2_3_deb():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('ip6tables -L -v -n')
    if success:
        if len(success.splitlines()) > 8:
            return_value.append('IPv6 Table contains config')
            return_value.append('PASS')
            return_value.append('verify all rules for new outbound, and established connections match site policy\n' +
                                success + '\nFollowing uses ipv6\n' + result_success)
        else:
            return_value.append('IPv6 Table contains no config')
            return_value.append('FAIL')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
    else:
        if result_success:
            return_value.append('ipv6 used though disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_5_2_4_deb():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('netstat -ln')
    if success:
        open_ports = [s.split()[0].split('6')[0]
                      for s in success.splitlines() if '6' in s.split()[0] and s.split()[0] != 'Active' and s.split()[0] != 'Proto' and s.split()[0] != 'unix']
        if len(open_ports):
            result_success = success
            success, error = check('ip6tables -L INPUT -v -n')
            if success:
                rules = [s.split()[0] for s in success.splitlines() if s.split()[0] != 'Chain' and s.split()[
                    0] != 'pkts' and s.split()[2] not in ['ACCEPT', 'DROP', 'QUEUE', 'RETURN']]
                if all(o in rules for o in open_ports):
                    return_value.append('all open ports have firewall rule')
                    return_value.append('PASS')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\nIPv6 input table configuration\n' + success)
                else:
                    return_value.append('open ports no firewall rule')
                    return_value.append('FAIL')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\nIPv6 input table configuration\n' + success)
            else:
                return_value.append('IPv6 input Table not found')
                return_value.append('FAIL')
                return_value.append(
                    error + '\nFollowing open ports were found\n' + result_success)
        else:
            return_value.append('no open ports found')
            return_value.append('PASS')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
    else:
        if result_success:
            return_value.append('ipv6 used though disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_5_3_deb():
    return_value = list()
    success, error = check('dpkg -s iptables')
    if 'Status: install ok installed' in success:
        return_value.append('iptables installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('iptables not installed')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_6_deb():
    return_value = list()
    success, error = check('iwconfig')
    if success:
        result_success = success
        success, error = check('ip link show up')
        if success:
            active_wlan = [s for s in success.splitlines() if 'wlan' in s.split()[
                1]]
            if not active_wlan:
                return_value.append('wireless interfaces inactive')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + success)
            else:
                return_value.append('wireless interfaces active')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + success)
        else:
            return_value.append('ip link status unkown')
            return_value.append('CHEK')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('wireless interfaces disabled')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _3_7_deb():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disabled=1')
    if success:
        return_value.append('IPv6 enabled')
        return_value.append('FAIL')
        return_value.append('The following use IPv6\n' + success)
    else:
        return_value.append('IPv6 disabled')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _4_1_1_1_deb():
    return_value = list()
    success, error = check(
        'grep max_log_file /etc/audit/auditd.conf')
    if success:
        return_value.append('audit log storage size is configured')
        return_value.append('PASS')
        return_value.append(
            'Ensure output is in compliance with site policy\n' + success)
    else:
        return_value.append('audit log storage size not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_1_1_2_deb():
    return_value = list()
    success, error = check(
        'grep space_left_action /etc/audit/auditd.conf')
    if success:
        result_success = success + '\n'
        success, error = check('grep action_mail_acct /etc/audit/auditd.conf')
        if success:
            result_success = success + '\n'
            success, error = check(
                'grep admin_space_left_action /etc/audit/auditd.conf')
            if success:
                return_value.append('system disabled when audit logs full')
                return_value.append('PASS')
                return_value.append(result_success + success)
            else:
                return_value.append('admin_space_left_action not set')
                return_value.append('FAIL')
                return_value.append(
                    'grep admin_space_left_action /etc/audit/auditd.conf returned the following\n' + error)
        else:
            return_value.append('action_mail_acct not set')
            return_value.append('FAIL')
            return_value.append(
                'grep action_mail_acct /etc/audit/auditd.conf returned the following\n' + error)
    else:
        return_value.append('system not disabled when audit logs full')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_1_1_3_deb():
    return_value = list()
    success, error = check(
        'grep max_log_file_action /etc/audit/auditd.conf')
    if success:
        if 'max_log_file_action = keep_logs' in success:
            return_value.append('audit logs not automatically deleted')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('audit logs automatically deleted')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('audit log file action not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_1_2_deb():
    return_value = list()
    success, error = check('systemctl is-enabled auditd')
    if 'enabled' in success:
        return_value.append('auditd service is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('auditd not enabled')
        return_value.append('FAIL')
        return_value.append(
            'systemctl is-enabled auditd returned the following\n' + success + '\n' + error)
    return return_value


# bootloader specific
def _4_1_3_deb():
    return_value = list()
    success, error = check('grep "^\s*linux" /boot/grub*/grub.cfg')
    if success:
        if all('audit=1' in s for s in success.splitlines()):
            return_value.append('processes prior to auditd audited')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('processes prior to auditd not audited')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('process prior to auditd not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_1_4_deb():
    return_value = list()
    success, error = check('grep time-change /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep time-change')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change' in result_success or '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' in result_success:
            if '-a always,exit -F arch=b64 -S clock_settime -k time-change' in result_success or '-a always,exit -F arch=b32 -S clock_settime -k time-change' in result_success:
                if '-w /etc/localtime -p wa -k time-change' in result_success:
                    return_value.append('events modifying date and time coll')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('localtime time-change not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('clock_settime not collected')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('adjtimex and settimeofday not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('events modifying date and time not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_5_deb():
    return_value = list()
    success, error = check('grep identity /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep identity')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /etc/group -p wa -k identity' in result_success:
            if '-w /etc/passwd -p wa -k identity' in result_success:
                if '-w /etc/gshadow -p wa -k identity' in result_success:
                    if '-w /etc/shadow -p wa -k identity' in result_success:
                        if '-w /etc/security/opasswd -p wa -k identity' in result_success:
                            return_value.append(
                                'events modifying u/g info collected')
                            return_value.append('PASS')
                            return_value.append(result_success)
                        else:
                            return_value.append(
                                'opasswd identity events not coll')
                            return_value.append('FAIL')
                            return_value.append(result_success)
                    else:
                        return_value.append('shadow identity events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('gshadow identity events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('passwd identity events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('group identity events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('events modifying u/g info not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_6_deb():
    return_value = list()
    success, error = check('grep system-locale /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grepsystem-locale')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale' in result_success or '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' in result_success:
            if '-w /etc/issue -p wa -k system-locale' in result_success:
                if '-w /etc/issue.net -p wa -k system-locale' in result_success:
                    if '-w /etc/hosts -p wa -k system-locale' in result_success:
                        if '-w /etc/sysconfig/network -p wa -k system-locale' in result_success:
                            return_value.append(
                                "events modifying system's n/w env coll")
                            return_value.append('PASS')
                            return_value.append(result_success)
                        else:
                            return_value.append(
                                'network system-locale events not coll')
                            return_value.append('FAIL')
                            return_value.append(result_success)
                    else:
                        return_value.append(
                            'hosts system-locale events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append(
                        'issue.net system-locale events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('issue system-locale events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('system-locale name change not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append("events modifying system's n/w env not coll")
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_7_deb():
    return_value = list()
    success, error = check('grep MAC-policy /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep MAC-policy')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /etc/selinux/ -p wa -k MAC-policy' in result_success or '-w /etc/apparmor/ -p wa -k MAC-policy' in result_success:
            if '-w /usr/share/selinux/ -p wa -k MAC-policy' in result_success or '-w /etc/apparmor.d/ -p wa -k MAC-policy' in result_success:
                return_value.append("events modifying system's MAC coll")
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('dir MAC-policy events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('etc MAC-policy events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append("events modifying system's MAC not coll")
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_8_deb():
    return_value = list()
    success, error = check('grep logins /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep logins')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /var/log/faillog -p wa -k logins' in result_success:
            if '-w /var/log/lastlog -p wa -k logins' in result_success:
                if '-w /var/log/tallylog -p wa -k logins' in result_success:
                    return_value.append(
                        'login and logout events are collected')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('tallylog logins events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('lastlog logins events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('faillog logins events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('login and logout events not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_9_deb():
    return_value = list()
    success, error = check(
        "grep -E '(session|logins)' /etc/audit/audit.rules")
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check("auditctl -l | grep -E '(session|logins)'")
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /var/run/utmp -p wa -k session' in result_success:
            if '-w /var/log/wtmp -p wa -k logins' in result_success:
                if '-w /var/log/btmp -p wa -k logins' in result_success:
                    return_value.append('session initiation info is collected')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('btmp logins events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('wtmp logins events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('utmp session events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('session initiation info not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_10_deb():
    return_value = list()
    success, error = check('grep perm_mod /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep perm_mod')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod' in result_success:
            if '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod' in result_success:
                if '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' in result_success:
                    if '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod' in result_success:
                        if '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod' in result_success:
                            if '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod' in result_success:
                                return_value.append(
                                    'access control mod events collected')
                                return_value.append('PASS')
                                return_value.append(result_success)
                            else:
                                return_value.append(
                                    'setxattr auditctl events not coll')
                                return_value.append('FAIL')
                                return_value.append(result_success)
                        else:
                            return_value.append(
                                'chown auditctl events not coll')
                            return_value.append('FAIL')
                            return_value.append(result_success)
                    else:
                        return_value.append('chmod auditctl events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('setxattr *.rules events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('chown *.rules events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('chmod *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('access control mod events not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_11_deb():
    return_value = list()
    success, error = check('grep access /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep access')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access' in result_success:
            if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access' in result_success:
                if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access' in result_success:
                    if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access' in result_success:
                        return_value.append(
                            'unauthorized file access collected')
                        return_value.append('PASS')
                        return_value.append(result_success)
                    else:
                        return_value.append('EPERM auditctl events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('EACCES auditctl events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('EPERM *.rules events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('EACCES *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('unauthorized file access not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_12_deb():
    return_value = list()
    success, error = check('mount | grep -e "/dev/sd"')
    partitions = [s.split()[0] for s in success.splitlines()]
    if len(partitions):
        result_success = 'Following partitions were found\n' + success
        flag = 0
        for p in partitions:
            success, error = check(
                "find " + p + " -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \"-a always,exit -F path=\" $1 \" -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged\" }'")
            result_success += success if success else error + \
                '\nABOVE was found on ' + p + '\n'
            flag += 1 if success else 0
        if not flag:
            return_value.append('privileged commands not collected')
            return_value.append('FAIL')
            return_value.append(result_success)
        else:
            return_value.append('privileged commands collected')
            return_value.append('PASS')
            return_value.append(
                'Verify all resulting lines are a .rules file in /etc/audit/rules.d/ and the output of auditctl -l AND .rules file output should be auid!=-1 not auid!=4294967295\n' + result_success)
    else:
        return_value.append('no partitions found')
        return_value.append('CHEK')
        return_value.append(success + error)
    return return_value


def _4_1_13_deb():
    return_value = list()
    success, error = check('grep mounts /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep mounts')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts' in result_success or '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts' in result_success:
            if '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mounts' in result_success or '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mounts' in result_success:
                return_value.append('successful fs mounts collected')
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('mount auditctl events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('mount *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('successful fs mounts not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_14_deb():
    return_value = list()
    success, error = check('grep delete /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep delete')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete' in result_success or '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete' in result_success:
            if '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete' in result_success or '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete' in result_success:
                return_value.append('user file deletion events collected')
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('unlink, rename auditctl events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('unlink, rename *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('user file deletion events not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_15_deb():
    return_value = list()
    success, error = check('grep scope /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep scope')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /etc/sudoers -p wa -k scope' in result_success:
            if '-w /etc/sudoers.d/ -p wa -k scope' in result_success:
                return_value.append('changes to sudoers collected')
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('directory scope events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('sudoers scope events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('changes to sudoers not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_16_deb():
    return_value = list()
    success, error = check('grep actions /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep actions')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /var/log/sudo.log -p wa -k actions' in result_success:
            return_value.append('sudolog collected')
            return_value.append('PASS')
            return_value.append(result_success)
        else:
            return_value.append('sudo.log actions events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('sudolog not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_17_deb():
    return_value = list()
    success, error = check('grep modules /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep modules')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b32 -S init_module -S delete_module -k modules' in result_success or '-a always,exit -F arch=b64 -S init_module -S delete_module-k modules' in result_success:
            if '-w /sbin/insmod -p x -k modules' in result_success:
                if '-w /sbin/rmmod -p x -k modules' in result_success:
                    if '-w /sbin/modprobe -p x -k modules' in result_success:
                        return_value.append('kernel module monitored')
                        return_value.append('PASS')
                        return_value.append(result_success)
                    else:
                        return_value.append('modprobe modules events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('rmmod modules events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('insmod modules events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('modules *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('kernel module not monitored')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_18_deb():
    return_value = list()
    success, error = check(
        'grep "^\s*[^#]" /etc/audit/audit.rules | tail -1')
    if '-e 2' in success:
        return_value.append('audit configuration immutable')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('audit configuration is mutable')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _4_2_1_1_deb():
    return_value = list()
    success, error = check('systemctl is-enabled rsyslog | grep enabled')
    if 'enabled' in success:
        return_value.append('rsyslog is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('rsyslog is disabled')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _4_2_1_2_deb():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('cat /etc/rsyslog.conf')
    if success:
        result_success += 'Review the contents of rsyslog.conf\n' + success
    else:
        result_error += error
    success, error = check('cat /etc/rsyslog.d/*.conf')
    if success:
        result_success += 'Review the contents of rsyslog.d/*.conf\n' + success
    else:
        result_error += error
    success, error = check('ls -l /var/log/')
    if success:
        result_success += 'verify that the log files are logging information\n' + success
    else:
        result_error += error
    if len(result_success):
        return_value.append('logging is configured')
        return_value.append('CHEK')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('logging not configured')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_2_1_3_deb():
    return_value = list()
    success, error = check(
        'grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf')
    if success:
        allowed_perms = ['0640', '0600', '0440', '0400', '0240', '0200']
        perms = [s.split(':')[1].split()[1] for s in success.splitlines()]
        if all(p in allowed_perms for p in perms):
            return_value.append('rsyslog file permissions configured')
            return_value.append('PASS')
            return_value.append(success + '\n' + error)
        else:
            return_value.append('rsyslog file permissions not configured')
            return_value.append('PASS')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('rsyslog file permissions not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_1_4_deb():
    return_value = list()
    success, error = check(
        'grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf')
    if success:
        return_value.append('rsyslog sends logs to remote log host')
        return_value.append('PASS')
        return_value.append(
            'verify that logs are sent to central log host\n' + success + '\n' + error)
    else:
        return_value.append('rsyslog does not sends logs')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_1_5_deb():
    return_value = list()
    success, error = check(
        "grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check(
        "grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
    result_success = success if success else ''
    result_error = error if error else ''
    if len(result_success):
        return_value.append('rsyslog messages accepted designated')
        return_value.append('PASS')
        return_value.append(
            'verify the resulting lines are uncommented on designated log hosts and commented or removed on all others\n' + result_success + '\n' + result_error)
    else:
        return_value.append('rsyslog messages not config')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_2_2_1_deb():
    return_value = list()
    success, error = check('systemctl is-enabled syslog-ng | grep enabled')
    if 'enabled' in success:
        return_value.append('syslog-ng is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('syslog-ng is disabled')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _4_2_2_2_deb():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('cat /etc/syslog-ng/syslog-ng.conf')
    if success:
        result_success += 'Review the contents of syslog-ng.conf\n' + success
    else:
        result_error += error
    success, error = check('ls -l /var/log/')
    if success:
        result_success += 'verify that the log files are logging information\n' + success
    else:
        result_error += error
    if len(result_success):
        return_value.append('logging is configured')
        return_value.append('CHEK')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('logging not configured')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_2_2_3_deb():
    return_value = list()
    success, error = check(
        'grep ^options /etc/syslog-ng/syslog-ng.conf')
    if success:
        allowed_perms = ['0640', '0600', '0440', '0400', '0240', '0200']
        if any(ap in success for ap in allowed_perms):
            return_value.append('syslog-ng file permissions configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('syslog-ng file permissions not configured')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('syslog-ng file permissions not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_2_4_deb():
    return_value = list()
    success, error = check(
        'cat /etc/syslog-ng/syslog-ng.conf | grep "destination logserver"')
    if success:
        return_value.append('syslog-ng sends logs to remote log host')
        return_value.append('PASS')
        return_value.append(
            'verify that logs are sent to central log host\n' + success + '\n' + error)
    else:
        return_value.append('syslog-ng does not sends logs')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_2_5_deb():
    return_value = list()
    success, error = check('cat /etc/syslog-ng/syslog-ng.conf')
    if success:
        return_value.append('syslog-ng messages accepted designated')
        return_value.append('PASS')
        return_value.append(
            'verify the resulting lines are configured appropriately on designated log hosts\n' + success)
    else:
        return_value.append('syslog-ng messages not config')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_3_deb():
    return_value = list()
    success, error = check('dpkg -s rsyslog')
    if success:
        return_value.append('rsyslog is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        result_error = error + '\n'
        success, error = check('dpkg -s syslog-ng')
        if success:
            return_value.append('syslog-ng is installed')
            return_value.append('PASS')
            return_value.append(success)
        else:
            result_error += error
            return_value.append('rsyslog and syslog-ng is not installed')
            return_value.append('FAIL')
            return_value.append(result_error)
    return return_value


def _4_2_4_deb():
    return_value = list()
    success, error = check('find /var/log -type f -ls')
    if success:
        if all('r-----' in s.split()[2][-6:] for s in success.splitlines()):
            return_value.append('permissions on all logfiles config')
            return_value.append('PASS')
            return_value.append(success + '\nfollowing not checked\n' + error)
        else:
            return_value.append('permissions not config on all logfiles')
            return_value.append('FAIL')
            return_value.append('other has permissions on files OR group has write or execute permissions\n' +
                                success + '\nfollowing not checked\n' + error)
    else:
        return_value.append('permissions on logfiles not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_3_deb():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('cat /etc/logrotate.conf')
    if success:
        result_success += 'verify logs in logrotate.conf are rotated according to site policy\n' + success
    else:
        result_error += error
    success, error = check('cat /etc/logrotate.d/*')
    if success:
        result_success += 'verify logs in logrotate directory are rotated according to site policy\n' + success
    else:
        result_error += error
    if len(result_success):
        return_value.append('lograte is configured')
        return_value.append('CHEK')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('lograte not configured')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _5_1_1_deb():
    return_value = list()
    success, error = check('systemctl is-enabled cron')
    if 'enabled' in success:
        return_value.append('cron daemon is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('cron daemon not found')
        return_value.append('FAIL')
        return_value.append(
            'systemctl is-enabled cron returned the following\n' + success + '\n' + error)
    return return_value


def _5_1_2_deb():
    return_value = list()
    success, error = check('stat /etc/crontab')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/crontab configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/crontab not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/crontab not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/crontab returned the following\n' + error)
    return return_value


def _5_1_3_deb():
    return_value = list()
    success, error = check('stat /etc/cron.hourly')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.hourly configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.hourly not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.hourly not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.hourly returned the following\n' + error)
    return return_value


def _5_1_4_deb():
    return_value = list()
    success, error = check('stat /etc/cron.daily')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.daily configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.daily not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.daily not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.daily returned the following\n' + error)
    return return_value


def _5_1_5_deb():
    return_value = list()
    success, error = check('stat /etc/cron.weekly')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.weekly configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.weekly not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.weekly not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.weekly returned the following\n' + error)
    return return_value


def _5_1_6_deb():
    return_value = list()
    success, error = check('stat /etc/cron.monthly')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.monthly configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.monthly not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.monthly not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.monthly returned the following\n' + error)
    return return_value


def _5_1_7_deb():
    return_value = list()
    success, error = check('stat /etc/cron.d')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.d configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.d not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.d not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.d returned the following\n' + error)
    return return_value


def _5_1_8_deb():
    return_value = list()
    success, error = check('stat /etc/cron.deny')
    if 'No such file or directory' in error:
        result_error = error
        success, error = check('stat /etc/at.deny')
        if 'No such file or directory' in error:
            result_error += error
            success, error = check('stat /etc/cron.allow')
            if success:
                go_perm = success.splitlines()[0].split()[1][-7:-1]
                if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
                    result_success = success
                    success, error = check('stat /etc/at.allow')
                    if success:
                        go_perm = success.splitlines()[0].split()[1][-7:-1]
                        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
                            return_value.append(
                                'at/cron restricted to authorized users')
                            return_value.append('PASS')
                            return_value.append(
                                result_error + '\n' + result_success + '\n' + success)
                        else:
                            return_value.append('/etc/at.allow not configured')
                            return_value.append('FAIL')
                            return_value.append(
                                result_error + '\n' + result_success + '\n' + success + '\n' + error)
                    else:
                        return_value.append('/etc/at.allow not found')
                        return_value.append('FAIL')
                        return_value.append(result_error + '\n' + result_success +
                                            '\nstat /etc/at.allow returned the following\n' + error)
                else:
                    return_value.append('/etc/cron.allow not configured')
                    return_value.append('FAIL')
                    return_value.append(result_error + '\n' + result_success +
                                        '\nstat /etc/at.allow returned the following\n' + success)
            else:
                return_value.append('/etc/cron.allow not found')
                return_value.append('FAIL')
                return_value.append(
                    result_error + '\nstat /etc/at.allow returned the following\n' + error)
        else:
            return_value.append('/etc/at.deny exists')
            return_value.append('FAIL')
            return_value.append(
                result_error + '\nstat /etc/at.deny returned the following\n' + error)
    else:
        return_value.append('/etc/cron.deny exists')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.deny returned the following\n' + error)
    return return_value


def _5_2_1_deb():
    return_value = list()
    success, error = check('stat /etc/ssh/sshd_config')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/ssh/sshd_config configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on sshd_config not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/ssh/sshd_config not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/ssh/sshd_config returned the following\n' + error)
    return return_value


def _5_2_2_deb():
    return_value = list()
    success, error = check(
        "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;")
    if success:
        result_success = success
        success, error = check(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | grep \"Access: (\"")
        if all(s.split()[1][-7:-1] == '------' and 'Uid: (    0/    root)   Gid: (    0/    root)' in s for s in success.splitlines()):
            return_value.append('SSH private host keys perms config')
            return_value.append('PASS')
            return_value.append(result_success)
        else:
            return_value.append('SSH private host keys perms not config')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('SSH private host keys not found')
        return_value.append('FAIL')
        return_value.append(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;\n" + error)
    return return_value


def _5_2_3_deb():
    return_value = list()
    success, error = check(
        "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;")
    if success:
        result_success = success
        success, error = check(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \; | grep \"Access: (\"")
        if all(s.split()[1][-7:-1] in ['------', 'r--r--', 'r-----', '---r--'] and 'Uid: (    0/    root)   Gid: (    0/    root)' in s for s in success.splitlines()):
            return_value.append('SSH public host keys perms config')
            return_value.append('PASS')
            return_value.append(result_success)
        else:
            return_value.append('SSH public host keys perms not config')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('SSH public host keys not found')
        return_value.append('FAIL')
        return_value.append(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;\n" + error)
    return return_value


def _5_2_4_deb():
    return_value = list()
    success, error = check('grep ^Protocol /etc/ssh/sshd_config')
    if 'Protocol 2' in success:
        return_value.append('SSH Protocol set to 2')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH Protocol not 2')
        return_value.append('FAIL')
        return_value.append(
            'grep ^Protocol /etc/ssh/sshd_config returned the following\n' + success + error)
    return return_value


def _5_2_5_deb():
    return_value = list()
    success, error = check('sshd -T | grep loglevel')
    if 'LogLevel VERBOSE' in success or 'loglevel INFO' in success:
        return_value.append('SSH LogLevel is appropriate')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH LogLevel not appropriate')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep loglevel returned the following\n' + success + error)
    return return_value


def _5_2_6_deb():
    return_value = list()
    success, error = check('sshd -T | grep x11forwarding')
    if 'X11Forwarding no' in success:
        return_value.append('SSH X11 forwarding is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH X11 forwarding not disabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep x11forwarding returned the following\n' + success + error)
    return return_value


def _5_2_7_deb():
    return_value = list()
    success, error = check('sshd -T | grep maxauthtries')
    if success:
        tries = success.split()[1]
        if int(tries) <= 4:
            return_value.append('SSH MaxAuthTries is set to ' + tries)
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SSH MaxAuthTries is more than 4')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('SSH MaxAuthTries not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep maxauthtries returned the following\n' + error)
    return return_value


def _5_2_8_deb():
    return_value = list()
    success, error = check('sshd -T | grep ignorerhosts')
    if 'IgnoreRhosts yes' in success:
        return_value.append('SSH IgnoreRhosts is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH IgnoreRhosts is disabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep ignorerhosts returned the following\n' + success + error)
    return return_value


def _5_2_9_deb():
    return_value = list()
    success, error = check('sshd -T | grep hostbasedauthentication')
    if 'HostbasedAuthentication no' in success:
        return_value.append('SSH HBA is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH HBA is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep hostbasedauthentication returned the following\n' + success + error)
    return return_value


def _5_2_10_deb():
    return_value = list()
    success, error = check('sshd -T | grep permitrootlogin')
    if 'PermitRootLogin no' in success:
        return_value.append('SSH root login is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH root login is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep permitrootlogin returned the following\n' + success + error)
    return return_value


def _5_2_11_deb():
    return_value = list()
    success, error = check('sshd -T | grep permitemptypasswords')
    if 'PermitEmptyPasswords no' in success:
        return_value.append('SSH PermitEmptyPasswords is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH PermitEmptyPasswords is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep permitemptypasswords returned the following\n' + success + error)
    return return_value


def _5_2_12_deb():
    return_value = list()
    success, error = check('sshd -T | grep permituserenvironment')
    if 'PermitUserEnvironment no' in success:
        return_value.append('SSH PermitUserEnvironment is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH PermitUserEnvironment is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep permituserenvironment returned the following\n' + success + error)
    return return_value


def _5_2_13_deb():
    return_value = list()
    success, error = check('sshd -T | grep ciphers')
    weak_cyphers = ['3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour',
                    'arcfour128', 'arcfour256', 'blowfish-cbc', 'cast128-cbc', 'rijndael-cbc@lysator.liu.se']
    if success and not any(s in weak_cyphers for s in success.splitlines()):
        return_value.append('SSH only strong Ciphers are used')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH strong Ciphers not used')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep ciphers returned the following\n' + success + error)
    return return_value


def _5_2_14_deb():
    return_value = list()
    success, error = check('sshd -T | grep -i "MACs"')
    weak_mac = ['hmac-md5', 'hmac-md5-96', 'hmac-ripemd160', 'hmac-sha1', 'hmac-sha1-96', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-md5-etm@openssh.com',
                'hmac-md5-96-etm@openssh.com', 'hmac-ripemd160-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'hmac-sha1-96-etm@openssh.com', 'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com']
    if success and not any(s in weak_mac for s in success.splitlines()):
        return_value.append('SSH only strong MAC algorithms are used')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH strong MAC algorithms not used')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep -i "MACs" returned the following\n' + success + error)
    return return_value


def _5_2_15_deb():
    return_value = list()
    success, error = check('sshd -T | grep kexalgorithms')
    weak_keys = ['diffie-hellman-group1-sha1',
                 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1']
    if success and not any(s in weak_keys for s in success.splitlines()):
        return_value.append('SSH only strong Key Exchange algorithms are used')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH strong Key Exchange algorithms not used')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep kexalgorithms returned the following\n' + success + error)
    return return_value


def _5_2_16_deb():
    return_value = list()
    success, error = check('sshd -T | grep clientaliveinterval')
    if success:
        result_success = success
        alive = success.split()[1]
        if 1 <= int(alive) <= 300:
            success, error = check('sshd -T | grep clientalivecountmax')
            if success:
                count = success.split()[1]
                if int(count) <= 3:
                    return_value.append('SSH Idle Timeout Interval configured')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('SSH ClientAliveCountMax more than 3')
                    return_value.append('FAIL')
                    return_value.append(result_success + '\n' + success)
            else:
                return_value.append('SSH ClientAliveCountMax not found')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('SSH ClientAliveInterval more than 300')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('SSH ClientAliveInterval not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep clientaliveinterval returned the following\n' + error)
    return return_value


def _5_2_17_deb():
    return_value = list()
    success, error = check('sshd -T | grep logingracetime')
    if success:
        grace = success.split()[1]
        if 1 <= int(grace) <= 60:
            return_value.append('SSH LoginGraceTime is ' + grace)
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SSH LoginGraceTime more than 60')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('SSH LoginGraceTime not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep logingracetime returned the following\n' + error)
    return return_value


def _5_2_18_deb():
    return_value = list()
    success, error = check('sshd -T | grep allowusers')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('sshd -T | grep allowgroups')
    result_success += success if success else ''
    result_error += error if error else ''
    success, error = check('sshd -T | grep denyusers')
    result_success += success if success else ''
    result_error += error if error else ''
    success, error = check('sshd -T | grep denygroups')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        return_value.append('SSH access is limited')
        return_value.append('PASS')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('SSH access is not limited')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _5_2_19_deb():
    return_value = list()
    success, error = check('sshd -T | grep banner')
    if 'Banner /etc/issue.net' in success:
        return_value.append('SSH warning banner is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH warning banner is not configured')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep banner returned the following\n' + success + error)
    return return_value


def _5_3_1_deb():
    return_value = list()
    success, error = check('grep pam_pwquality.so /etc/pam.d/common-password')
    if 'retry=' in success:
        result_success = 'Check number of retry attempts\n' + success
        success, error = check('grep ^minlen /etc/security/pwquality.conf')
        if success:
            if success.split(' = ')[1].split('\n')[0].isdigit() and int(success.split(' = ')[1].split('\n')[0]) >= 14:
                result_success += success
                success, error = check(
                    'grep ^dcredit /etc/security/pwquality.conf')
                if '0' not in success:
                    result_success += '\nCheck number of digits\n' + success
                    success, error = check(
                        'grep ^lcredit /etc/security/pwquality.conf')
                    if '0' not in success:
                        result_success += '\nCheck number of lower case characters\n' + success
                        success, error = check(
                            'grep ^ocredit /etc/security/pwquality.conf')
                        if '0' not in success:
                            result_success += '\nCheck number of special characters\n' + success
                            success, error = check(
                                'grep ^ucredit /etc/security/pwquality.conf')
                            if '0' not in success:
                                return_value.append(
                                    'password creation requirements configured')
                                return_value.append('PASS')
                                return_value.append(
                                    result_success + '\n' + success)
                            else:
                                return_value.append(
                                    'password does not require upper char')
                                return_value.append('FAIL')
                                return_value.append(
                                    result_success + '\n' + success + '\n' + error)
                        else:
                            return_value.append(
                                'password does not require special char')
                            return_value.append('FAIL')
                            return_value.append(
                                result_success + '\n' + success + '\n' + error)
                    else:
                        return_value.append(
                            'password does not require lowercase')
                        return_value.append('FAIL')
                        return_value.append(
                            result_success + '\n' + success + '\n' + error)
                else:
                    return_value.append('password does not require one digit')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\n' + success + '\n' + error)
            else:
                return_value.append('password minlen not 14 or more')
                return_value.append('FAIL')
                return_value.append(
                    result_success + '\n' + success + '\n' + error)
        else:
            return_value.append('password minlen not set')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('password retry not set')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _5_3_2_deb():
    return_value = list()
    success, error = check('grep "pam_tally2" /etc/pam.d/common-auth')
    if success:
        result_success = 'determine the current settings for user lockout\n' + success
        success, error = check(
            'grep -E "pam_tally2\.so" /etc/pam.d/common-account')
        if success:
            return_value.append('failed password lockout configured')
            return_value.append('PASS')
            return_value.append(result_success + '\n' + success)
        else:
            return_value.append('pam_tally2.so module not included')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('current user lockout settings not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _5_3_3_deb():
    return_value = list()
    success, error = check(
        "egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/common-password")
    if success:
        if success.split('remember=')[1].split('\n')[0].isdigit() and int(success.split('remember=')[1].split('\n')[0]) >= 5:
            return_value.append('password reuse is limited')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('password remember not gt 5')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('password reuse not limited')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _5_3_4_deb():
    return_value = list()
    success, error = check(
        "egrep '^password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512' /etc/pam.d/common-password")
    if success:
        return_value.append('password hashing algorithm is SHA-512')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('password hashing algorithm not SHA-512')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _5_4_1_1_deb():
    return_value = list()
    success, error = check('grep PASS_MAX_DAYS /etc/login.defs')
    days = [d[1].split()[0] for d in [s.split() for s in success.splitlines(
    ) if not s.startswith('#')] if d[1].split()[0].lstrip('-').isdigit()]
    if days:
        if int(days[0]) <= 365 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                'egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,5')
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) <= 365 and int(d) != -1 for d in days):
                    return_value.append(
                        'password expiration less than 365 days')
                    return_value.append('PASS')
                    return_value.append('verify PASS_MAX_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MAX_DAYS\n' + success)
                else:
                    return_value.append('user password expiration gt 365 days')
                    return_value.append('FAIL')
                    return_value.append('verify PASS_MAX_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MAX_DAYS\n' + success)
            else:
                return_value.append('users password expiration not found')
                return_value.append('FAIL')
                return_value.append('verify PASS_MAX_DAYS conforms to site policy\n' +
                                    result_success + '\nUsers PASS_MAX_DAYS\n' + success)
        else:
            return_value.append('password expiration not 365 days or less')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('password expiration not found')
        return_value.append('FAIL')
        return_value.append(
            'grep PASS_MAX_DAYS /etc/login.defs returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_2_deb():
    return_value = list()
    success, error = check('grep PASS_MIN_DAYS /etc/login.defs')
    days = [d[1].split()[0] for d in [s.split() for s in success.splitlines(
    ) if not s.startswith('#')] if d[1].split()[0].lstrip('-').isdigit()]
    if days:
        if int(days[0]) >= 7 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                'egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4')
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) >= 7 and int(d) != -1 for d in days):
                    return_value.append('password changes gt 7 days')
                    return_value.append('PASS')
                    return_value.append('verify PASS_MIN_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MIN_DAYS\n' + success)
                else:
                    return_value.append('user password changes lt 7 days')
                    return_value.append('FAIL')
                    return_value.append('verify PASS_MIN_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MIN_DAYS\n' + success)
            else:
                return_value.append('users password changes days not found')
                return_value.append('FAIL')
                return_value.append('verify PASS_MIN_DAYS conforms to site policy\n' +
                                    result_success + '\nUsers PASS_MIN_DAYS\n' + success)
        else:
            return_value.append('password changes not 7 days or more')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('password changes days not found')
        return_value.append('FAIL')
        return_value.append(
            'grep PASS_MIN_DAYS /etc/login.defs returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_3_deb():
    return_value = list()
    success, error = check('grep PASS_WARN_AGE /etc/login.defs')
    days = [d[1].split()[0] for d in [s.split() for s in success.splitlines(
    ) if not s.startswith('#')] if d[1].split()[0].lstrip('-').isdigit()]
    if days:
        if int(days[0]) >= 7 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                'egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,6')
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) >= 7 and int(d) != -1 for d in days):
                    return_value.append('password change warning gt 7 days')
                    return_value.append('PASS')
                    return_value.append('verify PASS_WARN_AGE conforms to site policy\n' +
                                        result_success + '\nUsers PASS_WARN_AGE\n' + success)
                else:
                    return_value.append(
                        'user password change warning lt 7 days')
                    return_value.append('FAIL')
                    return_value.append('verify PASS_WARN_AGE conforms to site policy\n' +
                                        result_success + '\nUsers PASS_WARN_AGE\n' + success)
            else:
                return_value.append('users password warn not found')
                return_value.append('FAIL')
                return_value.append('verify PASS_WARN_AGE conforms to site policy\n' +
                                    result_success + '\nUsers PASS_WARN_AGE\n' + success)
        else:
            return_value.append('password expiration warning lt 7 days')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('password expiration warning not found')
        return_value.append('FAIL')
        return_value.append(
            'grep PASS_WARN_AGE /etc/login.defs returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_4_deb():
    return_value = list()
    success, error = check('useradd -D | grep INACTIVE')
    days = [d for d in [s.split('=')[1] for s in success.splitlines(
    ) if not s.startswith('#')] if d.lstrip('-').isdigit()]
    if days:
        if int(days[0]) <= 30 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                'egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7')
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) <= 30 and int(d) != -1 for d in days):
                    return_value.append(
                        'inactive password lock less than 30 days')
                    return_value.append('PASS')
                    return_value.append('verify INACTIVE conforms to site policy\n' +
                                        result_success + '\nUsers INACTIVE\n' + success)
                else:
                    return_value.append('user password lock more than 30 days')
                    return_value.append('FAIL')
                    return_value.append('verify INACTIVE conforms to site policy\n' +
                                        result_success + '\nUsers INACTIVE\n' + success)
            else:
                return_value.append('users password lock not found')
                return_value.append('FAIL')
                return_value.append('verify INACTIVE conforms to site policy\n' +
                                    result_success + '\nUsers INACTIVE\n' + success)
        else:
            return_value.append('inactive password lock more than 30 days')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('inactive password lock not found')
        return_value.append('FAIL')
        return_value.append(
            'useradd -D | grep INACTIVE returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_5_deb():
    return_value = list()
    success, error = check(
        "for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo \"$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)\"; done")
    if not success:
        return_value.append('last password change date in past')
        return_value.append('PASS')
        return_value.append(
            "for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo \"$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)\"; done\nreturned the following\n" + error)
    else:
        return_value.append('last password change date not in past')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


def _5_4_2_deb():
    return_value = list()
    success, error = check(
        'egrep -v "^\+" /etc/passwd | awk -F: \'($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}\'')
    if not success:
        result_error = error
        success, error = check(
            "for user in `awk -F: '($1!=\"root\" && $3 < 1000) {print $1 }' /etc/passwd`; do passwd -S $user | awk -F ' ' '($2!=\"L\") {print $1}'; done")
        if not success:
            return_value.append('system accounts are non-login')
            return_value.append('PASS')
            return_value.append(result_error + '\n' + error)
        else:
            return_value.append('system accounts are login')
            return_value.append('FAIL')
            return_value.append(result_error + '\n' + success)
    else:
        return_value.append('shell field not /usr/sbin/nologin')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


def _5_4_3_deb():
    return_value = list()
    success, error = check('grep "^root:" /etc/passwd | cut -f4 -d:')
    if '0' in success:
        return_value.append('root account GID is 0')
        return_value.append('PASS')
        return_value.append(
            'grep "^root:" /etc/passwd | cut -f4 -d: returned\n' + success)
    else:
        return_value.append('root account GID not 0')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _5_4_4_deb():
    return_value = list()
    success, error = check('grep "umask" /etc/bashrc')
    if success:
        umask_permissions = ['22', '23', '27',
                             '32', '33', '37', '72', '73', '77']
        if any(u in success for u in umask_permissions):
            result_success = success
            success, error = check('grep "umask" /etc/profile')
            if success:
                if any(u in success for u in umask_permissions):
                    result_success += success
                    success, error = check('grep "umask" /etc/profile.d/*.sh')
                    if success:
                        if all(any(u in s for u in umask_permissions) for s in success.splitlines()):
                            return_value.append(
                                'default user umask is restrictive')
                            return_value.append('PASS')
                            return_value.append(
                                result_success + '\n' + success)
                        else:
                            return_value.append(
                                'profile.d/*.sh umask not less than 027')
                            return_value.append('FAIL')
                            return_value.append(success)
                    else:
                        return_value.append(
                            'umask not found in profile.d/*.sh')
                        return_value.append('FAIL')
                        return_value.append(result_success + '\n' + error)
                else:
                    return_value.append(
                        'profile umask not restrictive than 027')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('umask not found in profile')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('bashrc umask not 027 or more restrictive')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('umask not found in bashrc')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _5_4_5_deb():
    return_value = list()
    success, error = check('grep "^TMOUT" /etc/bashrc')
    if success:
        if all(s.strip('=')[1].lstrip('-').isdigit() and int(s.strip('=')[1]) != -1 and int(s.strip('=')[1]) <= 900 for s in success.splitlines()):
            result_success = success
            success, error = check('grep "^TMOUT" /etc/profile')
            if success:
                if all(s.strip('=')[1].lstrip('-').isdigit() and int(s.strip('=')[1]) != -1 and int(s.strip('=')[1]) <= 900 for s in success.splitlines()):
                    return_value.append('user shell timeout is lt 900 sec')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('profile shell timeout not lt 900 sec')
                    return_value.append('FAIL')
                    return_value.append(result_success + '\n' + success)
            else:
                return_value.append('shell timeout not in profile')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('bashrc shell timeout not lt 900 sec')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('shell timeout not in bashrc')
        return_value.append('FAIL')
        return_value.append(
            'grep "^TMOUT" /etc/bashrc returned the following\n' + error)
    return return_value


def _5_5_deb():
    return_value = list()
    success, error = check('cat /etc/securetty')
    if success:
        return_value.append('root login is restricted to system')
        return_value.append('PASS')
        return_value.append(
            'check if following are valid terminals that may be logged in directly as root\n' + success)
    else:
        return_value.append('root login not restricted to system')
        return_value.append('FAIL')
        return_value.append(
            'cat /etc/securetty returned the following\n' + error)
    return return_value


def _5_6_deb():
    return_value = list()
    success, error = check('grep pam_wheel.so /etc/pam.d/su')
    if success:
        if any('auth       required   pam_wheel.so use_uid' in s and not s.startswith('#') for s in success.splitlines()):
            result_success = success
            success, error = check('grep sudo /etc/group')
            if success:
                if all(s.startswith('sudo:x:10:root,') for s in success.splitlines()):
                    return_value.append('access to su command is restricted')
                    return_value.append('PASS')
                    return_value.append(
                        result_success + '\nverify users in sudo group match site policy\n' + success)
                else:
                    return_value.append('access to su command not restricted')
                    return_value.append('FAIL')
                    return_value.append(result_success + '\n' + success)
            else:
                return_value.append('access to su command not restricted')
                return_value.append('FAIL')
                return_value.append(
                    result_success + '\ngrep sudo /etc/group returned the following\n' + error)
        else:
            return_value.append('access to su command not restricted')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('access to su command not restricted')
        return_value.append('FAIL')
        return_value.append(
            'grep pam_wheel.so /etc/pam.d/su returned the following\n' + error)
    return return_value


def _6_1_1_deb():
    return_value = list()
    global log_file
    write_log = log_file.split(
        '_SeBAz_logs/')[0] + '.system_file_permissions.SeBAz.log'
    success, error = check('dpkg --verify > ' + write_log)
    return_value.append('Audit system file permissions')
    return_value.append('CHEK')
    return_value.append('Verify the contents of ' +
                        write_log.split('/')[-1] + '\n' + success + '\n' + error)
    return return_value


def _6_1_2_deb():
    return_value = list()
    success, error = check('stat /etc/gshadow | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith('shadow)'):
                allowed_access = [
                    '(0640/-rw-r-----)', '(0600/-rw-------)', '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/gshadow permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/gshadow permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/gshadow invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/gshadow invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/gshadow not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/gshadow | grep Access did not return anything\n' + error)
    return return_value


def _6_1_3_deb():
    return_value = list()
    success, error = check('stat /etc/shadow- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith('shadow)'):
                allowed_access = [
                    '(0640/-rw-r-----)', '(0600/-rw-------)', '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/shadow- permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/shadow- permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/shadow- invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/shadow- invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/shadow- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/shadow- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_4_deb():
    return_value = list()
    success, error = check('stat /etc/gshadow- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith('shadow)'):
                allowed_access = [
                    '(0640/-rw-r-----)', '(0600/-rw-------)', '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/gshadow- permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/gshadow- permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/gshadow- invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/gshadow- invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/gshadow- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/gshadow- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_5_deb():
    return_value = list()
    success, error = check('stat /etc/passwd | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/passwd permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/passwd permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/passwd invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/passwd not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/passwd | grep Access did not return anything\n' + error)
    return return_value


def _6_1_6_deb():
    return_value = list()
    success, error = check('stat /etc/shadow | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith('shadow)'):
                allowed_access = ['(0640/-rw-r-----)', '(0600/-rw-------)',
                                  '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/shadow permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/shadow permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/shadow invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/shadow invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/shadow not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/shadow | grep Access did not return anything\n' + error)
    return return_value


def _6_1_7_deb():
    return_value = list()
    success, error = check('stat /etc/group | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/group permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/group permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/group invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/group not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/group | grep Access did not return anything\n' + error)
    return return_value


def _6_1_8_deb():
    return_value = list()
    success, error = check('stat /etc/passwd- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            allowed_access = ['(0644/-rw-r--r--)', '(0640/-rw-r-----)', '(0600/-rw-------)',
                              '(0444/-r--r--r--)', '(0440/-r--r-----)', '(0400/-r--------)']
            if any(a in success for a in allowed_access):
                return_value.append('/etc/passwd- permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/passwd- permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/passwd- invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/passwd- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/passwd- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_9_deb():
    return_value = list()
    success, error = check('stat /etc/group- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            allowed_access = ['(0644/-rw-r--r--)', '(0640/-rw-r-----)', '(0600/-rw-------)',
                              '(0444/-r--r--r--)', '(0440/-r--r-----)', '(0400/-r--------)']
            if any(a in success for a in allowed_access):
                return_value.append('/etc/group- permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/group- permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/group- invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/group- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/group- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_10_deb():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check(
                    'find ' + p + ' -xdev -type f -perm -0002')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('world writable files does not exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 confirms that all world writable directories have the sticky variable set\n" + result_error)
            else:
                return_value.append('world writable files exist in partitions')
                return_value.append('FAIL')
                return_value.append(
                    'The following world writable files exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('world writable files does not exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 confirms that all world writable directories have the sticky variable set\n" + result_error + '\n' + error)
    else:
        return_value.append('world writable files exist')
        return_value.append('FAIL')
        return_value.append(
            'The following world writable files exist\n' + success)
    return return_value


def _6_1_11_deb():
    return_value = list()
    success, error = check(
        "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check('find ' + p + ' -xdev -nouser')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('no unowned files or directories exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser confirms that no unowned files or directories exist\n" + result_error)
            else:
                return_value.append('unowned files or directories exist')
                return_value.append('FAIL')
                return_value.append(
                    'The following unowned files or directories exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('no unowned files or directories exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser confirms that no unowned files or directories exist\n" + result_error + '\n' + error)
    else:
        return_value.append('unowned files or directories exist')
        return_value.append('FAIL')
        return_value.append(
            'The following unowned files or directories exist\n' + success)
    return return_value


def _6_1_12_deb():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check('find ' + p + ' -xdev -nogroup')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('no ungrouped files or directories exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup confirms that no ungrouped files or directories exist\n" + result_error)
            else:
                return_value.append('ungrouped files or directories exist')
                return_value.append('FAIL')
                return_value.append(
                    'The following ungrouped files or directories exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('no ungrouped files or directories exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup confirms that no ungrouped files or directories exist\n" + result_error + '\n' + error)
    else:
        return_value.append('ungrouped files or directories exist')
        return_value.append('FAIL')
        return_value.append(
            'The following ungrouped files or directories exist\n' + success)
    return return_value


def _6_1_13_deb():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check(
                    'find ' + p + ' -xdev -type f -perm -4000')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('SUID executables does not exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 confirms that SUID executables does not exist\n" + result_error)
            else:
                return_value.append('SUID executables found')
                return_value.append('FAIL')
                return_value.append(
                    'The following SUID executables exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('SUID executables does not exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 confirms that SUID executables does not exist\n" + result_error + '\n' + error)
    else:
        return_value.append('SUID executables found')
        return_value.append('FAIL')
        return_value.append(
            'The following SUID executables exist\n' + success)
    return return_value


def _6_1_14_deb():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check(
                    'find ' + p + ' -xdev -type f -perm -2000')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('SGID executables does not exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 confirms that SGID executables does not exist\n" + result_error)
            else:
                return_value.append('SGID executables found')
                return_value.append('FAIL')
                return_value.append(
                    'The following SGID executables exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('SGID executables does not exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 confirms that SGID executables does not exist\n" + result_error + '\n' + error)
    else:
        return_value.append('SGID executables found')
        return_value.append('FAIL')
        return_value.append(
            'The following SGID executables exist\n' + success)
    return return_value


def _6_2_1_deb():
    return_value = list()
    success, error = check(
        'cat /etc/shadow | awk -F: \'($2 == "" ) { print $1 " does not have a password "}\'')
    if not success:
        return_value.append('password fields are not empty')
        return_value.append('PASS')
        return_value.append(
            'cat /etc/shadow | awk -F: \'($2 == "" ) { print $1 " does not have a password "}\' returned the following\n' + error)
    else:
        return_value.append('password fields are empty')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have empty password fields\n' + success)
    return return_value


def _6_2_2_deb():
    return_value = list()
    success, error = check("grep '^\+:' /etc/passwd")
    if not success:
        return_value.append('no legacy "+" entries exist in /etc/passwd')
        return_value.append('PASS')
        return_value.append(
            "grep '^\+:' /etc/passwd returned the following\n" + error)
    else:
        return_value.append('legacy "+" entries exist in /etc/passwd')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have legacy "+" entries in /etc/passwd\n' + success)
    return return_value


def _6_2_3_deb():
    return_value = list()
    success, error = check("grep '^\+:' /etc/shadow")
    if not success:
        return_value.append('no legacy "+" entries exist in /etc/shadow')
        return_value.append('PASS')
        return_value.append(
            "grep '^\+:' /etc/shadow returned the following\n" + error)
    else:
        return_value.append('legacy "+" entries exist in /etc/shadow')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have legacy "+" entries in /etc/shadow\n' + success)
    return return_value


def _6_2_4_deb():
    return_value = list()
    success, error = check("grep '^\+:' /etc/group")
    if not success:
        return_value.append('no legacy "+" entries exist in /etc/group')
        return_value.append('PASS')
        return_value.append(
            "grep '^\+:' /etc/group returned the following\n" + error)
    else:
        return_value.append('legacy "+" entries exist in /etc/group')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have legacy "+" entries in /etc/group\n' + success)
    return return_value


def _6_2_5_deb():
    return_value = list()
    success, error = check(
        "cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'")
    if success:
        if 'root\n' == success:
            return_value.append('root is the only UID 0 account')
            return_value.append('PASS')
            return_value.append(
                "cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' returned the following\n" + success)
        else:
            return_value.append('root is not the only UID 0 account')
            return_value.append('FAIL')
            return_value.append(
                "cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' returned the following UID 0 accounts\n" + success)
    else:
        return_value.append('no UID 0 account found')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _6_2_6_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_6.sh')
    check('sudo cat ' + script + ' > ./root_path_integrity.sh')
    check('chmod +x ./root_path_integrity.sh')
    success, error = check('./root_path_integrity.sh')
    if not success:
        return_value.append('root PATH Integrity maintained')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_6.sh returned the following\n' + error)
    else:
        return_value.append('writable dir in root\'s executable path')
        return_value.append('FAIL')
        return_value.append(
            'The following writable directories were found in root\'s executable path\n' + success)
    check('rm ./root_path_integrity.sh')
    return return_value


def _6_2_7_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_7.sh')
    check('sudo cat ' + script + ' > ./home_directories.sh')
    check('chmod +x ./home_directories.sh')
    success, error = check('./home_directories.sh')
    if not success:
        return_value.append('all users\' home directories exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_7.sh returned the following\n' + error)
    else:
        return_value.append('users without home directory')
        return_value.append('FAIL')
        return_value.append(
            'The following users are without home directory\n' + success)
    check('rm ./home_directories.sh')
    return return_value


def _6_2_8_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_8.sh')
    check('sudo cat ' + script + ' > ./home_directory_permissions.sh')
    check('chmod +x ./home_directory_permissions.sh')
    success, error = check('./home_directory_permissions.sh')
    if not success:
        return_value.append('home directories permissions are gt 750')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_8.sh returned the following\n' + error)
    else:
        return_value.append('Group or world-writable home directories')
        return_value.append('FAIL')
        return_value.append(
            'The following users have Group or world-writable home directories\n' + success)
    check('rm ./home_directory_permissions.sh')
    return return_value


def _6_2_9_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_9.sh')
    check('sudo cat ' + script + ' > ./own_home_directory.sh')
    check('chmod +x ./own_home_directory.sh')
    success, error = check('./own_home_directory.sh')
    if not success:
        return_value.append('users own their home directories')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_9.sh returned the following\n' + error)
    else:
        return_value.append('user not owner of home directory')
        return_value.append('FAIL')
        return_value.append(
            'The following users are not the not owner of their home directories\n' + success)
    check('rm ./own_home_directory.sh')
    return return_value


def _6_2_10_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_10.sh')
    check('sudo cat ' + script + ' > ./user_dot_file.sh')
    check('chmod +x ./user_dot_file.sh')
    success, error = check('./user_dot_file.sh')
    if not success:
        return_value.append('users\' . files not group or world-writable')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_10.sh returned the following\n' + error)
    else:
        return_value.append('users\' . files group or world-writable')
        return_value.append('FAIL')
        return_value.append(
            'The following  users\' dot files are group or world writable\n' + success)
    check('rm ./user_dot_file.sh')
    return return_value


def _6_2_11_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_11.sh')
    check('sudo cat ' + script + ' > ./user_forward_file.sh')
    check('chmod +x ./user_forward_file.sh')
    success, error = check('./user_forward_file.sh')
    if not success:
        return_value.append('no users have .forward files')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_11.sh returned the following\n' + error)
    else:
        return_value.append('users have .forward files')
        return_value.append('FAIL')
        return_value.append(
            'The following users have .forward files\n' + success)
    check('rm ./user_forward_file.sh')
    return return_value


def _6_2_12_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_12.sh')
    check('sudo cat ' + script + ' > ./user_netrc_file.sh')
    check('chmod +x ./user_netrc_file.sh')
    success, error = check('./user_netrc_file.sh')
    if not success:
        return_value.append('no users have .netrc files')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_12.sh returned the following\n' + error)
    else:
        return_value.append('users have .netrc files')
        return_value.append('FAIL')
        return_value.append(
            'The following users have .netrc files\n' + success)
    check('rm ./user_netrc_file.sh')
    return return_value


def _6_2_13_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_13.sh')
    check('sudo cat ' + script + ' > ./user_netrc_writable.sh')
    check('chmod +x ./user_netrc_writable.sh')
    success, error = check('./user_netrc_writable.sh')
    if not success:
        return_value.append('users\' .netrc not group or world accessible')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_13.sh returned the following\n' + error)
    else:
        return_value.append('users\' .netrc group or world accessible')
        return_value.append('FAIL')
        return_value.append(
            'The following users\' .netrc Files are not group or world accessible\n' + success)
    check('rm ./user_netrc_writable.sh')
    return return_value


def _6_2_14_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_14.sh')
    check('sudo cat ' + script + ' > ./user_rhosts_file.sh')
    check('chmod +x ./user_rhosts_file.sh')
    success, error = check('./user_rhosts_file.sh')
    if not success:
        return_value.append('no users have .rhosts files')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_14.sh returned the following\n' + error)
    else:
        return_value.append('users have .rhosts files')
        return_value.append('FAIL')
        return_value.append(
            'The following users have .rhosts files\n' + success)
    check('rm ./user_rhosts_file.sh')
    return return_value


def _6_2_15_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_15.sh')
    check('sudo cat ' + script + ' > ./group_passwd.sh')
    check('chmod +x ./group_passwd.sh')
    success, error = check('./group_passwd.sh')
    if not success:
        return_value.append('all groups in passwd exist in group')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_15.sh returned the following\n' + error)
    else:
        return_value.append('groups in passwd don\'t exist in group')
        return_value.append('FAIL')
        return_value.append(
            'The following groups in /etc/passwd don\'t exist in /etc/group\n' + success)
    check('rm ./group_passwd.sh')
    return return_value


def _6_2_16_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_16.sh')
    check('sudo cat ' + script + ' > ./duplicate_uid.sh')
    check('chmod +x ./duplicate_uid.sh')
    success, error = check('./duplicate_uid.sh')
    if not success:
        return_value.append('no duplicate UIDs exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_16.sh returned the following\n' + error)
    else:
        return_value.append('duplicate UIDs exist')
        return_value.append('FAIL')
        return_value.append('The following duplicate UIDs exist\n' + success)
    check('rm ./duplicate_uid.sh')
    return return_value


def _6_2_17_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_17.sh')
    check('sudo cat ' + script + ' > ./duplicate_gid.sh')
    check('chmod +x ./duplicate_gid.sh')
    success, error = check('./duplicate_gid.sh')
    if not success:
        return_value.append('no duplicate GIDs exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_17.sh returned the following\n' + error)
    else:
        return_value.append('duplicate GIDs exist')
        return_value.append('FAIL')
        return_value.append('The following duplicate GIDs exist\n' + success)
    check('rm ./duplicate_gid.sh')
    return return_value


def _6_2_18_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_18.sh')
    check('sudo cat ' + script + ' > ./duplicate_user_name.sh')
    check('chmod +x ./duplicate_user_name.sh')
    success, error = check('./duplicate_user_name.sh')
    if not success:
        return_value.append('no duplicate user names exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_18.sh returned the following\n' + error)
    else:
        return_value.append('duplicate user names exist')
        return_value.append('FAIL')
        return_value.append(
            'The following duplicate user names exist\n' + success)
    check('rm ./duplicate_user_name.sh')
    return return_value


def _6_2_19_deb():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/deb/6_2_19.sh')
    check('sudo cat ' + script + ' > ./duplicate_group_name.sh')
    check('chmod +x ./duplicate_group_name.sh')
    success, error = check('./duplicate_group_name.sh')
    if not success:
        return_value.append('no duplicate group names exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/deb/6_2_19.sh returned the following\n' + error)
    else:
        return_value.append('duplicate group names exist')
        return_value.append('FAIL')
        return_value.append(
            'The following duplicate group names exist\n' + success)
    check('rm ./duplicate_group_name.sh')
    return return_value


def _6_2_20_deb():
    return_value = list()
    success, error = check('grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group')
    if not success:
        return_value.append('users not assigned to shadow group')
        return_value.append('PASS')
        return_value.append(
            'grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group returned the following\n' + error)
    else:
        result_success = ''
        result_error = ''
        for shadow_gid in success.splitlines():
            result = check("awk -F: '($4 == \"" + shadow_gid +
                           "\") { print }' /etc/passwd")
            result_success += result[0]
            result_error += result[1]
        if len(result_success):
            return_value.append('users not assigned to shadow group')
            return_value.append('PASS')
            return_value.append(
                'Following GIDs don\'t have entries in passwd\n' + success + '\n' + result_error)
        else:
            return_value.append(
                'users assigned to shadow group in /etc/passwd')
            return_value.append('FAIL')
            return_value.append('The following users are assigned to the shadow group in /etc/passwd\n' +
                                success + '\n' + result_success + '\n' + result_error + '\n' + error)
    return return_value


"""
Definitions of Functions that perform Fedora checks against benchmarks
return_value[0] = result
return_value[1] = PASS/FAIL/CHEK
return_value[2] = success/error message
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_fed():
    return_value = list()
    success, error = check('modprobe -n -v cramfs')
    if 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep cramfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('cramfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('cramfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('cramfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_2_fed():
    return_value = list()
    success, error = check("grep -E -i '\svfat\s' /etc/fstab")
    if success:
        return_value.append('vfat is mounted')
        return_value.append('CHEK')
        return_value.append(success)
    else:
        success, error = check('modprobe -n -v vfat')
        if 'insmod' in success:
            return_value.append('vfat can be mounted')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            result_success = success
            result_error = error
            success, error = check('lsmod | grep vfat')
            if 'install /bin/true' in result_success or 'not found in directory' in result_error:
                if not success:
                    return_value.append('vfat cannot be mounted')
                    return_value.append('PASS')
                    return_value.append(
                        result_success if result_success else result_error)
                else:
                    return_value.append('vfat is mounted')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success if result_success else result_error + '\n' + success)
            else:
                return_value.append('vfat mount status undetermined')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_3_fed():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'insmod' in success:
        return_value.append('squashfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep squashfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('squashfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('squashfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('squashfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_4_fed():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep udf')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('udf cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('udf is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('udf mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_2_fed():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_value.append('/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('/tmp is not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_3_fed():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything\n" + success)
        else:
            return_value.append('nodev is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' returned the following\n" + return_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nodev is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_4_fed():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything\n" + success)
        else:
            return_value.append('nosuid is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid returned\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nosuid is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_5_fed():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything\n" + success)
        else:
            return_value.append('noexec is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec returned the following\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('noexec is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_6_fed():
    return_value = list()
    success, error = check("mount | grep -E '\s/var\s'")
    if success:
        return_value.append('/var is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep -E '\s/var\s' did not return any result")
    return return_value


def _1_1_7_fed():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        return_value.append('/var/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/tmp is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/tmp did not return any result")
    return return_value


def _1_1_8_fed():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_fed():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_fed():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_11_fed():
    return_value = list()
    success, error = check('mount | grep /var/log')
    if success:
        return_value.append('/var/log is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/log did not return any result")
    return return_value


def _1_1_12_fed():
    return_value = list()
    success, error = check('mount | grep /var/log/audit')
    if success:
        return_value.append('/var/log/audit is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log/audit is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep /var/log/audit did not return any result")
    return return_value


def _1_1_13_fed():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        return_value.append('/home is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/home is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /home did not return any result")
    return return_value


def _1_1_14_fed():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        success, error = check("mount | grep -E '\s/home\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /home')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /home')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append(
            "/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_fed():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_fed():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_fed():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_18_fed():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nodev = [drive for drive in success.splitlines()
                 if 'nodev' not in drive]
        if not nodev:
            return_value.append('nodev is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nodev is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nodev" set\n'
            for n in nodev:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_19_fed():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nosuid = [drive for drive in success.splitlines()
                  if 'nosuid' not in drive]
        if not nosuid:
            return_value.append('nosuid is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nosuid is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nosuid" set\n'
            for n in nosuid:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_20_fed():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        noexec = [drive for drive in success.splitlines()
                  if 'noexec' not in drive]
        if not noexec:
            return_value.append('noexec is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('noexec is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "noexec" set\n'
            for n in noexec:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_21_fed():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append(
            "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append(
            'The following directories does not have their sticky bit set\n' + success)
    return return_value


def _1_1_22_fed():
    return_value = list()
    success, error = check('systemctl is-enabled autofs | grep enabled')
    if error:
        return_value.append('automounting could not be checked')
        return_value.append('CHEK')
        return_value.append(error)
    else:
        if 'enabled' in success:
            return_value.append('automounting is enabled')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            return_value.append('automounting is disabled')
            return_value.append('PASS')
            return_value.append(success)
    return return_value


def _1_1_23_fed():
    return_value = list()
    success, error = check('modprobe -n -v usb-storage')
    if 'insmod' in success:
        return_value.append('usb-storage can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep usb-storage')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('usb-storage cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('usb-storage is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('usb-storage mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


"""
Definitions of Functions that perform RedHat checks against benchmarks
return_value[0] = result
return_value[1] = PASS/FAIL/CHEK
return_value[2] = success/error message
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_red():
    return_value = list()
    success, error = check('modprobe -n -v cramfs')
    if 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep cramfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('cramfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('cramfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('cramfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_2_red():
    return_value = list()
    success, error = check("grep -E -i '\svfat\s' /etc/fstab")
    if success:
        return_value.append('vfat is mounted')
        return_value.append('CHEK')
        return_value.append(success)
    else:
        success, error = check('modprobe -n -v vfat')
        if 'insmod' in success:
            return_value.append('vfat can be mounted')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            result_success = success
            result_error = error
            success, error = check('lsmod | grep vfat')
            if 'install /bin/true' in result_success or 'not found in directory' in result_error:
                if not success:
                    return_value.append('vfat cannot be mounted')
                    return_value.append('PASS')
                    return_value.append(
                        result_success if result_success else result_error)
                else:
                    return_value.append('vfat is mounted')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success if result_success else result_error + '\n' + success)
            else:
                return_value.append('vfat mount status undetermined')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_3_red():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'insmod' in success:
        return_value.append('squashfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep squashfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('squashfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('squashfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('squashfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_4_red():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep udf')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('udf cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('udf is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('udf mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_2_red():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_value.append('/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('/tmp is not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_3_red():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything\n" + success)
        else:
            return_value.append('nodev is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' returned the following\n" + return_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nodev is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_4_red():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything\n" + success)
        else:
            return_value.append('nosuid is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid returned\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nosuid is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_5_red():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything\n" + success)
        else:
            return_value.append('noexec is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec returned the following\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('noexec is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_6_red():
    return_value = list()
    success, error = check("mount | grep -E '\s/var\s'")
    if success:
        return_value.append('/var is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep -E '\s/var\s' did not return any result")
    return return_value


def _1_1_7_red():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        return_value.append('/var/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/tmp is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/tmp did not return any result")
    return return_value


def _1_1_8_red():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_red():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_red():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_11_red():
    return_value = list()
    success, error = check('mount | grep /var/log')
    if success:
        return_value.append('/var/log is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/log did not return any result")
    return return_value


def _1_1_12_red():
    return_value = list()
    success, error = check('mount | grep /var/log/audit')
    if success:
        return_value.append('/var/log/audit is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log/audit is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep /var/log/audit did not return any result")
    return return_value


def _1_1_13_red():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        return_value.append('/home is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/home is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /home did not return any result")
    return return_value


def _1_1_14_red():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        success, error = check("mount | grep -E '\s/home\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /home')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /home')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append(
            "/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_red():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_red():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_red():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_18_red():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nodev = [drive for drive in success.splitlines()
                 if 'nodev' not in drive]
        if not nodev:
            return_value.append('nodev is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nodev is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nodev" set\n'
            for n in nodev:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_19_red():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nosuid = [drive for drive in success.splitlines()
                  if 'nosuid' not in drive]
        if not nosuid:
            return_value.append('nosuid is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nosuid is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nosuid" set\n'
            for n in nosuid:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_20_red():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        noexec = [drive for drive in success.splitlines()
                  if 'noexec' not in drive]
        if not noexec:
            return_value.append('noexec is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('noexec is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "noexec" set\n'
            for n in noexec:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_21_red():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append(
            "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append(
            'The following directories does not have their sticky bit set\n' + success)
    return return_value


def _1_1_22_red():
    return_value = list()
    success, error = check('systemctl is-enabled autofs | grep enabled')
    if error:
        return_value.append('automounting could not be checked')
        return_value.append('CHEK')
        return_value.append(error)
    else:
        if 'enabled' in success:
            return_value.append('automounting is enabled')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            return_value.append('automounting is disabled')
            return_value.append('PASS')
            return_value.append(success)
    return return_value


def _1_1_23_red():
    return_value = list()
    success, error = check('modprobe -n -v usb-storage')
    if 'insmod' in success:
        return_value.append('usb-storage can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep usb-storage')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('usb-storage cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('usb-storage is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('usb-storage mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


"""
Definitions of Functions that perform SUSE checks against benchmarks
return_value[0] = result
return_value[1] = PASS/FAIL/CHEK
return_value[2] = success/error message
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_sus():
    return_value = list()
    success, error = check('modprobe -n -v cramfs')
    if 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep cramfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('cramfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('cramfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('cramfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_2_sus():
    return_value = list()
    success, error = check('modprobe -n -v freevxfs')
    if 'insmod' in success:
        return_value.append('freevxfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep freevxfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('freevxfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('freevxfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('freevxfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_3_sus():
    return_value = list()
    success, error = check('modprobe -n -v jffs2')
    if 'insmod' in success:
        return_value.append('jffs2 can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep jffs2')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('jffs2 cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('jffs2 is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('jffs2 mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_4_sus():
    return_value = list()
    success, error = check('modprobe -n -v hfs')
    if 'insmod' in success:
        return_value.append('hfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep hfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('hfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('hfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('hfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_5_sus():
    return_value = list()
    success, error = check('modprobe -n -v hfsplus')
    if 'insmod' in success:
        return_value.append('hfsplus can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep hfsplus')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('hfsplus cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('hfsplus is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('hfsplus mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_6_sus():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'insmod' in success:
        return_value.append('squashfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep squashfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('squashfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('squashfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('squashfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_7_sus():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep udf')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('udf cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('udf is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('udf mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_8_sus():
    return_value = list()
    success, error = check('modprobe -n -v vfat')
    if 'insmod' in success:
        return_value.append('vfat can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep vfat')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('vfat cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('vfat is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('vfat mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_2_sus():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_value.append('/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/tmp is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep -E '\s/tmp\s'\ndid not return any result")
    return return_value


def _1_1_3_sus():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything\n" + success)
        else:
            return_value.append('nodev is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' returned the following\n" + return_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nodev is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_4_sus():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything\n" + success)
        else:
            return_value.append('nosuid is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid returned\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nosuid is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_5_sus():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything\n" + success)
        else:
            return_value.append('noexec is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec returned the following\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('noexec is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_6_sus():
    return_value = list()
    success, error = check("mount | grep -E '\s/var\s'")
    if success:
        return_value.append('/var is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep -E '\s/var\s' did not return any result")
    return return_value


def _1_1_7_sus():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        return_value.append('/var/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/tmp is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/tmp did not return any result")
    return return_value


def _1_1_8_sus():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_sus():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_sus():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_11_sus():
    return_value = list()
    success, error = check('mount | grep /var/log')
    if success:
        return_value.append('/var/log is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/log did not return any result")
    return return_value


def _1_1_12_sus():
    return_value = list()
    success, error = check('mount | grep /var/log/audit')
    if success:
        return_value.append('/var/log/audit is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log/audit is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep /var/log/audit did not return any result")
    return return_value


def _1_1_13_sus():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        return_value.append('/home is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/home is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /home did not return any result")
    return return_value


def _1_1_14_sus():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        success, error = check("mount | grep -E '\s/home\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /home')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /home')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append(
            "/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_sus():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_sus():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_sus():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_18_sus():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nodev = [drive for drive in success.splitlines()
                 if 'nodev' not in drive]
        if not nodev:
            return_value.append('nodev is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nodev is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nodev" set\n'
            for n in nodev:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_19_sus():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nosuid = [drive for drive in success.splitlines()
                  if 'nosuid' not in drive]
        if not nosuid:
            return_value.append('nosuid is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nosuid is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nosuid" set\n'
            for n in nosuid:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_20_sus():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        noexec = [drive for drive in success.splitlines()
                  if 'noexec' not in drive]
        if not noexec:
            return_value.append('noexec is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('noexec is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "noexec" set\n'
            for n in noexec:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_21_sus():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append(
            "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append(
            'The following directories does not have their sticky bit set\n' + success)
    return return_value


def _1_1_22_sus():
    return_value = list()
    success, error = check('systemctl is-enabled autofs | grep enabled')
    if error:
        return_value.append('automounting could not be checked')
        return_value.append('CHEK')
        return_value.append(error)
    else:
        if 'enabled' in success:
            return_value.append('automounting is enabled')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            return_value.append('automounting is disabled')
            return_value.append('PASS')
            return_value.append(success)
    return return_value


"""
Definitions of Functions that perform Ubuntu checks against benchmarks
return_value[0] = result
return_value[1] = PASS/FAIL/CHEK
return_value[2] = success/error message
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_ubu():
    return_value = list()
    success, error = check('modprobe -n -v cramfs')
    if 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep cramfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('cramfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('cramfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('cramfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_2_ubu():
    return_value = list()
    success, error = check('modprobe -n -v freevxfs')
    if 'insmod' in success:
        return_value.append('freevxfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep freevxfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('freevxfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('freevxfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('freevxfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_3_ubu():
    return_value = list()
    success, error = check('modprobe -n -v jffs2')
    if 'insmod' in success:
        return_value.append('jffs2 can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep jffs2')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('jffs2 cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('jffs2 is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('jffs2 mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_4_ubu():
    return_value = list()
    success, error = check('modprobe -n -v hfs')
    if 'insmod' in success:
        return_value.append('hfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep hfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('hfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('hfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('hfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_5_ubu():
    return_value = list()
    success, error = check('modprobe -n -v hfsplus')
    if 'insmod' in success:
        return_value.append('hfsplus can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep hfsplus')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('hfsplus cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('hfsplus is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('hfsplus mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_6_ubu():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'insmod' in success:
        return_value.append('squashfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep squashfs')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('squashfs cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('squashfs is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('squashfs mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_7_ubu():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep udf')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('udf cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('udf is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('udf mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_1_8_ubu():
    return_value = list()
    success, error = check('grep -i vfat /etc/fstab')
    if success:
        return_value.append('vfat is mounted')
        return_value.append('CHEK')
        return_value.append(success)
    else:
        success, error = check('modprobe -n -v vfat')
        if 'insmod' in success:
            return_value.append('vfat can be mounted')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            result_success = success
            result_error = error
            success, error = check('lsmod | grep vfat')
            if 'install /bin/true' in result_success or 'not found in directory' in result_error:
                if not success:
                    return_value.append('vfat cannot be mounted')
                    return_value.append('PASS')
                    return_value.append(
                        result_success if result_success else result_error)
                else:
                    return_value.append('vfat is mounted')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success if result_success else result_error + '\n' + success)
            else:
                return_value.append('vfat mount status undetermined')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_1_2_ubu():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_value.append('/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('/tmp is not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_3_ubu():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        return_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything\n" + success)
        else:
            return_value.append('nodev is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' returned the following\n" + return_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nodev is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_4_ubu():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything\n" + success)
        else:
            return_value.append('nosuid is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid returned\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('nosuid is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_5_ubu():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        result_success = success
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything\n" + success)
        else:
            return_value.append('noexec is not set on /tmp')
            return_value.append('FAIL')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec returned the following\n" + result_success)
    else:
        success, error = check('systemctl is-enabled tmp.mount')
        return_value.append('noexec is not set on /tmp')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_1_6_ubu():
    return_value = list()
    success, error = check("mount | grep -E '\s/var\s'")
    if success:
        return_value.append('/var is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep -E '\s/var\s' did not return any result")
    return return_value


def _1_1_7_ubu():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        return_value.append('/var/tmp is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/tmp is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/tmp did not return any result")
    return return_value


def _1_1_8_ubu():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_ubu():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_ubu():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check(
            "mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /var/tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is not set on /var/tmp')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append(
            "/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_11_ubu():
    return_value = list()
    success, error = check('mount | grep /var/log')
    if success:
        return_value.append('/var/log is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /var/log did not return any result")
    return return_value


def _1_1_12_ubu():
    return_value = list()
    success, error = check('mount | grep /var/log/audit')
    if success:
        return_value.append('/var/log/audit is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/var/log/audit is not configured')
        return_value.append('FAIL')
        return_value.append(
            "mount | grep /var/log/audit did not return any result")
    return return_value


def _1_1_13_ubu():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        return_value.append('/home is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/home is not configured')
        return_value.append('FAIL')
        return_value.append("mount | grep /home did not return any result")
    return return_value


def _1_1_14_ubu():
    return_value = list()
    success, error = check('mount | grep /home')
    if success:
        success, error = check("mount | grep -E '\s/home\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /home')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /home')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append(
            "/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_ubu():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
        else:
            return_value.append('nodev is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_ubu():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
        else:
            return_value.append('nosuid is not set on /dev/shm')
            return_value.append('PASS')
            return_value.append(success if success else error)
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_ubu():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check(
            "mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /dev/shm')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
        else:
            return_value.append('noexec is not set on /dev/shm')
            return_value.append('FAIL')
            return_value.append(success if success else error)
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append(
            "/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_18_ubu():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nodev = [drive for drive in success.splitlines()
                 if 'nodev' not in drive]
        if not nodev:
            return_value.append('nodev is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nodev is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nodev" set\n'
            for n in nodev:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_19_ubu():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        nosuid = [drive for drive in success.splitlines()
                  if 'nosuid' not in drive]
        if not nosuid:
            return_value.append('nosuid is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('nosuid is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "nosuid" set\n'
            for n in nosuid:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_20_ubu():
    return_value = list()
    success, error = check("mount | grep -e '/media/'")
    if success:
        noexec = [drive for drive in success.splitlines()
                  if 'noexec' not in drive]
        if not noexec:
            return_value.append('noexec is set on all removable drives')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('noexec is not set on all removable drives')
            return_value.append('FAIL')
            result = 'The following removable storage media does not have "noexec" set\n'
            for n in noexec:
                result += n + '\n'
            return_value.append(result)
    else:
        return_value.append('No mounted media found')
        return_value.append('PASS')
        return_value.append("mount | grep -e '/media/' returned no result")
    return return_value


def _1_1_21_ubu():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append(
            "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append(
            'The following directories does not have their sticky bit set\n' + success)
    return return_value


def _1_1_22_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled autofs | grep enabled')
    if error:
        return_value.append('automounting could not be checked')
        return_value.append('CHEK')
        return_value.append(error)
    else:
        if 'enabled' in success:
            return_value.append('automounting is enabled')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            return_value.append('automounting is disabled')
            return_value.append('PASS')
            return_value.append(success)
    return return_value


def _1_1_23_ubu():
    return_value = list()
    success, error = check('modprobe -n -v usb-storage')
    if 'insmod' in success:
        return_value.append('usb-storage can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep usb-storage')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('usb-storage cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('usb-storage is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('usb-storage mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _1_2_1_ubu():
    return_value = list()
    success, error = check('apt-cache policy')
    if success:
        return_value.append('check configuration of repos')
        return_value.append('CHEK')
        return_value.append(
            'The following are the configuration of the package manager repositories\n' + success)
    else:
        return_value.append('package configuration not checked')
        return_value.append('CHEK')
        return_value.append(
            'apt-cache policy did not return anything\n' + error)
    return return_value


def _1_2_2_ubu():
    return_value = list()
    success, error = check('apt-key list')
    if success:
        return_value.append('check GPG keys source')
        return_value.append('CHEK')
        return_value.append(
            'The following are the configuration of the GPG keys\n' + success)
    else:
        return_value.append('GPG keys not checked')
        return_value.append('CHEK')
        return_value.append(
            'apt-key list did not return any keys\n' + error)
    return return_value


def _1_3_1_ubu():
    return_value = list()
    success, error = check('dpkg -s sudo')
    if success:
        return_value.append('sudo is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_error = error
        success, error = check('dpkg -s sudo-ldap')
        if success:
            return_value.append('sudo-ldap is installed')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('sudo is not installed')
            return_value.append('FAIL')
            return_value.append(return_error + '\n' + error)
    return return_value


def _1_3_2_ubu():
    return_value = list()
    success, error = check(
        "grep -Ei '^\s*Defaults\s+([^#]+,\s*)?use_pty(,\s+\S+\s*)*(\s+#.*)?$' /etc/sudoers /etc/sudoers.d/*")
    if success:
        return_value.append('sudo commands use pty')
        return_value.append('PASS')
        return_value.append(
            'Verify that sudo can only run other commands from a psuedo-pty\n' + success)
    else:
        return_value.append('sudo commands does not use pty')
        return_value.append('FAIL')
        return_value.append(
            "grep -Ei '^\s*Defaults\s+([^#]+,\s*)?use_pty(,\s+\S+\s*)*(\s+#.*)?$' /etc/sudoers /etc/sudoers.d/* returned\n" + error)
    return return_value


def _1_3_3_ubu():
    return_value = list()
    success, error = check(
        "grep -Ei '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/*")
    if 'Defaults logfile=' in success:
        return_value.append('sudo log file exists')
        return_value.append('PASS')
        return_value.append(
            'Verify path is a file location that conforms with local site policy\n' + success)
    else:
        return_value.append('sudo log file does not exist')
        return_value.append('FAIL')
        return_value.append(
            "grep -Ei '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/* returned\n" + success + '\n' + error)
    return return_value


def _1_4_1_ubu():
    return_value = list()
    success, error = check('dpkg -s aide')
    if success:
        return_value.append('AIDE is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('AIDE is not installed')
        return_value.append('FAIL')
        return_value.append('dpkg -s aide returned\n' + error)
    return return_value


def _1_4_2_ubu():
    return_value = list()
    success, error = check('crontab -u root -l | grep aide')
    if success:
        result = success
        success, error = check('grep -r aide /etc/cron.* /etc/crontab')
        if success:
            result += '\nThe following cron jobs are scheduled\n' + success
            return_value.append('file integrity is checked')
            return_value.append('PASS')
            return_value.append(result)
        else:
            result += '\nNo cron jobs are scheduled for AIDE\n' + error
            return_value.append('file integrity is not checked')
            return_value.append('FAIL')
            return_value.append(result)
    else:
        return_value.append('No AIDE cron jobs scheduled')
        return_value.append('FAIL')
        return_value.append(
            'grep -r aide /etc/cron.* /etc/crontab returned the following\n' + success + '\n' + error)
    return return_value


# bootloader specific
def _1_5_1_ubu():
    return_value = list()
    success, error = check('stat /boot/grub*/grub.cfg | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '------' in success.splitlines()[0].split()[1][-7:-1]:
                return_value.append('bootloader permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('bootloader permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('bootloader invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('grub config not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /boot/grub*/grub.cfg | grep Access returned\n' + success + '\n' + error)
    return return_value


# bootloader specific
def _1_5_2_ubu():
    return_value = list()
    success, error = check('grep "^set superusers" /boot/grub/grub.cfg')
    if success:
        result_success = success
        success, error = check('grep "^password" /boot/grub/grub.cfg')
        if success:
            if all(s.startswith('password_pbkdf2') for s in success.splitlines()):
                return_value.append('bootloader password is set')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + success)
            else:
                return_value.append('bootloader pwd not password_pbkdf2')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + success)
        else:
            return_value.append('bootloader user pwd not found')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('bootloader superusers not found')
        return_value.append('FAIL')
        return_value.append(
            'grep "^set superusers" /boot/grub/grub.cfg returned\n' + error)
    return return_value


def _1_5_3_ubu():
    return_value = list()
    success, error = check('grep ^root:[*\!]: /etc/shadow')
    if success:
        return_value.append('auth required for single user mode')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('auth not required for single user mode')
        return_value.append('FAIL')
        return_value.append(
            'grep ^root:[*\!]: /etc/shadow returned the following\n' + error)
    return return_value


# bootloader specific
def _1_5_4_ubu():
    return_value = list()
    success, error = check(
        'grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot')
    if 'PROMPT_FOR_CONFIRM="no"' in success:
        return_value.append('interactive boot disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('interactive boot not checked')
        return_value.append('CHEK')
        return_value.append(
            'grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot returned the following\n' + success + '\n' + error)
    return return_value


def _1_6_1_ubu():
    return_value = list()
    success, error = check("journalctl | grep 'protection: active'")
    if success:
        return_value.append('XD/NX support is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        result_error = error
        success, error = check(
            "[[ -n $(grep noexec[0-9]*=off /proc/cmdline) || -z $(grep -E -i ' (pae|nx) ' /proc/cpuinfo) || -n $(grep '\sNX\s.*\sprotection:\s' /var/log/dmesg | grep -v active) ]] && echo \"NX Protection is not active\"")
        if not success:
            return_value.append('XD/NX support is enabled')
            return_value.append('PASS')
            return_value.append(error)
        else:
            return_value.append('XD/NX not enabled')
            return_value.append('FAIL')
            return_value.append(result_error + '\n' + success + '\n' + error)
    return return_value


def _1_6_2_ubu():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('sysctl kernel.randomize_va_space')
    if '2' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    success, error = check(
        'grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*')
    if '2' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    if len(result_success.splitlines()) == 4:
        return_value.append('ASLR enabled')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('ASLR not enabled')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success +
                            '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


def _1_6_3_ubu():
    return_value = list()
    success, error = check('dpkg -s prelink')
    if not success:
        return_value.append('prelink is not installed')
        return_value.append('PASS')
        return_value.append(error)
    else:
        return_value.append('prelink is installed')
        return_value.append('FAIL')
        return_value.append('dpkg -s prelink returned\n' + success)
    return return_value


def _1_6_4_ubu():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check(
        'grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check('sysctl fs.suid_dumpable')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check(
        'grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    if len(result_success.splitlines()) == 6:
        return_value.append('core dumps are restricted')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('core dumps not restricted')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success +
                            '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


def _1_7_1_1_ubu():
    return_value = list()
    success, error = check('dpkg -s apparmor apparmor-utils')
    if success:
        return_value.append('AppArmor is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('AppArmor is not installed')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_7_1_2_ubu():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1" | grep -v \'/boot/memtest86+.bin\'')
    if not success:
        result_error = error
        success, error = check(
            'grep "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor" | grep -v \'/boot/memtest86+.bin\'')
        if not success:
            return_value.append('AppArmor enabled in boot-config')
            return_value.append('PASS')
            return_value.append(result_error + '\n' + error)
        else:
            return_value.append('security=apparmor not set in boot-config')
            return_value.append('FAIL')
            return_value.append(result_error + '\n' + success)
    else:
        return_value.append('apparmor=1 not set in boot-config')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


def _1_7_1_3_ubu():
    return_value = list()
    success, error = check('apparmor_status | grep profiles')
    if success:
        result_success = 'ensure that profiles are loaded, and in either enforce or complain mode\n' + success
        success, error = check('apparmor_status | grep processes')
        if success:
            result_success += '\nensure no processes are unconfined\n' + success
            return_value.append('AppArmor Profiles enforcing or complaining')
            return_value.append('PASS')
            return_value.append(result_success)
        else:
            return_value.append('AppArmor unconfined processes')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('AppArmor unloaded profiles')
        return_value.append('FAIL')
        return_value.append(result_success + '\n' + error)
    return return_value


def _1_7_1_4_ubu():
    return_value = list()
    success, error = check('apparmor_status')
    if success:
        loaded_profiles = [
            p for p in success.splitlines() if 'profiles are loaded.' in p]
        complain_profiles = [p for p in success.splitlines(
        ) if 'profiles are in complain mode.' in p]
        unconfined_process = [
            p for p in success.splitlines() if 'processes are unconfined' in p]
        if loaded_profiles and not loaded_profiles[0].startswith('0'):
            if complain_profiles and complain_profiles[0].startswith('0'):
                if unconfined_process and unconfined_process[0].startswith('0'):
                    return_value.append('all AppArmor Profiles are enforcing')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append('AppArmor processes are confined')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('AppArmor profiles are in complain mode')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('No AppArmor profiles are loaded')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('AppArmor status not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _1_8_1_1_ubu():
    return_value = list()
    success, error = check('cat /etc/motd')
    if success:
        result_success = success
        success, error = check(
            "grep -E -i \"(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/motd")
        if not success:
            return_value.append('motd is configured properly')
            return_value.append('PASS')
            return_value.append(
                'check if the message of the day matches site policy\n' + result_success)
        else:
            return_value.append('motd contains sensitive information')
            return_value.append('FAIL')
            return_value.append(
                'Following OS [or] patch level information were found in the message of the day\n' + result_success)
    else:
        return_value.append('no message of the day')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _1_8_1_2_ubu():
    return_value = list()
    success, error = check('cat /etc/issue')
    if success:
        result_success = success
        success, error = check(
            "grep -E -i \"(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue")
        if not success:
            return_value.append('login banner configured properly')
            return_value.append('PASS')
            return_value.append(
                'check if the local login warning banner matches site policy\n' + result_success)
        else:
            return_value.append('login banner contains sensitive info')
            return_value.append('FAIL')
            return_value.append(
                'Following OS [or] patch level information were found in the local login banner\n' + result_success)
    else:
        return_value.append('no local login warning banner')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _1_8_1_3_ubu():
    return_value = list()
    success, error = check('cat /etc/issue.net')
    if success:
        result_success = success
        success, error = check(
            "grep -E -i \"(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue.net")
        if not success:
            return_value.append('remote login banner configured properly')
            return_value.append('PASS')
            return_value.append(
                'check if the remote login warning banner matches site policy\n' + result_success)
        else:
            return_value.append('remote banner contains sensitive info')
            return_value.append('FAIL')
            return_value.append(
                'Following OS [or] patch level information were found in the remote login banner\n' + result_success)
    else:
        return_value.append('no remote login warning banner')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _1_8_1_4_ubu():
    return_value = list()
    success, error = check('stat /etc/motd | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/motd permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/motd permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/motd invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/motd not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/motd | grep Access did not return anything\n' + error)
    return return_value


def _1_8_1_5_ubu():
    return_value = list()
    success, error = check('stat /etc/issue | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/issue permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/issue permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/issue invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/issue not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/issue | grep Access did not return anything\n' + error)
    return return_value


def _1_8_1_6_ubu():
    return_value = list()
    success, error = check('stat /etc/issue.net | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/issue.net permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/issue.net permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/issue.net invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/issue.net not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/issue.net | grep Access did not return anything\n' + error)
    return return_value


def _1_8_2_ubu():
    return_value = list()
    success, error = check('cat /etc/gdm3/greeter.dconf-defaults')
    if success:
        result_success = success
        success, error = check(
            'cat /etc/gdm3/greeter.dconf-defaults | grep banner-message-')
        if success:
            if 'banner-message-enable=true' in success and not success.splitlines()[0].startswith('#'):
                if "banner-message-text='" in success and not success.splitlines()[1].startswith('#'):
                    return_value.append('GDM login banner is configured')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('no GDM login banner message')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('GDM banner message not enabled')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('GDM login banner not configured')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('GDM not found')
        return_value.append('CHEK')
        return_value.append(
            'cat /etc/gdm3/greeter.dconf-defaults did not return anything\n' + error)
    return return_value


def _1_9_ubu():
    return_value = list()
    success, error = check('apt-get -s upgrade')
    if success:
        if '0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.' in success:
            return_value.append('software installed properly')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('software packages need checking')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('software state not checked')
        return_value.append('CHEK')
        return_value.append(
            'apt-get -s upgrade did not return anything\n' + error)
    return return_value


def _2_1_1_ubu():
    return_value = list()
    success, error = check('dpkg -s xinetd')
    if success:
        return_value.append('xinetd is installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('xinetd is not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_1_2_ubu():
    return_value = list()
    success, error = check('dpkg -s openbsd-inetd')
    if success:
        return_value.append('openbsd-inetd is installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('openbsd-inetd is not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_2_1_1_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled systemd-timesyncd')
    if 'enabled' in success:
        return_value.append('systemd-timesyncd is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        result_error = success + '\n' + error
        success, error = check('dpkg -s ntp')
        if 'Status: install ok installed' in success:
            return_value.append('ntp is installed')
            return_value.append('PASS')
            return_value.append(success)
        else:
            result_error = success + '\n' + error
            success, error = check('dpkg -s chrony')
            if 'Status: install ok installed' in success:
                return_value.append('chrony is installed')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('time sync not used')
                return_value.append('FAIL')
                return_value.append(result_error + '\n' +
                                    success + '\n' + error)
    return return_value


def _2_2_1_2_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled systemd-timesyncd.service')
    if 'enabled' in success:
        result_success = success
        success, error = check('cat /etc/systemd/timesyncd.conf')
        if success:
            result_success += '\nEnsure that the NTP servers, NTP FallbackNTP servers, and RootDistanceMaxSec listed are in accordance with local policy\n' + success
            success, error = check('timedatectl status')
            if success:
                return_value.append('system clock is synchronized')
                return_value.append('PASS')
                return_value.append(result_success + '\nCheck\n' + success)
            else:
                return_value.append('system clock not synchronized')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('no timesync daemon found')
            return_value.append('FAIL')
            return_value.append(
                result_success + '\ncat /etc/systemd/timesyncd.conf returned the following\n' + error)
    else:
        return_value.append('systemd-timesyncd is misconfigured')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _2_2_1_3_ubu():
    return_value = list()
    success, error = check('grep -E "^(server|pool)" /etc/chrony.conf')
    if success:
        result_success = 'Verify remote server configurations\n' + success
        success, error = check('ps -ef | grep chronyd')
        if success:
            if any(s.startswith('chrony') for s in success):
                return_value.append('chrony is configured')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + success)
            else:
                return_value.append('chrony not first field of chronyd')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + success)
        else:
            return_value.append('no chrony processes found')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('remote server not configured')
        return_value.append('FAIL')
        return_value.append(
            'grep -E "^(server|pool)" /etc/chrony.conf returned the following\n' + error)
    return return_value


def _2_2_1_4_ubu():
    return_value = list()
    success, error = check('grep "^restrict" /etc/ntp.conf | grep default')
    if success:
        ntp_restrict = ['kod', 'nomodify', 'notrap', 'nopeer', 'noquery']
        if all(r in s for r in ntp_restrict for s in success.splitlines()):
            result_success = success
            success, error = check('grep -E "^(server|pool)" /etc/ntp.conf')
            if success:
                result_success += '\nVerify remote server configurations\n' + success
                success, error = check('grep "^OPTIONS" /etc/sysconfig/ntpd')
                if 'OPTIONS="-u ntp:ntp"' in success:
                    return_value.append('ntp is configured')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    result_error = success + '\n' + error
                    success, error = check(
                        'grep "^NTPD_OPTIONS" /etc/sysconfig/ntp')
                    if 'OPTIONS="-u ntp:ntp"' in success:
                        return_value.append('ntp is configured')
                        return_value.append('PASS')
                        return_value.append(result_success + '\n' + success)
                    else:
                        result_error += success + '\n' + error
                        success, error = check(
                            'grep "RUNASUSER=ntp" /etc/init.d/ntp')
                        if success:
                            return_value.append('ntp is configured')
                            return_value.append('PASS')
                            return_value.append(
                                result_success + '\n' + success)
                        else:
                            return_value.append(
                                'ntp user configuration not found')
                            return_value.append('FAIL')
                            return_value.append('Following were found configured\n' + result_success +
                                                '\nFollowing are misconfigured\n' + result_error + '\n' + error)
            else:
                return_value.append('remote server misconfigured')
                return_value.append('FAIL')
                return_value.append(
                    'grep -E "^(server|pool)" /etc/ntp.conf returned the following\n' + error)
        else:
            return_value.append('ntp options misconfigured')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('ntp not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _2_2_2_ubu():
    return_value = list()
    success, error = check('dpkg -l xserver-xorg*')
    if success:
        return_value.append('X Window System installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('X Window System not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_2_3_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled avahi-daemon')
    if success:
        if 'enabled' in success:
            return_value.append('avahi-daemon is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled avahi-daemon returned the following\n' + success)
        else:
            return_value.append('avahi-daemon is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('avahi-daemon not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled avahi-daemon returned the following\n' + error)
    return return_value


def _2_2_4_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled cups')
    if success:
        if 'enabled' in success:
            return_value.append('cups is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled cups returned the following\n' + success)
        else:
            return_value.append('cups is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('cups not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled cups returned the following\n' + error)
    return return_value


def _2_2_5_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled isc-dhcp-server')
    if 'enabled' in success:
        return_value.append('dhcp server is enabled')
        return_value.append('FAIL')
        return_value.append(
            'systemctl is-enabled isc-dhcp-server returned the following\n' + success)
    else:
        result_success = success
        result_error = error
        success, error = check('systemctl is-enabled isc-dhcp-server6')
        if 'enabled' in success:
            return_value.append('dhcp server is enabled')
            return_value.append('FAIL')
            return_value.append(
                result_success + '\n' + result_error + '\nsystemctl is-enabled isc-dhcp-server6 returned the following\n' + success)
        else:
            return_value.append('dhcp server is disabled')
            return_value.append('PASS')
            return_value.append(result_success + '\n' +
                                result_error + '\n' + success + '\n' + error)
    return return_value


def _2_2_6_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled slapd')
    if success:
        if 'enabled' in success:
            return_value.append('slapd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled slapd returned the following\n' + success)
        else:
            return_value.append('slapd is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('slapd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled slapd returned the following\n' + error)
    return return_value


def _2_2_7_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled nfs-server')
    if 'enabled' in success:
        return_value.append('nfs server is enabled')
        return_value.append('FAIL')
        return_value.append(
            'systemctl is-enabled nfs-server returned the following\n' + success)
    else:
        result_success = success
        result_error = error
        success, error = check('systemctl is-enabled rpcbind')
        if 'enabled' in success:
            return_value.append('rpcbind is enabled')
            return_value.append('FAIL')
            return_value.append(
                result_success + '\n' + result_error + '\nsystemctl is-enabled rpcbind returned the following\n' + success)
        else:
            return_value.append('NFS and RPC are not enabled')
            return_value.append('PASS')
            return_value.append(result_success + '\n' +
                                result_error + '\n' + success + '\n' + error)
    return return_value


def _2_2_8_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled bind9')
    if success:
        if 'enabled' in success:
            return_value.append('bind9 is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled bind9 returned the following\n' + success)
        else:
            return_value.append('bind9 is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('bind9 not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled bind9 returned the following\n' + error)
    return return_value


def _2_2_9_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled vsftpd')
    if success:
        if 'enabled' in success:
            return_value.append('vsftpd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled vsftpd returned the following\n' + success)
        else:
            return_value.append('vsftpd is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('vsftpd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled vsftpd returned the following\n' + error)
    return return_value


def _2_2_10_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled apache2')
    if success:
        if 'enabled' in success:
            return_value.append('apache2 is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled apache2 returned the following\n' + success)
        else:
            return_value.append('apache2 is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('apache2 not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled apache2 returned the following\n' + error)
    return return_value


def _2_2_11_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled dovecot')
    if success:
        if 'enabled' in success:
            return_value.append('dovecot is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled dovecot returned the following\n' + success)
        else:
            return_value.append('dovecot is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('dovecot not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled dovecot returned the following\n' + error)
    return return_value


def _2_2_12_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled smbd')
    if success:
        if 'enabled' in success:
            return_value.append('smbd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled smbd returned the following\n' + success)
        else:
            return_value.append('smbd is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('smbd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled smbd returned the following\n' + error)
    return return_value


def _2_2_13_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled squid')
    if success:
        if 'enabled' in success:
            return_value.append('squid is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled squid returned the following\n' + success)
        else:
            return_value.append('squid is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('squid not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled squid returned the following\n' + error)
    return return_value


def _2_2_14_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled snmpd')
    if success:
        if 'enabled' in success:
            return_value.append('snmpd is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled snmpd returned the following\n' + success)
        else:
            return_value.append('snmpd is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('snmpd not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled snmpd returned the following\n' + error)
    return return_value


def _2_2_15_ubu():
    return_value = list()
    success, error = check(
        "ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'")
    if not success:
        return_value.append('mta is local only')
        return_value.append('PASS')
        return_value.append(
            "ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s' returned the following\n" + error)
    else:
        return_value.append('mta is not local only')
        return_value.append('FAIL')
        return_value.append(
            "ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s' returned the following\n" + success)
    return return_value


def _2_2_16_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled rsync')
    if success:
        if 'enabled' in success:
            return_value.append('rsync is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled rsync returned the following\n' + success)
        else:
            return_value.append('rsync is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('rsync not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled rsync returned the following\n' + error)
    return return_value


def _2_2_17_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled nis')
    if success:
        if 'enabled' in success:
            return_value.append('nis is enabled')
            return_value.append('FAIL')
            return_value.append(
                'systemctl is-enabled nis returned the following\n' + success)
        else:
            return_value.append('nis is disabled')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('nis not found')
        return_value.append('PASS')
        return_value.append(
            'systemctl is-enabled nis returned the following\n' + error)
    return return_value


def _2_3_1_ubu():
    return_value = list()
    success, error = check('dpkg -s nis')
    if 'Status: install ok installed' in success:
        return_value.append('NIS Client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('NIS Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_3_2_ubu():
    return_value = list()
    success, error = check('dpkg -s rsh-client')
    if 'Status: install ok installed' in success:
        return_value.append('rsh client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('dpkg -s rsh-redone-client')
        if 'Status: install ok installed' in success:
            return_value.append('rsh redone client installed')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            return_value.append('rsh Client not installed')
            return_value.append('PASS')
            return_value.append(result_success + '\n' +
                                result_error + '\n' + success + '\n' + error)
    return return_value


def _2_3_3_ubu():
    return_value = list()
    success, error = check('dpkg -s talk')
    if 'Status: install ok installed' in success:
        return_value.append('talk client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('talk Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_3_4_ubu():
    return_value = list()
    success, error = check('dpkg -s telnet')
    if 'Status: install ok installed' in success:
        return_value.append('telnet client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('telnet Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _2_3_5_ubu():
    return_value = list()
    success, error = check('dpkg -s ldap-utils')
    if 'Status: install ok installed' in success:
        return_value.append('ldap-utils client installed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('ldap-utils Client not installed')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _3_1_1_ubu():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.send_redirects')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.send_redirects')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('packet redirect sending is disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 redirects default packets')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 redirects default packets')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 redirects all packets')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 redirects all packets')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_1_2_ubu():
    return_value = list()
    success, error = check('sysctl net.ipv4.ip_forward')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf')
        if not success:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv6.conf.all.forwarding')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep -E -s "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf')
                if not success:
                    return_value.append('IP forwarding disabled')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv6 forwards packets')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv6 forwards packets')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 forwards packets')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 forwards packets')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_1_ubu():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.accept_source_route')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.accept_source_route')
            if success.endswith('0\n'):
                result_success += success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    result_success += success + '\n'
                    success, error = check(
                        'sysctl net.ipv6.conf.all.accept_source_route')
                    if success.endswith('0\n'):
                        result_success = success + '\n'
                        success, error = check(
                            'grep "net\.ipv6\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
                        ipv6 = [s.split(':')[1] for s in success.splitlines()]
                        if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                            result_success += success + '\n'
                            success, error = check(
                                'sysctl net.ipv6.conf.default.accept_source_route')
                            if success.endswith('0\n'):
                                result_success += success + '\n'
                                success, error = check(
                                    'grep "net\.ipv6\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
                                ipv6 = [s.split(':')[1]
                                        for s in success.splitlines()]
                                if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                                    return_value.append(
                                        'source routed packets are not accepted')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                                else:
                                    return_value.append(
                                        'ipv6 accepts default source packets')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                            else:
                                return_value.append(
                                    'ipv6 accepts default source packets')
                                return_value.append('FAIL')
                                return_value.append(result_success + success)
                        else:
                            return_value.append(
                                'ipv6 accepts all source packets')
                            return_value.append('FAIL')
                            return_value.append(result_success + success)
                    else:
                        return_value.append('ipv6 accepts all source packets')
                        return_value.append('FAIL')
                        return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 accepts default source packets')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 accepts default source packets')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 accepts all source packets')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 accepts all source packets')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_2_ubu():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.accept_redirects')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.accept_redirects')
            if success.endswith('0\n'):
                result_success += success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    result_success += success + '\n'
                    success, error = check(
                        'sysctl net.ipv6.conf.all.accept_redirects')
                    if success.endswith('0\n'):
                        result_success = success + '\n'
                        success, error = check(
                            'grep "net\.ipv6\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                        ipv6 = [s.split(':')[1] for s in success.splitlines()]
                        if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                            result_success += success + '\n'
                            success, error = check(
                                'sysctl net.ipv6.conf.default.accept_redirects')
                            if success.endswith('0\n'):
                                result_success += success + '\n'
                                success, error = check(
                                    'grep "net\.ipv6\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                                ipv6 = [s.split(':')[1]
                                        for s in success.splitlines()]
                                if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                                    return_value.append(
                                        'ICMP redirects not accepted')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                                else:
                                    return_value.append(
                                        'ipv6 accepts default redirects')
                                    return_value.append('PASS')
                                    return_value.append(
                                        result_success + success)
                            else:
                                return_value.append(
                                    'ipv6 accepts default redirects')
                                return_value.append('FAIL')
                                return_value.append(result_success + success)
                        else:
                            return_value.append('ipv6 accepts all redirects')
                            return_value.append('FAIL')
                            return_value.append(result_success + success)
                    else:
                        return_value.append('ipv6 accepts all redirects')
                        return_value.append('FAIL')
                        return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 accepts default redirects')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 accepts default redirects')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 accepts all redirects')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 accepts all redirects')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_3_ubu():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.secure_redirects')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check(
                'sysctl net.ipv4.conf.default.secure_redirects')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('secure ICMP redirects not accepted')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 redirects default secure ICMP')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 redirects default secure ICMP')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 redirects all secure ICMP')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 redirects all secure ICMP')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_4_ubu():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.log_martians')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv4.conf.default.log_martians')
            if success.endswith('1\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('suspicious packets are logged')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 default packets not logged')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 default packets not logged')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 all packets not logged')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 all packets not logged')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_5_ubu():
    return_value = list()
    success, error = check('sysctl net.ipv4.icmp_echo_ignore_broadcasts')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            return_value.append('broadcast ICMP requests ignored')
            return_value.append('PASS')
            return_value.append(result_success + success)
        else:
            return_value.append('ipv4 broadcasts not ignored')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 broadcasts not ignored')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_6_ubu():
    return_value = list()
    success, error = check('sysctl net.ipv4.icmp_ignore_bogus_error_responses')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            return_value.append('bogus ICMP responses ignored')
            return_value.append('PASS')
            return_value.append(result_success + success)
        else:
            return_value.append('ipv4 bogus responses not ignored')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 bogus responses not ignored')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_7_ubu():
    return_value = list()
    success, error = check('sysctl net.ipv4.conf.all.rp_filter')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv4.conf.default.rp_filter')
            if success.endswith('1\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
                    return_value.append('Reverse Path Filtering enabled')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv4 default rp filtering disabled')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv4 default rp filtering disabled')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv4 all rp filtering disabled')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 all rp filtering disabled')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_8_ubu():
    return_value = list()
    success, error = check('sysctl net.ipv4.tcp_syncookies')
    if success.endswith('1\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv4 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('1') or s.startswith('#') for s in ipv4) or not ipv4:
            return_value.append('TCP SYN Cookies enabled')
            return_value.append('PASS')
            return_value.append(result_success + success)
        else:
            return_value.append('ipv4 tcp syncookies disabled')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv4 tcp syncookies disabled')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_2_9_ubu():
    return_value = list()
    success, error = check('sysctl net.ipv6.conf.all.accept_ra')
    if success.endswith('0\n'):
        result_success = success + '\n'
        success, error = check(
            'grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*')
        ipv6 = [s.split(':')[1] for s in success.splitlines()]
        if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
            result_success += success + '\n'
            success, error = check('sysctl net.ipv6.conf.default.accept_ra')
            if success.endswith('0\n'):
                result_success = success + '\n'
                success, error = check(
                    'grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*')
                ipv4 = [s.split(':')[1] for s in success.splitlines()]
                if all(s.endswith('0') or s.startswith('#') for s in ipv6) or not ipv6:
                    return_value.append('IPv6 router advert not accepted')
                    return_value.append('PASS')
                    return_value.append(result_success + success)
                else:
                    return_value.append('ipv6 default ra accepted')
                    return_value.append('FAIL')
                    return_value.append(result_success + success)
            else:
                return_value.append('ipv6 default ra accepted')
                return_value.append('FAIL')
                return_value.append(result_success + success)
        else:
            return_value.append('ipv6 all ra accepted')
            return_value.append('FAIL')
            return_value.append(result_success + success)
    else:
        return_value.append('ipv6 all ra accepted')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_3_1_ubu():
    return_value = list()
    success, error = check('dpkg -s tcpd')
    if 'Status: install ok installed' in success:
        return_value.append('TCP Wrappers installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('TCP Wrappers not installed')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_3_2_ubu():
    return_value = list()
    success, error = check('cat /etc/hosts.allow')
    if not all(s.startswith('#') or not s for s in success.splitlines()):
        return_value.append('/etc/hosts.allow configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/etc/hosts.allow not configured')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_3_3_ubu():
    return_value = list()
    success, error = check('cat /etc/hosts.deny')
    if 'ALL: ALL' in success:
        return_value.append('/etc/hosts.deny configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('/etc/hosts.deny not configured')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_3_4_ubu():
    return_value = list()
    success, error = check('stat /etc/hosts.allow | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/hosts.allow permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/hosts.allow permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/hosts.allow invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/hosts.allow not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/hosts.allow | grep Access did not return anything\n' + error)
    return return_value


def _3_3_5_ubu():
    return_value = list()
    success, error = check('stat /etc/hosts.deny | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/hosts.deny permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('/etc/hosts.deny permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/hosts.deny invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/hosts.deny not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/hosts.deny | grep Access did not return anything\n' + error)
    return return_value


def _3_4_1_ubu():
    return_value = list()
    success, error = check('modprobe -n -v dccp')
    if 'insmod' in success:
        return_value.append('dccp can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep dccp')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('dccp cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('dccp is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('dccp mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_4_2_ubu():
    return_value = list()
    success, error = check('modprobe -n -v sctp')
    if 'insmod' in success:
        return_value.append('sctp can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep sctp')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('sctp cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('sctp is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('sctp mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_4_3_ubu():
    return_value = list()
    success, error = check('modprobe -n -v rds')
    if 'insmod' in success:
        return_value.append('rds can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep rds')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('rds cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('rds is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('rds mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_4_4_ubu():
    return_value = list()
    success, error = check('modprobe -n -v tipc')
    if 'insmod' in success:
        return_value.append('tipc can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_success = success
        result_error = error
        success, error = check('lsmod | grep tipc')
        if 'install /bin/true' in result_success or 'not found in directory' in result_error:
            if not success:
                return_value.append('tipc cannot be mounted')
                return_value.append('PASS')
                return_value.append(
                    result_success if result_success else result_error)
            else:
                return_value.append('tipc is mounted')
                return_value.append('FAIL')
                return_value.append(
                    result_success if result_success else result_error + '\n' + success)
        else:
            return_value.append('tipc mount status undetermined')
            return_value.append('PASS')
            return_value.append(
                result_success if result_success else result_error + '\n' + success + '\n' + error)
    return return_value


def _3_5_1_1_ubu():
    return_value = list()
    success, error = check('dpkg -s ufw | grep -i status')
    if 'Status: install ok installed' in success:
        return_value.append('ufw installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        result_error = error + '\n'
        success, error = check('dpkg -s nftables | grep -i status')
        if 'Status: install ok installed' in success:
            return_value.append('nftables installed')
            return_value.append('PASS')
            return_value.append(success)
        else:
            result_error += error + '\n'
            success, error = check('dpkg -s iptables | grep -i status')
            if 'Status: install ok installed' in success:
                return_value.append('iptables installed')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('Firewall package not installed')
                return_value.append('FAIL')
                return_value.append(result_error + '\n' + error)
    return return_value


def _3_5_2_1_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled ufw')
    if 'enabled' in success:
        result_success = success
        success, error = check('ufw status | grep Status')
        if 'Status: active' in success:
            return_value.append('ufw service is enabled')
            return_value.append('PASS')
            return_value.append(result_success + '\n' + success)
        else:
            return_value.append('ufw service is not active')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('ufw service is not enabled')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_2_2_ubu():
    return_value = list()
    success, error = check('ufw status verbose')
    if success:
        return_value.append('ufw default deny firewall policy')
        return_value.append('CHEK')
        return_value.append(
            'verify that the default policy for incoming, outgoing, and routed directions is deny or reject\n' + success)
    else:
        return_value.append('ufw firewall policy not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_2_3_ubu():
    return_value = list()
    success, error = check('ufw status verbose')
    if success:
        rules = 'To                         Action      From------------Anywhere on lo             ALLOW IN    Anywhere                   Anywhere                   DENY IN     127.0.0.0/8                Anywhere (v6) on lo        ALLOW IN    Anywhere (v6)             Anywhere (v6)              DENY IN     ::1                        Anywhere                   ALLOW OUT   Anywhere on lo            Anywhere (v6)              ALLOW OUT   Anywhere (v6) on lo'
        return_value.append('ufw loopback traffic configured')
        return_value.append('CHEK')
        return_value.append(
            'verify that the rules are listed in the given order\n' + rules + '\n' + success)
    else:
        return_value.append('ufw loopback traffic not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_2_4_ubu():
    return_value = list()
    success, error = check('ufw status numbered')
    if success:
        return_value.append('ufw firewall rules for all open ports')
        return_value.append('CHEK')
        return_value.append(
            'verify all rules for new outbound connections match site policy\n' + success)
    else:
        return_value.append('outbound conn rules not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_2_5_ubu():
    return_value = list()
    success, error = check('ss -4tuln')
    if success:
        open_ports = [s.split()[0]
                      for s in success.splitlines() if s.split()[0] != 'Netid']
        if len(open_ports):
            result_success = success
            success, error = check('ufw status')
            if success:
                if all(o in success for o in open_ports):
                    return_value.append(
                        'ufw firewall rules for all open ports')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('ufw no rules for all open ports')
                    return_value.append('FAIL')
                    return_value.append(result_success + '\n' + success)
            else:
                return_value.append('ufw status not found')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('no open ports found')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('no open ports found')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _3_5_3_1_ubu():
    return_value = list()
    success, error = check('iptables -w -L')
    if success:
        return_value.append('iptables not flushed')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        result_error = error
        success, error = check('ip6tables -L')
        if success:
            return_value.append('ip6tables not flushed')
            return_value.append('FAIL')
            return_value.append(success)
        else:
            return_value.append('iptables are flushed')
            return_value.append('PASS')
            return_value.append(result_error + '\n' + error)
    return return_value


def _3_5_3_2_ubu():
    return_value = list()
    success, error = check('nft list tables')
    if success:
        return_value.append('nft table exists')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('nft table does not exist')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_3_3_ubu():
    return_value = list()
    success, error = check("nft list ruleset | grep 'hook input'")
    if 'type filter hook input priority 0;' in success:
        result_success = success + '\n'
        success, error = check("nft list ruleset | grep 'hook forward'")
        if 'type filter hook forward priority 0;' in success:
            result_success += success
            success, error = check("nft list ruleset | grep 'hook output'")
            if 'type filter hook output priority 0;' in success:
                return_value.append('nft base chains exist')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + success)
            else:
                return_value.append('output base chain does not exist')
                return_value.append('FAIL')
                return_value.append(
                    result_success + '\n' + success + '\n' + error)
        else:
            return_value.append('forward base chain does not exist')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + success + '\n' + error)
    else:
        return_value.append('input base chain does not exist')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_5_3_4_ubu():
    return_value = list()
    success, error = check(
        "nft list ruleset | awk '/hook input/,/}/' | grep 'iif \"lo\" accept'")
    if 'iif "lo" accept' in success:
        result_success = success + '\n'
        success, error = check(
            "nft list ruleset | awk '/hook input/,/}/' | grep 'ip sddr'")
        if 'ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop' in success:
            result_success += success
            success, error = check(
                "nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'")
            if 'ip6 saddr ::1 counter packets 0 bytes 0 drop' in success:
                return_value.append('nft base chains exist')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + success)
            else:
                return_value.append('input saddr not config')
                return_value.append('FAIL')
                return_value.append(
                    result_success + '\n' + success + '\n' + error)
        else:
            return_value.append('input sddr not config')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + success + '\n' + error)
    else:
        return_value.append('input accept not config')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_5_3_5_ubu():
    return_value = list()
    success, error = check(
        "nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'")
    if success:
        if 'ip protocol tcp ct state' in success:
            if 'ip protocol udp ct state' in success:
                if 'ip protocol icmp ct state' in success:
                    return_value.append(
                        'outbound & established connections config')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append('icmp connections not config')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('udp connections not config')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('tcp connections not config')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('nft connections not config')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_3_6_ubu():
    return_value = list()
    success, error = check("nft list ruleset | grep 'hook input'")
    if 'type filter hook input priority 0; policy drop;' in success:
        result_success = success + '\n'
        success, error = check("nft list ruleset | grep 'hook forward'")
        if 'type filter hook forward priority 0; policy drop;' in success:
            result_success += success
            success, error = check("nft list ruleset | grep 'hook output'")
            if 'type filter hook output priority 0; policy drop;' in success:
                return_value.append('nft base chains exist')
                return_value.append('PASS')
                return_value.append(result_success + '\n' + success)
            else:
                return_value.append('output base chain does not drop')
                return_value.append('FAIL')
                return_value.append(
                    result_success + '\n' + success + '\n' + error)
        else:
            return_value.append('forward base chain does not drop')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + success + '\n' + error)
    else:
        return_value.append('input base chain does not drop')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _3_5_3_7_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled nftables')
    if 'enabled' in success:
        return_value.append('nftables service is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('nftables service is not enabled')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_3_8_ubu():
    return_value = list()
    success, error = check(
        'awk \'/hook input/,/}/\' $(awk \'$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }\' /etc/sysconfig/nftables.conf)')
    if success:
        result_success = 'Review the input base chain to ensure that it follows local site policy\n' + success
        success, error = check(
            'awk \'/hook forward/,/}/\' $(awk \'$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }\' /etc/sysconfig/nftables.conf)')
        if success:
            result_success += '\nReview the forward base chain to ensure that it follows local site policy\n' + success
            success, error = check(
                'awk \'/hook forward/,/}/\' $(awk \'$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }\' /etc/sysconfig/nftables.conf)')
            if success:
                return_value.append('nftables rules are permanent')
                return_value.append('CHEK')
                return_value.append(
                    result_success + '\nReview the output base chain to ensure that it follows local site policy\n' + success)
            else:
                return_value.append('nftables output base chain not perm')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('nftables forward base chain not perm')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('nftables input base chain not perm')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_4_1_1_ubu():
    return_value = list()
    success, error = check('iptables -w -L | grep Chain')
    if success:
        if all('policy DROP' in s or 'policy REJECT' in s for s in success.splitlines()):
            return_value.append('default deny firewall policy')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('no default deny firewall')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('firewall policy not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_4_1_2_ubu():
    return_value = list()
    success, error = check('iptables -w -L INPUT -v -n')
    if success:
        loopbacks = [s for s in success.splitlines()]
        flag = 1
        if len(loopbacks) > 2:
            flag = 0
            for i in range(2, len(loopbacks)):
                rule = loopbacks[i].split()
                if rule[2] == 'ACCEPT' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == 'lo':
                            if rule[-3] == '*':
                                if rule[-2] == '0.0.0.0/0':
                                    if rule[-1] == '0.0.0.0/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'fw input accpet destination not 0.0.0.0/0')
                                        return_value.append('FAIL')
                                        return_value.append(success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'fw input accpet source not 0.0.0.0/0')
                                    return_value.append('FAIL')
                                    return_value.append(success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'fw input accpet out not *')
                                return_value.append('FAIL')
                                return_value.append(success)
                                flag += 1
                                break
                        else:
                            return_value.append('fw input accpet in not lo')
                            return_value.append('FAIL')
                            return_value.append(success)
                            flag += 1
                            break
                    else:
                        return_value.append('fw input accept prot not all')
                        return_value.append('FAIL')
                        return_value.append(success)
                        flag += 1
                        break
                elif rule[2] == 'DROP' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == '*':
                            if rule[-3] == '*':
                                if rule[-2] == '127.0.0.0/8':
                                    if rule[-1] == '0.0.0.0/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'fw input drop destination not 0.0.0.0/0')
                                        return_value.append('FAIL')
                                        return_value.append(success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'fw input drop source not 127.0.0.0/8')
                                    return_value.append('FAIL')
                                    return_value.append(success)
                                    flag += 1
                                    break
                            else:
                                return_value.append('fw input drop out not *')
                                return_value.append('FAIL')
                                return_value.append(success)
                                flag += 1
                                break
                        else:
                            return_value.append('fw input drop in not *')
                            return_value.append('FAIL')
                            return_value.append(success)
                            flag += 1
                            break
                    else:
                        return_value.append('fw input drop prot not all')
                        return_value.append('FAIL')
                        return_value.append(success)
                        flag += 1
                        break
        else:
            return_value.append('fw input loopback no config')
            return_value.append('FAIL')
            return_value.append(success)
        if not flag:
            result_success = '\nConfig of firewall Input table\n' + success + '\n'
            success, error = check('iptables -w -L OUTPUT -v -n')
            if success:
                loopbacks = [s for s in success.splitlines()]
                if len(loopbacks) > 2:
                    for i in range(2, len(loopbacks)):
                        rule = loopbacks[i].split()
                        if rule[2] == 'ACCEPT' and not flag:
                            if rule[3] == 'all':
                                if rule[-4] == '*':
                                    if rule[-3] == 'lo':
                                        if rule[-2] == '0.0.0.0/0':
                                            if rule[-1] == '0.0.0.0/0':
                                                return_value.append(
                                                    'firewall loopback traffic configured')
                                                return_value.append('PASS')
                                                return_value.append(
                                                    success + result_success)
                                            else:
                                                return_value.append(
                                                    'fw output accpet destination not 0.0.0.0/0')
                                                return_value.append('FAIL')
                                                return_value.append(
                                                    success + result_success)
                                                flag += 1
                                                break
                                        else:
                                            return_value.append(
                                                'fw output accpet source not 0.0.0.0/0')
                                            return_value.append('FAIL')
                                            return_value.append(
                                                success + result_success)
                                            flag += 1
                                            break
                                    else:
                                        return_value.append(
                                            'fw output accpet out not lo')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'fw output accpet in not *')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'fw output accept prot not all')
                                return_value.append('FAIL')
                                return_value.append(success + result_success)
                                flag += 1
                                break
                else:
                    return_value.append('fw output loopback no config')
                    return_value.append('FAIL')
                    return_value.append(success + result_success)
            else:
                return_value.append('firewall output loopback not found')
                return_value.append('FAIL')
                return_value.append(error)
    else:
        return_value.append('firewall input loopback not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_4_1_3_ubu():
    return_value = list()
    success, error = check('iptables -w -L -v -n')
    if success:
        if len(success.splitlines()) > 8:
            return_value.append('iptables contains config')
            return_value.append('PASS')
            return_value.append(
                'verify all rules for new outbound, and established connections match site policy\n' + success)
        else:
            return_value.append('iptables contains no config')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('iptables not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _3_5_4_1_4_ubu():
    return_value = list()
    success, error = check('ss -4tuln')
    if success:
        open_ports = [s.split()[0]
                      for s in success.splitlines() if s.split()[0] != 'Netid']
        if len(open_ports):
            result_success = success
            success, error = check('iptables -w -L INPUT -v -n')
            if success:
                rules = [s.split()[0] for s in success.splitlines() if s.split()[0] != 'Chain' and s.split()[
                    0] != 'pkts' and s.split()[2] not in ['ACCEPT', 'DROP', 'QUEUE', 'RETURN']]
                if all(o in rules for o in open_ports):
                    return_value.append('all open ports have firewall rule')
                    return_value.append('PASS')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\niptables input configuration\n' + success)
                else:
                    return_value.append('open ports no firewall rule')
                    return_value.append('FAIL')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\niptables input configuration\n' + success)
            else:
                return_value.append('iptables input not found')
                return_value.append('FAIL')
                return_value.append(
                    error + '\nFollowing open ports were found\n' + result_success)
        else:
            return_value.append('no open ports found')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('no open ports found')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _3_5_4_2_1_ubu():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('ip6tables -L | grep Chain')
    if success:
        if all('policy DROP' in s or 'policy REJECT' in s for s in success.splitlines()):
            return_value.append('IPv6 default deny policy')
            return_value.append('PASS')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
        else:
            return_value.append('IPv6 default no deny policy')
            return_value.append('FAIL')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
    else:
        if result_success:
            return_value.append('ipv6 used though disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_5_4_2_2_ubu():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('ip6tables -L INPUT -v -n')
    if success:
        loopbacks = [s for s in success.splitlines()]
        flag = 1
        if len(loopbacks) > 2:
            flag = 0
            for i in range(2, len(loopbacks)):
                rule = loopbacks[i].split()
                if rule[2] == 'ACCEPT' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == 'lo':
                            if rule[-3] == '*':
                                if rule[-2] == '::/0':
                                    if rule[-1] == '::/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'IPv6 input accpet destination not ::/0')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + '\nFollowing uses ipv6\n' + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'IPv6 input accpet source not ::/0')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + '\nFollowing uses ipv6\n' + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'IPv6 input accpet out not *')
                                return_value.append('FAIL')
                                return_value.append(
                                    success + '\nFollowing uses ipv6\n' + result_success)
                                flag += 1
                                break
                        else:
                            return_value.append('IPv6 input accpet in not lo')
                            return_value.append('FAIL')
                            return_value.append(
                                success + '\nFollowing uses ipv6\n' + result_success)
                            flag += 1
                            break
                    else:
                        return_value.append('IPv6 input accept prot not all')
                        return_value.append('FAIL')
                        return_value.append(
                            success + '\nFollowing uses ipv6\n' + result_success)
                        flag += 1
                        break
                elif rule[2] == 'DROP' and not flag:
                    if rule[3] == 'all':
                        if rule[-4] == '*':
                            if rule[-3] == '*':
                                if rule[-2] == '::1':
                                    if rule[-1] == '::/0':
                                        flag = 0
                                    else:
                                        return_value.append(
                                            'IPv6 input drop destination not ::/0')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + '\nFollowing uses ipv6\n' + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'IPv6 input drop source not ::1')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + '\nFollowing uses ipv6\n' + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'IPv6 input drop out not *')
                                return_value.append('FAIL')
                                return_value.append(
                                    success + '\nFollowing uses ipv6\n' + result_success)
                                flag += 1
                                break
                        else:
                            return_value.append('IPv6 input drop in not *')
                            return_value.append('FAIL')
                            return_value.append(
                                success + '\nFollowing uses ipv6\n' + result_success)
                            flag += 1
                            break
                    else:
                        return_value.append('IPv6 input drop prot not all')
                        return_value.append('FAIL')
                        return_value.append(
                            success + '\nFollowing uses ipv6\n' + result_success)
                        flag += 1
                        break
        else:
            return_value.append('IPv6 input loopback no config')
            return_value.append('FAIL')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
        if not flag:
            result_success += '\nConfig of IPv6 Input table\n' + success + '\n'
            success, error = check('ip6tables -L OUTPUT -v -n')
            if success:
                loopbacks = [s for s in success.splitlines()]
                if len(loopbacks) > 2:
                    for i in range(2, len(loopbacks)):
                        rule = loopbacks[i].split()
                        if rule[2] == 'ACCEPT' and not flag:
                            if rule[3] == 'all':
                                if rule[-4] == '*':
                                    if rule[-3] == 'lo':
                                        if rule[-2] == '::/0':
                                            if rule[-1] == '::/0':
                                                return_value.append(
                                                    'IPv6 loopback traffic is configured')
                                                return_value.append('PASS')
                                                return_value.append(
                                                    success + '\nFollowing uses ipv6\n' + result_success)
                                            else:
                                                return_value.append(
                                                    'IPv6 output accpet destination not ::/0')
                                                return_value.append('FAIL')
                                                return_value.append(
                                                    success + '\nFollowing uses ipv6\n' + result_success)
                                                flag += 1
                                                break
                                        else:
                                            return_value.append(
                                                'IPv6 output accpet source not ::/0')
                                            return_value.append('FAIL')
                                            return_value.append(
                                                success + '\nFollowing uses ipv6\n' + result_success)
                                            flag += 1
                                            break
                                    else:
                                        return_value.append(
                                            'IPv6 output accpet out not lo')
                                        return_value.append('FAIL')
                                        return_value.append(
                                            success + '\nFollowing uses ipv6\n' + result_success)
                                        flag += 1
                                        break
                                else:
                                    return_value.append(
                                        'IPv6 output accpet in not *')
                                    return_value.append('FAIL')
                                    return_value.append(
                                        success + '\nFollowing uses ipv6\n' + result_success)
                                    flag += 1
                                    break
                            else:
                                return_value.append(
                                    'IPv6 output accept prot not all')
                                return_value.append('FAIL')
                                return_value.append(
                                    success + '\nFollowing uses ipv6\n' + result_success)
                                flag += 1
                                break
                else:
                    return_value.append('IPv6 output loopback no config')
                    return_value.append('FAIL')
                    return_value.append(
                        success + '\nFollowing uses ipv6\n' + result_success)
            else:
                if result_success:
                    return_value.append(
                        'ipv6 enabled output loopback disabled')
                    return_value.append('FAIL')
                    return_value.append(
                        'The following have ipv6 enabled\n' + result_success)
                else:
                    return_value.append('ipv6 disabled')
                    return_value.append('PASS')
                    return_value.append(
                        'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    else:
        if result_success:
            return_value.append('ipv6 enabled input loopback disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_5_4_2_3_ubu():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('ip6tables -L -v -n')
    if success:
        if len(success.splitlines()) > 8:
            return_value.append('IPv6 Table contains config')
            return_value.append('PASS')
            return_value.append('verify all rules for new outbound, and established connections match site policy\n' +
                                success + '\nFollowing uses ipv6\n' + result_success)
        else:
            return_value.append('IPv6 Table contains no config')
            return_value.append('FAIL')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
    else:
        if result_success:
            return_value.append('ipv6 used though disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_5_4_2_4_ubu():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('ss -6tuln')
    if success:
        open_ports = [s.split()[0]
                      for s in success.splitlines() if s.split()[0] != 'Netid']
        if len(open_ports):
            result_success = success
            success, error = check('ip6tables -L INPUT -v -n')
            if success:
                rules = [s.split()[0] for s in success.splitlines() if s.split()[0] != 'Chain' and s.split()[
                    0] != 'pkts' and s.split()[2] not in ['ACCEPT', 'DROP', 'QUEUE', 'RETURN']]
                if all(o in rules for o in open_ports):
                    return_value.append('all open ports have firewall rule')
                    return_value.append('PASS')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\nIPv6 input table configuration\n' + success)
                else:
                    return_value.append('open ports no firewall rule')
                    return_value.append('FAIL')
                    return_value.append('Following open ports were found\n' +
                                        result_success + '\nIPv6 input table configuration\n' + success)
            else:
                return_value.append('IPv6 input Table not found')
                return_value.append('FAIL')
                return_value.append(
                    error + '\nFollowing open ports were found\n' + result_success)
        else:
            return_value.append('no open ports found')
            return_value.append('PASS')
            return_value.append(
                success + '\nFollowing uses ipv6\n' + result_success)
    else:
        if result_success:
            return_value.append('ipv6 used though disabled')
            return_value.append('FAIL')
            return_value.append(
                'The following have ipv6 enabled\n' + result_success)
        else:
            return_value.append('ipv6 disabled')
            return_value.append('PASS')
            return_value.append(
                'ipv6 seems to be disabled\n' + result_error + '\n' + error)
    return return_value


def _3_6_ubu():
    return_value = list()
    success, error = check('iwconfig')
    if success:
        if success.splitlines()[1].split()[1] == 'disabled':
            if success.splitlines()[1].split()[3] == 'disabled':
                return_value.append('wireless interfaces disabled')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append('WWAN enabled')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('WIFI enabled')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('wireless interfaces disabled')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _3_7_ubu():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disabled=1')
    if success:
        return_value.append('IPv6 enabled')
        return_value.append('FAIL')
        return_value.append('The following use IPv6\n' + success)
    else:
        return_value.append('IPv6 disabled')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _4_1_1_1_ubu():
    return_value = list()
    success, error = check('dpkg -s auditd audispd-plugins')
    if success:
        return_value.append('auditd is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('auditd is not installed')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_1_1_2_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled auditd')
    if 'enabled' in success:
        return_value.append('auditd service is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('auditd not enabled')
        return_value.append('FAIL')
        return_value.append(
            'systemctl is-enabled auditd returned the following\n' + success + '\n' + error)
    return return_value


def _4_1_1_3_ubu():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub/grub.cfg | grep -v "audit=1" | grep -v \'/boot/memtest86+.bin\'')
    if success:
        return_value.append('processes prior to auditd not audited')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('processes prior to auditd audited')
        return_value.append('PASS')
        return_value.append(error)
    return return_value


def _4_1_1_4_ubu():
    return_value = list()
    success, error = check(
        'grep "^\s*linux" /boot/grub/grub.cfg | grep -v "audit_backlog_limit="')
    if not success:
        result_error = error
        success, error = check(
            'grep "audit_backlog_limit=" /boot/grub/grub.cfg')
        if success:
            if success.split('=')[1].split()[0].isdigit() and int(success.split('=')[1].split()[0]) >= 8192:
                return_value.append('audit_backlog_limit is sufficient')
                return_value.append('PASS')
                return_value.append(result_error + '\n' + success)
            else:
                return_value.append('audit_backlog_limit is insufficient')
                return_value.append('FAIL')
                return_value.append(result_error + '\n' + success)
        else:
            return_value.append('audit_backlog_limit not found')
            return_value.append('FAIL')
            return_value.append(result_error + '\n' + error)
    else:
        return_value.append('audit_backlog_limit not set')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


def _4_1_2_1_ubu():
    return_value = list()
    success, error = check(
        'grep max_log_file /etc/audit/auditd.conf')
    if success:
        return_value.append('audit log storage size is configured')
        return_value.append('PASS')
        return_value.append(
            'Ensure output is in compliance with site policy\n' + success)
    else:
        return_value.append('audit log storage size not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_1_2_2_ubu():
    return_value = list()
    success, error = check(
        'grep max_log_file_action /etc/audit/auditd.conf')
    if success:
        if 'max_log_file_action = keep_logs' in success:
            return_value.append('audit logs not automatically deleted')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('audit logs automatically deleted')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('audit log file action not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_1_2_3_ubu():
    return_value = list()
    success, error = check(
        'grep space_left_action /etc/audit/auditd.conf')
    if success:
        result_success = success + '\n'
        success, error = check('grep action_mail_acct /etc/audit/auditd.conf')
        if success:
            result_success = success + '\n'
            success, error = check(
                'grep admin_space_left_action /etc/audit/auditd.conf')
            if success:
                return_value.append('system disabled when audit logs full')
                return_value.append('PASS')
                return_value.append(result_success + success)
            else:
                return_value.append('admin_space_left_action not set')
                return_value.append('FAIL')
                return_value.append(
                    'grep admin_space_left_action /etc/audit/auditd.conf returned the following\n' + error)
        else:
            return_value.append('action_mail_acct not set')
            return_value.append('FAIL')
            return_value.append(
                'grep action_mail_acct /etc/audit/auditd.conf returned the following\n' + error)
    else:
        return_value.append('system not disabled when audit logs full')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_1_3_ubu():
    return_value = list()
    success, error = check('grep time-change /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep time-change')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change' in result_success or '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' in result_success:
            if '-a always,exit -F arch=b64 -S clock_settime -k time-change' in result_success or '-a always,exit -F arch=b32 -S clock_settime -k time-change' in result_success:
                if '-w /etc/localtime -p wa -k time-change' in result_success:
                    return_value.append('events modifying date and time coll')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('localtime time-change not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('clock_settime not collected')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('adjtimex and settimeofday not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('events modifying date and time not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_4_ubu():
    return_value = list()
    success, error = check('grep identity /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep identity')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /etc/group -p wa -k identity' in result_success:
            if '-w /etc/passwd -p wa -k identity' in result_success:
                if '-w /etc/gshadow -p wa -k identity' in result_success:
                    if '-w /etc/shadow -p wa -k identity' in result_success:
                        if '-w /etc/security/opasswd -p wa -k identity' in result_success:
                            return_value.append(
                                'events modifying u/g info collected')
                            return_value.append('PASS')
                            return_value.append(result_success)
                        else:
                            return_value.append(
                                'opasswd identity events not coll')
                            return_value.append('FAIL')
                            return_value.append(result_success)
                    else:
                        return_value.append('shadow identity events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('gshadow identity events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('passwd identity events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('group identity events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('events modifying u/g info not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_5_ubu():
    return_value = list()
    success, error = check('grep system-locale /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grepsystem-locale')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale' in result_success or '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' in result_success:
            if '-w /etc/issue -p wa -k system-locale' in result_success:
                if '-w /etc/issue.net -p wa -k system-locale' in result_success:
                    if '-w /etc/hosts -p wa -k system-locale' in result_success:
                        if '-w /etc/sysconfig/network -p wa -k system-locale' in result_success:
                            return_value.append(
                                "events modifying system's n/w env coll")
                            return_value.append('PASS')
                            return_value.append(result_success)
                        else:
                            return_value.append(
                                'network system-locale events not coll')
                            return_value.append('FAIL')
                            return_value.append(result_success)
                    else:
                        return_value.append(
                            'hosts system-locale events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append(
                        'issue.net system-locale events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('issue system-locale events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('system-locale name change not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append("events modifying system's n/w env not coll")
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_6_ubu():
    return_value = list()
    success, error = check('grep MAC-policy /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep MAC-policy')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /etc/selinux/ -p wa -k MAC-policy' in result_success or '-w /etc/apparmor/ -p wa -k MAC-policy' in result_success:
            if '-w /usr/share/selinux/ -p wa -k MAC-policy' in result_success or '-w /etc/apparmor.d/ -p wa -k MAC-policy' in result_success:
                return_value.append("events modifying system's MAC coll")
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('dir MAC-policy events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('etc MAC-policy events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append("events modifying system's MAC not coll")
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_7_ubu():
    return_value = list()
    success, error = check('grep logins /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep logins')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /var/log/faillog -p wa -k logins' in result_success:
            if '-w /var/log/lastlog -p wa -k logins' in result_success:
                if '-w /var/log/tallylog -p wa -k logins' in result_success:
                    return_value.append(
                        'login and logout events are collected')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('tallylog logins events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('lastlog logins events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('faillog logins events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('login and logout events not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_8_ubu():
    return_value = list()
    success, error = check(
        "grep -E '(session|logins)' /etc/audit/audit.rules")
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check("auditctl -l | grep -E '(session|logins)'")
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /var/run/utmp -p wa -k session' in result_success:
            if '-w /var/log/wtmp -p wa -k logins' in result_success:
                if '-w /var/log/btmp -p wa -k logins' in result_success:
                    return_value.append('session initiation info is collected')
                    return_value.append('PASS')
                    return_value.append(result_success)
                else:
                    return_value.append('btmp logins events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('wtmp logins events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('utmp session events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('session initiation info not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_9_ubu():
    return_value = list()
    success, error = check("awk '/^\s*UID_MIN/{print $2}' /etc/login.defs")
    uid_min = success.splitlines()[0] if success else '1000'
    success, error = check('grep perm_mod /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep perm_mod')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=' + uid_min + ' -F auid!=4294967295 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=' + uid_min + ' -F auid!=4294967295 -k perm_mod' in result_success:
            if '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=' + uid_min + ' -F auid!=4294967295 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=' + uid_min + ' -F auid!=4294967295 -k perm_mod' in result_success:
                if '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=' + uid_min + ' -F auid!=4294967295 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=' + uid_min + ' -F auid!=4294967295 -k perm_mod' in result_success:
                    if '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=' + uid_min + ' -F auid!=-1 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=' + uid_min + ' -F auid!=-1 -k perm_mod' in result_success:
                        if '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=' + uid_min + ' -F auid!=-1 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=' + uid_min + ' -F auid!=-1 -k perm_mod' in result_success:
                            if '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=' + uid_min + ' -F auid!=-1 -k perm_mod' in result_success or '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=' + uid_min + ' -F auid!=-1 -k perm_mod' in result_success:
                                return_value.append(
                                    'access control mod events collected')
                                return_value.append('PASS')
                                return_value.append(result_success)
                            else:
                                return_value.append(
                                    'setxattr auditctl events not coll')
                                return_value.append('FAIL')
                                return_value.append(result_success)
                        else:
                            return_value.append(
                                'chown auditctl events not coll')
                            return_value.append('FAIL')
                            return_value.append(result_success)
                    else:
                        return_value.append('chmod auditctl events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('setxattr *.rules events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('chown *.rules events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('chmod *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('access control mod events not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_10_ubu():
    return_value = list()
    success, error = check("awk '/^\s*UID_MIN/{print $2}' /etc/login.defs")
    uid_min = success.splitlines()[0] if success else '1000'
    success, error = check('grep access /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep access')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=' + uid_min + ' -F auid!=4294967295 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=' + uid_min + ' -F auid!=4294967295 -k access' in result_success:
            if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=' + uid_min + ' -F auid!=4294967295 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=' + uid_min + ' -F auid!=4294967295 -k access' in result_success:
                if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=' + uid_min + ' -F auid!=-1 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=' + uid_min + ' -F auid!=-1 -k access' in result_success:
                    if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=' + uid_min + ' -F auid!=-1 -k access' in result_success or '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=' + uid_min + ' -F auid!=-1 -k access' in result_success:
                        return_value.append(
                            'unauthorized file access collected')
                        return_value.append('PASS')
                        return_value.append(result_success)
                    else:
                        return_value.append('EPERM auditctl events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('EACCES auditctl events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('EPERM *.rules events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('EACCES *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('unauthorized file access not coll')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_11_ubu():
    return_value = list()
    success, error = check('mount | grep -e "/dev/sd"')
    partitions = [s.split()[0] for s in success.splitlines()]
    if len(partitions):
        result_success = 'Following partitions were found\n' + success
        flag = 0
        for p in partitions:
            success, error = check(
                "awk '/^\s*UID_MIN/{print $2}' /etc/login.defs")
            uid_min = success.splitlines()[0] if success else '1000'
            success, error = check(
                "find " + p + " -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \"-a always,exit -F path=\" $1 \" -F perm=x -F auid>=" + uid_min + " -F auid!=4294967295 -k privileged\" }'")
            result_success += success if success else error + \
                '\nABOVE was found on ' + p + '\n'
            flag += 1 if success else 0
        if not flag:
            return_value.append('privileged commands not collected')
            return_value.append('FAIL')
            return_value.append(result_success)
        else:
            return_value.append('privileged commands collected')
            return_value.append('PASS')
            return_value.append(
                'Verify all resulting lines are a .rules file in /etc/audit/rules.d/ and the output of auditctl -l AND .rules file output should be auid!=-1 not auid!=4294967295\n' + result_success)
    else:
        return_value.append('no partitions found')
        return_value.append('CHEK')
        return_value.append(success + error)
    return return_value


def _4_1_12_ubu():
    return_value = list()
    success, error = check("awk '/^\s*UID_MIN/{print $2}' /etc/login.defs")
    uid_min = success.splitlines()[0] if success else '1000'
    success, error = check('grep mounts /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep mounts')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S mount -F auid>=' + uid_min + ' -F auid!=4294967295 -k mounts' in result_success or '-a always,exit -F arch=b32 -S mount -F auid>=' + uid_min + ' -F auid!=4294967295 -k mounts' in result_success:
            if '-a always,exit -F arch=b64 -S mount -F auid>=' + uid_min + ' -F auid!=-1 -k mounts' in result_success or '-a always,exit -F arch=b32 -S mount -F auid>=' + uid_min + ' -F auid!=-1 -k mounts' in result_success:
                return_value.append('successful fs mounts collected')
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('mount auditctl events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('mount *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('successful fs mounts not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_13_ubu():
    return_value = list()
    success, error = check("awk '/^\s*UID_MIN/{print $2}' /etc/login.defs")
    uid_min = success.splitlines()[0] if success else '1000'
    success, error = check('grep delete /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep delete')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=' + uid_min + ' -F auid!=4294967295 -k delete' in result_success or '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=' + uid_min + ' -F auid!=4294967295 -k delete' in result_success:
            if '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=' + uid_min + ' -F auid!=-1 -k delete' in result_success or '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=' + uid_min + ' -F auid!=-1 -k delete' in result_success:
                return_value.append('user file deletion events collected')
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('unlink, rename auditctl events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('unlink, rename *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('user file deletion events not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_14_ubu():
    return_value = list()
    success, error = check('grep scope /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep scope')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-w /etc/sudoers -p wa -k scope' in result_success:
            if '-w /etc/sudoers.d/ -p wa -k scope' in result_success:
                return_value.append('changes to sudoers collected')
                return_value.append('PASS')
                return_value.append(result_success)
            else:
                return_value.append('directory scope events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('sudoers scope events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('changes to sudoers not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_15_ubu():
    return_value = list()
    success, error = check(
        'grep -E "^\s*-w\s+$(grep -r logfile /etc/sudoers* | sed -e \'s/.*logfile=//;s/,? .*//\')\s+-p\s+wa\s+-k\s+actions" /etc/audit/rules.d/*.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep actions')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        success, error = check(
            'echo "-w $(grep -r logfile /etc/sudoers* | sed -e \'s/.*logfile=//;s/,? .*//\') -p wa -k actions"')
        return_value.append('sudolog collected')
        return_value.append('PASS')
        return_value.append('verify\n' + result_success +
                            '\nmatches\n' + success + error)
    else:
        return_value.append('sudolog not collected')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_16_ubu():
    return_value = list()
    success, error = check('grep modules /etc/audit/audit.rules')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('auditctl -l | grep modules')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        if '-a always,exit -F arch=b32 -S init_module -S delete_module -k modules' in result_success or '-a always,exit -F arch=b64 -S init_module -S delete_module-k modules' in result_success:
            if '-w /sbin/insmod -p x -k modules' in result_success:
                if '-w /sbin/rmmod -p x -k modules' in result_success:
                    if '-w /sbin/modprobe -p x -k modules' in result_success:
                        return_value.append('kernel module monitored')
                        return_value.append('PASS')
                        return_value.append(result_success)
                    else:
                        return_value.append('modprobe modules events not coll')
                        return_value.append('FAIL')
                        return_value.append(result_success)
                else:
                    return_value.append('rmmod modules events not coll')
                    return_value.append('FAIL')
                    return_value.append(result_success)
            else:
                return_value.append('insmod modules events not coll')
                return_value.append('FAIL')
                return_value.append(result_success)
        else:
            return_value.append('modules *.rules events not coll')
            return_value.append('FAIL')
            return_value.append(result_success)
    else:
        return_value.append('kernel module not monitored')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_1_17_ubu():
    return_value = list()
    success, error = check(
        'grep "^\s*[^#]" /etc/audit/audit.rules | tail -1')
    if '-e 2' in success:
        return_value.append('audit configuration immutable')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('audit configuration is mutable')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _4_2_1_1_ubu():
    return_value = list()
    success, error = check('dpkg -s rsyslog')
    if success:
        return_value.append('rsyslog is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('rsyslog is not installed')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_1_2_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled rsyslog | grep enabled')
    if 'enabled' in success:
        return_value.append('rsyslog is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('rsyslog is disabled')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _4_2_1_3_ubu():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('cat /etc/rsyslog.conf')
    if success:
        result_success += 'Review the contents of rsyslog.conf\n' + success
    else:
        result_error += error
    success, error = check('cat /etc/rsyslog.d/*.conf')
    if success:
        result_success += 'Review the contents of rsyslog.d/*.conf\n' + success
    else:
        result_error += error
    success, error = check('ls -l /var/log/')
    if success:
        result_success += 'verify that the log files are logging information\n' + success
    else:
        result_error += error
    if len(result_success):
        return_value.append('logging is configured')
        return_value.append('CHEK')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('logging not configured')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_2_1_4_ubu():
    return_value = list()
    success, error = check(
        'grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf')
    if success:
        allowed_perms = ['0640', '0600', '0440', '0400', '0240', '0200']
        perms = [s.split(':')[1].split()[1] for s in success.splitlines()]
        if all(p in allowed_perms for p in perms):
            return_value.append('rsyslog file permissions configured')
            return_value.append('PASS')
            return_value.append(success + '\n' + error)
        else:
            return_value.append('rsyslog file permissions not configured')
            return_value.append('PASS')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('rsyslog file permissions not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_1_5_ubu():
    return_value = list()
    success, error = check(
        'grep -E "^[^#]\s*\S+\.\*\s+@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf')
    if success:
        return_value.append('rsyslog sends logs to remote log host')
        return_value.append('PASS')
        return_value.append(
            'verify that logs are sent to central log host\n' + success + '\n' + error)
    else:
        return_value.append('rsyslog does not sends logs')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_1_6_ubu():
    return_value = list()
    success, error = check(
        "grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check(
        "grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
    result_success = success if success else ''
    result_error = error if error else ''
    if len(result_success):
        return_value.append('rsyslog messages accepted designated')
        return_value.append('PASS')
        return_value.append(
            'verify the resulting lines are uncommented on designated log hosts and commented or removed on all others\n' + result_success + '\n' + result_error)
    else:
        return_value.append('rsyslog messages not config')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _4_2_2_1_ubu():
    return_value = list()
    success, error = check(
        'grep -E -i "^\s*ForwardToSyslog" /etc/systemd/journald.conf')
    if success:
        if 'ForwardToSyslog=yes' in success and not success.startswith('#'):
            return_value.append('journald sends logs to rsyslog')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('journald does not send logs to rsyslog')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('journald not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_2_2_ubu():
    return_value = list()
    success, error = check(
        'grep -E -i "^\s*Compress" /etc/systemd/journald.conf')
    if success:
        if 'Compress=yes' in success and not success.startswith('#'):
            return_value.append('jjournald compresses large log files')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('journald not compress large log files')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('journald not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_2_3_ubu():
    return_value = list()
    success, error = check(
        'grep -E -i "^\s*Storage" /etc/systemd/journald.conf')
    if success:
        if 'Storage=persistent' in success and not success.startswith('#'):
            return_value.append('journald writes logfiles to persistent disk')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('journald does not write logfiles')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('journald not configured')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_2_3_ubu():
    return_value = list()
    success, error = check('find /var/log -type f -ls')
    if success:
        if all('r-----' in s.split()[2][-6:] for s in success.splitlines()):
            return_value.append('permissions on all logfiles config')
            return_value.append('PASS')
            return_value.append(success + '\nfollowing not checked\n' + error)
        else:
            return_value.append('permissions not config on all logfiles')
            return_value.append('FAIL')
            return_value.append('other has permissions on files OR group has write or execute permissions\n' +
                                success + '\nfollowing not checked\n' + error)
    else:
        return_value.append('permissions on logfiles not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _4_3_ubu():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('cat /etc/logrotate.conf')
    if success:
        result_success += 'verify logs in logrotate.conf are rotated according to site policy\n' + success
    else:
        result_error += error
    success, error = check('cat /etc/logrotate.d/*')
    if success:
        result_success += 'verify logs in logrotate directory are rotated according to site policy\n' + success
    else:
        result_error += error
    if len(result_success):
        return_value.append('lograte is configured')
        return_value.append('CHEK')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('lograte not configured')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _5_1_1_ubu():
    return_value = list()
    success, error = check('systemctl is-enabled cron')
    if 'enabled' in success:
        return_value.append('cron daemon is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('cron daemon not found')
        return_value.append('FAIL')
        return_value.append(
            'systemctl is-enabled cron returned the following\n' + success + '\n' + error)
    return return_value


def _5_1_2_ubu():
    return_value = list()
    success, error = check('stat /etc/crontab')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/crontab configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/crontab not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/crontab not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/crontab returned the following\n' + error)
    return return_value


def _5_1_3_ubu():
    return_value = list()
    success, error = check('stat /etc/cron.hourly')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.hourly configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.hourly not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.hourly not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.hourly returned the following\n' + error)
    return return_value


def _5_1_4_ubu():
    return_value = list()
    success, error = check('stat /etc/cron.daily')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.daily configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.daily not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.daily not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.daily returned the following\n' + error)
    return return_value


def _5_1_5_ubu():
    return_value = list()
    success, error = check('stat /etc/cron.weekly')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.weekly configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.weekly not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.weekly not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.weekly returned the following\n' + error)
    return return_value


def _5_1_6_ubu():
    return_value = list()
    success, error = check('stat /etc/cron.monthly')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.monthly configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.monthly not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.monthly not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.monthly returned the following\n' + error)
    return return_value


def _5_1_7_ubu():
    return_value = list()
    success, error = check('stat /etc/cron.d')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/cron.d configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on /etc/cron.d not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/cron.d not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.d returned the following\n' + error)
    return return_value


def _5_1_8_ubu():
    return_value = list()
    success, error = check('stat /etc/cron.deny')
    if 'No such file or directory' in error:
        result_error = error
        success, error = check('stat /etc/at.deny')
        if 'No such file or directory' in error:
            result_error += error
            success, error = check('stat /etc/cron.allow')
            if success:
                go_perm = success.splitlines()[0].split()[1][-7:-1]
                if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
                    result_success = success
                    success, error = check('stat /etc/at.allow')
                    if success:
                        go_perm = success.splitlines()[0].split()[1][-7:-1]
                        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
                            return_value.append(
                                'at/cron restricted to authorized users')
                            return_value.append('PASS')
                            return_value.append(
                                result_error + '\n' + result_success + '\n' + success)
                        else:
                            return_value.append('/etc/at.allow not configured')
                            return_value.append('FAIL')
                            return_value.append(
                                result_error + '\n' + result_success + '\n' + success + '\n' + error)
                    else:
                        return_value.append('/etc/at.allow not found')
                        return_value.append('FAIL')
                        return_value.append(result_error + '\n' + result_success +
                                            '\nstat /etc/at.allow returned the following\n' + error)
                else:
                    return_value.append('/etc/cron.allow not configured')
                    return_value.append('FAIL')
                    return_value.append(result_error + '\n' + result_success +
                                        '\nstat /etc/at.allow returned the following\n' + success)
            else:
                return_value.append('/etc/cron.allow not found')
                return_value.append('FAIL')
                return_value.append(
                    result_error + '\nstat /etc/at.allow returned the following\n' + error)
        else:
            return_value.append('/etc/at.deny exists')
            return_value.append('FAIL')
            return_value.append(
                result_error + '\nstat /etc/at.deny returned the following\n' + error)
    else:
        return_value.append('/etc/cron.deny exists')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/cron.deny returned the following\n' + error)
    return return_value


def _5_2_1_ubu():
    return_value = list()
    success, error = check('stat /etc/ssh/sshd_config')
    if success:
        go_perm = success.splitlines()[0].split()[1][-7:-1]
        if '------' == go_perm and 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            return_value.append('perms on /etc/ssh/sshd_config configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('perms on sshd_config not configured')
            return_value.append('FAIL')
            return_value.append(success + '\n' + error)
    else:
        return_value.append('/etc/ssh/sshd_config not found')
        return_value.append('FAIL')
        return_value.append(
            'stat /etc/ssh/sshd_config returned the following\n' + error)
    return return_value


def _5_2_2_ubu():
    return_value = list()
    success, error = check(
        "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;")
    if success:
        result_success = success
        success, error = check(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | grep \"Access: (\"")
        if all(s.split()[1][-7:-1] == '------' and 'Uid: (    0/    root)   Gid: (    0/    root)' in s for s in success.splitlines()):
            return_value.append('SSH private host keys perms config')
            return_value.append('PASS')
            return_value.append(result_success)
        else:
            return_value.append('SSH private host keys perms not config')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('SSH private host keys not found')
        return_value.append('FAIL')
        return_value.append(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;\n" + error)
    return return_value


def _5_2_3_ubu():
    return_value = list()
    success, error = check(
        "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;")
    if success:
        result_success = success
        success, error = check(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \; | grep \"Access: (\"")
        if all(s.split()[1][-7:-1] in ['------', 'r--r--', 'r-----', '---r--'] and 'Uid: (    0/    root)   Gid: (    0/    root)' in s for s in success.splitlines()):
            return_value.append('SSH public host keys perms config')
            return_value.append('PASS')
            return_value.append(result_success)
        else:
            return_value.append('SSH public host keys perms not config')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('SSH public host keys not found')
        return_value.append('FAIL')
        return_value.append(
            "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;\n" + error)
    return return_value


def _5_2_4_ubu():
    return_value = list()
    success, error = check(
        "sshd -T | grep -Ei '^\s*protocol\s+(1|1\s*,\s*2|2\s*,\s*1)\s*'")
    if not success:
        return_value.append('SSH Protocol not set to 1')
        return_value.append('PASS')
        return_value.append(error)
    else:
        return_value.append('SSH Protocol set to 1')
        return_value.append('FAIL')
        return_value.append(
            "sshd -T | grep -Ei '^\s*protocol\s+(1|1\s*,\s*2|2\s*,\s*1)\s*' returned the following\n" + success)
    return return_value


def _5_2_5_ubu():
    return_value = list()
    success, error = check('sshd -T | grep loglevel')
    if 'LogLevel VERBOSE' in success or 'loglevel INFO' in success:
        return_value.append('SSH LogLevel is appropriate')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH LogLevel not appropriate')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep loglevel returned the following\n' + success + error)
    return return_value


def _5_2_6_ubu():
    return_value = list()
    success, error = check('sshd -T | grep x11forwarding')
    if 'X11Forwarding no' in success:
        return_value.append('SSH X11 forwarding is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH X11 forwarding not disabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep x11forwarding returned the following\n' + success + error)
    return return_value


def _5_2_7_ubu():
    return_value = list()
    success, error = check('sshd -T | grep maxauthtries')
    if success:
        tries = success.split()[1]
        if int(tries) <= 4:
            return_value.append('SSH MaxAuthTries is set to ' + tries)
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SSH MaxAuthTries is more than 4')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('SSH MaxAuthTries not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep maxauthtries returned the following\n' + error)
    return return_value


def _5_2_8_ubu():
    return_value = list()
    success, error = check('sshd -T | grep ignorerhosts')
    if 'IgnoreRhosts yes' in success:
        return_value.append('SSH IgnoreRhosts is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH IgnoreRhosts is disabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep ignorerhosts returned the following\n' + success + error)
    return return_value


def _5_2_9_ubu():
    return_value = list()
    success, error = check('sshd -T | grep hostbasedauthentication')
    if 'HostbasedAuthentication no' in success:
        return_value.append('SSH HBA is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH HBA is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep hostbasedauthentication returned the following\n' + success + error)
    return return_value


def _5_2_10_ubu():
    return_value = list()
    success, error = check('sshd -T | grep permitrootlogin')
    if 'PermitRootLogin no' in success:
        return_value.append('SSH root login is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH root login is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep permitrootlogin returned the following\n' + success + error)
    return return_value


def _5_2_11_ubu():
    return_value = list()
    success, error = check('sshd -T | grep permitemptypasswords')
    if 'PermitEmptyPasswords no' in success:
        return_value.append('SSH PermitEmptyPasswords is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH PermitEmptyPasswords is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep permitemptypasswords returned the following\n' + success + error)
    return return_value


def _5_2_12_ubu():
    return_value = list()
    success, error = check('sshd -T | grep permituserenvironment')
    if 'PermitUserEnvironment no' in success:
        return_value.append('SSH PermitUserEnvironment is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH PermitUserEnvironment is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep permituserenvironment returned the following\n' + success + error)
    return return_value


def _5_2_13_ubu():
    return_value = list()
    success, error = check('sshd -T | grep ciphers')
    weak_cyphers = ['3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour',
                    'arcfour128', 'arcfour256', 'blowfish-cbc', 'cast128-cbc', 'rijndael-cbc@lysator.liu.se']
    if success and not any(s in weak_cyphers for s in success.splitlines()):
        return_value.append('SSH only strong Ciphers are used')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH strong Ciphers not used')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep ciphers returned the following\n' + success + error)
    return return_value


def _5_2_14_ubu():
    return_value = list()
    success, error = check('sshd -T | grep -i "MACs"')
    weak_mac = ['hmac-md5', 'hmac-md5-96', 'hmac-ripemd160', 'hmac-sha1', 'hmac-sha1-96', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-md5-etm@openssh.com',
                'hmac-md5-96-etm@openssh.com', 'hmac-ripemd160-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'hmac-sha1-96-etm@openssh.com', 'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com']
    if success and not any(s in weak_mac for s in success.splitlines()):
        return_value.append('SSH only strong MAC algorithms are used')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH strong MAC algorithms not used')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep -i "MACs" returned the following\n' + success + error)
    return return_value


def _5_2_15_ubu():
    return_value = list()
    success, error = check('sshd -T | grep kexalgorithms')
    weak_keys = ['diffie-hellman-group1-sha1',
                 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1']
    if success and not any(s in weak_keys for s in success.splitlines()):
        return_value.append('SSH only strong Key Exchange algorithms are used')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH strong Key Exchange algorithms not used')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep kexalgorithms returned the following\n' + success + error)
    return return_value


def _5_2_16_ubu():
    return_value = list()
    success, error = check('sshd -T | grep clientaliveinterval')
    if success:
        result_success = success
        alive = success.split()[1]
        if 1 <= int(alive) <= 300:
            success, error = check('sshd -T | grep clientalivecountmax')
            if success:
                count = success.split()[1]
                if int(count) <= 3:
                    return_value.append('SSH Idle Timeout Interval configured')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('SSH ClientAliveCountMax more than 3')
                    return_value.append('FAIL')
                    return_value.append(result_success + '\n' + success)
            else:
                return_value.append('SSH ClientAliveCountMax not found')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('SSH ClientAliveInterval more than 300')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('SSH ClientAliveInterval not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep clientaliveinterval returned the following\n' + error)
    return return_value


def _5_2_17_ubu():
    return_value = list()
    success, error = check('sshd -T | grep logingracetime')
    if success:
        grace = success.split()[1]
        if 1 <= int(grace) <= 60:
            return_value.append('SSH LoginGraceTime is ' + grace)
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SSH LoginGraceTime more than 60')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('SSH LoginGraceTime not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep logingracetime returned the following\n' + error)
    return return_value


def _5_2_18_ubu():
    return_value = list()
    success, error = check('sshd -T | grep allowusers')
    result_success = success if success else ''
    result_error = error if error else ''
    success, error = check('sshd -T | grep allowgroups')
    result_success += success if success else ''
    result_error += error if error else ''
    success, error = check('sshd -T | grep denyusers')
    result_success += success if success else ''
    result_error += error if error else ''
    success, error = check('sshd -T | grep denygroups')
    result_success += success if success else ''
    result_error += error if error else ''
    if len(result_success):
        return_value.append('SSH access is limited')
        return_value.append('PASS')
        return_value.append(result_success + '\n' + result_error)
    else:
        return_value.append('SSH access is not limited')
        return_value.append('FAIL')
        return_value.append(result_error)
    return return_value


def _5_2_19_ubu():
    return_value = list()
    success, error = check('sshd -T | grep banner')
    if 'Banner /etc/issue.net' in success:
        return_value.append('SSH warning banner is configured')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH warning banner is not configured')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep banner returned the following\n' + success + error)
    return return_value


def _5_2_20_ubu():
    return_value = list()
    success, error = check('sshd -T | grep -i usepam')
    if 'usepam yes' in success:
        return_value.append('SSH PAM is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH PAM is disabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep usepam returned the following\n' + success + error)
    return return_value


def _5_2_21_ubu():
    return_value = list()
    success, error = check('sshd -T | grep -i allowtcpforwarding')
    if 'AllowTcpForwarding no' in success:
        return_value.append('SSH AllowTcpForwarding is disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('SSH AllowTcpForwarding is enabled')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep -i allowtcpforwarding returned the following\n' + success + error)
    return return_value


def _5_2_22_ubu():
    return_value = list()
    success, error = check('sshd -T | grep -i maxstartups')
    if success:
        if 'maxstartups 10:30:60' in success:
            return_value.append('SSH MaxStartups is configured')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SSH MaxStartups is configured')
            return_value.append('CHEK')
            return_value.append(
                'verify that output of MaxStartups matches site policy\n' + success + error)
    else:
        return_value.append('SSH MaxStartups not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep -i maxstartups returned the following\n' + error)
    return return_value


def _5_2_23_ubu():
    return_value = list()
    success, error = check('sshd -T | grep -i maxsessions')
    if success:
        sessions = success.split()[1]
        if int(sessions) <= 4:
            return_value.append('SSH MaxSessions is set to ' + sessions)
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('SSH MaxSessions is set to ' + sessions)
            return_value.append('CHEK')
            return_value.append(
                'verify that output of MaxSessions matches site policy\n' + success + error)
    else:
        return_value.append('SSH MaxSessions not found')
        return_value.append('FAIL')
        return_value.append(
            'sshd -T | grep -i maxsessions returned the following\n' + error)
    return return_value


def _5_3_1_ubu():
    return_value = list()
    success, error = check("grep '^\s*minlen\s*' /etc/security/pwquality.conf")
    if success:
        if success.split(' = ')[1].split('\n')[0].isdigit() and int(success.split(' = ')[1].split('\n')[0]) >= 14:
            result_success = success
            success, error = check(
                "grep '^\s*minclass\s*' /etc/security/pwquality.conf")
            if success:
                if success.split(' = ')[1].split('\n')[0].isdigit() and int(success.split(' = ')[1].split('\n')[0]) >= 4:
                    result_success += success
                    success, error = check(
                        "grep -E '^\s*password\s+(requisite|required)\s+pam_pwquality\.so\s+(\S+\s+)*retry=[1-3]\s*(\s+\S+\s*)*(\s+#.*)?$' /etc/pam.d/common-password")
                    if success:
                        if success.split('retry=')[1].split('\n')[0].isdigit() and int(success.split('retry=')[1].split('\n')[0]) <= 3:
                            return_value.append(
                                'password creation requirements configured')
                            return_value.append('PASS')
                            return_value.append(
                                result_success + '\n' + success)
                        else:
                            return_value.append(
                                'password wrong attempts more than 3')
                            return_value.append('FAIL')
                            return_value.append(
                                result_success + '\n' + success)
                    else:
                        return_value.append(
                            'password wrong attempts not found')
                        return_value.append('FAIL')
                        return_value.append(
                            result_success + '\n' + success)
                else:
                    return_value.append('password complexity misconfigured')
                    return_value.append('FAIL')
                    return_value.append(
                        result_success + '\n' + success)
            else:
                return_value.append('password complexity not found')
                return_value.append('FAIL')
                return_value.append(
                    result_success + '\n' + success)
        else:
            return_value.append('password min length less than 14')
            return_value.append('FAIL')
            return_value.append(
                result_success + '\n' + success)
    else:
        return_value.append('password min length not found')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _5_3_2_ubu():
    return_value = list()
    success, error = check('grep "pam_tally2" /etc/pam.d/common-auth')
    if success:
        result_success = 'determine the current settings for user lockout\n' + success
        success, error = check(
            'grep -E "pam_(tally2|deny)\.so" /etc/pam.d/common-account')
        if success:
            return_value.append('failed password lockout configured')
            return_value.append('PASS')
            return_value.append(result_success + '\n' + success)
        else:
            return_value.append('pam modules not included')
            return_value.append('FAIL')
            return_value.append(result_success + '\n' + error)
    else:
        return_value.append('current user lockout settings not found')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _5_3_3_ubu():
    return_value = list()
    success, error = check(
        "grep -E '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/common-password")
    if success:
        if success.split('remember=')[1].split('\n')[0].isdigit() and int(success.split('remember=')[1].split('\n')[0]) >= 5:
            return_value.append('password reuse is limited')
            return_value.append('PASS')
            return_value.append(success)
        else:
            return_value.append('password remember not gt 5')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('password reuse not limited')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _5_3_4_ubu():
    return_value = list()
    success, error = check(
        "grep -E '^\s*password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512\s*(\S+\s*)*(\s+#.*)?$' /etc/pam.d/common-password")
    if success:
        return_value.append('password hashing algorithm is SHA-512')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('password hashing algorithm not SHA-512')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _5_4_1_1_ubu():
    return_value = list()
    success, error = check('grep PASS_MAX_DAYS /etc/login.defs')
    days = [d[1].split()[0] for d in [s.split() for s in success.splitlines(
    ) if not s.startswith('#')] if d[1].split()[0].lstrip('-').isdigit()]
    if days:
        if int(days[0]) <= 365 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                'egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,5')
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) <= 365 and int(d) != -1 for d in days):
                    return_value.append(
                        'password expiration less than 365 days')
                    return_value.append('PASS')
                    return_value.append('verify PASS_MAX_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MAX_DAYS\n' + success)
                else:
                    return_value.append('user password expiration gt 365 days')
                    return_value.append('FAIL')
                    return_value.append('verify PASS_MAX_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MAX_DAYS\n' + success)
            else:
                return_value.append('users password expiration not found')
                return_value.append('FAIL')
                return_value.append('verify PASS_MAX_DAYS conforms to site policy\n' +
                                    result_success + '\nUsers PASS_MAX_DAYS\n' + success)
        else:
            return_value.append('password expiration not 365 days or less')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('password expiration not found')
        return_value.append('FAIL')
        return_value.append(
            'grep PASS_MAX_DAYS /etc/login.defs returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_2_ubu():
    return_value = list()
    success, error = check('grep PASS_MIN_DAYS /etc/login.defs')
    days = [d[1].split()[0] for d in [s.split() for s in success.splitlines(
    ) if not s.startswith('#')] if d[1].split()[0].lstrip('-').isdigit()]
    if days:
        if int(days[0]) >= 1 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                'grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4')
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) >= 1 and int(d) != -1 for d in days):
                    return_value.append('password changes gt 7 days')
                    return_value.append('PASS')
                    return_value.append('verify PASS_MIN_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MIN_DAYS\n' + success)
                else:
                    return_value.append('user password changes lt 7 days')
                    return_value.append('FAIL')
                    return_value.append('verify PASS_MIN_DAYS conforms to site policy\n' +
                                        result_success + '\nUsers PASS_MIN_DAYS\n' + success)
            else:
                return_value.append('users password changes days not found')
                return_value.append('FAIL')
                return_value.append('verify PASS_MIN_DAYS conforms to site policy\n' +
                                    result_success + '\nUsers PASS_MIN_DAYS\n' + success)
        else:
            return_value.append('password changes not 7 days or more')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('password changes days not found')
        return_value.append('FAIL')
        return_value.append(
            'grep PASS_MIN_DAYS /etc/login.defs returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_3_ubu():
    return_value = list()
    success, error = check('grep PASS_WARN_AGE /etc/login.defs')
    days = [d[1].split()[0] for d in [s.split() for s in success.splitlines(
    ) if not s.startswith('#')] if d[1].split()[0].lstrip('-').isdigit()]
    if days:
        if int(days[0]) >= 7 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                'grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,6')
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) >= 7 and int(d) != -1 for d in days):
                    return_value.append('password change warning gt 7 days')
                    return_value.append('PASS')
                    return_value.append('verify PASS_WARN_AGE conforms to site policy\n' +
                                        result_success + '\nUsers PASS_WARN_AGE\n' + success)
                else:
                    return_value.append(
                        'user password change warning lt 7 days')
                    return_value.append('FAIL')
                    return_value.append('verify PASS_WARN_AGE conforms to site policy\n' +
                                        result_success + '\nUsers PASS_WARN_AGE\n' + success)
            else:
                return_value.append('users password warn not found')
                return_value.append('FAIL')
                return_value.append('verify PASS_WARN_AGE conforms to site policy\n' +
                                    result_success + '\nUsers PASS_WARN_AGE\n' + success)
        else:
            return_value.append('password expiration warning lt 7 days')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('password expiration warning not found')
        return_value.append('FAIL')
        return_value.append(
            'grep PASS_WARN_AGE /etc/login.defs returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_4_ubu():
    return_value = list()
    success, error = check('useradd -D | grep INACTIVE')
    days = [d for d in [s.split('=')[1] for s in success.splitlines(
    ) if not s.startswith('#')] if d.lstrip('-').isdigit()]
    if days:
        if int(days[0]) <= 30 and int(days[0]) != -1:
            result_success = success
            success, error = check(
                'grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7')
            days = [s.split(':')[1] for s in success.splitlines()]
            if days:
                if all(int(d) <= 30 and int(d) != -1 for d in days):
                    return_value.append(
                        'inactive password lock less than 30 days')
                    return_value.append('PASS')
                    return_value.append('verify INACTIVE conforms to site policy\n' +
                                        result_success + '\nUsers INACTIVE\n' + success)
                else:
                    return_value.append('user password lock more than 30 days')
                    return_value.append('FAIL')
                    return_value.append('verify INACTIVE conforms to site policy\n' +
                                        result_success + '\nUsers INACTIVE\n' + success)
            else:
                return_value.append('users password lock not found')
                return_value.append('FAIL')
                return_value.append('verify INACTIVE conforms to site policy\n' +
                                    result_success + '\nUsers INACTIVE\n' + success)
        else:
            return_value.append('inactive password lock more than 30 days')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('inactive password lock not found')
        return_value.append('FAIL')
        return_value.append(
            'useradd -D | grep INACTIVE returned the following\n' + success + '\n' + error)
    return return_value


def _5_4_1_5_ubu():
    return_value = list()
    success, error = check(
        "awk -F: '{print $1}' /etc/shadow | while read -r usr; do [[ $(date --date=\"$(chage --list \"$usr\" | grep '^Last password change' | cut -d: -f2)\" +%s) > $(date +%s) ]] && echo \"$usr last password change was: $(chage --list \"$usr\" | grep '^Last password change' | cut -d: -f2)\"; done")
    if not success:
        return_value.append('last password change date in past')
        return_value.append('PASS')
        return_value.append(
            "awk -F: '{print $1}' /etc/shadow | while read -r usr; do [[ $(date --date=\"$(chage --list \"$usr\" | grep '^Last password change' | cut -d: -f2)\" +%s) > $(date +%s) ]] && echo \"$usr last password change was: $(chage --list \"$usr\" | grep '^Last password change' | cut -d: -f2)\"; done\nreturned the following\n" + error)
    else:
        return_value.append('last password change date not in past')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


def _5_4_2_ubu():
    return_value = list()
    success, error = check(
        'awk -F: \'($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print}\' /etc/passwd')
    if not success:
        result_error = error
        success, error = check(
            'awk -F: \'($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}\' /etc/passwd | xargs -I \'{}\' passwd -S \'{}\' | awk \'($2!="L" && $2!="LK") {print $1}\'')
        if not success:
            return_value.append('system accounts are secured')
            return_value.append('PASS')
            return_value.append(result_error + '\n' + error)
        else:
            return_value.append('system accounts are not secured')
            return_value.append('FAIL')
            return_value.append(result_error + '\n' + success)
    else:
        return_value.append('system accounts are not secured')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


def _5_4_3_ubu():
    return_value = list()
    success, error = check('grep "^root:" /etc/passwd | cut -f4 -d:')
    if '0' in success:
        return_value.append('root account GID is 0')
        return_value.append('PASS')
        return_value.append(
            'grep "^root:" /etc/passwd | cut -f4 -d: returned\n' + success)
    else:
        return_value.append('root account GID not 0')
        return_value.append('FAIL')
        return_value.append(success + '\n' + error)
    return return_value


def _5_4_4_ubu():
    return_value = list()
    success, error = check('grep "umask" /etc/bashrc')
    if success:
        umask_permissions = ['22', '23', '27',
                             '32', '33', '37', '72', '73', '77']
        if any(u in success for u in umask_permissions):
            result_success = success
            success, error = check('grep "umask" /etc/profile')
            if success:
                if any(u in success for u in umask_permissions):
                    result_success += success
                    success, error = check('grep "umask" /etc/profile.d/*.sh')
                    if success:
                        if all(any(u in s for u in umask_permissions) for s in success.splitlines()):
                            return_value.append(
                                'default user umask is restrictive')
                            return_value.append('PASS')
                            return_value.append(
                                result_success + '\n' + success)
                        else:
                            return_value.append(
                                'profile.d/*.sh umask not less than 027')
                            return_value.append('FAIL')
                            return_value.append(success)
                    else:
                        return_value.append(
                            'umask not found in profile.d/*.sh')
                        return_value.append('FAIL')
                        return_value.append(result_success + '\n' + error)
                else:
                    return_value.append(
                        'profile umask not restrictive than 027')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('umask not found in profile')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('bashrc umask not 027 or more restrictive')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('umask not found in bashrc')
        return_value.append('FAIL')
        return_value.append(error)
    return return_value


def _5_4_5_ubu():
    return_value = list()
    success, error = check(
        'grep -E -i "^\s*(\S+\s+)*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\s*(\S+\s*)*(\s+#.*)?$" /etc/bash.bashrc')
    if success:
        if all(s.strip('TMOUT=')[1].strip()[0].lstrip('-').isdigit() and int(s.strip('TMOUT=')[1].strip()[0]) != -1 and int(s.strip('TMOUT=')[1].strip()[0]) <= 900 for s in success.splitlines()):
            result_success = success
            success, error = check(
                'grep -E -i "^\s*(\S+\s+)*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\s*(\S+\s*)*(\s+#.*)?$" /etc/profile /etc/profile.d/*.sh')
            if success:
                if all(s.strip('TMOUT=')[1].strip()[0].lstrip('-').isdigit() and int(s.strip('TMOUT=')[1].strip()[0]) != -1 and int(s.strip('TMOUT=')[1].strip()[0]) <= 900 for s in success.splitlines()):
                    return_value.append('user shell timeout is lt 900 sec')
                    return_value.append('PASS')
                    return_value.append(result_success + '\n' + success)
                else:
                    return_value.append('profile shell timeout not lt 900 sec')
                    return_value.append('FAIL')
                    return_value.append(result_success + '\n' + success)
            else:
                return_value.append('shell timeout not in profile')
                return_value.append('FAIL')
                return_value.append(result_success + '\n' + error)
        else:
            return_value.append('bashrc shell timeout not lt 900 sec')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('shell timeout not in bashrc')
        return_value.append('FAIL')
        return_value.append(
            'grep -E -i "^\s*(\S+\s+)*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\s*(\S+\s*)*(\s+#.*)?$" /etc/bash.bashrc returned the following\n' + error)
    return return_value


def _5_5_ubu():
    return_value = list()
    success, error = check('cat /etc/securetty')
    if success:
        return_value.append('root login is restricted to system')
        return_value.append('PASS')
        return_value.append(
            'check if following are valid terminals that may be logged in directly as root\n' + success)
    else:
        return_value.append('root login not restricted to system')
        return_value.append('FAIL')
        return_value.append(
            'cat /etc/securetty returned the following\n' + error)
    return return_value


def _5_6_ubu():
    return_value = list()
    success, error = check('grep pam_wheel.so /etc/pam.d/su')
    if success:
        groups = [s.split('group=')[1].split('\n')[
            0] for s in success.splitlines() if not s.startswith('#') and 'group' in s]
        if groups:
            result_success = success
            for g in groups:
                success, error = check('grep ' + g + ' /etc/group')
                result_success += '\nverify that the ' + \
                    g + ' group contains no users\n' + success
            return_value.append('access to su command is restricted')
            return_value.append('PASS')
            return_value.append(
                result_success + '\nverify users in sudo group match site policy\n' + success)
        else:
            return_value.append('no groups in /etc/pam.d/su')
            return_value.append('PASS')
            return_value.append(success)
    else:
        return_value.append('access to su command not restricted')
        return_value.append('FAIL')
        return_value.append(
            'grep pam_wheel.so /etc/pam.d/su returned the following\n' + error)
    return return_value


def _6_1_1_ubu():
    return_value = list()
    global log_file
    write_log = log_file.split(
        '_SeBAz_logs/')[0] + '.system_file_permissions.SeBAz.log'
    success, error = check('dpkg --verify > ' + write_log)
    return_value.append('Audit system file permissions')
    return_value.append('CHEK')
    return_value.append('Verify the contents of ' +
                        write_log.split('/')[-1] + '\n' + success + '\n' + error)
    return return_value


def _6_1_2_ubu():
    return_value = list()
    success, error = check('stat /etc/passwd | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/passwd permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/passwd permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/passwd invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/passwd not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/passwd | grep Access did not return anything\n' + error)
    return return_value


def _6_1_3_ubu():
    return_value = list()
    success, error = check('stat /etc/gshadow- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith(('0/    root)', 'shadow)')):
                allowed_access = [
                    '(0640/-rw-r-----)', '(0600/-rw-------)', '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/gshadow- permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/gshadow- permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/gshadow- invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/gshadow- invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/gshadow- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/gshadow- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_4_ubu():
    return_value = list()
    success, error = check('stat /etc/shadow | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith(('0/    root)', 'shadow)')):
                allowed_access = ['(0640/-rw-r-----)', '(0600/-rw-------)',
                                  '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/shadow permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/shadow permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/shadow invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/shadow invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/shadow not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/shadow | grep Access did not return anything\n' + error)
    return return_value


def _6_1_5_ubu():
    return_value = list()
    success, error = check('stat /etc/group | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            if '(0644/-rw-r--r--)' in success:
                return_value.append('/etc/group permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/group permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/group invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/group not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/group | grep Access did not return anything\n' + error)
    return return_value


def _6_1_6_ubu():
    return_value = list()
    success, error = check('stat /etc/passwd- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            allowed_access = ['(0600/-rw-------)', '(0400/-r--------)']
            if any(a in success for a in allowed_access):
                return_value.append('/etc/passwd- permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/passwd- permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/passwd- invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/passwd- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/passwd- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_7_ubu():
    return_value = list()
    success, error = check('stat /etc/shadow- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith(('0/    root)', 'shadow)')):
                allowed_access = [
                    '(0640/-rw-r-----)', '(0600/-rw-------)', '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/shadow- permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/shadow- permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/shadow- invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/shadow- invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/shadow- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/shadow- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_8_ubu():
    return_value = list()
    success, error = check('stat /etc/group- | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (    0/    root)' in success:
            allowed_access = ['(0644/-rw-r--r--)', '(0640/-rw-r-----)', '(0600/-rw-------)',
                              '(0444/-r--r--r--)', '(0440/-r--r-----)', '(0400/-r--------)']
            if any(a in success for a in allowed_access):
                return_value.append('/etc/group- permissions configured')
                return_value.append('PASS')
                return_value.append(success)
            else:
                return_value.append(
                    '/etc/group- permits group and others')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/group- invalid uid and gid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/group- not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/group- | grep Access did not return anything\n' + error)
    return return_value


def _6_1_9_ubu():
    return_value = list()
    success, error = check('stat /etc/gshadow | grep Access')
    if success:
        if 'Uid: (    0/    root)   Gid: (' in success:
            if success.splitlines()[0].endswith('shadow)'):
                allowed_access = [
                    '(0640/-rw-r-----)', '(0600/-rw-------)', '(0440/-r--r-----)', '(0400/-r--------)']
                if any(a in success for a in allowed_access):
                    return_value.append('/etc/gshadow permissions configured')
                    return_value.append('PASS')
                    return_value.append(success)
                else:
                    return_value.append(
                        '/etc/gshadow permits group and others')
                    return_value.append('FAIL')
                    return_value.append(success)
            else:
                return_value.append('/etc/gshadow invalid gid')
                return_value.append('FAIL')
                return_value.append(success)
        else:
            return_value.append('/etc/gshadow invalid uid')
            return_value.append('FAIL')
            return_value.append(success)
    else:
        return_value.append('/etc/gshadow not found')
        return_value.append('CHEK')
        return_value.append(
            'stat /etc/gshadow | grep Access did not return anything\n' + error)
    return return_value


def _6_1_10_ubu():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check(
                    'find ' + p + ' -xdev -type f -perm -0002')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('world writable files does not exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 confirms that all world writable directories have the sticky variable set\n" + result_error)
            else:
                return_value.append('world writable files exist in partitions')
                return_value.append('FAIL')
                return_value.append(
                    'The following world writable files exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('world writable files does not exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 confirms that all world writable directories have the sticky variable set\n" + result_error + '\n' + error)
    else:
        return_value.append('world writable files exist')
        return_value.append('FAIL')
        return_value.append(
            'The following world writable files exist\n' + success)
    return return_value


def _6_1_11_ubu():
    return_value = list()
    success, error = check(
        "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check('find ' + p + ' -xdev -nouser')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('no unowned files or directories exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser confirms that no unowned files or directories exist\n" + result_error)
            else:
                return_value.append('unowned files or directories exist')
                return_value.append('FAIL')
                return_value.append(
                    'The following unowned files or directories exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('no unowned files or directories exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser confirms that no unowned files or directories exist\n" + result_error + '\n' + error)
    else:
        return_value.append('unowned files or directories exist')
        return_value.append('FAIL')
        return_value.append(
            'The following unowned files or directories exist\n' + success)
    return return_value


def _6_1_12_ubu():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check('find ' + p + ' -xdev -nogroup')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('no ungrouped files or directories exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup confirms that no ungrouped files or directories exist\n" + result_error)
            else:
                return_value.append('ungrouped files or directories exist')
                return_value.append('FAIL')
                return_value.append(
                    'The following ungrouped files or directories exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('no ungrouped files or directories exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup confirms that no ungrouped files or directories exist\n" + result_error + '\n' + error)
    else:
        return_value.append('ungrouped files or directories exist')
        return_value.append('FAIL')
        return_value.append(
            'The following ungrouped files or directories exist\n' + success)
    return return_value


def _6_1_13_ubu():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check(
                    'find ' + p + ' -xdev -type f -perm -4000')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('SUID executables does not exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 confirms that SUID executables does not exist\n" + result_error)
            else:
                return_value.append('SUID executables found')
                return_value.append('FAIL')
                return_value.append(
                    'The following SUID executables exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('SUID executables does not exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 confirms that SUID executables does not exist\n" + result_error + '\n' + error)
    else:
        return_value.append('SUID executables found')
        return_value.append('FAIL')
        return_value.append(
            'The following SUID executables exist\n' + success)
    return return_value


def _6_1_14_ubu():
    return_value = list()
    success, error = check(
        "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000")
    if not success:
        result_error = error
        success, error = check('mount | grep -e "/dev/sd"')
        partitions = [s.split()[0] for s in success.splitlines()]
        if len(partitions):
            result_success = ''
            for p in partitions:
                success, error = check(
                    'find ' + p + ' -xdev -type f -perm -2000')
                result_success += success if success else ''
                result_error += error
            if not result_success:
                return_value.append('SGID executables does not exist')
                return_value.append('PASS')
                return_value.append(
                    "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 confirms that SGID executables does not exist\n" + result_error)
            else:
                return_value.append('SGID executables found')
                return_value.append('FAIL')
                return_value.append(
                    'The following SGID executables exist\n' + result_success + '\n' + result_error)
        else:
            return_value.append('SGID executables does not exist')
            return_value.append('PASS')
            return_value.append(
                "running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 confirms that SGID executables does not exist\n" + result_error + '\n' + error)
    else:
        return_value.append('SGID executables found')
        return_value.append('FAIL')
        return_value.append(
            'The following SGID executables exist\n' + success)
    return return_value


def _6_2_1_ubu():
    return_value = list()
    success, error = check(
        "awk -F: '($2 == \"\" ) { print $1 \" does not have a password \"}' /etc/shadow")
    if not success:
        return_value.append('password fields are not empty')
        return_value.append('PASS')
        return_value.append(
            "awk -F: '($2 == \"\" ) { print $1 \" does not have a password \"}' /etc/shadow returned the following\n" + error)
    else:
        return_value.append('password fields are empty')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have empty password fields\n' + success)
    return return_value


def _6_2_2_ubu():
    return_value = list()
    success, error = check("grep '^\+:' /etc/passwd")
    if not success:
        return_value.append('no legacy "+" entries exist in /etc/passwd')
        return_value.append('PASS')
        return_value.append(
            "grep '^\+:' /etc/passwd returned the following\n" + error)
    else:
        return_value.append('legacy "+" entries exist in /etc/passwd')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have legacy "+" entries in /etc/passwd\n' + success)
    return return_value


def _6_2_3_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_3.sh')
    check('sudo cat ' + script + ' > ./home_directories.sh')
    check('chmod +x ./home_directories.sh')
    success, error = check('./home_directories.sh')
    if not success:
        return_value.append('all users\' home directories exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_3.sh returned the following\n' + error)
    else:
        return_value.append('users without home directory')
        return_value.append('FAIL')
        return_value.append(
            'The following users are without home directory\n' + success)
    check('rm ./home_directories.sh')
    return return_value


def _6_2_4_ubu():
    return_value = list()
    success, error = check("grep '^\+:' /etc/shadow")
    if not success:
        return_value.append('no legacy "+" entries exist in /etc/shadow')
        return_value.append('PASS')
        return_value.append(
            "grep '^\+:' /etc/shadow returned the following\n" + error)
    else:
        return_value.append('legacy "+" entries exist in /etc/shadow')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have legacy "+" entries in /etc/shadow\n' + success)
    return return_value


def _6_2_5_ubu():
    return_value = list()
    success, error = check("grep '^\+:' /etc/group")
    if not success:
        return_value.append('no legacy "+" entries exist in /etc/group')
        return_value.append('PASS')
        return_value.append(
            "grep '^\+:' /etc/group returned the following\n" + error)
    else:
        return_value.append('legacy "+" entries exist in /etc/group')
        return_value.append('FAIL')
        return_value.append(
            'The following accounts have legacy "+" entries in /etc/group\n' + success)
    return return_value


def _6_2_6_ubu():
    return_value = list()
    success, error = check("awk -F: '($3 == 0) { print $1 }' /etc/passwd")
    if success:
        if 'root\n' == success:
            return_value.append('root is the only UID 0 account')
            return_value.append('PASS')
            return_value.append(
                "awk -F: '($3 == 0) { print $1 }' /etc/passwd returned the following\n" + success)
        else:
            return_value.append('root is not the only UID 0 account')
            return_value.append('FAIL')
            return_value.append(
                "awk -F: '($3 == 0) { print $1 }' /etc/passwd returned the following UID 0 accounts\n" + success)
    else:
        return_value.append('no UID 0 account found')
        return_value.append('CHEK')
        return_value.append(error)
    return return_value


def _6_2_7_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_7.sh')
    check('sudo cat ' + script + ' > ./root_path_integrity.sh')
    check('chmod +x ./root_path_integrity.sh')
    success, error = check('./root_path_integrity.sh')
    if not success:
        return_value.append('root PATH Integrity maintained')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_7.sh returned the following\n' + error)
    else:
        return_value.append('writable dir in root\'s executable path')
        return_value.append('FAIL')
        return_value.append(
            'The following writable directories were found in root\'s executable path\n' + success)
    check('rm ./root_path_integrity.sh')
    return return_value


def _6_2_8_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_8.sh')
    check('sudo cat ' + script + ' > ./home_directory_permissions.sh')
    check('chmod +x ./home_directory_permissions.sh')
    success, error = check('./home_directory_permissions.sh')
    if not success:
        return_value.append('home directories permissions are gt 750')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_8.sh returned the following\n' + error)
    else:
        return_value.append('Group or world-writable home directories')
        return_value.append('FAIL')
        return_value.append(
            'The following users have Group or world-writable home directories\n' + success)
    check('rm ./home_directory_permissions.sh')
    return return_value


def _6_2_9_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_9.sh')
    check('sudo cat ' + script + ' > ./own_home_directory.sh')
    check('chmod +x ./own_home_directory.sh')
    success, error = check('./own_home_directory.sh')
    if not success:
        return_value.append('users own their home directories')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_9.sh returned the following\n' + error)
    else:
        return_value.append('user not owner of home directory')
        return_value.append('FAIL')
        return_value.append(
            'The following users are not the not owner of their home directories\n' + success)
    check('rm ./own_home_directory.sh')
    return return_value


def _6_2_10_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_10.sh')
    check('sudo cat ' + script + ' > ./user_dot_file.sh')
    check('chmod +x ./user_dot_file.sh')
    success, error = check('./user_dot_file.sh')
    if not success:
        return_value.append('users\' . files not group or world-writable')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_10.sh returned the following\n' + error)
    else:
        return_value.append('users\' . files group or world-writable')
        return_value.append('FAIL')
        return_value.append(
            'The following  users\' dot files are group or world writable\n' + success)
    check('rm ./user_dot_file.sh')
    return return_value


def _6_2_11_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_11.sh')
    check('sudo cat ' + script + ' > ./user_forward_file.sh')
    check('chmod +x ./user_forward_file.sh')
    success, error = check('./user_forward_file.sh')
    if not success:
        return_value.append('no users have .forward files')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_11.sh returned the following\n' + error)
    else:
        return_value.append('users have .forward files')
        return_value.append('FAIL')
        return_value.append(
            'The following users have .forward files\n' + success)
    check('rm ./user_forward_file.sh')
    return return_value


def _6_2_12_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_12.sh')
    check('sudo cat ' + script + ' > ./user_netrc_file.sh')
    check('chmod +x ./user_netrc_file.sh')
    success, error = check('./user_netrc_file.sh')
    if not success:
        return_value.append('no users have .netrc files')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_12.sh returned the following\n' + error)
    else:
        return_value.append('users have .netrc files')
        return_value.append('FAIL')
        return_value.append(
            'The following users have .netrc files\n' + success)
    check('rm ./user_netrc_file.sh')
    return return_value


def _6_2_13_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_13.sh')
    check('sudo cat ' + script + ' > ./user_netrc_writable.sh')
    check('chmod +x ./user_netrc_writable.sh')
    success, error = check('./user_netrc_writable.sh')
    if not success:
        return_value.append('users\' .netrc not group or world accessible')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_13.sh returned the following\n' + error)
    else:
        return_value.append('users\' .netrc group or world accessible')
        return_value.append('FAIL')
        return_value.append(
            'The following users\' .netrc Files are not group or world accessible\n' + success)
    check('rm ./user_netrc_writable.sh')
    return return_value


def _6_2_14_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_14.sh')
    check('sudo cat ' + script + ' > ./user_rhosts_file.sh')
    check('chmod +x ./user_rhosts_file.sh')
    success, error = check('./user_rhosts_file.sh')
    if not success:
        return_value.append('no users have .rhosts files')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_14.sh returned the following\n' + error)
    else:
        return_value.append('users have .rhosts files')
        return_value.append('FAIL')
        return_value.append(
            'The following users have .rhosts files\n' + success)
    check('rm ./user_rhosts_file.sh')
    return return_value


def _6_2_15_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_15.sh')
    check('sudo cat ' + script + ' > ./group_passwd.sh')
    check('chmod +x ./group_passwd.sh')
    success, error = check('./group_passwd.sh')
    if not success:
        return_value.append('all groups in passwd exist in group')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_15.sh returned the following\n' + error)
    else:
        return_value.append('groups in passwd don\'t exist in group')
        return_value.append('FAIL')
        return_value.append(
            'The following groups in /etc/passwd don\'t exist in /etc/group\n' + success)
    check('rm ./group_passwd.sh')
    return return_value


def _6_2_16_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_16.sh')
    check('sudo cat ' + script + ' > ./duplicate_uid.sh')
    check('chmod +x ./duplicate_uid.sh')
    success, error = check('./duplicate_uid.sh')
    if not success:
        return_value.append('no duplicate UIDs exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_16.sh returned the following\n' + error)
    else:
        return_value.append('duplicate UIDs exist')
        return_value.append('FAIL')
        return_value.append('The following duplicate UIDs exist\n' + success)
    check('rm ./duplicate_uid.sh')
    return return_value


def _6_2_17_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_17.sh')
    check('sudo cat ' + script + ' > ./duplicate_gid.sh')
    check('chmod +x ./duplicate_gid.sh')
    success, error = check('./duplicate_gid.sh')
    if not success:
        return_value.append('no duplicate GIDs exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_17.sh returned the following\n' + error)
    else:
        return_value.append('duplicate GIDs exist')
        return_value.append('FAIL')
        return_value.append('The following duplicate GIDs exist\n' + success)
    check('rm ./duplicate_gid.sh')
    return return_value


def _6_2_18_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_18.sh')
    check('sudo cat ' + script + ' > ./duplicate_user_name.sh')
    check('chmod +x ./duplicate_user_name.sh')
    success, error = check('./duplicate_user_name.sh')
    if not success:
        return_value.append('no duplicate user names exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_18.sh returned the following\n' + error)
    else:
        return_value.append('duplicate user names exist')
        return_value.append('FAIL')
        return_value.append(
            'The following duplicate user names exist\n' + success)
    check('rm ./duplicate_user_name.sh')
    return return_value


def _6_2_19_ubu():
    return_value = list()
    from sys import _MEIPASS
    from os.path import join
    script = join(_MEIPASS, 'scripts/ubu/6_2_19.sh')
    check('sudo cat ' + script + ' > ./duplicate_group_name.sh')
    check('chmod +x ./duplicate_group_name.sh')
    success, error = check('./duplicate_group_name.sh')
    if not success:
        return_value.append('no duplicate group names exist')
        return_value.append('PASS')
        return_value.append(
            'executing https://github.com/Deepak710/SeBAz/blob/master/linux/scripts/ubu/6_2_19.sh returned the following\n' + error)
    else:
        return_value.append('duplicate group names exist')
        return_value.append('FAIL')
        return_value.append(
            'The following duplicate group names exist\n' + success)
    check('rm ./duplicate_group_name.sh')
    return return_value


def _6_2_20_ubu():
    return_value = list()
    success, error = check('grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group')
    if not success:
        return_value.append('users not assigned to shadow group')
        return_value.append('PASS')
        return_value.append(
            'grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group returned the following\n' + error)
    else:
        result_success = ''
        result_error = ''
        for shadow_gid in success.splitlines():
            result = check("awk -F: '($4 == \"" + shadow_gid +
                           "\") { print }' /etc/passwd")
            result_success += result[0]
            result_error += result[1]
        if len(result_success):
            return_value.append('users not assigned to shadow group')
            return_value.append('PASS')
            return_value.append(
                'Following GIDs don\'t have entries in passwd\n' + success + '\n' + result_error)
        else:
            return_value.append(
                'users assigned to shadow group in /etc/passwd')
            return_value.append('FAIL')
            return_value.append('The following users are assigned to the shadow group in /etc/passwd\n' +
                                success + '\n' + result_success + '\n' + result_error + '\n' + error)
    return return_value


# function to call necessary recommendation benchmarks
def test(r, log, dist, verbosity, passd, faild, check, width):
    # test start time
    start = time()
    global log_file
    log_file = log
    # performing requested test
    return_value = eval('_' + r[0].replace('.', '_') + '_' + dist + '()')
    # return_score is 2 when test has passed (1) AND the test is scored (1)
    return_score = 0
    if 'PASS' == return_value[1] and r[1]:
        return_score = 2
        passd.update()
        if verbosity:
            print_success(r[0], return_value[0], return_value[1], width)
    elif 'PASS' == return_value[1]:
        return_score = 1
        passd.update()
        if verbosity:
            print_neutral(r[0], return_value[0], return_value[1], width)
    elif 'CHEK' == return_value[1]:
        check.update()
        if verbosity:
            print_neutral(r[0], return_value[0], return_value[1], width)
    else:
        faild.update()
        if verbosity:
            print_fail(r[0], return_value[0], return_value[1], width)

    return_value.insert(0, r[0])
    return_value.append(str(time() - start))

    # returning score
    return [return_score, return_value]


if __name__ == "__main__":
    exit('Please run ./SeBAz -h')
