from variables import total_score
from variables import etc_cron
from variables import uncommon_network_protocols
from variables import net_grep_1, net_sysctl_1
from variables import net_grep, net_sysctl
from variables import service_clients
from variables import time_sync
from variables import ntp_restrict
from variables import inetd_services
from variables import root_permissions
from variables import tmp_options
from variables import unused_filesystems
from variables import call
score = 0

# 1.1.1 unused filesystems
enabled_fs = [fs for fs in unused_filesystems if 'install /bin/true' not in call(
    'modprobe -n -v ' + fs) and 'not found in directory' not in call('modprobe -n -v ' + fs, 1)]
# enabled_fs contains unused filesystems that are not disabled
score += len(unused_filesystems) - len(enabled_fs)
del unused_filesystems

# 1.1.1.8 is not scored

# 1.1.2 -> 1.1.5 /tmp options
execute = call("mount | grep -E '\s/tmp\s'")
if execute:
    score += 1
    invalid_tmp = [option for option in tmp_options if option not in execute]
    # invalid_tmp comtains invalid /tmp mount options
    score += (len(tmp_options) - len(invalid_tmp))

# 1.1.6 -> 1.1.12 /var ; /var/tmp options ; /var/log ; /var/log/audit
if call("mount | grep -E '\s/var\s'"):
    score += 1
    execute = call("mount | grep -E '\s/var/tmp\s'")
    if execute:
        score += 1
        invalid_var_tmp = [
            option for option in tmp_options if option not in execute]
        # invalid_var_tmp contains invalid /var/tmp options
        score += (len(tmp_options) - len(invalid_var_tmp))
    if call("mount | grep -E '\s/var/log\s'"):
        score += 1
        if call("mount | grep -E '\s/var/log/audit\s'"):
            score += 1

# 1.1.13, 1.1.14 /home with nodev
execute = call("mount | grep /home")
if execute:
    score += 1
    if 'nodev' in execute:
        score += 1

# 1.1.15 -> 1.1.17 /dev/shm mount options
execute = call("mount | grep -E '\s/dev/shm\s'")
dev_shm_not_enabled = [option for option in tmp_options if option in execute]
# dev_shm_not_enabled contains mount options that are not enabled in /dev/shm
score += (len(tmp_options) - len(dev_shm_not_enabled))
del(tmp_options)

# 1.1.18 -> 1.1.20 is not scored

# 1.1.21 sticky world writable directories
non_sticky_world_writable = call(
    "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null").splitlines()
# non_sticky_world_writable contains all directories with non sticky world writable directories
if not non_sticky_world_writable:
    score += 1

# 1.1.22 automounting | chkconfig command not found in debian
if not call("systemctl is-enabled autofs | grep enabled"):
    execute = call('ls /etc/rc*.d | grep autofs').splitlines()
    # automout will contain all filesystems that will mount automatically
    automount = [s for s in execute if s.startswith('S')]
    if not automount:
        score += 1


# 1.1.23 disabled USB
if 'install /bin/true' in call("modprobe -n -v usb-storage") or 'not found in directory' in call("modprobe -n -v usb-storage", 1):
    score += 1

# 1.2 is not scored

# 1.3.1 AIDE installed is {version specific} [SCORED] ; doing for debian
if 'install ok installed' in call('dpkg -s aide | grep Status'):
    score += 1
    # 1.3.2 filesystem integrity using AIDE(1.3.1)
    if 'no crontab for root' in call('sudo crontab -u root -l | grep aide'):
        score += 1

# 1.4.1 bootloader configuration {depends on bootloader} ; doing for GRUB
execute = call('stat /boot/grub*/grub.cfg | grep Access').splitlines()[0]
if any(p in execute for p in root_permissions) and 'Uid: (    0/    root)   Gid: (    0/    root)' in execute:
    score += 1
del(root_permissions)

# 1.4.2 bootloader password {depends on bootloader} ; doing for GRUB
if call('grep "^\s*password" /boot/grub*/grub.cfg'):
    score += 1

# 1.4.3 root password
if not call('sudo grep ^root:[*\!]: /etc/shadow'):
    score += 1

# 1.4.4 is not scored

# 1.5.1 restrict core dumps
if '0' in call('grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*') and '0' in call('sysctl fs.suid_dumpable') and '0' in call('grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*'):
    if not call('systemctl is-enabled coredump.service'):
        score += 1
    else:
        # check configurations of coredump.service
        execute = call('cat /etc/systemd/coredump.conf')
        if 'Storage=none' in execute and 'ProcessSizeMax=0' in execute:
            score += 1

# 1.5.2 Ensure ND/NX support {for systems with journalctl}
if 'active' in call("journalctl | grep 'protection:"):
    score += 1

# 1.5.3 Active ASLR
if '2' in call('sysctl kernel.randomize_va_space') and '2' in call('grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*'):
    score += 1

# 1.5.4 Disable prelink {distributon specific} | doing for debian
if 'not installed' in call('dpkg -s prelink', 1):
    score += 1

# 1.6.1.1 SELinux or AppArmour {distribution specific} | doing for debian

# 1.6.2 Configure SELinux
if 'install ok installed' in call('dpkg -s libselinux1 | grep Status'):
    score += 1
    # 1.6.2.1 not disabled | {depends on bootloader} | changes for GRUB 2
    execute = call('grep "^\s*kernel" /boot/grub/menu.lst')
    if not execute:
        execute = call('grep "^\s*linux" /boot/grub2/grub.cfg')
    if 'selinux=0' not in execute and 'enforcing=0' not in execute:
        score += 1
    execute = call('cat /etc/selinux/config')
    if execute:
        # 1.6.2.2 enforcing
        if 'SELINUX=enforcing' in execute:
            score += 1
        # 1.6.2.3 policy configured
        if 'SELINUXTYPE=targeted' in execute:
            score += 1
    # 1.6.2.4 SETroubleshoot not installed
    if 'not installed' in call('dpkg -s setroubleshoot', 1):
        score += 1
    # 1.6.2.5 mcstrans not installed
    if 'not installed' in call('dpkg -s mcstrans', 1):
        score += 1
    # 1.6.2.6 unconfigured daemons
    if not call("ps -eZ | grep -E \"initrc\" | grep -E -v -w \"tr|ps|grep|bash|awk\" | tr ':' ' ' | awk '{ print $NF }'"):
        score += 1

# 1.6.3 Configure AppArmour
if 'install ok installed' in call('dpkg -s apparmor | grep Status'):
    score += 1
    # 1.6.3.1 not disabled | {depends on bootloader} | changes for GRUB 2
    if 'apparmor=0' not in call('grep "^\s*kernel" /boot/grub*/menu.lst') and 'apparmor=0' not in call('grep "^\s*linux" /boot/grub*/menu.lst'):
        score += 1
    # 1.6.3.2 profiles are enforcing
    execute = call('sudo apparmor_status')
    if '0 profiles are loaded.' not in execute and '0 profiles are in enforce mode.' not in execute and '0 processes are in complain mode.' in execute and '0 processes are unconfined but have a profile defined.' in execute:
        score += 1

# 1.7.1.1 message of the day
if not call("grep -E -i \"(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/motd"):
    score += 1

# 1.7.1.2 local login warning
if not call("grep -E -i \"(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue"):
    score += 1

# 1.7.1.3 remote login banner
if not call("grep -E -i \"(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue.net"):
    score += 1

# 1.7.1.4 /etc/motd permission configurations
if 'Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)' in call('stat /etc/motd | grep Access').splitlines()[0]:
    score += 1

# 1.7.1.5 /etc/issue permission configurations
if 'Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)' in call('stat /etc/issue | grep Access').splitlines()[0]:
    score += 1

# 1.7.1.6 /etc/issue.net permission configurations
if 'Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)' in call('stat /etc/issue.net | grep Access').splitlines()[0]:
    score += 1

# 1.7.2 GDM login banner | if message exists, comply with policy | DIFFERS FOR LOGIN SERVICES
if not '# banner-message-enable=true' in call('cat /etc/gdm3/greeter.dconf-defaults | grep banner-message'):
    score += 1

# 1.8 is not scored

# 2.1 inetd services
if 'No such file or directory' in call('/etc/inetd.*'):
    score += len(inetd_services) + 2
else:
    enabled_inetd = [s for s in inetd_services if (call('grep -R "^' + s + '" /etc/inetd.*') or any('disable = yes' in l for l in call(
        'cat /etc/xinetd.conf | grep ' + s).splitlines()) or any('disable = yes' in l for l in call('cat /etc/xinetd.d/* | grep ' + s).splitlines()))]
    score += len(inetd_services) - len(enabled_inetd)
    # 2.1.6 rsh services
    if not call('grep -R "^shell" /etc/inetd.*') and not call('grep -R "^login" /etc/inetd.*') and not call('grep -R "^exec" /etc/inetd.*'):
        if all('disable = yes' in l for l in call('cat /etc/xinetd.conf | grep rsh').splitlines()) and all('disable = yes' in l for l in call('cat /etc/xinetd.d/* | grep rsh').splitlines()):
            if all('disable = yes' in l for l in call('cat /etc/xinetd.conf | grep rlogin').splitlines()) and all('disable = yes' in l for l in call('cat /etc/xinetd.d/* | grep rlogin').splitlines()):
                if all('disable = yes' in l for l in call('cat /etc/xinetd.conf | grep rexec').splitlines()) and all('disable = yes' in l for l in call('cat /etc/xinetd.d/* | grep rexec').splitlines()):
                    score += 1
    else:
        enabled_inetd.append('rsh')
    # 2.1.7 talk services
    if not call('grep -R "^talk" /etc/inetd.*') and not call('grep -R "^ntalk" /etc/inetd.*'):
        if all('disable = yes' in l for l in call('cat /etc/xinetd.conf | grep talk').splitlines()):
            score += 1
    else:
        enabled_inetd.append('talk')

# 2.1.10 xinetd disabled | chkconfig command not found in debian
if not call("systemctl is-enabled xinetd | grep enabled"):
    execute = call('ls /etc/rc*.d | grep xinetd').splitlines()
    if not any(s for s in execute if s.startswith('S')):
        score += 1

# 2.2.1.1 is not scored

# 2.2.1.2 ntp configuration
execute = call('grep "^restrict" /etc/ntp.conf').splitlines()[:2]
if all(o in e for o in ntp_restrict for e in execute):
    # check if call('grep -E "^(server|pool)" /etc/ntp.conf') is configured properly
    if 'OPTIONS="-u ntp:ntp"' in call('grep "^OPTIONS" /etc/sysconfig/ntpd') or 'OPTIONS="-u ntp:ntp"' in call('grep "^NTPD_OPTIONS" /etc/sysconfig/ntp'):
        if 'RUNASUSER=ntp' in call('grep "RUNASUSER=ntp" /etc/init.d/ntp'):
            score += 1
del(ntp_restrict)

# 2.2.1.3 chrony configuration
# check if call('grep -E "^(server|pool)" /etc/chrony.conf') is configured properly
execute = call('ps -ef | grep chronyd').splitlines()
if any(p.startswith('chrony') for p in execute):
    score += 1

# 2.2.1.4 systemd-timesyncd configuration
if 'enabled' in call('systemctl is-enabled systemd-timesyncd.service'):
    # ensure call('timedatectl status') is in accordance with local policy
    score += 1

# 2.2.2 no X windows system | doing for debian
if not call('dpkg -l xserver-xorg* | grep ii'):
    score += 1

# 2.2.3 -> 2.2.14 ; 2.2.16 ; 2.2.17 ( - 2.2.7 ) disable time sync services | chkconfig command not found in debian
for s in time_sync:
    if not call("systemctl is-enabled " + s + " | grep enabled"):
        execute = call('ls /etc/rc*.d | grep ' + s).splitlines()
        if not any(e for e in execute if e.startswith('S')):
            score += 1
del(time_sync)
# 2.2.7 nfs and rpc
if not call("systemctl is-enabled nfs | grep enabled") and not call("systemctl is-enabled rpcbind | grep enabled"):
    execute = call('ls /etc/rc*.d | grep nfs').splitlines()
    if not any(e for e in execute if e.startswith('S')):
        execute = call('ls /etc/rc*.d | grep rpcbind').splitlines()
        if not any(e for e in execute if e.startswith('S')):
            score += 1

# 2.2.15 local only MTA
if not call("ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'"):
    score += 1

# 2.3.1 -> 2.3.4 no NIS client | doing for debian
installed_service_clients = [c for c in service_clients if 'install ok installed' in call(
    'dpkg -s ' + c + ' | grep Status')]
# installed_service_clients contains installed NIS clients
score += len(service_clients) - len(installed_service_clients)
del(service_clients)

# 2.3.5 ldap not installed | has alternate names for different packages | doing for debian
if 'not installed' in call('dpkg -s openldap-clients', 1) and 'not installed' in call('dpkg -s ldap-utils', 1):
    score += 1

# 3.1 ; 3.2.1 -> 3.2.3 ; 3.2.9 network parameters
for s, g in zip(net_sysctl, net_grep):
    if all(' = 0' in call(c) for c in s):
        execute = [call(c).splitlines() for c in g]
        if all('#' in c or '0' in c for c in execute):
            score += 1
del(net_sysctl, net_grep)

# 3.2.4 -> 3.2.8 network parameters
for s, g in zip(net_sysctl_1, net_grep_1):
    if all(' = 1' in call(c) for c in s):
        execute = [call(c).splitlines() for c in g]
        if all('#' in c or '1' in c for c in execute):
            score += 1
del(net_sysctl_1, net_grep_1)

# 3.3.1 -> 3.3.3 is not scored

# 3.3.4 configure hosts.allow
if 'Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)' in call('stat /etc/hosts.allow | grep Access').splitlines()[0]:
    score += 1

# 3.3.5 configure hosts.deny
if 'Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)' in call('stat /etc/hosts.deny | grep Access').splitlines()[0]:
    score += 1

# 3.4.1 -> 3.4.4 disable uncommon network protocols
enabled_pr = [pr for pr in uncommon_network_protocols if 'install /bin/true' not in call(
    'modprobe -n -v ' + pr) and 'not found in directory' not in call('modprobe -n -v ' + pr, 1)]
# enabled_pr contains unused protocols that are not disabled
score += len(uncommon_network_protocols) - len(enabled_pr)
del(uncommon_network_protocols)

# 3.5.1.1 ipv6 default block policy
if all('policy DROP' in e or 'policy REJECT' in e for e in call('sudo ip6tables -L | grep Chain').splitlines()):
    if not call('grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1'):
        score += 1

# 3.5.1.2 ipv6 configured loopback | WORSTU CODE
execute = call('sudo ip6tables -L INPUT -v -n').splitlines()
if len(execute) > 2:
    f = 0
    for i in range(2, len(execute)):
        if (execute[i].split()[6] == '::/0' or execute[i].split()[6] == '::1') and (execute[i].split()[7] == '::1' or execute[i].split()[7] == '::/0'):
            f += 1
    if f == len(execute) - 2:
        execute = call('sudo ip6tables -L OUTPUT -v -n').splitlines()
        if len(execute) > 2:
            f = 0
            for i in range(2, len(execute)):
                if (execute[i].split()[6] == '::/0' or execute[i].split()[6] == '::1') and (execute[i].split()[7] == '::1' or execute[i].split()[7] == '::/0'):
                    f += 1
            if f == len(execute) - 2:
                if not call('grep "^\s*linux" /boot/grub*/grub.cfg | grep -v ipv6.disable=1'):
                    score += 1

# 3.5.1.3 ; 3.5.1.4 is not scored

# 3.5.2.1 default deny firewall
if all('policy DROP' in e or 'policy REJECT' in e for e in call('sudo iptables -L | grep Chain').splitlines()):
    score += 1

# 3.5.2.2 configure loopback traffic | WORSTU CODE
execute = call('sudo iptables -L INPUT -v -n').splitlines()
if len(execute) > 2:
    f = 0
    for i in range(2, len(execute)):
        if (execute[i].split()[7] == '0.0.0.0/0' or execute[i].split()[7] == '127.0.0.0/8') and (execute[i].split()[8] == '0.0.0.0/0' or execute[i].split()[8] == '127.0.0.0/8'):
            f += 1
    if f == len(execute) - 2:
        execute = call('sudo iptables -L OUTPUT -v -n').splitlines()
        if len(execute) > 2:
            f = 0
            for i in range(2, len(execute)):
                if (execute[i].split()[7] == '0.0.0.0/0' or execute[i].split()[7] == '127.0.0.0/8') and (execute[i].split()[8] == '0.0.0.0/0' or execute[i].split()[8] == '127.0.0.0/8'):
                    f += 1
            if f == len(execute) - 2:
                score += 1

# 3.5.2.3 is not scored

# 3.5.2.4 firewall rules for open ports
# getting all open ports
execute = call('ss -4tuln').splitlines()[1:]
if execute:
    open_ports = [e.split()[4] for e in execute]
    open_ports = [e[e.rfind(':'):].strip(':') for e in open_ports]
    # checking for rules foor open ports
    if all(call('sudo iptables -L INPUT -v -n | grep ' + e) for e in open_ports):
        score += 1
else:
    # scoring if there are no open ports
    score += 1

# 3.5.6 install iptables
if ('install ok installed' in call('dpkg -s iptables | grep Status')):
    score += 1

# 3.6 ; 3.7 not scored

# 4.1.1.1 audit log storage size
if call('grep max_log_file /etc/audit/auditd.conf'):
    score += 1

# 4.1.1.2 disable system when audit is full
if call('grep space_left_action /etc/audit/auditd.conf') and call('grep action_mail_acct /etc/audit/auditd.conf') and call('grep admin_space_left_action /etc/audit/auditd.conf'):
    score += 1

# 4.1.1.3 audit logs are not automatically deleted
if 'max_log_file_action = keep_logs' in call('grep max_log_file_action /etc/audit/auditd.conf'):
    score += 1

# 4.1.2 auditd installed
if 'install ok installed' in call('dpkg -s auditd audispd-plugins | grep Status'):
    score += 1

# 4.1.3 enable auditd
if call("systemctl is-enabled auditd | grep enabled"):
    execute = call('ls /etc/rc*.d | grep auditd').splitlines()
    # S* lines returned for runlevels 2 through 5
    if all(s for s in execute if s.startswith('S')):
        score += 1

# 4.1.4 audit befoore auditd starts
execute = call('grep "^\s*linux" /boot/grub*/grub.cfg').splitlines()
if all('audit=1' in e for e in execute):
    execute = call('grep "^\s*kernel" /boot/grub*/menu.lst').splitlines()
    if all('audit=1' in e for e in execute):
        score += 1

# 4.1.5 -> 4.1.18 - 4.1.13 collect events | arch dependent
if 'No such file or directory' not in call('ls /etc/audit/rules.d/*.rules'):
    from variables import audit_events
    for e in audit_events:
        if call("grep -E '" + e + "' /etc/audit/rules.d/*.rules"):
            if call("auditctl -l | grep -E '" + e + "'"):
                score += 1
    del(audit_events)

# 4.1.13 collect priviedged commands | DON'T KNOW IF CORRECT
partitions = call('mount | grep -e "/dev/sd"').splitlines()
execute = [call(
    "find " + e + " -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \"-a always,exit -F path=\" $1 \" -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged\" }'") for e in partitions]
if execute:
    f = 0
    for e in execute:
        if all(call('cat ' + l + ' | grep auid!=-1') for l in e.splitlines()):
            f += 1
    if f:
        score += 1

# 4.1.19 immutable audit configurations
if '-e 2' in call('grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1'):
    score += 1

# 4.2.1.1 install rssyslog
if 'install ok installed' in call('dpkg -s rsyslog | grep Status'):
    score += 1

# 4.2.1.2 enable syslog
if call("systemctl is-enabled rsyslog | grep enabled"):
    execute = call('ls /etc/rc*.d | grep rsyslog').splitlines()
    # S* lines returned for runlevels 2 through 5
    if all(s for s in execute if s.startswith('S')):
        score += 1

# 4.2.1.3 is not scored

# 4.2.1.4 rsyslog file permissions
execute = call(
    'grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf').splitlines()
if all('$FileCreateMode 0640' in e and 'No such file or directory' not in e for e in execute):
    score += 1

# 4.2.1.5 send logs to remote log host
execute = call('grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf')
if execute and 'No such file or directory' not in execute:
    score += 1

# 4.2.1.6 is not scored

# 4.2.2.1 configure journald forward
if 'ForwardToSyslog=yes' in call('grep -e ForwardToSyslog /etc/systemd/journald.conf'):
    score += 1

# 4.2.2.2 configure journald compress
if 'Compress=yes' in call('grep -e Compress /etc/systemd/journald.conf'):
    score += 1

# 4.2.2.3 configure journald
if 'Storage=persistent' in call('grep -e Storage /etc/systemd/journald.conf'):
    score += 1

# 4.2.3 configure group and other permissioon on log files
execute = call('sudo find /var/log -type f -ls').splitlines()
if all('r-----' == e.split()[2][-6:] or '------' == e.split()[2][-6:] for e in execute):
    score += 1

# 4.3 is not scored

# 5.1.1 configure cron daemon
if call("systemctl is-enabled crond | grep enabled"):
    execute = call('ls /etc/rc*.d | grep crond').splitlines()
    # S* lines returned for runlevels 2 through 5
    if all(s for s in execute if s.startswith('S')):
        score += 1

# 5.1.2 configure permissions on /etc/crontab
if 'Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)' in call('stat /etc/crontab | grep Access').splitlines()[0]:
    score += 1

# 5.1.3 -> 5.1.7 configure permissions on /etc/cron
for e in etc_cron:
    execute = call('stat /etc/cron.' + e + ' | grep Access').splitlines()[0]
    if '------' == execute.split()[1][-7:-1] and 'Uid: (    0/    root)   Gid: (    0/    root)' in execute:
        score += 1
del(etc_cron)

# 5.1.8 no cron.deny and configure cron.allow
if 'No such file or directory' in call('stat /etc/cron.deny', 1) and 'No such file or directory' in call('stat /etc/at.deny', 1):
    execute = call('stat /etc/cron.allow | grep Access')
    if execute and '------' == execute.splitlines()[0].split()[1][-7:-1] and 'Uid: (    0/    root)   Gid: (    0/    root)' in execute.splitlines()[0]:
        execute = call('stat /etc/at.allow | grep Access')
        if execute and '------' == execute.splitlines()[0].split()[1][-7:-1] and 'Uid: (    0/    root)   Gid: (    0/    root)' in execute.splitlines()[0]:
            score += 1

# 5.2.1 configure /etc/ssh/sshd_config permissions
execute = call('stat /etc/ssh/sshd_config | grep Access').splitlines()[0]
if execute and '------' == execute.split()[1][-7:-1] and 'Uid: (    0/    root)   Gid: (    0/    root)' in execute:
    score += 1

# 5.2.2 SSH private host key permissions
execute = call(
    "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | grep \"Access: (\"").splitlines()
if all('------' in e.split()[1][-7:-1] and 'Uid: (    0/    root)   Gid: (    0/    root)' in e for e in execute):
    score += 1

# 5.2.3 SSH public host key permissions
execute = call(
    "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | grep \"Access: (\"").splitlines()
if all(('------' in e.split()[1][-7:-1] or 'r--r--' in e.split()[1][-7:-1] or 'r-----' in e.split()[1][-7:-1] or '---r--' in e.split()[1][-7:-1]) and 'Uid: (    0/    root)   Gid: (    0/    root)' in e for e in execute):
    score += 1

# 5.2.4 SSH Protocol 2
if 'Protocol 2' in call('grep ^Protocol /etc/ssh/sshd_config'):
    score += 1

# 5.2.5 appropriate SSH LogLevel
if 'loglevel INFO' or 'loglevel VERBOSE' in call('sshd -T | grep loglevel'):
    score += 1

print(str(score) + ' out of ' + str(total_score) + ' are enabled')
