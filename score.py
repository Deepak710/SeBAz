from variables import total_score
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
enabled = [fs for fs in unused_filesystems if fs in call(
    'modprobe -n -v ' + fs)]
# enabled contains unused filesystems that are not disabled
score += len(unused_filesystems) - len(enabled)
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
if not call("modprobe -n -v usb-storage"):
    score += 1

# 1.2 is not scored

# 1.3.1 AIDE installed is {version specific} [SCORED] ; doing for debian
if 'install ok installed' in call('dpkg -s aide'):
    score += 1
    # 1.3.2 filesystem integrity using AIDE(1.3.1)
    if 'no crontab for root' in call('sudo crontab -u root -l | grep aide'):
        score += 1

# 1.4.1 bootloader configuration {depends on bootloader} ; doing for GRUB
execute = call('stat /boot/grub*/grub.cfg | grep Access')
if any(p in execute for p in root_permissions):
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
if 'install ok installed' in call('dpkg -s libselinux1'):
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
if 'install ok installed' in call('dpkg -s apparmor'):
    score += 1
    # 1.6.3.1 not disabled | {depends on bootloader} | changes for GRUB 2
    if 'apparmor=0' not in call('grep "^\s*kernel" /boot/grub/menu.lst') and 'apparmor=0' not in call('grep "^\s*linux" /boot/grub/menu.lst'):
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
if '0644/-rw-r--r--' in call('stat /etc/motd | grep Access'):
    score += 1

# 1.7.1.5 /etc/issue permission configurations
if '0644/-rw-r--r--' in call('stat /etc/issue | grep Access'):
    score += 1

# 1.7.1.5 /etc/issue.net permission configurations
if '0644/-rw-r--r--' in call('stat /etc/issue.net | grep Access'):
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
installed_service_clients = [
    c for c in service_clients if 'install ok installed' in call('dpkg -s ' + c)]
# installed_service_clients contains installed NIS clients
score += len(service_clients) - len(installed_service_clients)
del(service_clients)

# 2.3.5 ldap not installed | has alternate names for different packages | doing for debian
if 'not installed' in call('dpkg -s openldap-clients', 1) and 'not installed' in call('dpkg -s ldap-utils', 1):
    score += 1

print(str(score) + ' out of ' + str(total_score) + ' are enabled')
