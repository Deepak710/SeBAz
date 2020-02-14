# count of total score
from subprocess import Popen, PIPE
total_score = 210

# calling subprocess function


def call(execute, pos=0):
    return Popen(execute, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True, executable='/bin/bash').communicate()[pos].decode('utf-8')


# 1.1.1 Disable unused filesystems
unused_filesystems = ['cramfs', 'freevxfs',
                      'jffs2', 'hfs', 'hfsplus', 'squashfs', 'udf']

# 1.1.2 -> 1.1.5 /tmp options
tmp_options = ['nodev', 'nosuid', 'noexec']

# 1.4.1 GRUB root permissions
root_permissions = ['004', '040', '044', '400', '404', '440', '444']

# 2.1 inetd services
inetd_services = ['chargen', 'daytime',
                  'discard', 'echo', 'time', 'telnet', 'tftp']

# 2.2.1.2 ntp restrict
ntp_restrict = ['default', 'kod', 'nomodify', 'notrap', 'nopeer', 'noquery']

# 2.2.3 -> 2.2.14 ; 2.2.16 ; 2.2.17 ( - 2.2.7 ) time sync services
time_sync = ['avahi-daemon', 'cups', 'dhcpd', 'slapd', 'named',
             'vsftpd', 'httpd', 'dovecot', 'smb', 'squid', 'snmpd', 'rsyncd', 'ypserv']

# 2.3.1 -> 2.3.4 service clients
service_clients = ['ypbind', 'rsh', 'talk', 'telnet']

# 3.1 ; 3.2.1 -> 3.2.3 ; 3.2.9 network parameters
net_sysctl = [['sysctl net.ipv4.ip_forward', 'sysctl net.ipv6.conf.all.forwarding'], ['sysctl net.ipv4.conf.all.send_redirects', 'sysctl net.ipv4.conf.default.send_redirects'], ['sysctl net.ipv4.conf.all.accept_source_route', 'sysctl net.ipv4.conf.default.accept_source_route', 'sysctl net.ipv6.conf.all.accept_source_route', 'sysctl net.ipv6.conf.default.accept_source_route'], [
    'sysctl net.ipv4.conf.all.accept_redirects', 'sysctl net.ipv4.conf.default.accept_redirects', 'sysctl net.ipv6.conf.all.accept_redirects', 'sysctl net.ipv6.conf.default.accept_redirects'], ['sysctl net.ipv4.conf.all.secure_redirects', 'sysctl net.ipv4.conf.default.secure_redirects'], ['sysctl net.ipv6.conf.all.accept_ra', 'sysctl net.ipv6.conf.default.accept_ra']]
net_grep = [['grep "net\.ipv4\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv6\.conf\.all\.forwarding" /etc/sysctl.conf /etc/sysctl.d/*'], ['grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*'], ['grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv6\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv6\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*'],
            ['grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv6\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv6\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*'], ['grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*'], ['grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*']]

# 3.2.4 network parameters enabled
net_sysctl_1 = [['sysctl net.ipv4.conf.all.log_martians', 'sysctl net.ipv4.conf.default.log_martians'], ['sysctl net.ipv4.icmp_echo_ignore_broadcasts'], [
    'sysctl net.ipv4.icmp_ignore_bogus_error_responses'], ['sysctl net.ipv4.conf.all.rp_filter', 'sysctl net.ipv4.conf.default.rp_filter'], ['sysctl net.ipv4.tcp_syncookies']]
net_grep_1 = [['grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*'], ['grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*'],
              ['grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*'], ['grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*'], ['grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*']]

# 3.4.1 -> 3.4.4 uncommon network protocols
uncommon_network_protocols = ['dccp', 'sctp', 'rds', 'tipc']

# 4.1.5 -> 4.1.18 ( - 4.1.13 ) collect audit events
audit_events = ['time-change', 'identity', 'system-locale', 'MAC-policy', 'logins',
                '(session|logins)', 'perm_mod', 'access', 'mounts', 'delete', 'scope', 'actions', 'modules']

# 5.1.3 -> 5.1.7 permissions on /etc/cron
etc_cron = ['hourly', 'daily', 'weekly', 'monthly', 'd']

# 5.2.13 weak cyphers
weak_cyphers = ['3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour',
                'arcfour128', 'arcfour256', 'blowfish-cbc', 'cast128-cbc', 'rijndael-cbc@lysator.liu.se']

# 5.2.14 weak MAC algorithms
weak_mac = ['hmac-md5', 'hmac-md5-96', 'hmac-ripemd160', 'hmac-sha1', 'hmac-sha1-96', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-md5-etm@openssh.com',
            'hmac-md5-96-etm@openssh.com', 'hmac-ripemd160-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'hmac-sha1-96-etm@openssh.com', 'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com']

# 5.2.15 weak Key Exchange Algorithms
weak_keys = ['diffie-hellman-group1-sha1',
             'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1']

# 5.3.1 password requirements
pwd_req = ['minlen=14', 'dcredit=-1',
           'ucredit=-1', 'ocredit=-1', 'lcredit=-1']

# 5.4.4 umask permissions
umask_permissions = ['22', '23', '27', '32', '33', '37', '72', '73', '77']
