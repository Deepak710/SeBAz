# count of total score
from subprocess import Popen, PIPE
total_score = 96  # till 3.2.9

# calling subprocess function


def call(execute, pos=0):
    return Popen(execute, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True).communicate()[pos].decode('utf-8')


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

# 3.2.4
net_sysctl_1 = [['sysctl net.ipv4.conf.all.log_martians', 'sysctl net.ipv4.conf.default.log_martians'], ['sysctl net.ipv4.icmp_echo_ignore_broadcasts'], [
    'sysctl net.ipv4.icmp_ignore_bogus_error_responses'], ['sysctl net.ipv4.conf.all.rp_filter', 'sysctl net.ipv4.conf.default.rp_filter'], ['sysctl net.ipv4.tcp_syncookies']]
net_grep_1 = [['grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*'], ['grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*'],
              ['grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*'], ['grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*', 'grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*'], ['grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*']]