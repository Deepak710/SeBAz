# count of total score
from subprocess import Popen, PIPE
total_score = 61

# calling subprocess function


def call(execute):
    return Popen(execute, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True).communicate()[0].decode('utf-8')


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
