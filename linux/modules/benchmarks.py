from modules.printProgressAuto.progressBar import printProgressBar
from modules.termcolor.termcolor import cprint
from subprocess import Popen, PIPE
from time import time
from csv import writer


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
    ['1.2.1', 0, 1, 1, 'Ensure package manager repositories are configured (distro specific)'],
    ['1.2.2', 0, 1, 1, 'Ensure GPG keys are configured (distro specific)'],
    ['1.3.1', 1, 1, 1, 'Ensure AIDE is installed (distro specific)'],
    ['1.3.2', 1, 1, 1, 'Ensure filesystem integrity is regularly checked'],
    ['1.4.1', 1, 1, 1, 'Ensure permissions on bootloader config are configured (bootloader specific)'],
    ['1.4.2', 1, 1, 1, 'Ensure bootloader password is set (bootloader specific)'],
    ['1.4.3', 1, 1, 1, 'Ensure authentication required for single user mode'],
    ['1.4.4', 0, 1, 1, 'Ensure interactive boot is not enabled (distro specific)'],
    ['1.5.1', 1, 1, 1, 'Ensure core dumps are restricted'],
    ['1.5.2', 1, 1, 1, 'Ensure XD/NX support is enabled'],
    ['1.5.3', 1, 1, 1, 'Ensure address space layout randomization (ASLR) is enabled'],
    ['1.5.4', 1, 1, 1, 'Ensure prelink is disabled (distro specific)'],
    ['1.6.1.1', 1, 2, 2, 'Ensure SELinux or AppArmor are installed (distro specific)'],
    ['1.6.2.1', 1, 2, 2, 'Ensure SELinux is not disabled in bootloader configuration'],
    ['1.6.2.2', 1, 2, 2, 'Ensure the SELinux state is enforcing'],
    ['1.6.2.3', 1, 2, 2, 'Ensure SELinux policy is configured'],
    ['1.6.2.4', 1, 2, 0, 'Ensure SETroubleshoot is not installed (distro specific)'],
    ['1.6.2.5', 1, 2, 2, 'Ensure the MCS Translation Service (mcstrans) is not installed (distro specific)'],
    ['1.6.2.6', 1, 2, 2, 'Ensure no unconfined daemons exist'],
    ['1.6.3.1', 1, 2, 2, 'Ensure AppArmor is not disabled in bootloader configuration'],
    ['1.6.3.2', 1, 2, 2, 'Ensure all AppArmor Profiles are enforcing'],
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
]


def print_success(r, x, p): cprint(
    '{:<8}   {:<50}\t{:>4}'.format(r, x, p), 'green', attrs=['bold'])


def print_fail(r, x, p): cprint('{:<8}   {:<50}\t{:>4}'.format(
    r, x, p), 'red', attrs=['bold'])


def print_neutral(r, x, p): cprint('{:<8}   {:<50}\t{:>4}'.format(
    r, x, p), 'grey', attrs=['bold'])


# function to execute the check
def check(execute):
    execute = Popen(execute, stdin=PIPE, stdout=PIPE, stderr=PIPE,
                    shell=True, executable='/bin/bash').communicate()
    execute = [e.decode('utf-8') for e in execute]
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
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value.append('cramfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('cramfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v cramfs did not return anything')
    return return_value


def _1_1_1_2_ind():
    return_value = list()
    success, error = check('modprobe -n -v freevxfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep freevxfs')[0]:
            return_value.append('freevxfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('freevxfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('freevxfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v freevxfs did not return anything')
    return return_value


def _1_1_1_3_ind():
    return_value = list()
    success, error = check('modprobe -n -v jffs2')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep jffs2')[0]:
            return_value.append('jffs2 cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('jffs2 can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('jffs2 could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v jffs2 did not return anything')
    return return_value


def _1_1_1_4_ind():
    return_value = list()
    success, error = check('modprobe -n -v hfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfs')[0]:
            return_value.append('hfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('hfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('hfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v hfs did not return anything')
    return return_value


def _1_1_1_5_ind():
    return_value = list()
    success, error = check('modprobe -n -v hfsplus')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfsplus')[0]:
            return_value.append('hfsplus cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('hfsplus can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('hfsplus could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v hfsplus did not return anything')
    return return_value


def _1_1_1_6_ind():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value.append('squashfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('squashfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('squashfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v squashfs did not return anything')
    return return_value


def _1_1_1_7_ind():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value.append('udf cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('udf could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v udf did not return anything')
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
        if 'install /bin/true' in success or 'not found in directory' in error:
            if not check('lsmod | grep vfat')[0]:
                return_value.append('vfat cannot be mounted')
                return_value.append('PASS')
                return_value.append(success if success else error)
        elif 'insmod' in success:
            return_value.append('vfat can be mounted')
            return_value.append('CHEK')
            return_value.append(success)
        else:
            return_value.append('vfat could not be checked')
            return_value.append('CHEK')
            return_value.append(
                'modprobe -n -v usb-storage did not return anything')
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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


def _1_1_23_ind():
    return_value = list()
    success, error = check('modprobe -n -v usb-storage')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep usb-storage')[0]:
            return_value.append('usb-storage cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('usb-storage can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('usb-storage could not be checked')
        return_value.append('CHEK')
        return_value.append(
            'modprobe -n -v usb-storage did not return anything')
    return return_value


# distro specific
def _1_2_1_ind():
    return_value = list()
    return_value.append('package configuration not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('sudo apt-cache policy')
    if success:
        return_value.append('check configuration of repos')
        return_value.append('CHEK')
        return_value.append('The following are the configuration of the package manager repositories\n' + success)
    else:
        return_value.append('package configuration not checked')
        return_value.append('CHEK')
        return_value.append('sudo apt-cache policy did not return anything\n' + error)
    return return_value


# distro specific
def _1_2_2_ind():
    return_value = list()
    return_value.append('GPG keys source not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('sudo apt-key list')
    if success:
        return_value.append('check GPG keys source')
        return_value.append('CHEK')
        return_value.append('The following are the configuration of the GPG keys\n' + success)
    else:
        return_value.append('GPG keys not checked')
        return_value.append('CHEK')
        return_value.append('sudo apt-key list did not return any keys\n' + error)
    return return_value


# distro specific
def _1_3_1_ind():
    return_value = list()
    return_value.append('AIDE not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('sudo dpkg -s aide')
    if success:
        return_value.append('AIDE is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('AIDE is not installed')
        return_value.append('FAIL')
        return_value.append('sudo dpkg -s aide returned\n' + error)
    return return_value


def _1_3_2_ind():
    return_value = list()
    success, error = check('sudo crontab -u root -l | grep aide')
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
        return_value.append('grep -r aide /etc/cron.* /etc/crontab returned the following\n' + success + '\n' + error)
    return return_value


# bootloader specific
def _1_4_1_ind():
    return_value = list()
    success, error = check('sudo stat /boot/grub*/grub.cfg | grep Access')
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
        return_value.append('stat /boot/grub*/grub.cfg | grep Access returned\n' + success + '\n' + error)
    return return_value


# bootloader specific
def _1_4_2_ind():
    return_value = list()
    success, error = check('sudo grep "^\s*password" /boot/grub/menu.lst')
    if success:
        return_value.append('bootloader password is set')
        return_value.append('PASS')
        return_value.append(success)
    else:
        success, error = check('sudo grep "^\s*password" /boot/grub/grub.cfg')
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
    success, error = check('sudo grep ^root:[*\!]: /etc/shadow')
    if success:
        return_value.append('auth required for single user mode')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('auth not required for single user mode')
        return_value.append('FAIL')
        return_value.append('sudo grep ^root:[*\!]: /etc/shadow returned the following\n' + error)
    return return_value


# distro specific
def _1_4_4_ind():
    return_value = list()
    success, error = check('sudo grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot')
    if 'PROMPT_FOR_CONFIRM="no"' in success:
        return_value.append('interactive boot disabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        return_value.append('interactive boot not checked')
        return_value.append('CHEK')
        return_value.append('sudo grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot returned the following\n' + success + '\n' + error)
    return return_value


def _1_5_1_ind():
    return_value = list()
    result_success = ''
    result_error = ''
    success, error = check('grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check('sysctl fs.suid_dumpable')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    success, error = check('grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*')
    if success:
        result_success += success + '\n'
    else:
        result_error += error + '\n'
    if  len(result_success.splitlines()) == 6:
        return_value.append('core dumps are restricted')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('core dumps not restricted')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success + '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


def _1_5_2_ind():
    return_value = list()
    success, error = check("sudo journalctl | grep 'protection: active'")
    if success:
        return_value.append('XD/NX support is enabled')
        return_value.append('PASS')
        return_value.append(success)
    else:
        result_error = error
        success, error = check("[[ -n $(grep noexec[0-9]*=off /proc/cmdline) || -z $(grep -E -i ' (pae|nx) ' /proc/cpuinfo) || -n $(grep '\sNX\s.*\sprotection:\s' /var/log/dmesg | grep -v active) ]] && echo \"NX Protection is not active\"")
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
    success, error = check('grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*')
    if '2' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    if  len(result_success.splitlines()) == 4:
        return_value.append('ASLR enabled')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('ASLR not enabled')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success + '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


# distro specific
def _1_5_4_ind():
    return_value = list()
    return_value.append('prelink not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('sudo dpkg -s prelink')
    if not success:
        return_value.append('prelink is not installed')
        return_value.append('PASS')
        return_value.append(error)
    else:
        return_value.append('prelink is installed')
        return_value.append('FAIL')
        return_value.append('sudo dpkg -s prelink returned\n' + success)
    return return_value


# distro specific
def _1_6_1_1_ind():
    return_value = list()
    return_value.append('SELinux or AppArmor not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('sudo dpkg -s libselinux1')
    if success:
        return_value.append('SELinux is installed')
        return_value.append('PASS')
        return_value.append(success)
    else:
        result_error = error + '\n'
        success, error = check('sudo dpkg -s apparmor')
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
    success, error = check('sudo sestatus')
    if 'SELinux status: enabled' in success and 'Current mode: enforcing' in success and 'Mode from config file: enforcing' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    if  len(result_success.splitlines()) == 4:
        return_value.append('SELinux state is enforcing')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('SELinux state is not enforcing')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success + '\n' + 'Following are configured improperly\n' + result_error)
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
    success, error = check('sudo sestatus')
    if 'Policy from config file: targeted' in success or 'Policy from config file: mls' in success:
        result_success += success + '\n'
    else:
        result_error += success + '\n' + error + '\n'
    if  len(result_success.splitlines()) == 4:
        return_value.append('SELinux policy is configured')
        return_value.append('PASS')
        return_value.append(result_success)
    else:
        return_value.append('SELinux policy is not configured')
        return_value.append('FAIL')
        return_value.append('Following are configured properly\n' + result_success + '\n' + 'Following are configured improperly\n' + result_error)
    return return_value


# distro specific
def _1_6_2_4_ind():
    return_value = list()
    return_value.append('SETroubleshoot not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('sudo dpkg -s setroubleshoot')
    if not success:
        return_value.append('SETroubleshoot is not installed')
        return_value.append('PASS')
        return_value.append(error)
    else:
        return_value.append('SETroubleshoot is installed')
        return_value.append('FAIL')
        return_value.append('sudo dpkg -s setroubleshoot returned\n' + success)
    return return_value


# distro specific
def _1_6_2_5_ind():
    return_value = list()
    return_value.append('mcstrans not checked (ind distro)')
    return_value.append('CHEK')
    return_value.append('Distribution was not specified')
    return return_value
    success, error = check('sudo dpkg -s mcstrans')
    if not success:
        return_value.append('mcstrans is not installed')
        return_value.append('PASS')
        return_value.append(error)
    else:
        return_value.append('mcstrans is installed')
        return_value.append('FAIL')
        return_value.append('sudo dpkg -s mcstrans returned\n' + success)
    return return_value


def _1_6_2_6_ind():
    return_value = list()
    success, error = check("ps -eZ | grep -E \"initrc\" | grep -E -v -w \"tr|ps|grep|bash|awk\" | tr ':' ' ' | awk '{ print $NF }'")
    if not success:
        return_value.append('no unconfined daemons exist')
        return_value.append('PASS')
        return_value.append("ps -eZ | grep -E \"initrc\" | grep -E -v -w \"tr|ps|grep|bash|awk\" | tr ':' ' ' | awk '{ print $NF }' returned nothing")
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
    success, error = check('sudo apparmor_status')
    if success:
        loaded_profiles = [p for p in success.splitlines() if 'profiles are loaded.' in p]
        complain_profiles = [p for p in success.splitlines() if 'profiles are in complain mode.' in p]
        unconfined_process = [p for p in success.splitlines() if 'processes are unconfined' in p]
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
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value.append('cramfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('cramfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v cramfs did not return anything')
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
        if 'install /bin/true' in success or 'not found in directory' in error:
            if not check('lsmod | grep vfat')[0]:
                return_value.append('vfat cannot be mounted')
                return_value.append('PASS')
                return_value.append(success if success else error)
        elif 'insmod' in success:
            return_value.append('vfat can be mounted')
            return_value.append('CHEK')
            return_value.append(success)
        else:
            return_value.append('vfat could not be checked')
            return_value.append('CHEK')
            return_value.append('modprobe -n -v vfat did not return anything')
    return return_value


def _1_1_1_3_cen():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value.append('squashfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('squashfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('squashfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v squashfs did not return anything')
    return return_value


def _1_1_1_4_cen():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value.append('udf cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('udf could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v udf did not return anything')
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep usb-storage')[0]:
            return_value.append('usb-storage cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('usb-storage can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
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
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep freevxfs')[0]:
            return_value.append('freevxfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('freevxfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('freevxfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v freevxfs did not return anything')
    return return_value


def _1_1_1_2_deb():
    return_value = list()
    success, error = check('modprobe -n -v jffs2')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep jffs2')[0]:
            return_value.append('jffs2 cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('jffs2 can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('jffs2 could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v jffs2 did not return anything')
    return return_value


def _1_1_1_3_deb():
    return_value = list()
    success, error = check('modprobe -n -v hfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfs')[0]:
            return_value.append('hfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('hfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('hfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v hfs did not return anything')
    return return_value


def _1_1_1_4_deb():
    return_value = list()
    success, error = check('modprobe -n -v hfsplus')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfsplus')[0]:
            return_value.append('hfsplus cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('hfsplus can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('hfsplus could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v hfsplus did not return anything')
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value.append('cramfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('cramfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v cramfs did not return anything')
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
        if 'install /bin/true' in success or 'not found in directory' in error:
            if not check('lsmod | grep vfat')[0]:
                return_value.append('vfat cannot be mounted')
                return_value.append('PASS')
                return_value.append(success if success else error)
        elif 'insmod' in success:
            return_value.append('vfat can be mounted')
            return_value.append('CHEK')
            return_value.append(success)
        else:
            return_value.append('vfat could not be checked')
            return_value.append('CHEK')
            return_value.append('modprobe -n -v vfat did not return anything')
    return return_value


def _1_1_1_3_fed():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value.append('squashfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('squshfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('squashfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v squashfs did not return anything')
    return return_value


def _1_1_1_4_fed():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value.append('udf cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('udf could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v udf did not return anything')
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep usb-storage')[0]:
            return_value.append('usb-storage cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('usb-storage can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
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
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value.append('cramfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('cramfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v cramfs did not return anything')
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
        if 'install /bin/true' in success or 'not found in directory' in error:
            if not check('lsmod | grep vfat')[0]:
                return_value.append('vfat cannot be mounted')
                return_value.append('PASS')
                return_value.append(success if success else error)
        elif 'insmod' in success:
            return_value.append('vfat can be mounted')
            return_value.append('CHEK')
            return_value.append(success)
        else:
            return_value.append('vfat could not be checked')
            return_value.append('CHEK')
            return_value.append('modprobe -n -v vfat did not return anything')
    return return_value


def _1_1_1_3_red():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value.append('squashfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('squashfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('vfat could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v vfat did not return anything')
    return return_value


def _1_1_1_4_red():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value.append('udf cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('udf could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v udf did not return anything')
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep usb-storage')[0]:
            return_value.append('usb-storage cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('usb-storage can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
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
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value.append('cramfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('cramfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v cramfs did not return anything')
    return return_value


def _1_1_1_2_sus():
    return_value = list()
    success, error = check('modprobe -n -v freevxfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep freevxfs')[0]:
            return_value.append('freevxfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('freevxfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('freevxfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v freevxfs did not return anything')
    return return_value


def _1_1_1_3_sus():
    return_value = list()
    success, error = check('modprobe -n -v jffs2')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep jffs2')[0]:
            return_value.append('jffs2 cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('jffs2 can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('jffs2 could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v jffs2 did not return anything')
    return return_value


def _1_1_1_4_sus():
    return_value = list()
    success, error = check('modprobe -n -v hfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfs')[0]:
            return_value.append('hfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('hfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('hfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v hfs did not return anything')
    return return_value


def _1_1_1_5_sus():
    return_value = list()
    success, error = check('modprobe -n -v hfsplus')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfsplus')[0]:
            return_value.append('hfsplus cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('hfsplus can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('hfsplus could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v hfsplus did not return anything')
    return return_value


def _1_1_1_6_sus():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value.append('squashfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('squashfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('squashfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v squashfs did not return anything')
    return return_value


def _1_1_1_7_sus():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value.append('udf cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('udf could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v udf did not return anything')
    return return_value


def _1_1_1_8_sus():
    return_value = list()
    success, error = check('modprobe -n -v vfat')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep vfat')[0]:
            return_value.append('vfat cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('vfat can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('vfat could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v vfat did not return anything')
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value.append('cramfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('cramfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('cramfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v cramfs did not return anything')
    return return_value


def _1_1_1_2_ubu():
    return_value = list()
    success, error = check('modprobe -n -v freevxfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep freevxfs')[0]:
            return_value.append('freevxfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('freevxfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('freevxfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v freevxfs did not return anything')
    return return_value


def _1_1_1_3_ubu():
    return_value = list()
    success, error = check('modprobe -n -v jffs2')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep jffs2')[0]:
            return_value.append('jffs2 cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('jffs2 can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('jffs2 could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v jffs2 did not return anything')
    return return_value


def _1_1_1_4_ubu():
    return_value = list()
    success, error = check('modprobe -n -v hfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfs')[0]:
            return_value.append('hfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('hfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('hfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v hfs did not return anything')
    return return_value


def _1_1_1_5_ubu():
    return_value = list()
    success, error = check('modprobe -n -v hfsplus')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfsplus')[0]:
            return_value.append('hfsplus cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('hfsplus can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('hfsplus could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v hfsplus did not return anything')
    return return_value


def _1_1_1_6_ubu():
    return_value = list()
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value.append('squashfs cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('squashfs can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('squashfs could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v squashfs did not return anything')
    return return_value


def _1_1_1_7_ubu():
    return_value = list()
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value.append('udf cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('udf can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    else:
        return_value.append('udf could not be checked')
        return_value.append('CHEK')
        return_value.append('modprobe -n -v udf did not return anything')
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
        if 'install /bin/true' in success or 'not found in directory' in error:
            if not check('lsmod | grep vfat')[0]:
                return_value.append('vfat cannot be mounted')
                return_value.append('PASS')
                return_value.append(success if success else error)
        elif 'insmod' in success:
            return_value.append('vfat can be mounted')
            return_value.append('CHEK')
            return_value.append(success)
        else:
            return_value.append('vfat could not be checked')
            return_value.append('CHEK')
            return_value.append('modprobe -n -v vfat did not return anything')
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nosuid")
        if not success and not error:
            return_value.append('nosuid is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v noexec")
        if not success and not error:
            return_value.append('noexec is set on /tmp')
            return_value.append('PASS')
            return_value.append(
                "mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep usb-storage')[0]:
            return_value.append('usb-storage cannot be mounted')
            return_value.append('PASS')
            return_value.append(success if success else error)
    elif 'insmod' in success:
        return_value.append('usb-storage can be mounted')
        return_value.append('FAIL')
        return_value.append(success)
    return return_value


# function to call necessary recommendation benchmarks
# i (current benchmark number) and l (total benchmarks scored)
# are only used when output is not required verbose-ly
# i.e. to print progressBar
def test(r, file_path, dist, i=None, l=None):
    start = time()

    return_value = eval('_' + r[0].replace('.', '_') + '_' + dist + '()')

    # return_score is 2 when test has passed (1) AND the test is scored (1)
    return_score = 0
    if 'PASS' == return_value[1] and r[1]:
        return_score = 2
    elif 'PASS' == return_value[1]:
        return_score = 1

    # if verbose output is needed | else print progressBar
    if i == None and l == None:
        if r[1]:
            print_success(r[0], return_value[0], return_value[1]) if return_score == 2 else print_fail(
                r[0], return_value[0], return_value[1])
        else:
            print_neutral(r[0], return_value[
                          0], return_value[1])
    else:
        printProgressBar(i, l, prefix='Progress:',
                         suffix='Complete', autosize=True) if i == l else printProgressBar(i, l, prefix=r[0] + ' (' + str(i) + '/' + str(l) + ')',
                                                                                           suffix='Complete', autosize=True)

    # writing findings to .SeBAz file
    return_value.insert(0, r[0])
    return_value.append(str(time() - start))
    with open(file_path, 'a', newline='') as csvfile:
        csvwriter = writer(csvfile, dialect='excel')
        csvwriter.writerow(return_value)

    # returning score
    return return_score


if __name__ == "__main__":
    exit('Please run ./SeBAz -h')
