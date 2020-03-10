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
    b[4] = Explaination
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
    ['1.1.21', 1, 1, 1, 'Ensure sticky bit is set on all world-writable directories'],
    ['1.1.22', 1, 1, 2, 'Disable Automounting'],
    ['1.1.23', 1, 1, 2, 'Disable USB Storage'],
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


def print_success(r, x): return cprint(
    '{:<8}   {:<50}\t{:>4}'.format(r, x, 'PASS'), 'green', attrs=['bold'])


def print_fail(r, x): return cprint('{:<8}   {:<50}\t{:>4}'.format(
    r, x, 'FAIL'), 'red', attrs=['bold'])


def print_neutral(r, x, p): return cprint('{:<8}   {:<50}\t{:>4}'.format(
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
        return_value.append("mount | grep -E '\s/var\s' did not return any result")
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
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        return_value.append('nodev is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_ind():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        return_value.append('nosuid is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_ind():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        return_value.append('noexec is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
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
        return_value.append("mount | grep /var/log/audit did not return any result")
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
        return_value.append('nodev is set on /home')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append("/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_ind():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        return_value.append('nodev is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_ind():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        return_value.append('nosuid is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_ind():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        return_value.append('noexec is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_21_ind():
    return_value = list()
    success, error = check("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append("running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append('The following directories does not have their sticky bit set\n' + success)
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
        return_value.append("mount | grep -E '\s/var\s' did not return any result")
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
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        return_value.append('nodev is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_cen():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        return_value.append('nosuid is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_cen():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        return_value.append('noexec is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
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
        return_value.append("mount | grep /var/log/audit did not return any result")
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
        return_value.append('nodev is set on /home')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append("/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_cen():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        return_value.append('nodev is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_cen():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        return_value.append('nosuid is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_cen():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        return_value.append('noexec is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_21_cen():
    return_value = list()
    success, error = check("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append("running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append('The following directories does not have their sticky bit set\n' + success)
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
        return_value.append("mount | grep -E '\s/var\s' did not return any result")
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
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        return_value.append('nodev is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_deb():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        return_value.append('nosuid is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_deb():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        return_value.append('noexec is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
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
        return_value.append("mount | grep /var/log/audit did not return any result")
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
        return_value.append('nodev is set on /home')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append("/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_deb():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        return_value.append('nodev is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_deb():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        return_value.append('nosuid is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_deb():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        return_value.append('noexec is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_21_deb():
    return_value = list()
    success, error = check("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append("running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append('The following directories does not have their sticky bit set\n' + success)
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
        return_value.append("mount | grep -E '\s/var\s' did not return any result")
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
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        return_value.append('nodev is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_fed():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        return_value.append('nosuid is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_fed():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        return_value.append('noexec is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
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
        return_value.append("mount | grep /var/log/audit did not return any result")
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
        return_value.append('nodev is set on /home')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append("/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_fed():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        return_value.append('nodev is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_fed():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        return_value.append('nosuid is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_fed():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        return_value.append('noexec is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_21_fed():
    return_value = list()
    success, error = check("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append("running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append('The following directories does not have their sticky bit set\n' + success)
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
        return_value.append("mount | grep -E '\s/var\s' did not return any result")
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
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        return_value.append('nodev is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_red():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        return_value.append('nosuid is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_red():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        return_value.append('noexec is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
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
        return_value.append("mount | grep /var/log/audit did not return any result")
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
        return_value.append('nodev is set on /home')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append("/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_red():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        return_value.append('nodev is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_red():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        return_value.append('nosuid is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_red():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        return_value.append('noexec is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_21_red():
    return_value = list()
    success, error = check("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append("running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append('The following directories does not have their sticky bit set\n' + success)
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
        return_value.append("mount | grep -E '\s/tmp\s'\ndid not return any result")
    return return_value


def _1_1_3_sus():
    return_value = list()
    success, error = check("mount | grep -E '\s/tmp\s'")
    if success:
        success, error = check("mount | grep -E '\s/tmp\s' | grep -v nodev")
        if not success and not error:
            return_value.append('nodev is set on /tmp')
            return_value.append('PASS')
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
        return_value.append("mount | grep -E '\s/var\s' did not return any result")
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
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        return_value.append('nodev is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_sus():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        return_value.append('nosuid is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_sus():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        return_value.append('noexec is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
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
        return_value.append("mount | grep /var/log/audit did not return any result")
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
        return_value.append('nodev is set on /home')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append("/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_sus():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        return_value.append('nodev is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_sus():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        return_value.append('nosuid is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_sus():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        return_value.append('noexec is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_21_sus():
    return_value = list()
    success, error = check("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append("running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append('The following directories does not have their sticky bit set\n' + success)
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nodev did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v nosuid did not return anything")
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
            return_value.append("mount | grep -E '\s/tmp\s' | grep -v noexec did not return anything")
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
        return_value.append("mount | grep -E '\s/var\s' did not return any result")
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
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nodev")
        return_value.append('nodev is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_9_ubu():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v nosuid")
        return_value.append('nosuid is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nodev is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_10_ubu():
    return_value = list()
    success, error = check('mount | grep /var/tmp')
    if success:
        success, error = check("mount | grep -E '\s/var/tmp\s' | grep -v noexec")
        return_value.append('noexec is set on /var/tmp')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/var/tmp\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /var/tmp')
        return_value.append('FAIL')
        return_value.append("/var/tmp does not exist. noexec cannot be set on a partition that does not exist")
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
        return_value.append("mount | grep /var/log/audit did not return any result")
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
        return_value.append('nodev is set on /home')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/home\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /home')
        return_value.append('FAIL')
        return_value.append("/home does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_15_ubu():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nodev")
        return_value.append('nodev is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nodev did not return anything")
    else:
        return_value.append('nodev is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nodev cannot be set on a partition that does not exist")
    return return_value


def _1_1_16_ubu():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v nosuid")
        return_value.append('nosuid is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v nosuid did not return anything")
    else:
        return_value.append('nosuid is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. nosuid cannot be set on a partition that does not exist")
    return return_value


def _1_1_17_ubu():
    return_value = list()
    success, error = check('mount | grep /dev/shm')
    if success:
        success, error = check("mount | grep -E '\s/dev/shm\s' | grep -v noexec")
        return_value.append('noexec is set on /dev/shm')
        return_value.append('PASS')
        return_value.append("mount | grep -E '\s/dev/shm\s' | grep -v noexec did not return anything")
    else:
        return_value.append('noexec is not set on /dev/shm')
        return_value.append('FAIL')
        return_value.append("/dev/shm does not exist. noexec cannot be set on a partition that does not exist")
    return return_value


def _1_1_21_ubu():
    return_value = list()
    success, error = check("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    if not success:
        return_value.append('sticky bit set on w-w directories')
        return_value.append('PASS')
        return_value.append("running df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null confirms that all world writable directories have the sticky variable set")
    else:
        return_value.append('directories without sticky bit found')
        return_value.append('FAIL')
        return_value.append('The following directories does not have their sticky bit set\n' + success)
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
            print_success(r[0], return_value[0]) if return_score == 2 else print_fail(
                r[0], return_value[0])
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
        csvwriter = writer(csvfile)
        csvwriter.writerow(return_value)

    # returning score
    return return_score


if __name__ == "__main__":
    exit('Please run ./SeBAz -h')
