from modules.progressBar import printProgressBar
from subprocess import Popen, PIPE
from termcolor import cprint
from time import time


"""
benchmark structure
for b in benchmark_*:
    b[0] = recommendation id number
    b[1] = Scored (1) [OR] Not Scored (0)
    b[2] = Profile  -> Level 1   (1) [OR] Level 2     (2)
    b[3] = Platform -> Server    (1) [OR] Workstation (2) [OR] Both (3)
"""
benchmark_ind = [
    ['1.1.1.1', 1, 1, 3, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 1, 1, 3, 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.3', 1, 1, 3, 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.4', 1, 1, 3, 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.5', 1, 1, 3, 'Ensure mounting of hfsplus filesystems is disabled'],
    ['1.1.1.6', 1, 1, 3, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.7', 1, 1, 3, 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.1.8', 0, 2, 3, 'Ensure mounting of FAT filesystems is limited'],
]
benchmark_cen = [
    ['1.1.1.1', 1, 1, 3, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 0, 2, 3, 'Ensure mounting of vFAT filesystems is limited'],
    ['1.1.1.3', 1, 1, 3, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.4', 1, 1, 3, 'Ensure mounting of udf filesystems is disabled'],
]
benchmark_deb = [
    ['1.1.1.1', 1, 1, 3, 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.2', 1, 1, 3, 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.3', 1, 1, 3, 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.4', 1, 1, 3, 'Ensure mounting of hfsplus filesystems is disabled'],
]
benchmark_fed = [
    ['1.1.1.1', 1, 1, 3, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 0, 2, 3, 'Ensure mounting of vFAT filesystems is limited'],
    ['1.1.1.3', 1, 1, 3, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.4', 1, 1, 3, 'Ensure mounting of udf filesystems is disabled'],
]
benchmark_red = [
    ['1.1.1.1', 1, 1, 3, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 0, 2, 3, 'Ensure mounting of vFAT filesystems is limited'],
    ['1.1.1.3', 1, 1, 3, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.4', 1, 1, 3, 'Ensure mounting of udf filesystems is disabled'],
]
benchmark_sus = [
    ['1.1.1.1', 1, 1, 3, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 1, 1, 3, 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.3', 1, 1, 3, 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.4', 1, 1, 3, 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.5', 1, 1, 3, 'Ensure mounting of hfsplus filesystems is disabled'],
    ['1.1.1.6', 1, 1, 3, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.7', 1, 1, 3, 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.1.8', 1, 2, 3, 'Ensure mounting of FAT filesystems is disabled'],
]
benchmark_ubu = [
    ['1.1.1.1', 1, 1, 3, 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 1, 1, 3, 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.3', 1, 1, 3, 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.4', 1, 1, 3, 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.5', 1, 1, 3, 'Ensure mounting of hfsplus filesystems is disabled'],
    ['1.1.1.6', 1, 1, 3, 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.7', 1, 1, 3, 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.1.8', 0, 2, 3, 'Ensure mounting of FAT filesystems is limited'],
]


def print_success(r, x): return cprint(
    '{:<8}   {:<50}\t{:>4}'.format(r, x, 'PASS'), 'green', attrs=['bold'])


def print_fail(r, x): return cprint('{:<8}   {:<50}\t{:>4}'.format(
    r, x, 'FAIL'), 'red', attrs=['bold'])


def print_neutral(r, x, p): return cprint('{:<8}   {:<50}\t{:>4}'.format(
    r, x, p), 'grey', attrs=['bold'])


# to write delimiters into .SeBAz file
def print_encodable(s): return str(s).replace('\t', '<TAB>').encode(
    'unicode-escape').decode().replace('\\\\', '\\')


# function to execute the check
def check(execute):
    execute = Popen(execute, stdin=PIPE, stdout=PIPE, stderr=PIPE,
                    shell=True, executable='/bin/bash').communicate()
    execute = [e.decode('utf-8') for e in execute]
    return execute


"""
Definitions of Functions that perform independent checks against benchmarks
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_ind():
    success, error = check('modprobe -n -v cramfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value = 'cramfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'cramfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_2_ind():
    success, error = check('modprobe -n -v freevxfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep freevxfs')[0]:
            return_value = 'freevxfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'freevxfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_3_ind():
    success, error = check('modprobe -n -v jffs2')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep jffs2')[0]:
            return_value = 'jffs2 cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'jffs2 can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_4_ind():
    success, error = check('modprobe -n -v hfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfs')[0]:
            return_value = 'hfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'hfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_5_ind():
    success, error = check('modprobe -n -v hfsplus')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfsplus')[0]:
            return_value = 'hfsplus cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'hfsplus can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_6_ind():
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value = 'squashfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'squashfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_7_ind():
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value = 'udf cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'udf can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_8_ind():
    success, error = check('grep -i vfat /etc/fstab')
    if success:
        return 'vfat is mounted\tCHEK\t' + print_encodable(success)
    else:
        if 'install /bin/true' in success or 'not found in directory' in error:
            if not check('lsmod | grep vfat')[0]:
                return_value = 'vfat cannot be mounted\tPASS\t'
                if success:
                    return_value += print_encodable(success)
                else:
                    return_value += print_encodable(error)
                return return_value
        elif 'insmod' in success:
            return 'vfat can be mounted\tFAIL\t' + print_encodable(success)


"""
Definitions of Functions that perform CentOS checks against benchmarks
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_cen():
    success, error = check('modprobe -n -v cramfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value = 'cramfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'cramfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_2_cen():
    success, error = check("grep -E -i '\svfat\s' /etc/fstab")
    if success:
        return 'vfat is mounted\tCHEK\t' + print_encodable(success)
    else:
        if 'install /bin/true' in success or 'not found in directory' in error:
            if not check('lsmod | grep vfat')[0]:
                return_value = 'vfat cannot be mounted\tPASS\t'
                if success:
                    return_value += print_encodable(success)
                else:
                    return_value += print_encodable(error)
                return return_value
        elif 'insmod' in success:
            return 'vfat can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_3_cen():
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value = 'cramfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'squashfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_4_cen():
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value = 'udf cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'udf can be mounted\tFAIL\t' + print_encodable(success)


"""
Definitions of Functions that perform Debian checks against benchmarks
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_deb():
    success, error = check('modprobe -n -v freevxfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep freevxfs')[0]:
            return_value = 'freevxfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'freevxfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_2_deb():
    success, error = check("modprobe -n -v jffs2")
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep jffs2')[0]:
            return_value = 'jffs2 cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'jffs2 can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_3_deb():
    success, error = check('modprobe -n -v hfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfs')[0]:
            return_value = 'hfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'hfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_4_deb():
    success, error = check('modprobe -n -v hfsplus')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfsplus')[0]:
            return_value = 'hfsplus cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'hfsplus can be mounted\tFAIL\t' + print_encodable(success)


"""
Definitions of Functions that perform Fedora checks against benchmarks
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_fed():
    success, error = check('modprobe -n -v cramfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value = 'cramfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'cramfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_2_fed():
    success, error = check("grep -E -i '\svfat\s' /etc/fstab")
    if success:
        return 'vfat is mounted\tCHEK\t' + print_encodable(success)
    else:
        if 'install /bin/true' in success or 'not found in directory' in error:
            if not check('lsmod | grep vfat')[0]:
                return_value = 'vfat cannot be mounted\tPASS\t'
                if success:
                    return_value += print_encodable(success)
                else:
                    return_value += print_encodable(error)
                return return_value
        elif 'insmod' in success:
            return 'vfat can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_3_fed():
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value = 'cramfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'squashfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_4_fed():
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value = 'udf cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'udf can be mounted\tFAIL\t' + print_encodable(success)


"""
Definitions of Functions that perform RedHat checks against benchmarks
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_red():
    success, error = check('modprobe -n -v cramfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value = 'cramfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'cramfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_2_red():
    success, error = check("grep -E -i '\svfat\s' /etc/fstab")
    if success:
        return 'vfat is mounted\tCHEK\t' + print_encodable(success)
    else:
        if 'install /bin/true' in success or 'not found in directory' in error:
            if not check('lsmod | grep vfat')[0]:
                return_value = 'vfat cannot be mounted\tPASS\t'
                if success:
                    return_value += print_encodable(success)
                else:
                    return_value += print_encodable(error)
                return return_value
        elif 'insmod' in success:
            return 'vfat can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_3_red():
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value = 'cramfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'squashfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_4_red():
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value = 'udf cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'udf can be mounted\tFAIL\t' + print_encodable(success)


"""
Definitions of Functions that perform SUSE checks against benchmarks
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_sus():
    success, error = check('modprobe -n -v cramfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value = 'cramfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'cramfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_2_sus():
    success, error = check('modprobe -n -v freevxfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep freevxfs')[0]:
            return_value = 'freevxfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'freevxfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_3_sus():
    success, error = check('modprobe -n -v jffs2')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep jffs2')[0]:
            return_value = 'jffs2 cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'jffs2 can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_4_sus():
    success, error = check('modprobe -n -v hfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfs')[0]:
            return_value = 'hfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'hfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_5_sus():
    success, error = check('modprobe -n -v hfsplus')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfsplus')[0]:
            return_value = 'hfsplus cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'hfsplus can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_6_sus():
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value = 'squashfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'squashfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_7_sus():
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value = 'udf cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'udf can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_8_sus():
    success, error = check('modprobe -n -v vfat')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep vfat')[0]:
            return_value = 'vfat cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'vfat can be mounted\tFAIL\t' + print_encodable(success)


"""
Definitions of Functions that perform Ubuntu checks against benchmarks
Goto line "156" in order to view definition of test()
"""


def _1_1_1_1_ubu():
    success, error = check('modprobe -n -v cramfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep cramfs')[0]:
            return_value = 'cramfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'cramfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_2_ubu():
    success, error = check('modprobe -n -v freevxfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep freevxfs')[0]:
            return_value = 'freevxfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'freevxfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_3_ubu():
    success, error = check('modprobe -n -v jffs2')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep jffs2')[0]:
            return_value = 'jffs2 cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'jffs2 can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_4_ubu():
    success, error = check('modprobe -n -v hfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfs')[0]:
            return_value = 'hfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'hfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_5_ubu():
    success, error = check('modprobe -n -v hfsplus')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep hfsplus')[0]:
            return_value = 'hfsplus cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'hfsplus can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_6_ubu():
    success, error = check('modprobe -n -v squashfs')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep squashfs')[0]:
            return_value = 'squashfs cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'squashfs can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_7_ubu():
    success, error = check('modprobe -n -v udf')
    if 'install /bin/true' in success or 'not found in directory' in error:
        if not check('lsmod | grep udf')[0]:
            return_value = 'udf cannot be mounted\tPASS\t'
            if success:
                return_value += print_encodable(success)
            else:
                return_value += print_encodable(error)
            return return_value
    elif 'insmod' in success:
        return 'udf can be mounted\tFAIL\t' + print_encodable(success)


def _1_1_1_8_ubu():
    success, error = check('grep -i vfat /etc/fstab')
    if success:
        return 'vfat is mounted\tCHEK\t' + print_encodable(success)
    else:
        if 'install /bin/true' in success or 'not found in directory' in error:
            if not check('lsmod | grep vfat')[0]:
                return_value = 'vfat cannot be mounted\tPASS\t'
                if success:
                    return_value += print_encodable(success)
                else:
                    return_value += print_encodable(error)
                return return_value
        elif 'insmod' in success:
            return 'vfat can be mounted\tFAIL\t' + print_encodable(success)


# function to call necessary recommendation benchmarks
# i (current benchmark number) and l (total benchmarks scored)
# are only used when output is not required verbose-ly
# i.e. to print progressBar
def test(r, file_path, dist, i=None, l=None):
    start = time()

    return_value = eval('_' + r[0].replace('.', '_') + '_' + dist + '()')

    # return_score is 2 when test has passed (1) AND the test is scored (1)
    return_score = 0
    if 'PASS' in return_value and r[1]:
        return_score = 2
    elif 'PASS' in return_value:
        return_score = 1

    # if verbose output is needed | else print progressBar
    if i == None and l == None:
        if r[1]:
            if return_score == 2:
                print_success(r[0], return_value.split('\t')[0])
            else:
                print_fail(r[0], return_value.split('\t')[0])
        else:
            print_neutral(r[0], return_value.split('\t')[
                          0], return_value.split('\t')[1])
    else:
        if i == l:
            printProgressBar(i, l, prefix='Progress:',
                             suffix='Complete', autosize=True)
        else:
            printProgressBar(i, l, prefix=r[0] + ' (' + str(i) + '/' + str(l) + ')',
                             suffix='Complete', autosize=True)

    # writing findings to .SeBAz file
    file_pointer = open(file_path, 'a')
    file_pointer.write(r[0] + '\t' + return_value + '\t')
    file_pointer.write(str(time() - start) + '\n')
    file_pointer.close()

    # returning score
    return return_score
