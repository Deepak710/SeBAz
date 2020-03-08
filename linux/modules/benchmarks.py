from modules.printProgressAuto.progressBar import printProgressBar
from modules.termcolor.termcolor import cprint
from subprocess import Popen, PIPE
from time import time
from csv import writer


"""
benchmark structure
for b in benchmark_*:
    b[0]    = recommendation id number
    b[1]    = Scored (1) [OR] Not Scored (0)
    b[2][0] = Platform -> Server      (1) [0 -> N/A]
    b[2][1] = Profile  -> Level 1 (1) [OR] Level 2 (2)
    b[3][0] = Platform -> Workstation (1) [0 -> N/A]
    b[3][1] = Profile  -> Level 1 (1) [OR] Level 2 (2)
    b[4]    = Explaination
"""
benchmark_ind = [
    ['1.1.1.1', 1, [1, 1], [1, 1], 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 1, [1, 1], [1, 1], 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.3', 1, [1, 1], [1, 1], 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.4', 1, [1, 1], [1, 1], 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.5', 1, [1, 1], [1, 1], 'Ensure mounting of hfsplus filesystems is disabled'],
    ['1.1.1.6', 1, [1, 1], [1, 1], 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.7', 1, [1, 1], [1, 1], 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.1.8', 0, [1, 2], [1, 2], 'Ensure mounting of FAT filesystems is limited'],
]
benchmark_cen = [
    ['1.1.1.1', 1, [1, 1], [1, 1], 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 0, [1, 2], [1, 2], 'Ensure mounting of vFAT filesystems is limited'],
    ['1.1.1.3', 1, [1, 1], [1, 1], 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.4', 1, [1, 1], [1, 1], 'Ensure mounting of udf filesystems is disabled'],
]
benchmark_deb = [
    ['1.1.1.1', 1, [1, 1], [1, 1], 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.2', 1, [1, 1], [1, 1], 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.3', 1, [1, 1], [1, 1], 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.4', 1, [1, 1], [1, 1], 'Ensure mounting of hfsplus filesystems is disabled'],
]
benchmark_fed = [
    ['1.1.1.1', 1, [1, 1], [1, 1], 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 0, [1, 2], [1, 2], 'Ensure mounting of vFAT filesystems is limited'],
    ['1.1.1.3', 1, [1, 1], [1, 1], 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.4', 1, [1, 1], [1, 1], 'Ensure mounting of udf filesystems is disabled'],
]
benchmark_red = [
    ['1.1.1.1', 1, [1, 1], [1, 1], 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 0, [1, 2], [1, 2], 'Ensure mounting of vFAT filesystems is limited'],
    ['1.1.1.3', 1, [1, 1], [1, 1], 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.4', 1, [1, 1], [1, 1], 'Ensure mounting of udf filesystems is disabled'],
]
benchmark_sus = [
    ['1.1.1.1', 1, [1, 1], [1, 1], 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 1, [1, 1], [1, 1], 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.3', 1, [1, 1], [1, 1], 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.4', 1, [1, 1], [1, 1], 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.5', 1, [1, 1], [1, 1], 'Ensure mounting of hfsplus filesystems is disabled'],
    ['1.1.1.6', 1, [1, 1], [1, 1], 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.7', 1, [1, 1], [1, 1], 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.1.8', 1, [1, 2], [1, 2], 'Ensure mounting of FAT filesystems is disabled'],
]
benchmark_ubu = [
    ['1.1.1.1', 1, [1, 1], [1, 1], 'Ensure mounting of cramfs filesystems is disabled'],
    ['1.1.1.2', 1, [1, 1], [1, 1], 'Ensure mounting of freevxfs filesystems is disabled'],
    ['1.1.1.3', 1, [1, 1], [1, 1], 'Ensure mounting of jffs2 filesystems is disabled'],
    ['1.1.1.4', 1, [1, 1], [1, 1], 'Ensure mounting of hfs filesystems is disabled'],
    ['1.1.1.5', 1, [1, 1], [1, 1], 'Ensure mounting of hfsplus filesystems is disabled'],
    ['1.1.1.6', 1, [1, 1], [1, 1], 'Ensure mounting of squashfs filesystems is disabled'],
    ['1.1.1.7', 1, [1, 1], [1, 1], 'Ensure mounting of udf filesystems is disabled'],
    ['1.1.1.8', 0, [1, 2], [1, 2], 'Ensure mounting of FAT filesystems is limited'],
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
