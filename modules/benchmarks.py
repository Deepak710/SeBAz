from modules.progressBar import printProgressBar
from subprocess import Popen, PIPE
from termcolor import cprint
from time import time


"""
benchmark structure
for b in benchmark:
    b[0] = recommendation id number
    b[1] = Scored (1) [OR] Not Scored (0)
    b[2] = Profile  -> Level 1 (1) [OR] Level 2 (2)
    b[3] = Platform -> Server (1)  [OR] Workstation (2) [OR] Both (3)
"""
benchmark = [
    ['1.1.1.1', 1, 1, 3],
    ['1.1.1.2', 1, 1, 3],
    ['1.1.1.3', 1, 1, 3],
    ['1.1.1.4', 1, 1, 3],
    ['1.1.1.5', 1, 1, 3],
    ['1.1.1.6', 1, 1, 3],
    ['1.1.1.7', 1, 1, 3]
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
Definitions of Functions that perform the checks against benchmarks
Goto line "152" in order to view definition of test()
"""


def _1_1_1_1_():
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


def _1_1_1_2_():
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


def _1_1_1_3_():
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


def _1_1_1_4_():
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


def _1_1_1_5_():
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


def _1_1_1_6_():
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


def _1_1_1_7_():
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


# function to call necessary recommendation benchmarks
# i (current benchmark number) and l (total benchmarks scored)
# are only used when output is not required verbose-ly
# i.e. to print progressBar
def test(r, file_path, i=None, l=None):
    start = time()
    scored = [b[1] for b in benchmark if b[0] == r]
    if i == None and l == None:  # if verbose
        return_value = eval('_' + r.replace('.', '_') + '_()')
        if scored[0]:
            if 'PASS' in return_value:
                print_success(r, return_value.split('\t')[0])
            else:
                print_fail(r, return_value.split('\t')[0])
        else:
            print_neutral(r, return_value.split('\t')[
                          0], return_value.split('\t')[1])
    else:
        return_value = eval('_' + r.replace('.', '_') + '_()')
        printProgressBar(i, l, prefix='Progress:',
                         suffix='Complete', autosize=True)
    # writing findings to .SeBAz file
    file_pointer = open(file_path, 'a')
    file_pointer.write(r + '\t' + return_value + '\t')
    file_pointer.write(str(time() - start) + '\n')
    file_pointer.close()
    # returning score
    if 'PASS' in return_value:
        return 1
    else:
        return 0
