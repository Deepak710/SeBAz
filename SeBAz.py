from modules.argumentParser import parser
from modules.optionsParser import get_recommendations
from modules.benchmarks import test
from os import system, path
from termcolor import cprint
import time


options = parser.parse_args()
system('sudo clear')
cprint('Welcome to SeBAz', attrs=['bold'])


print('\n\nPlease provide test details:')
details = {
    'aname': None,
    'acom': None,
    'comn': None,
    'sysid': None,
    'sysinfo': None
}
details['aname'] = input('Your name (Auditor):                ')
details['acom'] = input('Name of the firm you represent:     ')
details['comn'] = input('Name of the Company being Audited:  ')
if not details['comn']:
    details['comn'] = None
details['sysid'] = input('Unique ID of system in the company: ')
if not details['sysid']:
    details['sysid'] = None
details['sysinfo'] = input(
    'Descriptive notes about the system being audited: ')


print('\nGive me a moment to calculate the prerequisites...\n')
start = time.time()
gmtime = time.gmtime()
local = time.localtime()
# writing test details and start time to .SeBAz file
file_path = path.dirname(path.abspath(__file__)) + '/' + \
    str(details['comn']) + '-' + str(details['sysid']) + '.SeBAz'
f = open(file_path, 'w')
f.write('Details: ' + str(details) + '\n')
f.write('Start Time (UTC):   ' + str(gmtime.tm_year) + '-' + str(gmtime.tm_mon) + '-' + str(gmtime.tm_mday) +
        ' ' + str(gmtime.tm_hour) + ':' + str(gmtime.tm_min) + ':' + str(gmtime.tm_sec) + '\n')
f.write('Start Time (Local): ' + str(local.tm_year) + '-' + str(local.tm_mon) + '-' +
        str(local.tm_mday) + ' ' + str(local.tm_hour) + ':' + str(local.tm_min) + ':' + str(local.tm_sec) + '\n')
f.write('Options Given: ' + str(vars(options)) + '\n\n\n')
f.close()
# recommendations will contain list of benchmark recommendation ID's
# based on parameters passed during script call
recommendations = get_recommendations(options)
length = len(recommendations)
score = 0


if not options.verbose:
    print('Done. Performing ' + str(length) + ' tests now...\n')
else:
    # printing the legend for verbose output
    print('Done. Here\'s the legend for the test results:')
    cprint('Green Text indicates tests that have PASSED',
           'green', attrs=['bold'])
    cprint('Red   Text indicates tests that have FAILED',
           'red', attrs=['bold'])
    if options.score == None:
        cprint('Grey  Text indicates tests that are  NOT SCORED',
               'grey', attrs=['bold'])
    print('\nPerforming ' + str(length) + ' tests now...\n')


# calling the benchmark functions
for i, r in enumerate(recommendations):
    if options.verbose:
        score += test(r, file_path)
    else:
        # to print the progressBar
        score += test(r, file_path, i, length - 1)


# writing test finish time to .SeBAz file
f = open(file_path, 'a')
duration = '\n\nPerformed ' + str(length) + ' tests in '
end = time.time() - start
if (end // 60 % 60) < 1:
    duration += '{:.3f} seconds'.format(end)
else:
    duration += '{:.0f}'.format(end // 60 % 60) + \
        ' minutes and {:.3f} seconds'.format(end % 60)
gmtime = time.gmtime()
local = time.localtime()
f.write('\n\nFinish Time (UTC):   ' + str(gmtime.tm_year) + '-' + str(gmtime.tm_mon) + '-' + str(gmtime.tm_mday) +
        ' ' + str(gmtime.tm_hour) + ':' + str(gmtime.tm_min) + ':' + str(gmtime.tm_sec) + '\n')
f.write('Finish Time (Local): ' + str(local.tm_year) + '-' + str(local.tm_mon) + '-' +
        str(local.tm_mday) + ' ' + str(local.tm_hour) + ':' + str(local.tm_min) + ':' + str(local.tm_sec) + '\n')
f.write(duration)
f.close()


# printing test results
print(duration)
print(str(score) + ' out of ' + str(length) + ' have passed\n')
