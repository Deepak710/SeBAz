from modules.argumentParser import parser
from modules.optionsParser import get_recommendations, disp_exp
from modules.benchmarks import test
from os import system, path
from termcolor import cprint
import time


start = time.time()
gmtime = time.gmtime()
local = time.localtime()


options = parser.parse_args()
# setting distribution to independent if nothing is specified
if options.dist == None:
    options.dist = 'ind'

if options.exp != None:
    disp_exp(options)


system('sudo clear')
cprint('Welcome to SeBAz', attrs=['bold'])
print('\nGive me a moment to calculate the prerequisites...\n')


# writing test details and start time to .SeBAz file
file_path = path.dirname(path.abspath(__file__)) + '/' + \
    str(options.org) + '-' + str(options.unique) + '.SeBAz'
f = open(file_path, 'w')
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
passed = 0


if options.verbose:
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
else:
    print('Done. Performing ' + str(length) + ' tests now...\n')


# calling the benchmark functions
for i, r in enumerate(recommendations):
    s = test(r, file_path, options.dist) if options.verbose else test(
        r, file_path, options.dist, i + 1, length)
    if s:
        score += 1
    if s == 2:
        passed += 1


# writing test finish time to .SeBAz file
f = open(file_path, 'a')
duration = '\nPerformed ' + str(length) + ' tests in '
result = str(passed) + ' out of ' + str(length) + \
    ' have passed\nThis system\'s Score is ' + str(score)
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
f.write(duration + '\n')
f.write(result + '\n')
f.close()


# printing test results
print(duration)
print(result)
