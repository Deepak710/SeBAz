from modules.argumentParser import parser
from modules.optionsParser import get_recommendations, disp_exp
from modules.benchmarks import test
from modules.reportGenerator import createPDF, generatePDF
from modules.termcolor.termcolor import cprint
from os import system, path
from csv import writer
from colorama import init
import time


options = parser.parse_args()


start = time.time()
gmtime = time.gmtime()
local = time.localtime()


# setting distribution to independent if nothing is specified
if options.dist == None:
    options.dist = 'ind'

# recommendations will contain list of benchmark recommendation ID's
# based on parameters passed during script call
recommendations = get_recommendations(options)

if options.exp != None:
    disp_exp(recommendations)

if options.report != None:
    generatePDF(options.report)

system('sudo clear')
init()
cprint('Welcome to SeBAz', attrs=['bold'])
print('\nGive me a moment to calculate the prerequisites...\n')


# writing test details and start time to .SeBAz file
file_path = path.dirname(path.abspath(__file__)) + '/' + \
    str(options.org) + '-' + str(options.unique) + '.SeBAz.csv'
with open(file_path, 'w', newline='') as csvfile:
    csvwriter = writer(csvfile, dialect='excel')
    csvwriter.writerow(['Recommendation Number', 'Message',
                        'Result', 'Explanation', 'Time'])

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
        passed += 1
    if s == 2:
        score += 1


# writing test finish time to .SeBAz file
duration = '\nPerformed ' + str(length) + ' tests in '
result = str(passed) + ' out of ' + str(length) + \
    ' have passed\nThis system\'s Score is ' + str(score)
end = time.time() - start
if (end // 60 % 60) < 1:
    duration += '{:.3f} seconds'.format(end)
else:
    duration += '{:.0f}'.format(end // 60 % 60) + \
        ' minute ' if (end // 60 % 60) == 1 else ' minutes ' + \
        'and {:.3f} seconds'.format(end % 60)
gmtime = time.gmtime()
local = time.localtime()
with open(file_path, 'a', newline='') as csvfile:
    csvwriter = writer(csvfile, dialect='excel')
    csvwriter.writerows(['\n', ['---<DO NOT MODIFY ANYTHING BELOW>---'], '\n'])
    csvwriter.writerow(['Start Time (UTC): ' + str(gmtime.tm_year) + '-' + str(gmtime.tm_mon) + '-' + str(gmtime.tm_mday) +
                        ' ' + str(gmtime.tm_hour) + ':' + str(gmtime.tm_min) + ':' + str(gmtime.tm_sec)])
    csvwriter.writerow(['Start Time (Local): ' + str(local.tm_year) + '-' + str(local.tm_mon) + '-' +
                        str(local.tm_mday) + ' ' + str(local.tm_hour) + ':' + str(local.tm_min) + ':' + str(local.tm_sec)])
    csvwriter.writerow(['Options Given: '])
    for value in vars(options).items():
        csvwriter.writerow(value)
    gmtime = time.gmtime()
    local = time.localtime()
    csvwriter.writerow(['Finish Time (UTC): ' + str(gmtime.tm_year) + '-' + str(gmtime.tm_mon) + '-' + str(gmtime.tm_mday) +
                        ' ' + str(gmtime.tm_hour) + ':' + str(gmtime.tm_min) + ':' + str(gmtime.tm_sec)])
    csvwriter.writerow(['Finish Time (Local): ' + str(local.tm_year) + '-' + str(local.tm_mon) + '-' +
                        str(local.tm_mday) + ' ' + str(local.tm_hour) + ':' + str(local.tm_min) + ':' + str(local.tm_sec)])
    csvwriter.writerow([duration.splitlines()[1]])
    csvwriter.writerow([result.splitlines()[0]])
    csvwriter.writerow([result.splitlines()[1]])

print('\nGenerating ' + str(options.org) + '-' + str(options.unique) + '.pdf')
# Generating PDF
createPDF(file_path)
print('Done.')

# printing test results
print(duration)
print(result)
