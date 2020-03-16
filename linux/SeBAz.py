from modules.optionsParser import get_recommendations, disp_exp
from modules.reportGenerator import createPDF, generatePDF
from huepy import bold, red, green, yellow
from modules.argumentParser import parser
from time import time, gmtime, localtime
from os import system, path, geteuid
from modules.benchmarks import test
from enlighten import get_manager
from csv import writer
from sys import exit


# getting optional arguments from user
options = parser.parse_args()


# noting the start time
start = time()
gmt_time = gmtime()
local = localtime()


# setting distribution to independent if nothing is specified
if options.dist == None:
    options.dist = 'ind'

# recommendations will contain list of benchmark recommendation ID's
# based on parameters passed during script call
recommendations = get_recommendations(options)

# displays the explanation of commands and exits
if options.exp != None:
    disp_exp(options)

# generates report and exits
if options.report != None:
    generatePDF(options.report)

# exit if SeBAz isn't run as root
if not geteuid() == 0:
    exit('\nPlease run SeBAz as root\n')


print(bold('Welcome to SeBAz'))
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
    print(bold(green('Green  Text indicates tests that have PASSED')))
    print(bold(red('Red    Text indicates tests that have FAILED')))
    if options.score == None:
        print(bold(yellow('Yellow Text indicates tests that are  NOT SCORED')))
    print('\nPerforming ' + str(length) + ' tests now...\n')
else:
    print('Done. Performing ' + str(length) + ' tests now...\n')

# progressbar format
bar_format = u'{desc}{desc_pad}{percentage:3.0f}%|{bar}| ' + \
    bold(green('pass')) + u':{count_0:{len_total}d} ' + \
    bold(red('fail')) + u':{count_1:{len_total}d} ' + \
    bold(yellow('chek')) + u':{count_2:{len_total}d} ' + \
    u'[{elapsed}<{eta}, {rate:.1f}{unit_pad}{unit}/s]'
manager = get_manager()
passd = manager.counter(total=length, desc='Testing', unit='tests',
                        color='bright_white', bar_format=bar_format)
faild = passd.add_subcounter('bright_white')
check = passd.add_subcounter('bright_white')

# calling the benchmark functions
for i, r in enumerate(recommendations):
    passd.desc = '{rec:<8} {current:03d}/{total:03d}'.format(
        rec=r[0], current=i+1, total=length)
    if i + 1 == length:
        passd.desc = '{:<16}'.format('Done')
    s = test(r, file_path, options.dist, options.verbose,
             passd, faild, check, manager.width)
    if s:
        passed += 1
    if s == 2:
        score += 1
manager.stop()

# calculating runtime
duration = '\nPerformed ' + str(length) + ' tests in '
result = str(passed) + ' out of ' + str(length) + \
    ' have passed\nThis system\'s Score is ' + str(score)
end = time() - start
if (end // 60 % 60) < 1:
    duration += '{:.3f} seconds'.format(end)
elif (end // 60 % 60) == 1:
    duration += '1 minute and {:.3f} seconds'.format(end % 60)
else:
    duration += '{:.0f}'.format(end // 60 % 60) + \
        ' minutes and {:.3f} seconds'.format(end % 60)

# writing test finish time to .SeBAz.csv file
with open(file_path, 'a', newline='') as csvfile:
    csvwriter = writer(csvfile, dialect='excel')
    csvwriter.writerows(['\n', ['---<DO NOT MODIFY ANYTHING BELOW>---'], '\n'])
    csvwriter.writerow(['Start Time (UTC): ' + str(gmt_time.tm_year) + '-' + str(gmt_time.tm_mon) + '-' + str(gmt_time.tm_mday) +
                        ' ' + str(gmt_time.tm_hour) + ':' + str(gmt_time.tm_min) + ':' + str(gmt_time.tm_sec)])
    csvwriter.writerow(['Start Time (Local): ' + str(local.tm_year) + '-' + str(local.tm_mon) + '-' +
                        str(local.tm_mday) + ' ' + str(local.tm_hour) + ':' + str(local.tm_min) + ':' + str(local.tm_sec)])
    csvwriter.writerow(['Options Given: '])
    for value in vars(options).items():
        csvwriter.writerow(value)
    gmt_time = gmtime()
    local = localtime()
    csvwriter.writerow(['Finish Time (UTC): ' + str(gmt_time.tm_year) + '-' + str(gmt_time.tm_mon) + '-' + str(gmt_time.tm_mday) +
                        ' ' + str(gmt_time.tm_hour) + ':' + str(gmt_time.tm_min) + ':' + str(gmt_time.tm_sec)])
    csvwriter.writerow(['Finish Time (Local): ' + str(local.tm_year) + '-' + str(local.tm_mon) + '-' +
                        str(local.tm_mday) + ' ' + str(local.tm_hour) + ':' + str(local.tm_min) + ':' + str(local.tm_sec)])
    csvwriter.writerow([duration.splitlines()[1]])
    csvwriter.writerow([result.splitlines()[0]])
    csvwriter.writerow([result.splitlines()[1]])

# Generating PDF
print('\nGenerating ' + str(options.org) + '-' + str(options.unique) + '.pdf')
createPDF(file_path)
print('Done.')

# printing test results
print(duration)
print(result)
