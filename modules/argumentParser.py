from argparse import ArgumentParser, RawTextHelpFormatter

# initializing argument parser
parser = ArgumentParser(prog='SeBAz',
                        description='Perform CIS Benchmark scoring on your Linux System',
                        usage='# python3 %(prog)s.py [optional arguments]',
                        epilog='Enjoy Hardening your System!',
                        formatter_class=RawTextHelpFormatter)

# SeBAz version
parser.version = '%(prog)s v0.1.1'

# optional arguments

# inlcude
parser.add_argument('-i', '--include', type=str, nargs='+',
                    action='store', help='List recommendations to be INCLUDED in score (Whitelist)'
                    '\nDefault all recommendations are benchmarked'
                    '\nGive recommendations seperated by space'
                    '\nExample:'
                    '\n --include 1.*   [Will only score Initial Setup]'
                    '\n --include 2.1.* [Will only score inetd Services]')

# exclude
parser.add_argument('-e', '--exclude', type=str, nargs='+',
                    action='store', help='List recommendations to be EXCLUDED in score (Blacklist)'
                    '\nDefault NONE of the recommendations will be excluded'
                    '\nGive recommendations seperated by space'
                    '\nExample:'
                    '\n --exclude 3.*  [Skip scoring of Network Parameters]'
                    '\n --exclude 4.2* [Skip scoring of logging]')

# level 1 / level 2
parser.add_argument('-l', '--level', type=int, choices=[1, 2],
                    action='store', help='Select Profile Applicability ( Level 1 / Level 2 )'
                    '\nDefault both Level 1 AND Level 2 are benchmarked'
                    '\nExample:'
                    '\n --level 1 [Only Level 1 recommendations will be scored]'
                    '\n --level 2 [Only Level 2 recommendations will be scored]')

# Not Scored (0) / Scored (1)
parser.add_argument('-s', '--score', type=int, choices=[0, 1],
                    action='store', help='Choose to test (Not Scored) [or] (Scored)'
                    '\nDefault both Scored and Not Scored are benchmarked'
                    '\nExample:'
                    '\n --score 0 [Only Not Scored recommendations are checked]'
                    '\n --score 1 [Only Scored recommendations will be checked]')

# Server / Workstation
parser.add_argument('-p', '--platform', type=str, choices=['server', 'workstation'],
                    action='store', help='Choose to test Servers [or] Workstations'
                    '\nDefault both Servers and Workstations are benchmarked'
                    '\nExample:'
                    '\n -p server [Only recommendations of servers are checked]'
                    '\n -p workstation [Only check workstation recommendations]')

# Print result True/False
parser.add_argument('-v', '--verbose',
                    action='store_true', help='Display each score on the terminal')

# Print version
parser.add_argument('-V', '--version', action='version',
                    help='Display tool version and exit')
