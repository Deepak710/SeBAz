# Thank you to Greenstick for the progressbar code
# Copied from https://gist.github.com/greenstick/b23e475d2bfdc3a82e34eaa1f6781ee4

# This version of the printProgressBar function implements an optional autoresize argument.
# It has been updated from a previous version to use the shutil Python module to determine
# the terminal size. This update should allow it to work on most operating systems and does
# speed up the autosize feature quite a bit – though it still slows things down quite a bit.
# For more robust features, it's recommended you use a progress bar library like tdqm (see: https://github.com/tqdm/tqdm)


import shutil


def printProgressBar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█', autosize=False):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        autosize    - Optional  : automatically resize the length of the progress bar to the terminal window (Bool)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 *
                                                     (iteration / float(total)))
    styling = '%s |%s| %s%% %s' % (prefix, fill, percent, suffix)
    if autosize:
        cols, _ = shutil.get_terminal_size(fallback=(length, 1))
        length = cols - len(styling)
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print('\r%s' % styling.replace(fill, bar), end='\r')
    # Print New Line on Complete
    if iteration == total:
        print()


if __name__ == "__main__":
    exit('Please run ./SeBAz -h')
