from modules.benchmarks import benchmark


# returns a list f benchmarks that matchess the options
def get_recommendations(options):
    recommendations = list()

    # to weed out scored / not scored recommendations
    if options.score != None:
        recommendations = [b[0] for b in benchmark if b[1] == options.score]

    # to weed out recommendations based on platform
    if options.platform:
        if options.platform == 'server':
            platform = [b[0] for b in benchmark if 1 == b[3] or 3 == b[3]]
        else:
            platform = [b[0] for b in benchmark if 2 == b[3] or 3 == b[3]]
        if recommendations:
            recommendations = [p for p in platform if p in recommendations]
        else:
            recommendations = platform

    # to weed out recommendations based on Profile Level
    if options.level:
        level = [b[0] for b in benchmark if b[2] == options.level]
        if recommendations:
            recommendations = [l for l in level if l in recommendations]
        else:
            recommendations = level

    import re

    # to select (whitelist) recommendations based on option
    if options.include:
        include = list()
        for i in options.include:
            r = re.compile(i)
            include.extend(list(filter(r.match, [b[0] for b in benchmark])))
        if not include:
            if all(i.startswith(('1', '2', '3', '4', '5', '6')) for i in options.include):
                exit('Could not perform benchmarks on ' +
                     ' '.join(options.include) + ' with given conditions. Exiting.')
            else:
                exit('Can\'t inlcude recommendations not defined in CIS Benchmark document.\nRun -h/--help or refer to the documentation.')
        elif recommendations:
            recommendations = [i for i in include if i in recommendations]
        else:
            recommendations = include

    # to remove (blacklist) recommendations based on option
    if options.exclude:
        exclude = list()
        for e in options.exclude:
            r = re.compile(e)
            exclude.extend(list(filter(r.match, [b[0] for b in benchmark])))
        if recommendations:
            recommendations = [r for r in recommendations if r not in exclude]
        else:
            recommendations = [b for b in benchmark if b[0] not in exclude]

    if not recommendations and options.score == None and not options.platform and not options.level and not options.include and not options.exclude:
        recommendations = [b[0] for b in benchmark]

    # returning the requested recommendations
    return recommendations
