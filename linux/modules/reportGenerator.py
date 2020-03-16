from modules.optionsParser import get_recommendations
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from csv import reader
from sys import exit


colorPass = [76, 175, 80]
colorFail = [244, 67, 54]
colorWarn = [255, 152, 0]
colorPrimary = [0, 188, 212]
colorSecondary = [103, 58, 183]


def setInfo(pdf, SeBAz_contents):
    pdf.setAuthor(SeBAz_contents[-13][1])
    pdf.setCreator('SeBAz')
    pdf.setProducer('SeBAz')
    subject = 'Result of'
    if SeBAz_contents[-9][1] == 'ind':
        subject += ' Independent '
    if SeBAz_contents[-9][1] == 'cen':
        subject += ' CentOS 8 '
    if SeBAz_contents[-9][1] == 'deb':
        subject += ' Debian 9 '
    if SeBAz_contents[-9][1] == 'fed':
        subject += ' Fedora 28 Family '
    if SeBAz_contents[-9][1] == 'red':
        subject += ' RedHat Enterprise 8 '
    if SeBAz_contents[-9][1] == 'sus':
        subject += ' SUSE Enterprise 12 '
    if SeBAz_contents[-9][1] == 'ubu':
        subject += ' Ubuntu 18.04 LTS '
    subject += 'Linux CIS Benchmarking'
    pdf.setSubject(subject)
    return subject


def drawBorder(pdf):
    pdf.saveState()
    pdf.setStrokeColorRGB(
        colorPrimary[0]/256, colorPrimary[1]/256, colorPrimary[2]/256)
    pdf.setLineWidth(4)
    pdf.rect(A4[0]/12, A4[1]/17, A4[0]*10/12, A4[1]*15/17)
    pdf.restoreState()


def makeTitle(pdf, SeBAz_contents, subject):
    pdf.saveState()
    # border coloring
    pdf.setFillColorRGB(colorPrimary[0]/256,
                        colorPrimary[1]/256, colorPrimary[2]/256)
    pdf.rect(0, 0, A4[0]/12, A4[1], fill=1, stroke=0)
    pdf.rect(0, 0, A4[0], A4[1]/17, fill=1, stroke=0)
    pdf.rect(A4[0]*11/12, 0, A4[0]/12, A4[1], fill=1, stroke=0)
    pdf.rect(0, A4[1]*16/17, A4[0], A4[1]/17, fill=1, stroke=0)
    # title text
    pdf.setFillColorRGB(
        colorSecondary[0]/256, colorSecondary[1]/256, colorSecondary[2]/256)
    pdf.setFont('Helvetica-BoldOblique', 30)
    pdf.drawCentredString(A4[0]*4/10, A4[1]*18/50, SeBAz_contents[-12][1])
    pdf.drawCentredString(A4[0]*6/10, A4[1]*20/50, SeBAz_contents[-11][1])
    pdf.setFont('Helvetica-Bold', 15)
    # subject
    pdf.drawCentredString(A4[0]/2, A4[1]*25/50, subject)
    # passed
    pdf.drawCentredString(A4[0]/2, A4[1]*27/50, SeBAz_contents[-2][0])
    # score
    pdf.drawCentredString(A4[0]/2, A4[1]*29/50, SeBAz_contents[-1][0])
    # auditor name
    pdf.drawRightString(A4[0]*10/12, A4[1]*40/50, SeBAz_contents[-13][1])
    pdf.restoreState()
    pdf.showPage()


def makeResult(pdf, SeBAz_contents):
    drawBorder(pdf)
    pdf.saveState()
    pdf.setFont('Helvetica-Bold', 15)
    # start time utc
    pdf.drawString(3*(A4[0]/10)/2, A4[1]*3/8, SeBAz_contents[-21][0])
    # start time local
    pdf.drawString(3*(A4[0]/10)/2, A4[1]*3/8 + 30, SeBAz_contents[-20][0])
    # finish time utc
    pdf.drawString(3*(A4[0]/10)/2, A4[1]*3/8 + 60, SeBAz_contents[-5][0])
    # finish time local
    pdf.drawString(3*(A4[0]/10)/2, A4[1]*3/8 + 90, SeBAz_contents[-4][0])
    # test and time
    pdf.drawString(3*(A4[0]/10)/2, A4[1]*3/8 + 120, SeBAz_contents[-3][0])
    pdf.restoreState()
    pdf.showPage()


def makeIntro(pdf, SeBAz_contents):
    drawBorder(pdf)
    pdf.saveState()
    startColumn = 3*(A4[0]/10)/2
    startRow = A4[1]/8
    # auditor description
    pdf.setFont('Helvetica-Bold', 15)
    pdf.drawString(startColumn, startRow, 'Auditor Description')
    pdf.setFont('Courier-Bold', 11)
    index = 0
    line = 15
    for i in range(0, len(SeBAz_contents[-10][1])):
        if SeBAz_contents[-10][1][i] == '[' or SeBAz_contents[-10][1][i] == ',' or SeBAz_contents[-10][1][i] == ']' or SeBAz_contents[-10][1][i] == "'" or SeBAz_contents[-10][1][i] == '\\':
            continue
        elif SeBAz_contents[-10][1][i-1] == '\\' and SeBAz_contents[-10][1][i] == 'n':
            ''
        else:
            pdf.drawString(startColumn + 6.7*index, startRow +
                           line, SeBAz_contents[-10][1][i])
            index += 1
        if index == 60 or SeBAz_contents[-10][1][i-1] == '\\' and SeBAz_contents[-10][1][i] == 'n':
            line += 10
            index = 0
        if line > 605:
            index = 0
            line = 0
            pdf.restoreState()
            pdf.showPage()
            pdf.saveState()
            drawBorder(pdf)
            pdf.setFont('Courier-Bold', 11)
    # included controls
    if line + 45 > 600:
        index = 0
        line = 0
        pdf.restoreState()
        pdf.showPage()
        pdf.saveState()
        drawBorder(pdf)
    else:
        line += 30
    pdf.setFont('Helvetica-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Included Controls')
    index = 0
    line += 15
    pdf.setFont('Courier-Bold', 11)
    for i in range(0, len(SeBAz_contents[-18][1])):
        if SeBAz_contents[-18][1][i] == '[' or SeBAz_contents[-18][1][i] == ']' or SeBAz_contents[-18][1][i] == "'":
            continue
        elif SeBAz_contents[-18][1][i] != ',':
            pdf.drawString(startColumn + 6.7*index, startRow +
                           line, SeBAz_contents[-18][1][i])
            index += 1
        if index == 60 or SeBAz_contents[-18][1][i] == ',':
            line += 10
            index = -1
        if line > 605:
            index = 0
            line = 0
            pdf.restoreState()
            pdf.showPage()
            pdf.saveState()
            drawBorder(pdf)
            pdf.setFont('Courier-Bold', 11)
    # excluded controls
    if line + 45 > 600:
        index = 0
        line = 0
        pdf.restoreState()
        pdf.showPage()
        pdf.saveState()
        drawBorder(pdf)
    else:
        line += 30
    pdf.setFont('Helvetica-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Excluded Controls')
    index = 0
    line += 15
    pdf.setFont('Courier-Bold', 11)
    for i in range(0, len(SeBAz_contents[-17][1])):
        if SeBAz_contents[-17][1][i] == '[' or SeBAz_contents[-17][1][i] == ']' or SeBAz_contents[-17][1][i] == "'":
            continue
        elif SeBAz_contents[-17][1][i] != ',':
            pdf.drawString(startColumn + 6.7*index, startRow +
                           line, SeBAz_contents[-17][1][i])
            index += 1
        if index == 60 or SeBAz_contents[-17][1][i] == ',':
            line += 10
            index = -1
        if line > 605:
            index = 0
            line = 0
            pdf.restoreState()
            pdf.showPage()
            pdf.saveState()
            drawBorder(pdf)
            pdf.setFont('Courier-Bold', 11)
    # Level
    if line + 135 > 600:
        index = 0
        line = 0
        pdf.restoreState()
        pdf.showPage()
        pdf.saveState()
        drawBorder(pdf)
    else:
        line += 30
    pdf.setFont('Helvetica-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Scoring Level')
    pdf.setFont('Helvetica-Bold', 12)
    pdf.drawString(startColumn + 180, startRow + line,
                   'Both Level 1 and 2' if not SeBAz_contents[-16][1] else SeBAz_contents[-16][1][0])
    # Score
    line += 30
    pdf.setFont('Helvetica-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Score')
    pdf.setFont('Helvetica-Bold', 12)
    if not SeBAz_contents[-15][1]:
        pdf.drawString(startColumn + 180, startRow +
                       line, 'Both Scored and Not Scored')
    else:
        pdf.drawString(startColumn + 180, startRow + line,
                       'Scored' if SeBAz_contents[-15][1][0] else 'Not Scored')
    # Platform
    line += 30
    pdf.setFont('Helvetica-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Platform')
    pdf.setFont('Helvetica-Bold', 12)
    pdf.drawString(startColumn + 180, startRow + line, SeBAz_contents[-14][1])
    # Verbosity
    line += 30
    pdf.setFont('Helvetica-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Verbosity')
    pdf.setFont('Helvetica-Bold', 12)
    pdf.drawString(startColumn + 180, startRow + line, SeBAz_contents[-6][1])
    pdf.restoreState()
    pdf.showPage()


def makeIndex(pdf, SeBAz_contents):
    drawBorder(pdf)
    pdf.bookmarkPage('Index')
    pdf.saveState()
    # Title -> INDEX
    pdf.setFillColorRGB(
        colorSecondary[0]/256, colorSecondary[1]/256, colorSecondary[2]/256)
    pdf.setFont('Helvetica-BoldOblique', 20)
    pdf.drawCentredString(A4[0]/2, A4[1]/8, 'Index of Results')
    pdf.restoreState()
    # Index
    pdf.setFont('Courier-Bold', 11)
    line = 150
    for row in range(1, len(SeBAz_contents)-24):
        pdf.saveState()
        if SeBAz_contents[row][2] == 'PASS':
            pdf.setFillColorRGB(
                colorPass[0]/256, colorPass[1]/256, colorPass[2]/256)
        elif SeBAz_contents[row][2] == 'FAIL':
            pdf.setFillColorRGB(
                colorFail[0]/256, colorFail[1]/256, colorFail[2]/256)
        elif SeBAz_contents[row][2] == 'CHEK':
            pdf.setFillColorRGB(
                colorWarn[0]/256, colorWarn[1]/256, colorWarn[2]/256)
        # recommendation number
        pdf.drawCentredString(3*(A4[0]/10)/2, line, SeBAz_contents[row][0])
        # message
        pdf.drawString(A4[0]*5/20, line, SeBAz_contents[row][1])
        pdf.linkRect(SeBAz_contents[row][0], SeBAz_contents[row][0], (A4[0]*5/20, A4[1] -
                                                                      line - 2, A4[0]*5/20 + 6.7*len(SeBAz_contents[row][1]), A4[1] - line + 8), relative=1)
        # result
        pdf.drawCentredString(A4[0]*17/20, line, SeBAz_contents[row][2])
        line += 20
        if line > 770:
            line = 100
            pdf.restoreState()
            pdf.showPage()
            pdf.saveState()
            drawBorder(pdf)
            pdf.setFont('Courier-Bold', 11)
            continue
        pdf.restoreState()
    pdf.showPage()


def makeBody(pdf, SeBAz_contents, recommendations):
    for i, row in enumerate(range(1, len(SeBAz_contents)-24)):
        drawBorder(pdf)
        pdf.bookmarkPage(SeBAz_contents[row][0])
        pdf.saveState()
        # Recommendation number and explanation
        pdf.setFillColorRGB(
            colorSecondary[0]/256, colorSecondary[1]/256, colorSecondary[2]/256)
        pdf.setFont('Helvetica-BoldOblique', 15)
        pdf.drawCentredString(A4[0]/2, A4[1]/8, SeBAz_contents[row][0])
        if len(recommendations[i][4]) < 60:
            pdf.drawCentredString(A4[0]/2, A4[1]/8 + 20, recommendations[i][4])
        elif len(recommendations[i][4]) < 85:
            pdf.setFont('Helvetica-BoldOblique', 10)
            pdf.drawCentredString(A4[0]/2, A4[1]/8 + 20, recommendations[i][4])
        else:
            pdf.setFont('Helvetica-BoldOblique', 10)
            pdf.drawCentredString(A4[0]/2, A4[1]/8 + 20, recommendations[i][4])
        pdf.restoreState()
        pdf.saveState()
        startColumn = 3*(A4[0]/10)/2
        startRow = 250
        # Scored
        pdf.setFont('Helvetica-Bold', 15)
        pdf.drawString(
            startColumn, A4[1]/8 + 50, 'Scored' if recommendations[i][1] else 'Not Scored')
        # Server Level
        if recommendations[i][2]:
            profileServer = 'Level ' + \
                str(recommendations[i][2]) + ' Server'
        else:
            profileServer = 'N/A'
        pdf.drawString(startColumn, A4[1]/8 + 70, profileServer)
        # Workstation Level
        if recommendations[i][3]:
            profileWorkstation = 'Level ' + \
                str(recommendations[i][3]) + ' Workstation'
        else:
            profileWorkstation = 'N/A'
        pdf.drawString(startColumn, A4[1]/8 + 90, profileWorkstation)
        # result
        pdf.setFont('Helvetica-Bold', 13)
        pdf.drawString(startColumn, startRow, 'Result')
        pdf.setFont('Times-Roman', 12)
        if SeBAz_contents[row][2] == 'PASS':
            pdf.setFillColorRGB(
                colorPass[0]/256, colorPass[1]/256, colorPass[2]/256)
        elif SeBAz_contents[row][2] == 'FAIL':
            pdf.setFillColorRGB(
                colorFail[0]/256, colorFail[1]/256, colorFail[2]/256)
        elif SeBAz_contents[row][2] == 'CHEK':
            pdf.setFillColorRGB(
                colorWarn[0]/256, colorWarn[1]/256, colorWarn[2]/256)
        pdf.drawString(7*(A4[0]/10)/2, startRow, SeBAz_contents[row][2])
        pdf.restoreState()
        pdf.saveState()
        # Message
        pdf.setFont('Helvetica-Bold', 13)
        startRow += 30
        pdf.drawString(startColumn, startRow, 'Message')
        pdf.setFont('Times-Roman', 12)
        pdf.drawString(7*(A4[0]/10)/2, startRow, SeBAz_contents[row][1])
        # Time Taken
        pdf.setFont('Helvetica-Bold', 13)
        startRow += 30
        pdf.drawString(startColumn, startRow, 'Time Taken')
        pdf.setFont('Times-Roman', 12)
        if float(SeBAz_contents[row][4]) > 1.0:
            pdf.setFillColorRGB(
                colorFail[0]/256, colorFail[1]/256, colorFail[2]/256)
        elif float(SeBAz_contents[row][4]) > 0.01:
            pdf.setFillColorRGB(
                colorWarn[0]/256, colorWarn[1]/256, colorWarn[2]/256)
        else:
            pdf.setFillColorRGB(
                colorPass[0]/256, colorPass[1]/256, colorPass[2]/256)
        pdf.drawString(7*(A4[0]/10)/2, startRow,
                       SeBAz_contents[row][4] + ' seconds')
        pdf.restoreState()
        pdf.saveState()
        # explanation
        pdf.setFont('Helvetica-Bold', 13)
        startRow += 30
        pdf.drawString(startColumn, startRow, 'Explanation:')
        pdf.setFont('Courier-Bold', 11)
        index = 0
        startRow += 20
        for l in SeBAz_contents[row][3]:
            if l == '\n':
                startRow += 20
                index = 0
            elif l == '\t':
                index += 5
            else:
                pdf.drawString(startColumn + 6.7*index, startRow, l)
                index += 1
            if index == 65 or l == '\n':
                startRow += 10
                index = 0
            if startRow > 770:
                startRow = 100
                index = 0
                pdf.restoreState()
                pdf.showPage()
                pdf.saveState()
                drawBorder(pdf)
                pdf.setFont('Courier-Bold', 11)
        pdf.restoreState()
        pdf.showPage()


def makeOutline(pdf, SeBAz_contents):
    pdf.addOutlineEntry('Index', 'Index')
    for row in range(1, len(SeBAz_contents)-24):
        pdf.addOutlineEntry(
            SeBAz_contents[row][0] + ' - ' + SeBAz_contents[row][1], SeBAz_contents[row][0])


def createPDF(SeBAz):
    SeBAz_contents = list()
    with open(SeBAz, 'r', newline='') as f:
        csv_reader = reader(f, dialect='excel')
        for row in csv_reader:
            SeBAz_contents.append(row)

    class Options:
        def __init__(self, dist, score, platform, level, include, exclude):
            self.dist = dist
            self.score = score
            self.platform = platform
            self.level = level
            self.include = include
            self.exclude = exclude

    from re import sub
    option = Options(
        dist=SeBAz_contents[-9][1],
        score=None if not SeBAz_contents[-15][1] else int(
            SeBAz_contents[-15][1][0]),
        platform=None if not SeBAz_contents[-14][1] else SeBAz_contents[-14][1],
        level=None if not SeBAz_contents[-16][1] else int(
            SeBAz_contents[-16][1][0]),
        include=None if not SeBAz_contents[-18][1] else sub(
            r'\[|\]| |\'', '', SeBAz_contents[-18][1]).split(','),
        exclude=None if not SeBAz_contents[-17][1] else sub(
            r'\[|\]| |\'', '', SeBAz_contents[-17][1]).split(',')
    )
    recommendations = get_recommendations(option)

    pdf = canvas.Canvas(SeBAz.split('.csv')[
                        0] + '.pdf', pagesize=A4, bottomup=0, pageCompression=1)
    pdf.setTitle(SeBAz.split('.SeBAz.csv')[0])
    makeTitle(pdf, SeBAz_contents, setInfo(pdf, SeBAz_contents))
    makeResult(pdf, SeBAz_contents)
    makeIntro(pdf, SeBAz_contents)
    makeOutline(pdf, SeBAz_contents)
    makeIndex(pdf, SeBAz_contents)
    makeBody(pdf, SeBAz_contents, recommendations)
    pdf.save()


def generatePDF(SeBAz):
    from glob import glob
    for c in glob(SeBAz + '.SeBAz.csv'):
        print('\nGenerating ' + c.split('.csv')[0] + '.pdf')
        createPDF(c)
        print('Done.\n')
    exit()


if __name__ == "__main__":
    exit('Please run ./SeBAz -h')
