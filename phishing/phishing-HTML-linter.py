#!/usr/bin/python3

import os, sys, re
import string
import argparse
import yaml
import json

from bs4 import BeautifulSoup

options = {
    'format' : 'text',
}

class PhishingMailParser:
    def __init__(self, options):
        self.options = options
        self.results = {}

    def parse(self, html):
        self.html = html
        self.soup = BeautifulSoup(html, features="lxml")

        self.results['Embedded Images'] = self.testEmbeddedImages()
        self.results['Images without ALT'] = self.testImagesNoAlt()
        self.results['Masqueraded Links'] = self.testMaskedLinks()

        return {k: v for k, v in self.results.items() if v}

    @staticmethod
    def context(tag):
        s = str(tag)

        if len(s) < 100:
            return s

        beg = s[:50]
        end = s[-50:]

        return f'{beg}...{end}'

    def testMaskedLinks(self):
        links = self.soup('a')

        desc = 'Links that masquerade their href= attribute by displaying different link are considered harmful and will increase Spam score.'
        context = ''
        result = ''
        num = 0
        embed = ''

        for link in links:
            try:
                href = link['href']
            except:
                continue
        
            text = link.getText()

            url = re.compile(r'((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*')

            m1 = url.match(href)
            m2 = url.match(text)

            if m1 and m2:
                num += 1
                context += '- ' + PhishingMailParser.context(link) + '\n'
                context += f'\thref = "{href[:64]}"\n'
                context += f'\ttext = "{text[:64]}"\n\n'

        if num > 0:
            result += f'- Found {num} <a> tags that masquerade their href="" links with text!\n'
            result +=  '\t  Links that try to hide underyling URL are harmful and will be considered as Spam!\n'

        if len(result) == 0:
            return []

        return {
            'description' : desc,
            'context' : context,
            'analysis' : result
        }

    def testImagesNoAlt(self):
        images = self.soup('img')

        desc = 'Images without ALT="value" attribute may increase Spam scorage.'
        context = ''
        result = ''
        num = 0
        embed = ''

        for img in images:
            src = img['src']
            alt = ''

            try:
                alt = img['alt']
            except:
                pass

            if alt == '':
                num += 1
                context += '- ' + PhishingMailParser.context(img) + '\n'

        if num > 0:
            result += f'- Found {num} <img> tags without ALT="value" attribute.\n'
            result +=  '\t  Images without alternate text set in their attribute may increase Spam score\n'

        if len(result) == 0:
            return []

        return {
            'description' : desc,
            'context' : context,
            'analysis' : result
        }

    def testEmbeddedImages(self):
        images = self.soup('img')

        desc = 'Embedded images can increase Spam Confidence Level (SCL) in Office365 by 4 points. Embedded images are those with <img src="data:image/png;base64,<BLOB>"/> . They should be avoided.'
        context = ''
        result = ''
        num = 0
        embed = ''

        for img in images:
            src = img['src']
            alt = ''

            try:
                alt = img['alt']
            except:
                pass

            if src.lower().startswith('data:image/'):
                if len(embed) == 0:
                    embed = src[:30]

                num += 1
                if len(alt) > 0:
                    context += f'- ALT="{alt}": ' + PhishingMailParser.context(img) + '\n'
                else:
                    context += '- ' + PhishingMailParser.context(img) + '\n'

        if num > 0:
            result += f'- Found {num} <img> tags with embedded image ({embed}).\n'
            result +=  '\t  Embedded images increase Office365 SCL (Spam) level by 4 points!\n'

        if len(result) == 0:
            return []

        return {
            'description' : desc,
            'context' : context,
            'analysis' : result
        }


def printOutput(out):
    if options['format'] == 'text':
        width = 100
        num = 0

        for k, v in out.items():
            num += 1
            analysis = v['analysis']
            context = v['context']

            analysis = analysis.replace('- ', '\t- ')

            print(f'''
------------------------------------------
({num}) Test: {k}

CONTEXT: 
    {context}

ANALYSIS:
    {analysis}
''')
            
    elif options['format'] == 'json':
        print(json.dumps(out))

def opts(argv):
    global options
    global headers

    o = argparse.ArgumentParser(
        usage = 'phishing-HTML-linter.py [options] <file.html>'
    )
    
    req = o.add_argument_group('Required arguments')
    req.add_argument('file', help = 'Input HTML file')

    args = o.parse_args()
    return args

def main(argv):
    args = opts(argv)
    if not args:
        return False

    print('''
    :: Phishing HTML Linter
    Shows you bad smells in your HTML code that will get your mails busted!
    Mariusz B. / mgeeky
''')

    html = ''
    with open(args.file, 'rb') as f:
        html = f.read()

    p = PhishingMailParser({})
    ret = p.parse(html.decode())

    printOutput(ret)
    

if __name__ == '__main__':
    main(sys.argv)
