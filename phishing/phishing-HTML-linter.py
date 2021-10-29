#!/usr/bin/python3

import os, sys, re
import string
import argparse
import yaml
import textwrap
import json
from urllib import parse
from bs4 import BeautifulSoup

options = {
    'format' : 'text',
}

executable_extensions = [
    '.exe',
    '.dll',
    '.lnk',
    '.scr',
    '.sys',
    '.ps1',
    '.bat',
    '.js',
    '.jse',
    '.vbs',
    '.vba',
    '.vbe',
    '.wsl',
    '.cpl',
]


options = {
    'debug': False,
    'verbose': False,
    'nocolor' : False,
    'log' : sys.stderr,
    'format' : 'text',
}

class Logger:
    colors_map = {
        'red':      31, 
        'green':    32, 
        'yellow':   33,
        'blue':     34, 
        'magenta':  35, 
        'cyan':     36,
        'white':    37, 
        'grey':     38,
    }

    colors_dict = {
        'error': colors_map['red'],
        'trace': colors_map['magenta'],
        'info ': colors_map['green'],
        'debug': colors_map['grey'],
        'other': colors_map['grey'],
    }

    options = {}

    def __init__(self, opts = None):
        self.options.update(Logger.options)
        if opts != None and len(opts) > 0:
            self.options.update(opts)

    @staticmethod
    def with_color(c, s):
        return "\x1b[%dm%s\x1b[0m" % (c, s)

    def colored(self, txt, col):
        if self.options['nocolor']:
            return txt

        return Logger.with_color(Logger.colors_map[col], txt)
        
    # Invocation:
    #   def out(txt, mode='info ', fd=None, color=None, noprefix=False, newline=True):
    @staticmethod
    def out(txt, fd, mode='info ', **kwargs):
        if txt == None or fd == 'none':
            return 
        elif fd == None:
            raise Exception('[ERROR] Logging descriptor has not been specified!')

        args = {
            'color': None, 
            'noprefix': False, 
            'newline': True,
            'nocolor' : False
        }
        args.update(kwargs)

        if type(txt) != str:
            txt = str(txt)
            
        txt = txt.replace('\t', ' ' * 4)

        if args['nocolor']:
            col = ''
        elif args['color']:
            col = args['color']
            if type(col) == str and col in Logger.colors_map.keys():
                col = Logger.colors_map[col]
        else:
            col = Logger.colors_dict.setdefault(mode, Logger.colors_map['grey'])

        prefix = ''
        if mode:
            mode = '[%s] ' % mode
            
        if not args['noprefix']:
            if args['nocolor']:
                prefix = mode.upper()
            else:
                prefix = Logger.with_color(Logger.colors_dict['other'], '%s' 
                % (mode.upper()))
        
        nl = ''
        if 'newline' in args:
            if args['newline']:
                nl = '\n'

        if 'force_stdout' in args:
            fd = sys.stdout

        if type(fd) == str:
            with open(fd, 'a') as f:
                prefix2 = ''
                if mode: 
                    prefix2 = '%s' % (mode.upper())
                f.write(prefix2 + txt + nl)
                f.flush()

        else:
            if args['nocolor']:
                fd.write(prefix + txt + nl)
            else:
                fd.write(prefix + Logger.with_color(col, txt) + nl)

    # Info shall be used as an ordinary logging facility, for every desired output.
    def info(self, txt, forced = False, **kwargs):
        kwargs['nocolor'] = self.options['nocolor']
        if forced or (self.options['verbose'] or \
            self.options['debug'] ) \
            or (type(self.options['log']) == str and self.options['log'] != 'none'):
            Logger.out(txt, self.options['log'], 'info', **kwargs)

    def text(self, txt, **kwargs):
        kwargs['noPrefix'] = True
        kwargs['nocolor'] = self.options['nocolor']
        Logger.out(txt, self.options['log'], '', **kwargs)

    def dbg(self, txt, **kwargs):
        if self.options['debug']:
            kwargs['nocolor'] = self.options['nocolor']
            Logger.out(txt, self.options['log'], 'debug', **kwargs)

    def err(self, txt, **kwargs):
        kwargs['nocolor'] = self.options['nocolor']
        Logger.out(txt, self.options['log'], 'error', **kwargs)

    def fatal(self, txt, **kwargs):
        kwargs['nocolor'] = self.options['nocolor']
        Logger.out(txt, self.options['log'], 'error', **kwargs)
        os._exit(1)

logger = Logger(options)

class PhishingMailParser:
    def __init__(self, options):
        self.options = options
        self.results = {}

    def parse(self, html):
        self.html = html
        self.soup = BeautifulSoup(html, features="lxml")

        self.results['Embedded Images']                                         = self.testEmbeddedImages()
        self.results['Images without ALT']                                      = self.testImagesNoAlt()
        self.results['Masqueraded Links']                                       = self.testMaskedLinks()
        self.results['Use of underline tag <u>']                                = self.testUnderlineTag()
        self.results['HTML code in <a> link tags']                              = self.testLinksWithHtmlCode()
        self.results['<a href="..."> URL contained GET parameter']              = self.testLinksWithGETParams()
        self.results['<a href="..."> URL contained GET parameter with URL']     = self.testLinksWithGETParamsBeingURLs()
        self.results['<a href="..."> URL pointed to an executable file']        = self.testLinksWithDangerousExtensions()

        return {k: v for k, v in self.results.items() if v}

    @staticmethod
    def context(tag):
        s = str(tag)

        if len(s) < 100:
            return s

        beg = s[:50]
        end = s[-50:]

        return f'{beg}...{end}'

    def testUnderlineTag(self):
        links = self.soup('u')

        if not links or len(links) == 0:
            return []

        desc = 'Underline tags are recognized by anti-spam filters and trigger additional rule (Office365: 67856001), but by their own shouldnt impact spam score.'
        result = f'- Found {len(links)} <u> tags. This is not by itself an indication of spam, but is known to trigger some rules (like Office365: 67856001)\n'

        context = ''
        for i in range(len(links)):
            context += str(links[i]) + '\n\n'
            if i > 5: break

        return {
            'description' : desc,
            'context' : context,
            'analysis' : result
        }

    def testLinksWithHtmlCode(self):
        links = self.soup('a')

        desc = 'Links that contain HTML code within <a> ... </a> may increase Spam score heavily'
        context = ''
        result = ''
        num = 0
        embed = ''

        for link in links:       
            text = str(link)
            pos = text.find('>')
            code = text[pos+1:]

            m = re.search(r'(.+)<\s*/\s*a\s*>', code, re.I)
            if m:
                code = m.group(1)

            suspicious = '<' in text and '>' in text

            if suspicious:
                num += 1

                if num < 5:
                    N = 70
                    tmp = text[:N]

                    if len(text) > N:
                        tmp += ' ... ' + text[-N:]

                    context += tmp + '\n'

                    code2 = PhishingMailParser.context(code)
                    context += f"\n\t- {logger.colored('Code inside of <a> tag:','red')}\n\t\t" + logger.colored(code2, 'yellow') + '\n'

        if num > 0:
            result += f'- Found {num} <a> tags that contained HTML code inside!\n'
            result +=  '\t  Links conveying HTML code within <a> ... </a> may greatly increase message Spam score!\n'

        if len(result) == 0:
            return []

        return {
            'description' : desc,
            'context' : context,
            'analysis' : result
        }


    def testLinksWithGETParams(self):
        links = self.soup('a')

        desc = 'Links with URLs containing GET parameters will be noticed by anti-spam filters resulting in another rule triggering on message (Office365: 21615005).'
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
            params = dict(parse.parse_qsl(parse.urlsplit(href).query))

            if len(params) > 0:
                num += 1

                if num < 5:
                    context += PhishingMailParser.context(link) + '\n'
                    hr = href[:90]
                    pos = hr.find('?')
                    hr = hr[:pos] + logger.colored(hr[pos:], 'yellow')

                    context += f'\thref = "{hr}"\n'
                    context += f'\ttext = "{text[:90]}"\n\n'

        if num > 0:
            result += f'- Found {num} <a> tags with href="..." URLs containing GET params.\n'
            result +=  '\t  Links with URLs that contain GET params might trigger anti-spam rule (Office365: 21615005)\n'

        if len(result) == 0:
            return []

        return {
            'description' : desc,
            'context' : context,
            'analysis' : result
        }

    def testLinksWithDangerousExtensions(self):
        links = self.soup('a')

        desc = 'Message contained <a> tags with href="..." links pointing to a file with dangerous extension (such as .exe)'
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
            parsed = parse.urlsplit(href)

            if '.' not in parsed.path: 
                continue

            pos = parsed.path.rfind('.')
            if pos == -1:
                continue

            extension = parsed.path.lower()[pos:]

            if extension in executable_extensions:
                num += 1

                if num < 5:
                    context += PhishingMailParser.context(link) + '\n'
                    hr = href[:90]
                    pos1 = hr.lower().find(extension.lower())

                    hr = logger.colored(hr[:pos1], 'yellow') + logger.colored(hr[pos1:pos1+len(extension)], 'red') + logger.colored(hr[pos1+len(extension):], 'yellow')

                    context += f'\thref = "{hr}"\n'
                    context += f'\ttext = "{text[:90]}"\n\n'

                    context += f'\tExtension matched: {logger.colored(extension, "red")}\n'

        if num > 0:
            result += f'- Found {num} <a> tags with href="..." URLs pointing to files with dangerous extensions (such as .exe).\n'
            result +=  '\t  Links with URLs that point to potentially executable files might trigger anti-spam rule (Office365: 460985005)\n'

        if len(result) == 0:
            return []

        return {
            'description' : desc,
            'context' : context,
            'analysis' : result
        }

    def testLinksWithGETParamsBeingURLs(self):
        links = self.soup('a')

        desc = 'Links with URLs that contain GET parameters pointing to another URL, will trigger two Office365 anti-spam rules (Office365: 45080400002).'
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
            params = dict(parse.parse_qsl(parse.urlsplit(href).query))

            url = re.compile(r'((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*')

            if len(params) > 0:
                for k, v in params.items():
                    m = url.match(v)

                    if m:
                        urlmatched = m.group(1)
                        num += 1

                        if num < 5:
                            context += PhishingMailParser.context(link) + '\n'

                            hr = href[:90]
                            hr = logger.colored(hr, 'yellow')

                            context += f'\thref = "{hr}"\n'
                            context += f'\ttext = "{text[:90]}"\n\n'
                            context += f'\thref URL GET parameter contained another URL:\n\t\t' + logger.colored(v, "red") + '\n'

        if num > 0:
            result += f'- Found {num} <a> tags with href="..." URLs containing GET params containing another URL.\n'
            result +=  '\t  Links with URLs that contain GET params with another URL might trigger anti-spam rule (Office365: 45080400002)\n'

        if len(result) == 0:
            return []

        return {
            'description' : desc,
            'context' : context,
            'analysis' : result
        }


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

                if num < 5:
                    context += PhishingMailParser.context(link) + '\n'
                    context += f'\thref = "{logger.colored(href[:90],"green")}"\n'
                    context += f'\ttext = "{logger.colored(text[:90],"red")}"\n\n'

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

                if num < 5:
                    context += PhishingMailParser.context(img) + '\n\n'

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

                if num < 5:
                    if len(alt) > 0:
                        context += f'- ALT="{alt}": ' + PhishingMailParser.context(img) + '\n'
                    else:
                        ctx = PhishingMailParser.context(img)
                        pos = ctx.find('data:')
                        pos2 = ctx.find('"', pos+1)

                        ctx = logger.colored(ctx[:pos], 'yellow') + logger.colored(ctx[pos:pos2], 'red') + logger.colored(ctx[pos2:], 'yellow')

                        context += ctx + '\n'

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
            analysis = v['analysis'].strip()
            context = v['context'].strip()
            desc = '\n'.join(textwrap.wrap(
                v['description'],
                width = 80,
                initial_indent = '',
                subsequent_indent = '    '
            )).strip()

            analysis = analysis.replace('- ', '\t- ')

            print(f'''
------------------------------------------
({num}) Test: {logger.colored(k, "cyan")}

{logger.colored("DESCRIPTION", "blue")}: 

    {desc}

{logger.colored("CONTEXT", "blue")}: 

    {context}

{logger.colored("ANALYSIS", "blue")}: 

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
    options.update(vars(args))
    return args

def main(argv):
    args = opts(argv)
    if not args:
        return False

    print('''
    :: Phishing HTML Linter
    Shows you bad smells in your HTML code that will get your mails busted!
    Mariusz Banach / mgeeky
''')

    html = ''
    with open(args.file, 'rb') as f:
        html = f.read()

    p = PhishingMailParser({})
    ret = p.parse(html.decode())

    if len(ret) > 0:
        printOutput(ret)

    else:
        print('\n[+] Congrats! Your message does not have any known bad smells that could trigger anti-spam rules.\n')
    

if __name__ == '__main__':
    main(sys.argv)
