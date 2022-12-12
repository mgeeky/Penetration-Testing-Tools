#!/usr/bin/python3

import os, sys, re
import string
import argparse
import yaml
import textwrap
import json
from urllib import parse

try:
    from bs4 import BeautifulSoup
except ImportError:
    print('[!] You need to install bs4:\n\t\tcmd> pip install bs4')
    sys.exit(1)

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

    #
    # Based on:
    #    https://journeys.autopilotapp.com/blog/email-spam-trigger-words/
    #    https://www.activecampaign.com/blog/spam-words
    #    https://blog.hubspot.com/blog/tabid/6307/bid/30684/the-ultimate-list-of-email-spam-trigger-words.aspx
    #
    Suspicious_Words = {
        'Manipulative': (
            'creating unnecessary urgency or pressure',
            (
                "Act now", "Action", "Apply now", "Apply online", "Buy", "Buy direct", "Call", "Call now", "Click here",
                "Clearance", "Click here", "Do it today", "Don't delete", "Drastically reduced", "Exclusive deal", "Expire",
                "Get", "Get it now", "Get started now", "Important information regarding", "Instant", "Limited time",
                "New customers only", "Now only", "Offer expires", "Once in a lifetime", "Order now", "Please read",
                "Special promotion", "Take action", "This won't last", "Urgent", "While stocks last"
            )
        ),
        
        'Needy' : (
            'sounding desperate or exaggerated claims',
            (
                "All-new", "Bargain", "Best price", "Bonus", "Email marketing", "Free", "For instant access", "Free gift",
                "Free trial", "Have you been turned down?", "Great offer", "Join millions of Americans", "Incredible deal",
                "Prize", "Satisfaction guaranteed", "Will not believe your eyes"
            )
        ),
        
        'Sleazy' : (
            'being too pushy',
            (
                "As seen on", "Click here", "Click below", "Deal", "Direct email", "Direct marketing", "Do it today",
                "Order now", "Order today", "Unlimited", "What are you waiting for?", "Visit our website"
            )
        ),
        
        'Cheap' : (
            'no pre-qualifications, everybody wins',
            (
                "Acceptance", "Access", "Avoid bankruptcy", "Boss", "Cancel", "Card accepted", "Certified",
                "Cheap", "Compare", "Compare rates", "Congratulations", "Credit card offers", "Cures", "Dear ",
                "Dear friend", "Drastically reduced", "Easy terms", "Free grant money", "Free hosting", "Free info",
                "Free membership", "Friend", "Get out of debt", "Giving away", "Guarantee", "Guaranteed",
                "Have you been turned down?", "Hello", "Information you requested", "Join millions", "No age restrictions", 
                "No catch", "No experience", "No obligation", "No purchase necessary", "No questions asked", 
                "No strings attached", "Offer", "Opportunity", "Save big", "Winner", "Winning", "Won", "You are a winner!",
                "You've been selected!"
            )
        ),
        
        'Far-fetched' : (
            'statements that are too good to be true',
            (
                "Additional income", "All-natural", "Amazing", "Be your own boss", "Big bucks", "Billion",
                "Billion dollars", "Cash", "Cash bonus", "Consolidate debt and credit", "Consolidate your debt", 
                "Double your income", "Earn", "Earn cash", "Earn extra cash", "Eliminate bad credit", "Eliminate debt",
                "Extra", "Fantastic deal", "Financial freedom", "Financially independent", "Free investment", "Free money",
                "Get paid", "Home", "Home-based", "Income", "Increase sales", "Increase traffic", "Lose", "Lose weight",
                "Money back", "No catch", "No fees", "No hidden costs", "No strings attached", "Potential earnings", 
                "Pure profit", "Removes wrinkles", "Reverses aging", "Risk-free", "Serious cash", "Stop snoring",
                "Vacation", "Vacation offers", "Weekend getaway", "Weight loss", "While you sleep", "Work from home"
            )
        ),

        'Exaggeration' : (
            'exaggerated claims and promises',
            (
                "100% more", "100% free", "100% satisfied", "Additional income", "Be your own boss", "Best price",
                "Big bucks", "Billion", "Cash bonus", "Cents on the dollar", "Consolidate debt", "Double your cash",
                "Double your income", "Earn extra cash", "Earn money", "Eliminate bad credit", "Extra cash", "Extra income",
                "Expect to earn", "Fast cash", "Financial freedom", "Free access", "Free consultation", "Free gift",
                "Free hosting", "Free info", "Free investment", "Free membership", "Free money", "Free preview", "Free quote",
                "Free trial", "Full refund", "Get out of debt", "Get paid", "Giveaway", "Guaranteed", "Increase sales",
                "Increase traffic", "Incredible deal", "Lower rates", "Lowest price", "Make money", "Million dollars", "Miracle",
                "Money back", "Once in a lifetime", "One time", "Pennies a day", "Potential earnings", "Prize",
                "Promise", "Pure profit", "Risk-free", "Satisfaction guaranteed", "Save big money", "Save up to", "Special promotion",
            )
        ),

        'Urgency' : (
            'create unnecessary urgency and pressure',
            (
                "Act now", "Apply now", "Become a member", "Call now", "Click below", "Click here", "Get it now",
                "Do it today", "Don’t delete", "Exclusive deal", "Get started now", "Important information regarding", 
                "Information you requested", "Instant", "Limited time", "New customers only", "Order now", "Please read",
                "See for yourself", "Sign up free", "Take action", "This won’t last", "Urgent", "What are you waiting for?",
                "While supplies last", "Will not believe your eyes", "Winner", "Winning", "You are a winner", "You have been selected",

            )
        ),

        'Spammy' : (
            'shady, spammy, or unethical behavior',
            (
                "Bulk email", "Buy direct", "Cancel at any time", "Check or money order", "Congratulations", "Confidentiality",
                "Cures", "Dear friend", "Direct email", "Direct marketing", "Hidden charges", "Human growth hormone", "Internet marketing",
                "Lose weight", "Mass email", "Meet singles", "Multi-level marketing", "No catch", "No cost", "No credit check",
                "No fees", "No gimmick", "No hidden costs", "No hidden fees", "No interest", "No investment", "No obligation",
                "No purchase necessary", "No questions asked", "No strings attached", "Not junk", "Notspam", "Obligation",
                "Passwords", "Requires initial investment", "Social security number", "This isn’t a scam", "This isn’t junk", 
                "This isn’t spam", "Undisclosed", "Unsecured credit", "Unsecured debt", "Unsolicited", "Valium",
                "Viagra", "Vicodin", "We hate spam", "Weight loss", "Xanax",
            )
        ),

        'Jargon' : (
            'jargon or legalese',
            (
                "Accept credit cards", "All new", "As seen on", "Bargain", "Beneficiary", "Billing", "Bonus",
                "Cards accepted", "Cash", "Certified", "Cheap", "Claims", "Clearance", "Compare rates", "Credit card offers", 
                "Deal", "Debt", "Discount", "Fantastic", "In accordance with laws", "Income", "Investment", "Join millions",
                "Lifetime", "Loans", "Luxury", "Marketing solution", "Message contains", "Mortgage rates", "Name brand",
                "Offer", "Online marketing", "Opt in", "Pre-approved", "Quote", "Rates", "Refinance", "Removal", "Reserves the right",
                "Score", "Search engine", "Sent in compliance", "Subject to", "Terms and conditions", "Trial", "Unlimited",
                "Warranty", "Web traffic", "Work from home", 
            )
        ),
        
        'Shady' : (
            'ethically or legally questionable behavior',
            (
                "Addresses", "Beneficiary", "Billing", "Casino", "Celebrity", "Collect child support", "Copy DVDs", 
                "Fast viagra delivery", "Hidden", "Human growth hormone", "In accordance with laws", "Investment",
                "Junk", "Legal", "Life insurance", "Loan", "Lottery", "Luxury car", "Medicine", "Meet singles", "Message contains",
                "Miracle", "Money", "Multi-level marketing", "Nigerian", "Offshore", "Online degree", "Online pharmacy", "Passwords",
                "Refinance", "Request", "Rolex", "Score", "Social security number", "Spam", "This isn't spam", "Undisclosed recipient",
                "University diplomas", "Unsecured credit", "Unsolicited", "US dollars", "Valium", "Viagra", "Vicodin",
                "Warranty", "Xanax"
            )
        ),

        "Commerce" : (
            "",
            (
                "As seen on", "Buy", "Buy direct", "Buying judgments", "Clearance", "Order", "Order status", "Orders shipped by shopper",
            )
        ),

        "Personal" : (
            "",
            (
                "Dig up dirt on friends", "Meet singles", "Score with babes", "XXX", "Near you",
            )
        ),

        "Employment" : (
            "",
            (
                "Additional income", "Be your own boss", "Compete for your business", "Double your", "Earn $", "Earn extra cash",
                "Earn per week", "Expect to earn", "Extra income", "Home based", "Home employment", "Homebased business", "Income from home",
                "Make $", "Make money", "Money making", "Online biz opportunity", "Online degree", "Opportunity",
                "Potential earnings", "University diplomas", "While you sleep", "Work at home", "Work from home",
            )
        ),

        "Financial - General" : (
            "",
            (
                "$$$", "Affordable", "Bargain", "Beneficiary", "Best price", "Big bucks", "Cash", "Cash bonus", "Cashcashcash",
                "Cents on the dollar", "Cheap", "Check", "Claims", "Collect", "Compare rates", "Cost", "Credit", "Credit bureaus",
                "Discount", "Earn", "Easy terms", "F r e e", "Fast cash", "For just $XXX", "Hidden assets", "hidden charges",
                "Income", "Incredible deal", "Insurance", "Investment", "Loans", "Lowest price", "Million dollars", "Money",
                "Money back", "Mortgage", "Mortgage rates", "No cost", "No fees", "One hundred percent free", "Only $", "Pennies a day",
                "Price", "Profits", "Pure profit", "Quote", "Refinance", "Save $", "Save big money", "Save up to", "Serious cash",
                "Subject to credit", "They keep your money — no refund!", "Unsecured credit", "Unsecured debt",
                "US dollars", "Why pay more?",
            )
        ),

        "Financial - Business" : (
            "",
            (
                "Accept credit cards", "Cards accepted", "Check or money order", "Credit card offers", "Explode your business",
                "Full refund", "Investment decision", "No credit check", "No hidden Costs", "No investment",
                "Requires initial investment", "Sent in compliance", "Stock alert", "Stock disclaimer statement", "Stock pick",
            )
        ),

        "Financial - Personal" : (
            "",
            (
                "Avoice bankruptcy", "Calling creditors", "Collect child support", "Consolidate debt and credit", 
                "Consolidate your debt", "Eliminate bad credit", "Eliminate debt", "Financially independent",
                "Get out of debt", "Get paid", "Lower interest rate", "Lower monthly payment", "Lower your mortgage rate",
                "Lowest insurance rates", "Pre-approved", "Refinance home", "Social security number", "Your income",
            )
        ),

        "General" : (
            "",
            (
                "Acceptance", "Accordingly", "Avoid", "Chance", "Dormant", "Freedom", "Here", "Hidden", "Home", "Leave",
                "Lifetime", "Lose", "Maintained", "Medium", "Miracle", "Never", "Passwords", "Problem", "Remove", "Reverses",
                "Sample", "Satisfaction", "Solution", "Stop", "Success", "Teen", "Wife",
            )
        ),

        "Greetings" : (
            "",
            (
                "Dear ", "Friend", "Hello",
            )
        ),

        "Marketing" : (
            "",
            (
                "Ad", "Auto email removal", "Bulk email", "Click", "Click below", "Click here", "Click to remove", "Direct email",
                "Direct marketing", "Email harvest", "Email marketing", "Form", "Increase sales", "Increase traffic",
                "Increase your sales", "Internet market", "Internet marketing", "Marketing", "Marketing solutions", "Mass email",
                "Member", "Month trial offer", "More Internet Traffic", "Multi level marketing", "Notspam", "One time mailing",
                "Online marketing", "Open", "Opt in", "Performance", "Removal instructions", "Sale", "Sales",
                "Search engine listings", "Search engines", "Subscribe", "The following form", "This isn't junk", "This isn't spam",
                "Undisclosed recipient", "Unsubscribe", "Visit our website", "We hate spam", "Web traffic", "Will not believe your eyes",
            )
        ),

        "Medical" : (
            "",
            (
                "Cures baldness", "Diagnostic", "Fast Viagra delivery", "Human growth hormone", "Life insurance",
                "Lose weight", "Lose weight spam", "Medicine", "No medical exams", "Online pharmacy", "Removes wrinkles",
                "Reverses aging", "Stop snoring", "Valium", "Viagra", "Vicodin", "Weight loss", "Xanax", 
            )
        ),

        "Numbers" : (
            "",
            (
                "#1", "100% free", "100% satisfied", "4U", "50% off", "Billion", "Billion dollars", "Join millions", 
                "Join millions of Americans", "Million", "One hundred percent guaranteed", "Thousands",
            )
        ),

        "Offers" : (
            "",
            (
                "Being a member", "Billing address", "Call", "Cannot be combined with any other offer", 
                "Confidentially on all orders", "Deal", "Financial freedom", "Gift certificate", "Giving away",
                "Guarantee", "Have you been turned down?", "If only it were that easy", "Important information regarding", 
                "In accordance with laws", "Long distance phone offer", "Mail in order form", "Message contains",
                "Name brand", "Nigerian", "No age restrictions", "No catch", "No claim forms", "No disappointment",
                "No experience", "No gimmick", "No inventory", "No middleman", "No obligation", "No purchase necessary", 
                "No questions asked", "No selling", "No strings attached", "No-obligation", "Not intended",
                "Obligation", "Off shore", "Offer", "Per day", "Per week", "Priority mail", "Prize", "Prizes", 
                "Produced and sent out", "Reserves the right", "Shopping spree", "Stuff on sale", "Terms and conditions",
                "The best rates", "They’re just giving it away", "Trial", "Unlimited", "Unsolicited", "Vacation",
                "Vacation offers", "Warranty", "We honor all", "Weekend getaway", "What are you waiting for?", "Who really wins?",
                "Win", "Winner", "Winning", "Won", "You are a winner!", "You have been selected", "You’re a Winner!",
            )
        ),

        "Calls-to-Action" : (
            "",
            (
                "Cancel at any time", "Compare", "Copy accurately", "Get", "Give it away", "Print form signature", 
                "Print out and fax", "See for yourself", "Sign up free today",
            )
        ),

        "Free" : (
            "",
            (
                "Free", "Free access", "Free cell phone", "Free consultation", "Free DVD", "Free gift", "Free grant money",
                "Free hosting", "Free installation", "Free Instant", "Free investment", "Free leads", "Free membership",
                "Free money", "Free offer", "Free preview", "Free priority mail", "Free quote", "Free sample",
                "Free trial", "Free website",
            )
        ),

        "Descriptions/Adjectives" : (
            "",
            (
                "All natural", "All new", "Amazing", "Certified", "Congratulations", "Drastically reduced", "Fantastic deal",
                "For free", "Guaranteed", "It’s effective", "Outstanding values", "Promise you", "Real thing",
                "Risk free", "Satisfaction guaranteed",
            )
        ),

        "Sense of Urgency" : (
            "",
            (
                "Access", "Act now!", "Apply now", "Apply online", "Call free", "Call now", "Can't live without", "Do it today",
                "Don't delete", "Don't hesitate", "For instant access", "For Only", "For you", "Get it now", "Get started now",
                "Great offer", "Info you requested", "Information you requested", "Instant", "Limited time", "New customers only",
                "Now", "Now only", "Offer expires", "Once in lifetime", "One time", "Only", "Order now", "Order today",
                "Please read", "Special promotion", "Supplies are limited", "Take action now", "Time limited", "Urgent",
                "While supplies last",
            )
        ),

        "Nouns" : (
            "",
            (
                "Addresses on CD", "Beverage", "Bonus", "Brand new pager", "Cable converter", "Casino", "Celebrity",
                "Copy DVDs", "Laser printer", "Legal", "Luxury car", "New domain extensions", "Phone", "Rolex", "Stainless steel"
            )
        )
    }

    #
    # This list is imperfect - it was gathered from multiple sources all around the internet.
    # By no means it represents actual HTML tags whitelist used by any vendor
    #
    # https://help.zapier.com/hc/en-us/articles/8496101927181-What-HTML-tags-are-supported-in-Gmail-#supported-html-tags-0-0
    # https://helpdesk.bitrix24.com/open/14099114/
    # https://www.outlook-apps.com/html-ignored-by-outlook/
    # https://www.caniemail.com/search/
    #
    SupportedHTMLTags = (
        'a', 'b', 'br', 'big', 'blockquote', 'caption', 'code', 'del', 'div', 'dt', 'dd', 'font', 'h1', 'h2', 'h3', 'h4', 'h5', 
        'h6', 'hr', 'i', 'img', 'ins', 'li', 'map', 'ol', 'p', 'pre', 's', 'small', 'strong', 'span', 'sub', 'sup', 'table', 
        'tbody', 'td', 'tfoot', 'th', 'thead', 'tr', 'u', 'ul', 'php', 'html', 'head', 'body', 'meta', 'title', 'style', 'link', 
        'abbr', 'acronym', 'address', 'area', 'bdo',
    )

    # Based on the following:
    #   https://medium.com/@ranadeepbhuyan/supported-html-tags-in-common-email-clients-2cc11e1ae283
    SupportedHTMLTagsAndRelatedAttribs = {
        'a': ('href', 'title', 'name', 'style', 'id', 'class', 'shape', 'coords', 'alt', 'target'),
        'b': ('style', 'id', 'class'),
        'br': ('style', 'id', 'class'),
        'big': ('style', 'id', 'class'),
        'blockquote': ('title', 'style', 'id', 'class'),
        'caption': ('style', 'id', 'class'),
        'code': ('style', 'id', 'class'),
        'del': ('title', 'style', 'id', 'class'),
        'div': ('title', 'style', 'id', 'class', 'align'),
        'dt': ('style', 'id', 'class'),
        'dd': ('style', 'id', 'class'),
        'font': ('color', 'size', 'face', 'style', 'id', 'class'),
        'h1': ('style', 'id', 'class', 'align'),
        'h2': ('style', 'id', 'class', 'align'),
        'h3': ('style', 'id', 'class', 'align'),
        'h4': ('style', 'id', 'class', 'align'),
        'h5': ('style', 'id', 'class', 'align'),
        'h6': ('style', 'id', 'class', 'align'),
        'hr': ('style', 'id', 'class'),
        'i': ('style', 'id', 'class'),
        'img': ('style', 'id', 'class', 'src', 'alt', 'height', 'width', 'title'),
        'ins': ('title', 'style', 'id', 'class'),
        'li': ('style', 'id', 'class'),
        'map': ('shape', 'coords', 'href', 'alt', 'title', 'style', 'id', 'class', 'name'),
        'ol': ('style', 'id', 'class'),
        'p': ('style', 'id', 'class', 'align'),
        'pre': ('style', 'id', 'class'),
        's': ('style', 'id', 'class'),
        'small': ('style', 'id', 'class'),
        'strong': ('style', 'id', 'class'),
        'span': ('title', 'style', 'id', 'class', 'align'),
        'sub': ('style', 'id', 'class'),
        'sup': ('style', 'id', 'class'),
        'table': ('border', 'width', 'style', 'id', 'class', 'cellspacing', 'cellpadding'),
        'tbody': ('align', 'valign', 'style', 'id', 'class'),
        'td': ('width', 'height', 'style', 'id', 'class', 'align', 'valign', 'colspan', 'rowspan'),
        'tfoot': ('align', 'valign', 'style', 'id', 'class', 'align', 'valign'),
        'th': ('width', 'height', 'style', 'id', 'class', 'colspan', 'rowspan'),
        'thead': ('align', 'valign', 'style', 'id', 'class'),
        'tr': ('align', 'valign', 'style', 'id', 'class'),
        'u': ('style', 'id', 'class'),
        'ul': ('style', 'id', 'class'),
        'php': ('id', ),
        'html': ('xmlns', ),
        'meta': ('content', 'name', 'http-equiv'),
        'style': ('Editor::STYLIST_TAG_ATTR', 'type'),
        'link': ('type', 'rel', 'href'),
    }

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
        self.results['Mail message contained suspicious words']                 = self.testSuspiciousWords()
        self.results['Mail message contained unsupported HTML tags']            = self.testUnsupportedHtmlTags()
        self.results['Mail message contained unsupported HTML attributes']      = self.testUnsupportedHtmlAttribs()

        return {k: v for k, v in self.results.items() if v}

    @staticmethod
    def context(tag, part=''):
        s = str(tag)

        if len(s) < 200:
            return s

        if part == '':
            beg = s[:100]
            end = s[-100:]
        else:
            pos = s.find(part)
            if pos != -1:
                a = pos - 100
                if a < 0: a = 0 
                b = pos + len(part) + 100
                if b > len(s): b = -1
                return f'... {s[a:b]} ...'

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

    def testSuspiciousWords(self):
        desc = '''

Input text message contained words considered as suspicious in context of E-Mails.  
Therefore you will have better chances of delivering your phishing e-mail when you get rid of them.

'''
        context = ''
        result = ''

        text = self.html
        foundWords = set()
        totalChecked = 0
        totalFound = 0

        for title, words in PhishingMailParser.Suspicious_Words.items():
            found = set()

            for word in words[1]:
                if word.lower() in foundWords: 
                    continue

                totalChecked += 1
                if re.search(r'\b' + re.escape(word) + r'\b', text, re.I):
                    found.add(word.lower())

                    foundWords.add(word.lower())
                    pos = text.find(word.lower())

                    if pos != -1:
                        line = ''
                        N = 50
                        if pos > N:
                            line = text[pos-N:pos]

                        line += text[pos:pos+N]
                        pos2 = line.find(word.lower())

                        line = line[:pos2] + logger.colored(line[pos2:pos2+len(word)], "red") + line[pos2+len(word):]
                        line = line.replace('\n', '')
                        line = re.sub(r' {2,}', '  ', line)

                        context += '\n' + line + '\n'

            if len(found) > 0:
                totalFound += len(found)
                result += f'- Found {logger.colored(len(found), "red")} {logger.colored(title, "yellow")} words {logger.colored(words[0], "cyan")}:\n'

                for w in found:
                    result += f'\t- {w}\n'

                result += '\n'

        if totalFound == 0:
            return {}

        result += f'- Found in total {logger.colored(totalFound, "red")} suspicious words (out of {totalChecked} total checked).\n'

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

        desc = 'Links in URLs contained potentially suspicious GET parameters that are known from Phishing platforms or other TA campaigns. They might be noticed by anti-spam filters.'
        context = ''
        result = ''
        num = 0
        embed = ''

        for link in links:
            try:
                href = link['href']
            except:
                continue
        
            text = link.getText().replace('\n', '').strip()
            params = dict(parse.parse_qsl(parse.urlsplit(href).query))

            if len(params) > 0:
                num += 1

                if num < 5:
                    context += PhishingMailParser.context(link) + '\n\n'
                    hr = href
                    pos = hr.find('?')
                    if pos != -1:
                        hr = hr[:pos] + logger.colored(hr[pos:], 'yellow')

                    hr = hr.replace('\n', '').strip()
                    context += f'\thref = "{hr}"\n\n'
                    f = ''
                    for k, v in params.items():
                        f += f'{k}={v[:5]}..., '

                    context += f'\tparams = {f}\n\n'

        if num > 0:
            result += f'- Found {logger.colored(num, "red")} links that contained {logger.colored("potentially dodgy GET parameters", "yellow")}.\n'

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
        
            text = link.getText().replace('\n', '').strip()
            params = dict(parse.parse_qsl(parse.urlsplit(href).query))

            if len(params) > 0:
                num += 1

                if num < 5:
                    context += PhishingMailParser.context(link) + '\n\n'
                    hr = href
                    pos = hr.find('?')
                    if pos != -1:
                        hr = hr[:pos] + logger.colored(hr[pos:], 'yellow')

                    hr = hr.replace('\n', '').strip()
                    context += f'\thref = "{hr}"\n\n'
                    f = ''
                    for k, v in params.items():
                        f += f'{k}={v[:5]}..., '

                    context += f'\tparams = {f}\n\n'

        if num > 0:
            result += f'- Found {logger.colored(num, "red")} <a> tags with href="..." {logger.colored("URLs containing GET params", "yellow")}.\n'
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
            url2 = re.compile(r'((http|https)\:\/\/)[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*')

            m1 = url.match(href)
            m2 = url2.search(text)

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

        x = '<img src="data:image/png;base64,<BLOB>"/>'
        desc = f'Embedded images can increase Spam Confidence Level (SCL) in Office365. Embedded images are those with {logger.colored(x,"yellow")} . They should be avoided.'
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
            result += f'- Found {logger.colored(num, "red")} <img> tags with embedded image ({logger.colored(embed, "yellow")}).\n'
            result +=  '\t  Embedded images increase Office365 SCL (Spam) level!\n'

        if len(result) == 0:
            return []

        return {
            'description' : desc,
            'context' : context,
            'analysis' : result
        }

    def testUnsupportedHtmlTags(self):
        tags = self.soup.find_all()

        desc = f'Mail clients are using HTML rendering engines which might not support certain HTML tags (they strip them for security reasons).'
        context = ''
        result = ''
        num = 0
        embed = ''
        found = set()

        for tag in tags:
            if tag.name.lower() not in PhishingMailParser.SupportedHTMLTags:
                ctx = PhishingMailParser.context(tag)
                pos = ctx.lower().find(f'<{tag.name.lower()}')
                pos2 = ctx.find(' ', pos+1)

                if pos2 == -1:
                    pos2 = ctx.find('>', pos+1)

                ctx = logger.colored(ctx[:pos], 'yellow') + logger.colored(ctx[pos:pos2], 'red') + logger.colored(ctx[pos2:], 'yellow')

                context += ctx + '\n'
                if tag.name.lower() not in found:
                    num += 1
                    found.add(tag.name.lower())

        if num > 0:
            result += f'- Found {logger.colored(num, "red")} potentially unsupported HTML tags in your phishing email.\n'
            result +=  '\t  Be sure to redesign your email so that it doesnt contain these tags.\n\n'
            result +=  '- You can check if these suspicious tags can be used against your target email client by looking here:\n'

            for f in found:
                result += f'\t  - {logger.colored(f, "red")} - https://www.caniemail.com/search/?s={f}\n'

        if len(result) == 0:
            return []

        return {
            'description' : desc,
            'context' : context,
            'analysis' : result
        }
    
    def testUnsupportedHtmlAttribs(self):
        tags = self.soup.find_all()

        desc = f'Mail clients are using HTML rendering engines which might not support certain HTML attributes on specific tags (they strip them for security reasons).'
        context = ''
        result = ''
        num = 0
        embed = ''
        found = set()

        for tag in tags:
            if tag.name.lower() in PhishingMailParser.SupportedHTMLTagsAndRelatedAttribs:
                for k, v in tag.attrs.items():
                    if k.lower() not in PhishingMailParser.SupportedHTMLTagsAndRelatedAttribs[tag.name.lower()]:
                        ctx = PhishingMailParser.context(tag)
                        pos = ctx.lower().find(k.lower())
                        pos2 = pos + len(k.lower())

                        ctx = logger.colored(ctx[:pos], 'yellow') + logger.colored(ctx[pos:pos2], 'red') + logger.colored(ctx[pos2:], 'yellow')
                        #ctx = str(tag)

                        context += ctx + '\n'

                        if k.lower() not in found:
                            num += 1
                            found.add(k.lower())

        if num > 0:
            result += f'- Found {logger.colored(num, "red")} potentially unsupported HTML attributes in your phishing email.\n'
            result +=  '\t  Be sure to redesign your email so that it doesnt contain these attributes.\n\n'
            result +=  '- You can check if these suspicious attributes can be used against your target email client by looking here:\n'

            for f in found:
                result += f'\t  - {logger.colored(f, "red")} - https://www.caniemail.com/search/?s={f}\n'

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
