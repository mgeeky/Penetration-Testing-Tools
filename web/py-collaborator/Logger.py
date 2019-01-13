import sys

class Logger:
    @staticmethod
    def _out(x):
        sys.stderr.write(str(x) + u'\n')

    @staticmethod
    def dbg(x):
        sys.stderr.write(u'[dbg] ' + str(x) + u'\n')

    @staticmethod
    def out(x):
        Logger._out(u'[.] ' + str(x))

    @staticmethod
    def info(x):
        Logger._out(u'[?] ' + str(x))

    @staticmethod
    def err(x):
        sys.stderr.write(u'[!] ' + str(x) + u'\n')

    @staticmethod
    def warn(x):
        Logger._out(u'[-] ' + str(x))

    @staticmethod
    def ok(x):
        Logger._out(u'[+] ' + str(x))
