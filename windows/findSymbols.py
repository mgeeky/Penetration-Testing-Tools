#!/usr/bin/python3
#
# A script that enumerates Imports and Exports of PE files and prints them according to search criterias.
#
# Let's the user find imported/exported symbols matching criterias such as:
#   - symbol being import or export
#   - symbol matching name
#   - symbol NOT matching name
#   - module matching name
#   - module NOT matching name
#
# Mariusz Banach / mgeeky, '21
# <mb [at] binary-offensive.com>
#

import os
import re
import sys
import glob
import json
import time
import signal
import pprint
import pefile
import tabulate
import platform
import textwrap
import argparse
import tempfile
import subprocess
import multiprocessing

from datetime import datetime 
from itertools import product
from multiprocessing import Pool, Queue, Process, freeze_support, Manager, Lock


DEFAULT_COLUMN_SORTED = 'filename'

headers = [
    'filename',
    'symbol type',
    'module',
    'symbol',
    'file size',
    'path',
]

symbol_idx = headers.index('symbol')

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

    @staticmethod
    def with_color(c, s):
        return "\x1b[%dm%s\x1b[0m" % (c, s)

    @staticmethod
    def end_color(s):
        return "%s\x1b[0m" % (s)

    @staticmethod
    def colored(args, txt, col):
        if not args.color:
            return txt

        return Logger.with_color(Logger.colors_map[col], txt)

def out(x):
    sys.stderr.write(x + '\n')

def verbose(args, x):
    if args.verbose:
        sys.stderr.write('[verbose] ' + x + '\n')

def collectImports(args, mod):
    imports = []
    if not hasattr(mod, 'DIRECTORY_ENTRY_IMPORT') or not mod.DIRECTORY_ENTRY_IMPORT:
        return imports

    try:
        for entry in mod.DIRECTORY_ENTRY_IMPORT:
            module = entry.dll.decode('utf-8').lower()
            for func in entry.imports:
                if not func.name:
                    continue
                func = func.name.decode()
                imports.append(('import', module, func))

    except Exception as e:
        verbose(args, f'Exception occured while collecting PE imports: {e}')

    return imports

def collectExports(args, filename, mod):
    exports = []
    if not hasattr(mod, 'DIRECTORY_ENTRY_EXPORT') or not mod.DIRECTORY_ENTRY_EXPORT:
        return exports

    try:
        for entry in mod.DIRECTORY_ENTRY_EXPORT.symbols:
            if not entry.name:
                continue

            func = entry.name.decode()
            exports.append(('export', os.path.basename(filename), func))

    except Exception as e:
        verbose(args, f'Exception occured while collecting PE exports: {e}')

    return exports

def verifyCriterias(args, regexes, infos, uniqueSymbols):
    if args.unique and infos['symbol'] in uniqueSymbols:
        verbose(args, f'(-) Skipping symbol {infos["module"]}.{infos["symbol"]} because it is not unique in our results.')
        return False

    if args.imports and infos['symbol type'] != 'import':
        verbose(args, f'(-) Skipping symbol {infos["module"]}.{infos["symbol"]} because it was not an import.')
        return False

    if args.exports and infos['symbol type'] != 'export':
        verbose(args, f'(-) Skipping symbol {infos["module"]}.{infos["symbol"]} because it was not an export.')
        return False

    regexesVerified = sum([len(v) for k, v in regexes.items()])

    regexes_name = len(regexes['name'])
    regexes_not_name = len(regexes['not-name'])
    regexes_module = len(regexes['module'])
    regexes_not_module = len(regexes['not-module'])

    for name, rex in regexes['not-name']:
        match = rex.search(infos['symbol'])
        if match:
            matched = match.group(1)
            infos['symbol'] = infos['symbol'].replace(matched, Logger.colored(args, matched, 'red'))
            verbose(args, f'(-) Skipping symbol {infos["module"]}.{infos["symbol"]} as it DID satisfy not-name ({name}) regex.')
            return False

    if regexes_not_module+regexes_module+regexes_name == 0:
        verbose(args, f'(+) Symbol {infos["module"]}.{infos["symbol"]} satisfied all criterias.')
        return True

    for name, rex in regexes['not-module']:
        match = rex.search(infos['module'])
        if match:
            matched = match.group(1)
            infos['module'] = infos['module'].replace(matched, Logger.colored(args, matched, 'red'))
            verbose(args, f'(-) Skipping symbol\'s module {infos["module"]}.{infos["symbol"]} as it DID satisfy not-module ({name}) regex.')
            return False

    if regexes_module+regexes_name == 0:
        verbose(args, f'(+) Symbol {infos["module"]}.{infos["symbol"]} satisfied all criterias.')
        return True

    satisifed = False
    carryOn = False

    if len(regexes['module']) > 0:
        for name, rex in regexes['module']:
            match = rex.search(infos['module'])
            if match:
                matched = match.group(1)
                infos['module'] = infos['module'].replace(matched, Logger.colored(args, matched, 'green'))
                verbose(args, f'(+) Symbol\'s module {infos["module"]}.{infos["symbol"]} satisfied module ({name}) regex.')
                carryOn = True
                break
    else:
        carryOn = True

    if regexes_name == 0:
        verbose(args, f'(+) Symbol {infos["module"]}.{infos["symbol"]} satisfied all criterias.')
        return True

    if carryOn:
        for name, rex in regexes['name']:
            match = rex.search(infos['symbol'])
            if match:
                matched = match.group(1)
                infos['symbol'] = infos['symbol'].replace(matched, Logger.colored(args, matched, 'green'))
                verbose(args, f'(+) Symbol {infos["module"]}.{infos["symbol"]} satisfied name ({name}) regex.')
                satisifed = True
                break

    if regexesVerified == 0 or satisifed:
        verbose(args, f'(+) Symbol {infos["module"]}.{infos["symbol"]} satisfied all criterias.')
        return True
    else:
        verbose(args, f'(-) Skipping symbol {infos["module"]}.{infos["symbol"]} as it DID NOT satisfy all criterias.')
        return False

def processFileWorker(arguments):
    out = None
    try:
        (args, regexes, path, results, uniqueSymbols, filesProcessed, symbolsProcessed) = arguments
        out = processFile(args, regexes, path, results, uniqueSymbols, filesProcessed, symbolsProcessed)
    
    except (KeyboardInterrupt, SystemExit) as e:
        out(e)

    return out

def processFile(args, regexes, path, results, uniqueSymbols, filesProcessed, symbolsProcessed):
    verbose(args, 'Processing file: ' + path)

    mod = None

    try:
        mod = pefile.PE(path, fast_load = True)
        mod.parse_data_directories()

    except:
        mod.close()
        return

    imports = collectImports(args, mod)
    exports = collectExports(args, os.path.basename(path), mod)
    symbols = imports + exports

    mod.close()
    once = False

    for (symbolType, symbolModule, symbolName) in symbols:
        infos = {
            'path' : path,
            'filename' : os.path.basename(path),
            'file size' : os.path.getsize(path),
            'symbol type' : symbolType,
            'symbol' : symbolName,
            'module' : symbolModule,
        }

        if not once:
            assert len(infos.keys()) == len(headers), "headers and infos.keys() mismatch"
            assert list(infos.keys()).sort() == list(headers).sort(), "headers and infos.keys() mismatch while sorted"
            once = True

        if args.format == 'text':
            appendRow = verifyCriterias(args, regexes, infos, uniqueSymbols)

            if args.color:
                if infos['symbol type'] == 'import': 
                    infos['symbol type'] = Logger.colored(args, infos['symbol type'], 'cyan')
                else:
                    infos['symbol type'] = Logger.colored(args, infos['symbol type'], 'yellow')
        
            if appendRow:
                row = []
                MaxWidth = 40

                for h in headers:
                    obj = None

                    if type(infos[h]) == set or type(infos[h]) == list or type(infos[h]) == tuple:
                        obj = ', '.join(infos[h])
                    else:
                        obj = infos[h]

                    if type(obj) == str and len(obj) > MaxWidth:
                        if h == 'path':
                            obj = '\n'.join(textwrap.wrap(obj, width = 2 * MaxWidth))
                        else:
                            obj = '\n'.join(textwrap.wrap(obj, width = MaxWidth))

                    row.append(obj)

                results.append(row)
                uniqueSymbols.append(symbolName)

                #verbose(args, 'Processed results:\n' + pprint.pformat(infos))

            else:
                verbose(args, f'Symbol {symbolModule}.{symbolName} did not met filter criterias.')

        elif args.format == 'json':
            appendRow = verifyCriterias(args, regexes, infos, uniqueSymbols)

            if args.color:
                if infos['symbol type'] == 'import': 
                    infos['symbol type'] = Logger.colored(args, infos['symbol type'], 'cyan')
                else:
                    infos['symbol type'] = Logger.colored(args, infos['symbol type'], 'yellow')
        
            if appendRow:
                results.append(infos)
                uniqueSymbols.append(symbolName)

                #verbose(args, 'Processed results:\n' + pprint.pformat(infos))

            else:
                verbose(args, f'Symbol {symbolModule}.{symbolName} did not met filter criterias.')

    filesProcessed.value += 1
    symbolsProcessed.value += len(symbols)

def trap_handler(signum, frame):
    out('[-] CTRL-C pressed. Wait a minute until all processes wrap up or manually terminate python\'s child processes tree.')

def init_worker():
    signal.signal(signal.SIGINT, trap_handler)

def processDir(args, regexes, path, results, uniqueSymbols, filesProcessed, symbolsProcessed):
    filePaths = []

    out('[.] Building list of files to process...')
    for file in glob.glob(os.path.join(path, '**'), recursive=args.recurse):
        try:
            if len(args.extension) > 0:
                skip = True
                for ext in args.extension:
                    if file.lower().endswith(f'.{ext}'):
                        skip = False
                        break
                if skip:
                    verbose(args, f'[-] Skipping file as it not matched extension ({ext}): {file}')
                    continue

            if os.path.isfile(file):
                looks_like_pe = False
                with open(file, 'rb') as f:
                    mz = f.read(2)
                    if len(mz) == 2:
                        looks_like_pe = (mz[0] == ord('M') and mz[1] == ord('Z')) or (mz[1] == ord('M') and mz[0] == ord('Z'))

                if looks_like_pe: filePaths.append(file)
        
        except Exception as e:
            verbose(args, f'[-] Could not open file: ({file}). Exception: {e}')
            continue

    cpu_count = multiprocessing.cpu_count()

    pool = Pool(cpu_count, initializer=init_worker)

    try:
        arguments = [[args, regexes, _path, results, uniqueSymbols, filesProcessed, symbolsProcessed] for _path in filePaths]

        out(f'[.] Scanning {Logger.colored(args, len(filePaths), "yellow")} files...')
        if len(filePaths) > 5000:
            out(f'[.] Be patient that\'s gonna take a long while...')

        res = pool.map(processFileWorker, arguments)

    except KeyboardInterrupt:
        out(f'[-] User interrupted the scan after {Logger.colored(args, filesProcessed.value, "red")} files.')
        pool.terminate()
        pool.join()

def opts(argv):

    params = argparse.ArgumentParser(
        prog = argv[0], 
        usage='%(prog)s [options] <path>'
    )

    params.add_argument('path', help = 'Path to a PE file or directory.')
    params.add_argument('-r', '--recurse', action='store_true', help='If <path> is a directory, perform recursive scan.')
    params.add_argument('-v', '--verbose', action='store_true', help='Verbose mode.')
    params.add_argument('-f', '--format', choices=['text', 'json'], default='text', help='Output format. Text or JSON.')
    params.add_argument('-E', '--extension', default=[], action='append', help='Extensions of files to scan. By default will scan all files. Can be repeated: -E exe -E dll')
    params.add_argument('-o', '--output', metavar='PATH', help='Write output to file.')
    params.add_argument('-C', '--color', default=False, action='store_true', help='Add colors to text output. May uglify table text output')

    sorting = params.add_argument_group('Output sorting')
    sorting.add_argument('-u', '--unique', action='store_true', help = 'Return unique symbols only. The first symbol with a name that occurs in results, will be returned.')
    sorting.add_argument('-d', '--descending', action='store_true', help = 'Sort in descending order instead of default of descending.')
    sorting.add_argument('-c', '--column', default=DEFAULT_COLUMN_SORTED, choices=headers, metavar='COLUMN', help = 'Sort by this column name. Default: filename. Available columns: "' + '", "'.join(headers) + '"')
    sorting.add_argument('-n', '--first', type=int, default=0, metavar='NUM', help='Show only first N results, as specified in this paremeter. By default will show all candidates.')

    filters = params.add_argument_group('Output filtering')
    filters.add_argument('-i', '--imports', action='store_true', help = 'Filter only Imports.')
    filters.add_argument('-e', '--exports', action='store_true', help = 'Filter only Exports.')
    filters.add_argument('-s', '--name', action='append', default=[], help = 'Search for symbols with name matching this regular expression. Can be repeated, case insensitive')
    filters.add_argument('-S', '--not-name', action='append', default=[], help = 'Search for symbols with name NOT matching this regular expression.')
    filters.add_argument('-m', '--module', action='append', default=[], help = 'Search for symbols exported in/imported from this module matching regular expression.')
    filters.add_argument('-M', '--not-module', action='append', default=[], help = 'Search for symbols NOT exported in/NOT imported from this module matching regular expression.')
    
    args = params.parse_args()

    if args.imports and args.exports:
        out('[!] --imports and --exports are mutually exclusive. Pick only one of them!')
        sys.exit(1)

    accomodate_rex = lambda x: f'({x})'

    regexes = {
        'name': [],
        'not-name': [],
        'module': [],
        'not-module': []
    }

    for name in args.name:
        regexes['name'].append((name, re.compile(accomodate_rex(name), re.I)))

    for not_name in args.not_name:
        regexes['not-name'].append((not_name, re.compile(accomodate_rex(not_name), re.I)))

    for module in args.module:
        regexes['module'].append((module, re.compile(accomodate_rex(module), re.I)))

    for not_module in args.not_module:
        regexes['not-module'].append((not_module, re.compile(accomodate_rex(not_module), re.I)))

    for i in range(len(args.extension)):
        args.extension[i] = args.extension[i].lower()
        if args.extension[i].startswith('.'): 
            args.extension[i] = args.extension[i][1:]

    return args, regexes

def main():
    results = Manager().list()
    uniqueSymbols = Manager().list()
    filesProcessed = Manager().Value('i', 0)
    symbolsProcessed = Manager().Value('i', 0)

    out('''
    :: findSymbols.py - Finds PE Import/Exports based on supplied filters.
    
    Mariusz Banach / mgeeky, '21
    <mb [at] binary-offensive.com> 
''')

    args, regexes = opts(sys.argv)

    is_wow64 = (platform.architecture()[0] == '32bit' and 'ProgramFiles(x86)' in os.environ)

    start_time = datetime.now() 
    try:
        if '\\system32\\' in args.path.lower() and is_wow64:
            verbose(args, 'Redirecting input path from System32 to SysNative as we run from 32bit Python.')
            args.path = args.path.lower().replace('\\system32\\', '\\SysNative\\')

        if os.path.isdir(args.path):
            processDir(args, regexes, args.path, results, uniqueSymbols, filesProcessed, symbolsProcessed)

        else:
            if not os.path.isfile(args.path):
                out(f'[!] Input file does not exist! Path: {args.path}')
                sys.exit(1)

            processFile(args, regexes, args.path, results, uniqueSymbols, filesProcessed, symbolsProcessed)

    except KeyboardInterrupt:
        out(f'[-] User interrupted the scan.')

    time_elapsed = datetime.now() - start_time 

    if args.format == 'json':
        resultsList = list(results)
        dumped = str(json.dumps(resultsList, indent=4))

        if args.output:
            with open(args.output, 'w') as f:
                f.write(dumped)
        else:
            print('\n' + dumped)
    else:
        resultsList = list(results)
        if len(resultsList) > 0:

            idx = headers.index(args.column)

            resultsList.sort(key = lambda x: x[idx], reverse = args.descending)
            headers[idx] = '▼ ' + headers[idx] if args.descending else '▲ ' + headers[idx]

            if args.first > 0:
                for i in range(len(resultsList) - args.first):
                    resultsList.pop()

            table = tabulate.tabulate(resultsList, headers=['#',] + headers, showindex='always', tablefmt='pretty')

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(str(table))
            else:
                print('\n' + table)

            if args.first > 0:
                out(f'\n[+] Found {Logger.colored(args, len(resultsList), "green")} symbols meeting all the criterias (but shown only first {Logger.colored(args, args.first, "magenta")} ones).\n')
            else:
                out(f'\n[+] Found {Logger.colored(args, len(resultsList), "green")} symbols meeting all the criterias.\n')

        else:
            out(f'[-] Did not find symbols meeting specified criterias.')

        out(f'[.] Processed {Logger.colored(args, filesProcessed.value, "green")} files and {Logger.colored(args, symbolsProcessed.value, "green")} symbols.')
        out('[.] Time elapsed: {}'.format(Logger.colored(args, time_elapsed, "magenta")))

if __name__ == '__main__':
    freeze_support()
    main()