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
# Mariusz B. / mgeeky, '21
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


DEFAULT_COLUMN_SORTED = 'symbol'

headers = [
    'filename',
    'symbol type',
    'module',
    'symbol',
    'file size',
    'path',
]

symbol_idx = headers.index('symbol')

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

    for name, rex in regexes['not-name']:
        match = rex.search(infos['symbol'])
        if match:
            verbose(args, f'(-) Skipping symbol {infos["module"]}.{infos["symbol"]} as it DID satisfy not-name ({name}) regex.')
            return False

    for name, rex in regexes['not-module']:
        match = rex.search(infos['module'])
        if match:
            verbose(args, f'(-) Skipping symbol\'s module {infos["module"]}.{infos["symbol"]} as it DID satisfy not-module ({name}) regex.')
            return False

    satisifed = False
    carryOn = False

    if len(regexes['module']) > 0:
        for name, rex in regexes['module']:
            match = rex.search(infos['module'])
            if match:
                verbose(args, f'(+) Symbol\'s module {infos["module"]}.{infos["symbol"]} satisfied module ({name}) regex.')
                carryOn = True
                break
    else:
        carryOn = True

    if carryOn:
        for name, rex in regexes['name']:
            match = rex.search(infos['symbol'])
            if match:
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
        
            if appendRow:
                row = []
                MaxWidth = 80

                for h in headers:
                    obj = None

                    if type(infos[h]) == set or type(infos[h]) == list or type(infos[h]) == tuple:
                        obj = ', '.join(infos[h])
                    else:
                        obj = infos[h]

                    if type(obj) == str and len(obj) > MaxWidth:
                        obj = '\n'.join(textwrap.wrap(obj, width = MaxWidth))

                    row.append(obj)

                results.append(row)
                uniqueSymbols.append(symbolName)

                #verbose(args, 'Processed results:\n' + pprint.pformat(infos))

            else:
                verbose(args, f'Symbol {symbolModule}.{symbolName} did not met filter criterias.')

        elif args.format == 'json':
            appendRow = verifyCriterias(args, regexes, infos, uniqueSymbols)
        
            if appendRow:
                results.append(row)
                uniqueSymbols.append(symbolName)

                #verbose(args, 'Processed results:\n' + pprint.pformat(infos))

            else:
                verbose(args, f'Symbol {symbolModule}.{symbolName} did not met filter criterias.')

    filesProcessed.value += 1
    symbolsProcessed.value += len(symbols)

def trap_handler(signum, frame):
    out('[-] CTRL-C pressed. Wait a minute until all processes wrap up.')

def init_worker():
    signal.signal(signal.SIGINT, trap_handler)

def processDir(args, regexes, path, results, uniqueSymbols, filesProcessed, symbolsProcessed):
    filePaths = []

    for file in glob.glob(os.path.join(path, '**'), recursive=args.recurse):
        if os.path.isfile(file):
            looks_like_pe = False
            with open(file, 'rb') as f:
                mz = f.read(2)
                if len(mz) == 2:
                    looks_like_pe = (mz[0] == ord('M') and mz[1] == ord('Z')) or (mz[1] == ord('M') and mz[0] == ord('Z'))

            if looks_like_pe: filePaths.append(file)

    cpu_count = multiprocessing.cpu_count()

    pool = Pool(cpu_count, initializer=init_worker)

    try:
        arguments = [[args, regexes, _path, results, uniqueSymbols, filesProcessed, symbolsProcessed] for _path in filePaths]

        out(f'[.] Will scan {len(filePaths)} files...')
        res = pool.map(processFileWorker, arguments)

    except KeyboardInterrupt:
        out(f'[-] User interrupted the scan after {filesProcessed.value} files.')
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

    sorting = params.add_argument_group('Output sorting')
    sorting.add_argument('-u', '--unique', action='store_true', help = 'Return unique symbols only. The first symbol with a name that occurs in results, will be returned.')
    sorting.add_argument('-d', '--descending', action='store_true', help = 'Sort in descending order instead of default of descending.')
    sorting.add_argument('-c', '--column', default=DEFAULT_COLUMN_SORTED, choices=headers, metavar='COLUMN', help = 'Sort by this column name. Default: filename. Available columns: "' + '", "'.join(headers) + '"')
    sorting.add_argument('-n', '--first', type=int, default=0, metavar='NUM', help='Show only first N results, as specified in this paremeter. By default will show all candidates.')

    filters = params.add_argument_group('Output filtering')
    sorting.add_argument('-i', '--imports', action='store_true', help = 'Filter only Imports.')
    sorting.add_argument('-e', '--exports', action='store_true', help = 'Filter only Exports.')
    filters.add_argument('-s', '--name', action='append', default=[], help = 'Search for symbols with name matching this regular expression. Can be repeated, case insensitive, constructs: ".+VALUE.+"')
    filters.add_argument('-S', '--not-name', action='append', default=[], help = 'Search for symbols with name NOT matching this regular expression.')
    filters.add_argument('-m', '--module', action='append', default=[], help = 'Search for symbols exported in/imported from this module matching regular expression.')
    filters.add_argument('-M', '--not-module', action='append', default=[], help = 'Search for symbols NOT exported in/NOT imported from this module matching regular expression.')
    
    args = params.parse_args()

    if args.imports and args.exports:
        out('[!] --imports and --exports are mutually exclusive. Pick only one of them!')
        sys.exit(1)

    accomodate_rex = lambda x: x

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

    return args, regexes

def main():
    results = Manager().list()
    uniqueSymbols = Manager().list()
    filesProcessed = Manager().Value('i', 0)
    symbolsProcessed = Manager().Value('i', 0)

    out('''
    :: scanSymbols.py - Searches PE Import/Exports based on supplied conditions.
    
    Mariusz B. / mgeeky, '21
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
        print(json.dumps(resultsList, indent=4))

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

            print(table)

            if args.first > 0:
                out(f'\n[+] Found {len(resultsList)} symbols meeting all the criterias (but shown only first {args.first} ones).\n')
            else:
                out(f'\n[+] Found {len(resultsList)} symbols meeting all the criterias.\n')

        else:
            out(f'[-] Did not find symbols meeting specified criterias.')

        out(f'[.] Processed {filesProcessed.value} files and {symbolsProcessed.value} symbols.')
        out('[.] Time elapsed: {}'.format(time_elapsed))

if __name__ == '__main__':
    freeze_support()
    main()