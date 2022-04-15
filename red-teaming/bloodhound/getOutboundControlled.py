#!/usr/bin/python3
#
# getOutboundControlled.py
#
# Collects first-degree and group-delegated outbound controlled objects number based on input node names list.
#
# Mariusz Banach / mgeeky
#

import sys
import os
import time
import math

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

try:
    from neo4j import GraphDatabase
except ImportError:
    print('[!] "neo4j >= 1.7.0" required. Install it with: python3 -m pip install neo4j')

#
# ===========================================
#

config = {
    'host': 'bolt://localhost:7687',
    'user': 'neo4j',
    'pass': 'neo4j1',
    'output' : '',
    'include_group_delegated' : False
}

#
# ===========================================
#

nodesToCheckPerStep = 10

columns1 = 'name,outbound_first_degree'
columns2 = 'name,outbound_first_degree,outbound_group_delegated'

query_first_degree_outbound = '''
MATCH p=(u)-[r1]->(n) WHERE r1.isacl=true AND (__CONDITION__)
WITH u.name as name, COUNT(DISTINCT(n)) as controlled 
RETURN name, controlled 
'''

query_group_delegated_outbound = '''
MATCH p=(u)-[r1:MemberOf*1..]->(g:Group)-[r2]->(n) WHERE r2.isacl=true AND (__CONDITION__)
WITH u.name as name, COUNT(DISTINCT(n)) as controlled
RETURN name, controlled 
'''

results = {}

def checkNodes(tx, nodes):
    global results

    conditionList = []

    for node in nodes:
        conditionList.append(f'u.name = "{node}"')

        if node not in results.keys():
            results[node] = {
                'name' : node,
                'first-degree' : 0,
                'group-delegated': 0,
            }

    condition = ' OR '.join(conditionList)
    interimResults = {}

    for node in nodes:
        interimResults[node] = {
            'name' : node,
            'first-degree' : 0,
            'group-delegated' : 0,
        }
    
    # first-degree
    query = query_first_degree_outbound.replace('__CONDITION__', condition).strip().replace('\t', ' ').replace('\n', ' ')
    result1 = list(tx.run(query))

    for result in result1:
        interimResults[result['name']]['first-degree'] = result['controlled']

    if config['include_group_delegated']:
        # group delegated
        query = query_group_delegated_outbound.replace('__CONDITION__', condition).strip().replace('\t', ' ').replace('\n', ' ')
        result2 = list(tx.run(query))

        for result in result2:
            interimResults[result['name']]['group-delegated'] = result['controlled']

    results.update(interimResults)

    if len(config['output']) > 0:
        output = ''

        for k, v in interimResults.items():
            if config['include_group_delegated']:
                output += f"{v['name']},{v['first-degree']},{v['group-delegated']}\n"
            else:
                output += f"{v['name']},{v['first-degree']}\n"

        with open(config['output'], 'a') as f:
            f.write(output)

def log(x):
    sys.stderr.write(x + '\n')

def opts(args):
    global config
    parser = ArgumentParser(description = 'getOutboundControlled.py - collects first-degree and group-delegated outbound controlled objects number based on input node names list.', formatter_class = ArgumentDefaultsHelpFormatter)
    parser.add_argument('-H', '--host', dest = 'host', help = 'Neo4j BOLT URI', default = 'bolt://localhost:7687')
    parser.add_argument('-u', '--user', dest = 'user', help = 'Neo4j User', default = 'neo4j')
    parser.add_argument('-p', '--password', dest = 'pass', help = 'Neo4j Password', default = 'neo4j1')
    parser.add_argument('-g', '--include-group-delegated', dest = 'include_group_delegated', action='store_true', help = 'To optimize time the script by default only computes number of first-degree outbound controlled objects. Use this option to include in final results also group-delegated numbers (takes considerable time to evaluate!)')
    parser.add_argument('-o', '--output', dest = 'output', help = 'Write output to CSV file specified by this path.', default = '<stdout>')

    parser.add_argument('nodesList', help = 'Path to file containing list of node names to check. Lines starting with "#" will be skipped.')
    
    arguments = parser.parse_args()
    config.update(vars(arguments))

    return arguments

def main(argv):
    if len(argv) < 2:
        print('''
Takes a file containing node names on input and computes number of Outbound controlled objects by those nodes.

Usage:  ./getOutboundControlled.py [options] <nodes-file>
''')
        return False

    args = opts(argv)

    nodesFile = args.nodesList

    programStart = time.time()

    if not os.path.isfile(nodesFile):
        log(f'[!] Input file containing nodes does not exist: "{nodesFile}"!')
        return False

    nodes = []
    with open(nodesFile) as f: 
        for x in f.readlines():
            if x.strip().startswith('#'):
                continue

            if not '@' in x:
                raise Exception('Node names must include "@" and be in form: NAME@DOMAIN !')
            nodes.append(x.strip())

    try:
        driver = GraphDatabase.driver(
            config['host'],
            auth = (config['user'], config['pass']),
            encrypted = False,
            connection_timeout = 10,
            keep_alive = True
        )
    except Exception as e:
        log(f'[-] Could not connect to the neo4j database. Reason: {str(e)}')
        return False

    finishEta = 0.0
    totalTime = 0.0
    runs = 0

    try:
        with driver.session() as session:

            log('[+] Connected to database. Working...')
            output = ''

            if config['include_group_delegated']:
                output = columns2 + '\n'
            else:
                output = columns1 + '\n'

            with open(config['output'], 'w') as f:
                f.write(output)

            for a in range(0, len(nodes), nodesToCheckPerStep):
                b = a + min(nodesToCheckPerStep, len(nodes) - a)

                start = time.time()
                checkNodes(session, nodes[a:b])
                stop = time.time()

                totalTime += (stop - start)
                runs += 1

                finishEta = ((len(nodes) / nodesToCheckPerStep) - runs) * (totalTime / float(runs))

                if finishEta < 0: 
                    finishEta = 0

                log(f'[+] Checked {b}/{len(nodes)} nodes in {stop - start:.3f} seconds. Finish ETA: in {finishEta:.3f} seconds.')

    except KeyboardInterrupt:
        log('[.] User interrupted.')
        driver.close()
        return False

    driver.close()
    programStop = time.time()

    log(f'\n[+] Nodes checked in {programStop - programStart:.3f} seconds.')

    if config['output'] == '':
        for k, v in results.items():
            if config['include_group_delegated']:
                output += f"{v['name']},{v['first-degree']},{v['group-delegated']}\n"
            else:
                output += f"{v['name']},{v['first-degree']}\n"

        print(output)
    else:
        log(f'[+] Finished. Results written to file:\n\t{config["output"]}')

if __name__ == '__main__':
    main(sys.argv)
