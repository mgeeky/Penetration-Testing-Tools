#!/usr/bin/python3
#
# This script takes an input file containing Node names to be marked in Neo4j database as
#   owned = True. The strategy for working with neo4j and Bloodhound becomes fruitful during
# complex Active Directory Security Review assessments or Red Teams. Imagine you've kerberoasted 
# a number of accounts, access set of workstations or even cracked userPassword hashes. Using this
# script you can quickly instruct Neo4j to mark that principals as owned, which will enrich your
# future use of BloodHound.
#
# Mariusz B. / mgeeky
#

import sys
import os
import time
try:
    from neo4j import GraphDatabase
except ImportError:
    print('[!] "neo4j >= 1.7.0" required. Install it with: python3 -m pip install neo4j')

#
# ===========================================
#

# Specify neo4j connection details
NEO4J_CONNECTION_DETAILS = \
{
    'Host': '127.0.0.1',    # neo4j listening address.
    'Port': 7687,           # Bolt port
    'User': 'neo4j',
    'Pass': 'neo4j1'
}

#
# ===========================================
#

#
# Construct a MATCH ... SET owned=TRUE query of not more than this number of nodes.
# This number impacts single query execution time. If it is more than 1000, neo4j may complain
# about running out of heap memory space (java...).
#
numberOfNodesToAddPerStep = 500

def markNodes(tx, nodes):
    query = ''

    for i in range(len(nodes)):
        n = nodes[i]
        query += 'MATCH (n {name: "' + n + '"}) SET n.owned=TRUE RETURN 1'
        if i < len(nodes) - 1: query += ' UNION'
        query += '\n'

    tx.run(query)

def main(argv):
    if len(argv) != 2:
        print('''
    Takes a file containing node names on input and marks them as Owned in specified neo4j database.     

Usage:  ./markOwnedNodesInNeo4j.py <nodes-file>
''')
        return False

    nodesFile = argv[1]
    programStart = time.time()

    if not os.path.isfile(nodesFile):
        print(f'[!] Input file containing nodes does not exist: "{nodesFile}"!')
        return False

    nodes = []
    with open(nodesFile) as f: nodes = [x.strip() for x in f.readlines()]

    try:
        driver = GraphDatabase.driver(
            f"bolt://{NEO4J_CONNECTION_DETAILS['Host']}:{NEO4J_CONNECTION_DETAILS['Port']}",
            auth = (NEO4J_CONNECTION_DETAILS['User'], NEO4J_CONNECTION_DETAILS['Pass']),
            encrypted = False,
            connection_timeout = 10,
            max_retry_time = 5,
            keep_alive = True
        )
    except Exception as e:
        print(f'[-] Could not connect to the neo4j database. Reason: {str(e)}')
        return False

    print('[.] Connected to neo4j instance.')

    if len(nodes) >= 200:
        print('[*] Warning: Working with a large number of nodes may be time-consuming in large databases.')
        print('\te.g. setting 1000 nodes as owned can take up to 10 minutes easily.')
        print()

    finishEta = 0.0
    totalTime = 0.0
    runs = 0

    print('[+] To be marked: {} nodes.'.format(len(nodes)))

    try:
        with driver.session() as session:
            for a in range(0, len(nodes), numberOfNodesToAddPerStep):
                b = a + min(numberOfNodesToAddPerStep, len(nodes) - a)
                print(f'[.] Marking nodes ({a}..{b}) ...')
                start = time.time()
                session.write_transaction(markNodes, nodes[a:b])
                stop = time.time()

                totalTime += (stop - start)
                runs += 1

                finishEta = ((len(nodes) / numberOfNodesToAddPerStep) - runs) * (totalTime / float(runs))
                if finishEta < 0: finishEta = 0

                print(f'[+] Marked {b-a} nodes in {stop - start:.3f} seconds. Finish ETA: in {finishEta:.3f} seconds.')

    except KeyboardInterrupt:
        print('[.] User interruption.')
        driver.close()
        return False

    driver.close()
    programStop = time.time()
    print(f'\n[+] Nodes marked as owned successfully in {programStop - programStart:.3f} seconds.')

if __name__ == '__main__':
    main(sys.argv)
