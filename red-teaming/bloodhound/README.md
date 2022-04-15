## Bloodhound related utilities & scripts

- **`getOutboundControlled.py`** - Takes list of node names on input (must be in `NAME@DOMAIN` form) and for each node computes number of first-degree outbound controlled (or also number of group-delegated outbound controlled if specified so), then prints output CSV table containing these results. Handy to estimate number of outbound controlled objects through compromise of an input list of users.

```
$ py ./getOutboundControlled.py -o affected-users-outbound.csv affected-users.txt
[+] Connected to database. Working...
[+] Checked 5/1282 nodes in 7.381 seconds. Finish ETA: in 1885.190 seconds.
[+] Checked 10/1282 nodes in 5.259 seconds. Finish ETA: in 1607.888 seconds.
[+] Checked 15/1282 nodes in 7.204 seconds. Finish ETA: in 1676.210 seconds.
[+] Checked 20/1282 nodes in 7.152 seconds. Finish ETA: in 1703.490 seconds.
[+] Checked 25/1282 nodes in 6.109 seconds. Finish ETA: in 1664.574 seconds.
...
```

- **`markNodesOwned.py`** - This script takes an input file containing Node names to be marked in Neo4j database as owned = True. The strategy for working with neo4j and Bloodhound becomes fruitful during complex Active Directory Security Review assessments or Red Teams. Imagine you've kerberoasted a number of accounts, access set of workstations or even cracked userPassword hashes. Using this script you can quickly instruct Neo4j to mark that principals as owned, which will enrich your future use of BloodHound.

```bash
$ ./markNodesOwned.py kerberoasted.txt
[.] Connected to neo4j instance.
[.] Marking nodes (0..10) ...
[+] Marked 10 nodes in 4.617 seconds. Finish ETA: in 16.622 seconds.
[.] Marking nodes (10..20) ...
[+] Marked 10 nodes in 4.663 seconds. Finish ETA: in 12.064 seconds.
[.] Marking nodes (20..30) ...
[+] Marked 10 nodes in 4.157 seconds. Finish ETA: in 7.167 seconds.
[.] Marking nodes (30..40) ...
[+] Marked 10 nodes in 4.365 seconds. Finish ETA: in 2.670 seconds.
[.] Marking nodes (40..46) ...
[+] Marked 6 nodes in 2.324 seconds. Finish ETA: in 0 seconds.
[+] Nodes marked as owned successfully in 20.246 seconds.
```
