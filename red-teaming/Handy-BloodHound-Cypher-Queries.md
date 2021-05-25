- Returns computer names and their operating system for statistics purposes
```
MATCH (c:Computer) WHERE c.operatingsystem is not null RETURN c.name as Name, c.operatingsystem as OS
```

- Returns a summary report of machines grouped by their operating systems versions, along with number of machines running specific OS version:
```
MATCH (c:Computer) WHERE c.operatingsystem is not null MATCH (n:Computer {operatingsystem: c.operatingsystem}) RETURN c.operatingsystem as OS, count(distinct n) AS Number ORDER BY Number DESC
```

- Returns non-DC computers that enable unconstrained delegation along with their LDAP DN paths and operating systems.:
```
MATCH (c:Computer {unconstraineddelegation: True}), (g:Group) WHERE g.name starts with 'DOMAIN CONTROLLERS' MATCH (c) WHERE NOT (c)-[:MemberOf]->(g) RETURN c.name, c.distinguishedname, c.operatingsystem
```

- Returns all objects that have SPNs set and checks whether they are allowed to delegate, have admincount set or can be used for unconstrained delegation:
```
MATCH (c {hasspn: True}) RETURN c.name as name, c.allowedtodelegate as AllowedToDelegate, c.unconstraineddelegation as UnconstrainedDelegation, c.admincount as AdminCount, c.serviceprincipalnames as SPNs
```

- Pulls users eligible for ASREP roasting
```
MATCH (u:User {dontreqpreauth: true}) RETURN u
```

- Shortest path from ASREP roastable users to Domain Admins
```
MATCH (A:User {dontreqpreauth: true}), (B:Group), x=shortestPath((A)-[*1..]->(B)) WHERE B.name STARTS WITH 'DOMAIN ADMINS' RETURN x
```

- Pulls users eligible for Kerberoasting
```
MATCH (u:User {hasspn: True}) WHERE NOT u.name starts with 'KRBTGT' RETURN u
```
- Shortest path from Kerberoastable users to Domain Admins
```
MATCH (A:User),(B:Group),p=shortestPath((A)-[*1..]->(B)) WHERE A.hasspn=true AND B.name STARTS WITH 'DOMAIN ADMINS' RETURN p
```

- Pull GPOs linked to users being member of a specified group:
```
MATCH p = (:GPO)-[:GpLink]->(d)-[:Contains*1..]->(u:User)-[:MemberOf*1..]->(g:Group {name:'GROUP_NAME@CONTOSO.LOCAL'}) RETURN p
```

- Return users that have PASSWORD_NOT_REQUIRED flag set in their UserAccountControl field (thus they have an empty password set) and are enabled
```
MATCH (n:User {enabled: True, passwordnotreqd: True}) RETURN n
```

- Find a shortest path from any user that has PASSWORD_NOT_REQUIRED set to Domain Admins group:
```
MATCH (m:User {enabled: True, passwordnotreqd: True}), (n:Group), p = shortestPath((m)-[*1..]->(n)) WHERE n.name STARTS WITH 'DOMAIN ADMINS' RETURN p
```

- Shortest path from any user that has PASSWORD_NOT_REQUIRED set to any computer
```
MATCH (m:User {enabled: True, passwordnotreqd: True}), (n:Computer), p = shortestPath((m)-[*1..]->(n)) RETURN p
```

- Find all users that have userPassword attribute not empty
```
MATCH (u:User) WHERE u.userpassword =~ ".+" RETURN u.name, u.userpassword
```

- Counts unrolled members of Tier-0 privileged AD groups (copy all query lines, as they are UNION ALL joined):
```
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "ENTERPRISE ADMINS" RETURN g.name AS GroupName, count(u) AS MembersCounted UNION ALL
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "DOMAIN ADMINS" RETURN g.name AS GroupName, count(u) AS MembersCounted UNION ALL
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "SCHEMA ADMIN" RETURN g.name AS GroupName, count(u) AS MembersCounted UNION ALL
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "ACCOUNT OPERATORS" RETURN g.name AS GroupName, count(u) AS MembersCounted UNION ALL
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "BACKUP OPERATORS" RETURN g.name AS GroupName, count(u) AS MembersCounted UNION ALL
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "PRINT OPERATORS" RETURN g.name AS GroupName, count(u) AS MembersCounted UNION ALL
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "SERVER OPERATORS" RETURN g.name AS GroupName, count(u) AS MembersCounted UNION ALL
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "DOMAIN CONTROLLERS" RETURN g.name AS GroupName, count(u) AS MembersCounted UNION ALL
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "READ-ONLY DOMAIN CONTROLLERS" RETURN g.name AS GroupName, count(u) AS MembersCounted UNION ALL
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "GROUP POLICY CREATOR OWNERS" RETURN g.name AS GroupName, count(u) AS MembersCounted UNION ALL
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "CRYPTOGRAPHIC OPERATORS" RETURN g.name AS GroupName, count(u) AS MembersCounted UNION ALL
MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "DISTRIBUTED COM USERS" RETURN g.name AS GroupName, count(u) AS MembersCounted
```

- Retrieves nodes having particular juicy keywords in their description properties:
```
MATCH (n) WHERE n.description CONTAINS 'pass' RETURN n.name, n.description UNION 
MATCH (n) WHERE n.description CONTAINS 'secret' RETURN n.name, n.description UNION 
MATCH (n) WHERE n.description CONTAINS 'admin' RETURN n.name, n.description UNION
MATCH (n) WHERE n.description CONTAINS 'sensitive' RETURN n.name, n.description
```

- Show only owned nodes of the above ones:
```
MATCH (n) WHERE n.description CONTAINS 'pass' and n.owned = TRUE RETURN n.name, n.description UNION 
MATCH (n) WHERE n.description CONTAINS 'secret' and n.owned = TRUE RETURN n.name, n.description UNION 
MATCH (n) WHERE n.description CONTAINS 'admin' and n.owned = TRUE RETURN n.name, n.description UNION
MATCH (n) WHERE n.description CONTAINS 'sensitive' and n.owned = TRUE RETURN n.name, n.description UNION
MATCH (n) WHERE n.description CONTAINS '\\' and n.owned = TRUE RETURN n.name, n.description
```

- Retrieves nodes that contain UNC paths to SMB shares in their description fields:
```
MATCH (n) WHERE n.description CONTAINS '\\\\' RETURN n.name, n.description
```

- Returns shortest path from any of owned nodes to any of highvalue nodes:
```
RETURN shortestPath((O:{owned:True})-[*1..]->(H {highvalue: True}))
```

- Find all users that have direct or indirect admin privileges over a computer:
```
MATCH (u:User)-[r:AdminTo|MemberOf*1..]->(c:Computer) RETURN u.name
```

- Returns username and number of computers where it has admin rights to for top 10 users (author: [jeffmcjunkin](https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12) ):
```
MATCH 
(U:User)-[r:MemberOf|:AdminTo*1..]->(C:Computer)
WITH
U.name as n,
COUNT(DISTINCT(C)) as c 
RETURN n,c
ORDER BY c DESC
LIMIT 10
```

- Returns group and number of computers that group has admin rights to - for top 10 groups (author: [jeffmcjunkin](https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12) ):
```
MATCH 
(G:Group)-[r:MemberOf|:AdminTo*1..]->(C:Computer)
WITH
G.name as n,
COUNT(DISTINCT(C)) as c 
RETURN n,c
ORDER BY c DESC
LIMIT 10
```

- Show all users that are administrators on more than one machine (author: [jeffmcjunkin](https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12) ):
```
MATCH 
(U:User)-[r:MemberOf|:AdminTo*1..]->(C:Computer)
WITH
U.name as n,
COUNT(DISTINCT(C)) as c 
WHERE c>1
RETURN n
ORDER BY c DESC
```

- Show all users that are administrative on at least one machine, ranked by the number of machines they are admin on. (author: [jeffmcjunkin](https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12) ):
```
MATCH (u:User)
WITH u
OPTIONAL MATCH (u)-[r:AdminTo]->(c:Computer)
WITH u,COUNT(c) as expAdmin
OPTIONAL MATCH (u)-[r:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(c:Computer)
WHERE NOT (u)-[:AdminTo]->(c)
WITH u,expAdmin,COUNT(DISTINCT(c)) as unrolledAdmin
RETURN u.name,expAdmin,unrolledAdmin,expAdmin + unrolledAdmin as totalAdmin
ORDER BY totalAdmin ASC
```

- Find all other Rights Domain Users shouldn't have (author: [jeffmcjunkin](https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12) ):
```
MATCH p=(m:Group)-[r:Owns|:WriteDacl|:GenericAll|:WriteOwner|:ExecuteDCOM|:GenericWrite|:AllowedToDelegate|:ForceChangePassword]->(n:Computer) WHERE m.name STARTS WITH 'DOMAIN USERS' RETURN p
```

- Riccardo Ancarani's cypher queries (src: [GPOPowerParser](https://github.com/RiccardoAncarani/GPOPowerParser)) useful for any lateral movement insights:
  - Find all the NTLM relay opportunities for computer accounts:
```
MATCH (u1:Computer)-[:AdminTo]->(c1:Computer {signing: false}) RETURN u1.name, c1.name
MATCH (u2)-[:MemberOf*1..]->(g:Group)-[:AdminTo]->(c2 {signing: false}) RETURN u2.name, c2.name
```

  - Find all the users that can RDP into a machine where they have special privileges:
```
MATCH (u:User)-[:CanRDP]->(c:Computer) WITH u,c
OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)-[:CanRDP]->(c) WITH u,c
MATCH (u)-[:CanPrivesc]->(c) RETURN u.name, c.name
```

## CREATE Nodes and Edges

- Add `HasSession` edge for user `ALICE@DOMAIN` being logged onto `COMPUTER@DOMAIN` : 
```
MATCH (A:Computer {name: "COMPUTER@DOMAIN"}) 
MATCH (B:User {name: "ALICE@DOMAIN"})
CREATE (A)-[:HasSession]->(B)
```

- Adds `HasSession` relationship on all domain controllers to Domain Admins group:
```
MATCH (u:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.name starts with "DOMAIN CONTROLLERS" 
MATCH (h:Group) WHERE h.name starts with "DOMAIN ADMINS" 
CREATE (u)-[:HasSession]->(h)
```

- Adds `AdminTo` relationship from User to Computer:
```
MATCH (A:User {name: "ALICE@DOMAIN"})
MATCH (B:Computer {name: "COMPUTER.DOMAIN"})
CREATE (A)-[:AdminTo]->(B)
```

## Other sources of great Cypher Queries:
- Hausec - https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
- Jeffmcjunkin - https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12
- seajaysec - https://gist.github.com/seajaysec/c7f0995b5a6a2d30515accde8513f77d 