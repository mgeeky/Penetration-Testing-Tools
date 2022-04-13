### General

- Counts various Active Directory statistics and weaknesses. Change `contoso.com` to your own domain name or leave it empty (`ENDS WITH ""`) for all domains:
```
MATCH (u:User)                                        WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Users in total" AS what, count(u) AS number UNION ALL
MATCH (u:User {enabled: false})                       WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Disabled Users" AS what, count(u) AS number UNION ALL
MATCH (u:User {enabled: true, allowedtodelegate: true}) WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Enabled Users with Allowed to Delegate" AS what, count(u) AS number UNION ALL
MATCH (u:User {enabled: true, unconstraineddelegation: true}) WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Enabled Users with Unconstrained Delegation" AS what, count(u) AS number UNION ALL
MATCH (u:User {enabled: true, admincount: true})      WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Enabled Users with Admin Count = 1" AS what, count(u) AS number UNION ALL
MATCH (u:User {enabled: true,  hasspn: True})         WHERE toLower(u.name) ENDS WITH "contoso.com" AND NOT u.name STARTS WITH 'KRBTGT' RETURN "Kerberoastable & Enabled Users" AS what, count(u) AS number UNION ALL
MATCH (u:User {enabled: false, hasspn: True})         WHERE toLower(u.name) ENDS WITH "contoso.com" AND NOT u.name STARTS WITH 'KRBTGT' RETURN "Kerberoastable Users" AS what, count(u) AS number UNION ALL
MATCH (u:User {enabled: true, passwordnotreqd: true}) WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Enabled Users with Password Not Required" AS what, count(u) AS number UNION ALL
MATCH (u:User {enabled: true, pwdneverexpires: true}) WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Enabled Users with Password Never Expires" AS what, count(u) AS number UNION ALL
MATCH (u:User {enabled: true, dontreqpreauth: true})  WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Enabled Users with Dont Require Pre-Authentication (ASREP roastable)" AS what, count(u) AS number UNION ALL
MATCH (u:User {enabled: true})                        WHERE toLower(u.name) ENDS WITH "contoso.com" AND u.pwdlastset > 0 AND u.lastlogon > 0 WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.pwdlastset) }) AS pwdlastset, duration.inDays(datetime({ epochSeconds:toInteger(u.pwdlastset) }), date()).days AS days_since_pwdlastset, datetime({ epochSeconds:toInteger(u.lastlogon) }) AS lastlogon, duration.inDays(datetime({ epochSeconds:toInteger(u.lastlogon) }), date()).days AS days_since_lastlogon WHERE days_since_pwdlastset > 90 AND days_since_lastlogon < 7 RETURN "Enabled Users pwdlastset > 90 days and lastlogon < 7 days" AS what, count(name) AS number UNION ALL
MATCH (u:User {enabled: true})                        WHERE toLower(u.name) ENDS WITH "contoso.com" AND u.pwdlastset > 0 AND u.lastlogon > 0 WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.pwdlastset) }) AS pwdlastset, duration.inDays(datetime({ epochSeconds:toInteger(u.pwdlastset) }), date()).days AS days_since_pwdlastset WHERE days_since_pwdlastset > 90 RETURN "Enabled Users pwdlastset > 90 days" AS what, count(name) AS number UNION ALL
MATCH (u:User {enabled: true})                        WHERE toLower(u.name) ENDS WITH "contoso.com" AND u.pwdlastset > 0 AND u.lastlogon > 0 WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.lastlogon) }) AS lastlogon, duration.inDays(datetime({ epochSeconds:toInteger(u.lastlogon) }), date()).days AS days_since_lastlogon WHERE days_since_lastlogon > 90 RETURN "Enabled Users lastlogon > 180 days" AS what, count(name) AS number UNION ALL
MATCH (u:User {enabled: false})                       WHERE toLower(u.name) ENDS WITH "contoso.com" AND u.pwdlastset > 0 AND u.lastlogon > 0 WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.pwdlastset) }) AS pwdlastset, duration.inDays(datetime({ epochSeconds:toInteger(u.pwdlastset) }), date()).days AS days_since_pwdlastset, datetime({ epochSeconds:toInteger(u.lastlogon) }) AS lastlogon, duration.inDays(datetime({ epochSeconds:toInteger(u.lastlogon) }), date()).days AS days_since_lastlogon WHERE days_since_pwdlastset > 90 AND days_since_lastlogon < 7 RETURN "Disabled Users pwdlastset > 90 days and lastlogon < 7 days" AS what, count(name) AS number UNION ALL
MATCH (u:User {enabled: false})                       WHERE toLower(u.name) ENDS WITH "contoso.com" AND u.pwdlastset > 0 AND u.lastlogon > 0 WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.pwdlastset) }) AS pwdlastset, duration.inDays(datetime({ epochSeconds:toInteger(u.pwdlastset) }), date()).days AS days_since_pwdlastset WHERE days_since_pwdlastset > 90 RETURN "Disabled Users pwdlastset > 90 days" AS what, count(name) AS number UNION ALL
MATCH (u:User {enabled: false})                       WHERE toLower(u.name) ENDS WITH "contoso.com" AND u.pwdlastset > 0 AND u.lastlogon > 0 WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.lastlogon) }) AS lastlogon, duration.inDays(datetime({ epochSeconds:toInteger(u.lastlogon) }), date()).days AS days_since_lastlogon WHERE days_since_lastlogon > 90 RETURN "Disabled Users lastlogon > 180 days" AS what, count(name) AS number UNION ALL
MATCH (u:Computer)                                    WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Computers in total" AS what, count(u) AS number UNION ALL
MATCH (u:Group)                                       WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Groups in total" AS what, count(u) AS number UNION ALL
MATCH (u:Domain)                                      WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Domains in total" AS what, count(u) AS number UNION ALL
MATCH (u:OU)                                          WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "OUs in total" AS what, count(u) AS number UNION ALL
MATCH (u:GPO)                                         WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "GPOs in total" AS what, count(u) AS number UNION ALL
MATCH (u {admincount: True})                          WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "adminCount=1" AS what, count(u) AS number UNION ALL
MATCH (u)                                             WHERE toLower(u.name) ENDS WITH "contoso.com" AND u.userpassword =~ ".+" RETURN "userPassword Not Empty" AS what, count(u) AS number UNION ALL
MATCH (u:Computer {unconstraineddelegation: True}), (g:Group) WHERE toLower(u.name) ENDS WITH "contoso.com" AND g.name starts with 'DOMAIN CONTROLLERS' MATCH (u) WHERE (u)-[:MemberOf]->(g) RETURN "Unconstrained Delegation Computers" AS what, count(u) AS number UNION ALL
MATCH (u {owned: true})                               WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "Owned Principals" AS what, count(u) AS number UNION ALL
MATCH (u {highvalue: true})                           WHERE toLower(u.name) ENDS WITH "contoso.com" RETURN "High Value" AS what, count(u) AS number
```

- Returns all objects that have SPNs set and checks whether they are allowed to delegate, have admincount set or can be used for unconstrained delegation:
```
MATCH (c {hasspn: True}) RETURN c.name as name, c.allowedtodelegate as AllowedToDelegate, c.unconstraineddelegation as UnconstrainedDelegation, c.admincount as AdminCount, c.serviceprincipalnames as SPNs
```

### Principals with most Outbound Controlled objects

- Returns Top 100 **Outbound Control Rights** --> **First Degree Object Control** principals in domain:
```
MATCH p=(u)-[r1]->(n) WHERE r1.isacl=true 
WITH u.name as name, LABELS(u)[1] as type, 
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL 
RETURN type, name, controlled 
ORDER BY controlled DESC 
LIMIT 100
```

- Returns Top 100 **Outbound Control Rights** --> **Group Delegated Object Control** principals in domain and whether that object is member of high privileged group (such a `Domain Admins` or `Domain Controllers`):
```
MATCH p=(u)-[r1:MemberOf*1..]->(g:Group)-[r2]->(n) WHERE r2.isacl=true
WITH u.name as name, LABELS(u)[1] as type, g.highvalue as highly_privileged,
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL 
RETURN type, name, highly_privileged, controlled 
ORDER BY controlled DESC 
LIMIT 100
```

- Returns Top 50 **Outbound Control Rights** --> **Transitive Object Control** in domain (TAKES ENORMOUS TIME TO COMPUTE! You were warned):
```
MATCH p=shortestPath((u)-[r1:MemberOf|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n))
WHERE u<>n
WITH u.name as name, LABELS(u)[1] as type, 
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL
RETURN type, name, controlled 
ORDER BY controlled DESC 
LIMIT 50
```

- Returns principals having more than 1000 **Outbound Control Rights** --> **First Degree Object Control** controlled:
```
MATCH p=(u)-[r1]->(n) WHERE r1.isacl=true 
WITH u.name as name, LABELS(u)[1] as type, 
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL AND controlled > 1000
RETURN type, name, controlled 
ORDER BY controlled DESC 
```

- Returns principals having more than 1000 **Outbound Control Rights** --> **Group Delegated Object Control** controlled and whether that object is member of high privileged group (such a `Domain Admins` or `Domain Controllers`):
```
MATCH p=(u)-[r1:MemberOf*1..]->(g:Group)-[r2]->(n) WHERE r2.isacl=true
WITH u.name as name, LABELS(u)[1] as type, g.highvalue as highly_privileged,
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL AND controlled > 1000
RETURN type, name, highly_privileged, controlled 
ORDER BY controlled DESC 
```

- Returns principals having more than 1000 **Outbound Control Rights** --> **Transitive Object Control** controlled (TAKES ENORMOUS TIME TO COMPUTE! You were warned):
```
MATCH p=shortestPath((u)-[r1:MemberOf|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n))
WHERE u<>n
WITH u.name as name, LABELS(u)[1] as type, 
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL AND controlled > 1000
RETURN type, name, controlled 
ORDER BY controlled DESC 
```

### Users

- Enabled Users with Password Last Set > 90 days and Last Logon < 7 days:
```
MATCH (u:User {enabled: true}) WHERE u.pwdlastset > 0 AND u.lastlogon > 0
WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.pwdlastset) }) AS pwdlastset, duration.inDays(datetime({ epochSeconds:toInteger(u.pwdlastset) }), date()).days AS days_since_pwdlastset, datetime({ epochSeconds:toInteger(u.lastlogon) }) AS lastlogon, duration.inDays(datetime({ epochSeconds:toInteger(u.lastlogon) }), date()).days AS days_since_lastlogon
WHERE days_since_pwdlastset > 90 AND days_since_lastlogon < 7
RETURN name, description, days_since_lastlogon, days_since_pwdlastset, pwdlastset, lastlogon
ORDER BY days_since_pwdlastset DESC
```

- Enabled Users with Last Logon earlier than 90 days ago:
```
MATCH (u:User {enabled: true}) WHERE u.lastlogon > 0 
WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.lastlogon) }) AS lastlogon, duration.inDays(datetime({ epochSeconds:toInteger(u.lastlogon) }), date()).days AS days_since_lastlogon
WHERE days_since_lastlogon > 90
RETURN name, description, days_since_lastlogon, lastlogon 
ORDER BY days_since_lastlogon DESC 
```

- Enabled Users with Password Last Set earlier than 90 days ago:
```
MATCH (u:User {enabled: true}) WHERE u.pwdlastset > 0 
WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.pwdlastset) }) AS pwdlastset, duration.inDays(datetime({ epochSeconds:toInteger(u.pwdlastset) }), date()).days AS days_since_pwdlastset
WHERE days_since_pwdlastset > 90
RETURN name, description, days_since_pwdlastset, pwdlastset 
ORDER BY days_since_pwdlastset DESC 
```

- Pulls users eligible for ASREP roasting
```
MATCH (u:User {dontreqpreauth: true}) RETURN u.name, u.displayname, u.description, u.objectid
```

- Shortest path from ASREP roastable users to Domain Admins
```
MATCH (A:User {dontreqpreauth: true}), (B:Group), x=shortestPath((A)-[*1..]->(B)) WHERE B.name STARTS WITH 'DOMAIN ADMINS' RETURN x
```

- Pulls users with `adminCount=1`
```
MATCH (u:User {admincount: True}) WHERE NOT u.name starts with 'KRBTGT' RETURN u.name, u.displayname, u.description, u.objectid
```

- Pulls users with `PasswordNeverExpires` set.
```
MATCH (u:User {pwdneverexpires: True}) WHERE NOT u.name starts with 'KRBTGT' RETURN u.name, u.displayname, u.description, u.objectid
```

- Pulls kerberoastable users with `adminCount=1`
```
MATCH (u:User {admincount: True, hasspn: True}) WHERE NOT u.name starts with 'KRBTGT' RETURN u.name, u.displayname, u.hasspn as Kerberoastable, u.description, u.objectid
```

- Pulls users with `adminCount=1` and displays whether they're Kerberoastable, ASREPRoastable or Owned
```
MATCH (u:User {admincount: True}) WHERE NOT u.name starts with 'KRBTGT' RETURN u.name, u.displayname, u.owned as owned, u.hasspn as Kerberoastable, u.dontreqpreauth as ASREPRoastable, u.description, u.objectid
```

- Pulls users eligible for Kerberoasting
```
MATCH (u:User {hasspn: True}) WHERE NOT u.name starts with 'KRBTGT' RETURN u.name, u.displayname, u.description, u.objectid
```

- Return Kerberoastable users with a path to High Value groups:
```
MATCH p=shortestPath((u:User {hasspn: true})-[r:MemberOf*1..]->(g:Group {highvalue: true})) RETURN u.name AS kerberoastable_user, g.name AS high_value_group, u.displayname AS user_displayname
```

- Shortest path from Kerberoastable users to Domain Admins
```
MATCH (A:User),(B:Group),p=shortestPath((A)-[*1..]->(B)) WHERE A.hasspn=true AND B.name STARTS WITH 'DOMAIN ADMINS' RETURN p
```

- Shortest path from any user that has PASSWORD_NOT_REQUIRED set to any computer
```
MATCH (m:User {enabled: True, passwordnotreqd: True}), (n:Computer), p = shortestPath((m)-[*1..]->(n)) RETURN p
```

- Find all users that have userPassword attribute not empty
```
MATCH (u:User) WHERE u.userpassword =~ ".+" RETURN u.name, u.userpassword, u.displayname, u.description, u.objectid
```

- Return enabled users that have PASSWORD_NOT_REQUIRED flag set in their UserAccountControl field (thus they have an empty password set)
```
MATCH (u:User {enabled: True, passwordnotreqd: True}) RETURN u.name, u.displayname, u.description, u.objectid
```

- Find enabled users not requiring Pre-Authentication (their passwords will be a lot easier to crack):
```
MATCH (u:User {enabled: True, dontreqpreauth: true}) RETURN u.name, u.displayname, u.description, u.objectid
```

- Find a shortest path from any user that has PASSWORD_NOT_REQUIRED set to Domain Admins group:
```
MATCH (m:User {enabled: True, passwordnotreqd: True}), (n:Group), p = shortestPath((m)-[*1..]->(n)) WHERE n.name STARTS WITH 'DOMAIN ADMINS' RETURN p
```

- Find all users that have direct or indirect admin privileges over a computer:
```
MATCH (u:User)-[r:AdminTo|MemberOf*1..]->(c:Computer) RETURN u.name
```

- Find all the users that can RDP into a machine where they have special privileges:
```
MATCH (u:User)-[:CanRDP]->(c:Computer) WITH u,c
OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)-[:CanRDP]->(c) WITH u,c
MATCH (u)-[:CanPrivesc]->(c) RETURN u.name, c.name
```

- Pulls Kerberoastable users and returns their **Outbound Control Rights** --> **First Degree Object Control** in domain:
```
MATCH (u:User {hasspn: True}), p=(u)-[r1]->(n)
WHERE NOT u.name starts with 'KRBTGT' AND r1.isacl=true
WITH u.name as name, LABELS(u)[1] as type, 
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL 
RETURN type, name, controlled 
ORDER BY controlled DESC 
```

- Pulls Kerberoastable users and returns their **Outbound Control Rights** --> **Group Delegated Object Control** in domain and whether that object is member of high privileged group (such a `Domain Admins` or `Domain Controllers`):
```
MATCH (u:User {hasspn: True}), p=(u)-[r1:MemberOf*1..]->(g:Group)-[r2]->(n) 
WHERE NOT u.name starts with 'KRBTGT' AND r2.isacl=true
WITH u.name as name, LABELS(u)[1] as type, g.highvalue as highly_privileged,
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL 
RETURN type, name, highly_privileged, controlled 
ORDER BY controlled DESC 
```

- Pulls Kerberoastable users and returns their **Outbound Control Rights** --> **Transitive Object Control** in domain (TAKES ENORMOUS TIME TO COMPUTE! You were warned):
```
MATCH (u:User {hasspn: True}), p=shortestPath((u)-[r1:MemberOf|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n))
WHERE NOT u.name starts with 'KRBTGT' AND u<>n
WITH u.name as name, LABELS(u)[1] as type, 
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL
RETURN type, name, controlled 
ORDER BY controlled DESC 
```

- Returns username and number of computers where it has admin rights to for top 10 users (author: [jeffmcjunkin](https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12) ):
```
MATCH 
(U:User)-[r:MemberOf|AdminTo*1..]->(C:Computer)
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
(G:Group)-[r:MemberOf|AdminTo*1..]->(C:Computer)
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
(U:User)-[r:MemberOf|AdminTo*1..]->(C:Computer)
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

- Returns shortest path from any of owned nodes to any of highvalue nodes:
```
RETURN shortestPath((O:{owned:True})-[*1..]->(H {highvalue: True}))
```


### Groups

- Find the most privileged groups on the domain (author: [hausec](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/) ):
```
MATCH (g:Group) OPTIONAL MATCH (g)-[:AdminTo]->(c1:Computer) OPTIONAL MATCH (g)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c2:Computer) WITH g, COLLECT(c1) + COLLECT(c2) AS tempVar UNWIND tempVar AS computers RETURN g.name AS GroupName,COUNT(DISTINCT(computers)) AS AdminRightCount ORDER BY AdminRightCount DESC
```

- Find groups with most local admins (either explicit admins or derivative/unrolled) (modified version of query taken from almighty [hausec](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/) ):
```
MATCH (g:Group) WITH g OPTIONAL MATCH (g)-[r:AdminTo]->(c1:Computer) WITH g,COUNT(c1) as explicitAdmins OPTIONAL MATCH (g)-[r:MemberOf*1..]->(a:Group)-[r2:AdminTo]->(c2:Computer) WITH g,explicitAdmins,COUNT(DISTINCT(c2)) as unrolledAdmins where g.name IS NOT NULL AND (explicitAdmins + unrolledAdmins) > 0 RETURN g.name,explicitAdmins,unrolledAdmins, explicitAdmins + unrolledAdmins as totalAdmins ORDER BY totalAdmins DESC
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

### Computers

- Returns enabled computers with PwdLastSet > 30 days and LastLogon < 30 days:
```
MATCH (u:Computer {enabled: true}) WHERE u.pwdlastset > 0 AND u.lastlogon > 0
WITH u.name AS name, u.description AS description, u.enabled AS enabled, datetime({ epochSeconds:toInteger(u.pwdlastset) }) AS pwdlastset, duration.inDays(datetime({ epochSeconds:toInteger(u.pwdlastset) }), date()).days AS days_since_pwdlastset, datetime({ epochSeconds:toInteger(u.lastlogon) }) AS lastlogon, duration.inDays(datetime({ epochSeconds:toInteger(u.lastlogon) }), date()).days AS days_since_lastlogon
WHERE days_since_pwdlastset > 30 AND days_since_lastlogon < 30
RETURN name, description, days_since_lastlogon, days_since_pwdlastset, pwdlastset, lastlogon
ORDER BY days_since_pwdlastset DESC
```

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

- Riccardo Ancarani's cypher queries (src: [GPOPowerParser](https://github.com/RiccardoAncarani/GPOPowerParser)) useful for any lateral movement insights:
  - Find all the NTLM relay opportunities for computer accounts:
```
MATCH (u1:Computer)-[:AdminTo]->(c1:Computer {signing: false}) RETURN u1.name, c1.name
MATCH (u2)-[:MemberOf*1..]->(g:Group)-[:AdminTo]->(c2 {signing: false}) RETURN u2.name, c2.name
```

### GPOs

- Print GPO names and their container paths:
```
MATCH (n:GPO) return n.name,n.gpcpath
```

- Pull GPOs linked to users being member of a specified group:
```
MATCH p = (:GPO)-[:GpLink]->(d)-[:Contains*1..]->(u:User)-[:MemberOf*1..]->(g:Group {name:'GROUP_NAME@CONTOSO.LOCAL'}) RETURN p
```

- Print GPOs with interesting words in their names along with their container paths:
```
unwind ["360totalsecurity", "access", "acronis", "adaware", "admin", "admin", "aegislab", "ahnlab", "alienvault", "altavista", "amsi", "anti-virus", "antivirus", "antiy", "apexone", "applock", "arcabit", "arcsight", "atm", "atp", "av", "avast", "avg", "avira", "baidu", "baiduspider", "bank", "barracuda", "bingbot", "bitdefender", "bluvector", "canary", "carbon", "carbonblack", "certificate", "check", "checkpoint", "citrix", "clamav", "code42", "comodo", "countercept", "countertack", "credential", "crowdstrike", "custom", "cyberark", "cybereason", "cylance", "cynet360", "cyren", "darktrace", "datadog", "defender", "druva", "drweb", "duckduckbot", "edr", "egambit", "emsisoft", "encase", "endgame", "ensilo", "escan", "eset", "exabot", "exception", "f-secure", "f5", "falcon", "fidelis", "fireeye", "firewall", "fix", "forcepoint", "forti", "fortigate", "fortil", "fortinet", "gdata", "gravityzone", "guard", "honey", "huntress", "identity", "ikarussecurity", "insight", "ivanti", "juniper", "k7antivirus", "k7computing", "kaspersky", "kingsoft", "kiosk", "laps", "lightcyber", "logging", "logrhythm", "lynx", "malwarebytes", "manageengine", "mass", "mcafee", "microsoft", "mj12bot", "msnbot", "nanoav", "nessus", "netwitness", "office365", "onedrive", "orion", "palo", "paloalto", "paloaltonetworks", "panda", "pass", "powershell", "proofpoint", "proxy", "qradar", "rdp", "rsa", "runasppl", "sandboxe", "sap", "scanner", "scanning", "sccm", "script", "secret", "secureage", "secureworks", "security", "sensitive", "sentinel", "sentinelone", "slurp", "smartcard", "sogou", "solarwinds", "sonicwall", "sophos", "splunk", "superantispyware", "symantec", "tachyon", "temporary", "tencent", "totaldefense", "transfer", "trapmine", "trend micro", "trendmicro", "trusteer", "trustlook", "uac", "vdi", "virusblokada", "virustotal", "virustotalcloud", "vpn", "vuln", "webroot", "whitelist", "wifi", "winrm", "workaround", "yubikey", "zillya", "zonealarm", "zscaler"] as word match (n:GPO) where toLower(n.name) CONTAINS toLower(word) RETURN word, n.name, n.description, n.gpcpath ORDER BY n.name
```


### OUs

- Returns a list of OUs along with their members count (source: [hausec.com](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/) )
```
MATCH (o:OU)-[:Contains]->(c) RETURN o.name,o.guid, COUNT(c) ORDER BY COUNT(c) DESC
```

### Other


- Retrieves nodes having particular juicy keywords in their name or description properties:
```
UNWIND ["admin", "amministratore", "contrase", "empfidlich", "geheim", "hasło", "important", "azure", "MSOL", "Kennwort", "parol", "parola", "pass", "passe", "secret", "secreto", "segreto", "sekret", "sensibil", "sensibile", "sensible", "sensitive", "wrażliw"] AS word MATCH (n) WHERE (toLower(n.name) CONTAINS toLower(word)) OR (toLower(n.description) CONTAINS toLower(word)) RETURN word, n.name, n.description ORDER BY n.name
```

- Retrieves nodes that contain UNC paths to SMB shares in their description fields:
```
MATCH (n) WHERE n.description CONTAINS '\\\\' RETURN n.name, n.description
```

- Print **Security Solutions** (think SIEM, EDRs, AVs, Anomaly detection systems, etc) deployed in the company by searching for keywords in _name, description, distinguishedname_ of all objects (User, Group, Computer, OU, ...)
```
UNWIND ["360totalsecurity", "acronis", "adaware", "aegislab", "ahnlab", "alienvault", "altavista", "anti-virus", "antivirus", "antiy", "apexone", "arcabit", "arcsight", "attivo", "avast", "avg", "avira", "baidu", "baiduspider", "barracuda", "bingbot", "bitdefender", "bitdefender", "bluecoat", "bluvector", "canary", "carbon", "carbonblack", "carbonblack", "check", "checkpoint", "clamav", "code42", "comodo", "cortex", "countercept", "countertack", "crowdstrike", "cyberark", "cybereason", "cylance", "cynet360", "cyren", "darktrace", "datadog", "defender", "druva", "drweb", "duckduckbot", "edr", "egambit", "emsisoft", "encase", "endgame", "ensilo", "escan", "eset", "exabot", "f-secure", "f5", "falcon", "fidelis", "fireeye", "forcepoint", "fortigate", "fortil", "fortinet", "gdata", "gdata", "gravityzone", "honey", "huntress", "ia_archiver", "ikarussecurity", "ivanti", "juniper", "k7antivirus", "k7computing", "kaspersky", "kingsoft", "lightcyber", "lynx", "malwarebytes", "mcafee", "microsoft", "mj12bot", "morphisec", "msnbot", "nanoav", "nessus", "netwitness", "office365", "palo", "paloalto", "paloaltonetworks", "panda", "proofpoint", "qradar", "sandboxe", "scanner", "scanning", "secureage", "secureworks", "security", "sentinelone", "simplepie", "slurp", "sogou", "solarwinds", "sonicwall", "sophos", "splunk", "superantispyware", "symantec", "tachyon", "tencent", "totaldefense", "trapmine", "trend", "trendmicro", "trusteer", "trustlook", "virus", "virustotal", "virustotalcloud", "webroot", "zillya", "zonealarm", "zscaler"] AS word MATCH (n) WHERE toLower(n.name) CONTAINS toLower(word) OR toLower(n.description) CONTAINS toLower(word) OR toLower(n.distinguishedname) CONTAINS toLower(word) RETURN word as keyword, LABELS(n)[1] as type, n.name, n.description, n.distinguishedname ORDER BY n.name
```

- Find all other Rights Domain Users shouldn't have (author: [jeffmcjunkin](https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12) ):
```
MATCH p=(m:Group)-[r:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(n:Computer) WHERE m.name STARTS WITH 'DOMAIN USERS' RETURN p
```

---

## CREATE Nodes and Edges

- Mark nodes as Owned:
```
MATCH (u) WHERE toLower(u.name) = "user1@contoso.com" SET u.owned RETURN 1 UNION
MATCH (u) WHERE toLower(u.name) = "group2@contoso.com" SET u.owned RETURN 1 UNION
MATCH (u) WHERE toLower(u.name) = "computer3@contoso.com" SET u.owned RETURN 1
```

- Mark High Value all members of High Value groups:
```
MATCH (u)-[:MemberOf]->(n {highvalue: true}) SET u.highvalue = true
```

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

- Authored by **Knavesec** on a #cypher_queries Bloodhound slack: Prints graph paths of the returns yielded by query in `p` variable. Modify the first line to determine paths you would like to be printed (for later grepping, searching). Example:
```
match p=shortestPath((g:Group)-[*1..]->(n {highvalue:true})) where g.objectid ends with "-513"

WITH [node in nodes(p) | coalesce(node.name, '')] as nodeLabels,
     [rel in relationships(p) | type(rel)] as relationshipLabels,
     length(p) as path_len
WITH reduce(path='', x in range(0,path_len-1) | path + nodeLabels[x] + ' - ' + relationshipLabels[x] + ' -> ') as path,
     nodeLabels[path_len] as final_node
return distinct path + final_node as full_path
limit 3
```

Example output:
```
DOMAIN USERS@WINDOMAIN.LOCAL - AdminTo -> SECWWKS1000000.WINDOMAIN.LOCAL - GenericAll -> ELMER_GUERRERO@WINDOMAIN.LOCAL - MemberOf -> DOMAIN CONTROLLERS@WINDOMAIN.LOCAL
DOMAIN USERS@WINDOMAIN.LOCAL - AdminTo -> SECWWKS1000000.WINDOMAIN.LOCAL - GenericAll -> GENARO_PARKER@WINDOMAIN.LOCAL - MemberOf -> GROUP POLICY CREATOR OWNERS@WINDOMAIN.LOCAL
```

---

## Other sources of great Cypher Queries

- Hausec - https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
- Jeffmcjunkin - https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12
- seajaysec - https://gist.github.com/seajaysec/c7f0995b5a6a2d30515accde8513f77d 