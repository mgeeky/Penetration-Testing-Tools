## SQLMap Tamper scripts evaluation against F5 Big-IP ASM WAF

The below table represents results of tests launched against F5 Big-IP ASM WAF appliance in it's XX version of YY and ZZ version of XY

Below names are to be passed to the `--tamper=` parameter of `sqlmap`. 

The column **Violation Rating** represents most dominant rating of topmost 20 Requests observed by F5 in it's `Security>>Event Logs:Application:Requests` view.

The scale is **0-5**.

Tamper script(s) used | Violation Rating
--- | ---
`apostrophemask` | 3-5
`apostrophenullencode` | 4
`appendnullbyte` | 5
`base64encode` | 3
`between` | 4
`bluecoat` | 4
`chardoubleencode` | 4
`charencode` | 4
`charunicodeencode` | 4
`charunicodeescape` | 4
`commalesslimit` | 3-4
`commalessmid` | 4
`concat2concatws` | 4
`equaltolike` | 4
`greatest` | 4
`halfversionedmorekeywords` | 4
`htmlencode` | 4
`ifnull2ifisnull` | 4
`informationschemacomment` | 4
`least` | 4
`lowercase` | 4
`modsecurityversioned` | 4
`modsecurityzeroversioned` | 3-4
`multiplespaces` | 4
**`nonrecursivereplacement`** | **1-3**
`overlongutf8` | 3
`overlongutf8more` | 3
`percentage` | 2
`plus2concat` | 4
`plus2fnconcat` | 4
`randomcase` | 4
`randomcomments` | 2-3
`securesphere` | 4
`space2comment` | 4
`space2dash` | 3-4
**`space2hash`** | **1-3**
`space2morecomment` | 4
**`space2morehash`** | **1**
`space2mssqlblank` | 2-4
`space2mssqlhash` | 4
`space2mysqlblank` | 3-4
`space2mysqldash` | 4
`space2plus` | 3-4
`space2randomblank` | 4
`symboliclogical` | 4
`sp_password` | 4
`unionalltounion` | 4
`unmagicquotes` | 4
`uppercase` | 4
`varnish` | 4
`versionedkeywords` | 2
`versionedmorekeywords` | 4
`xforwardedfor` | 4
`nonrecursivereplacement,space2morehash,space2hash` | 1

---

Among longer combinations:


Tamper script(s) used | Violation Rating
--- | ---
`apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzerovers` | 1
**`between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor`** | **1**
`apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes` | 1
`apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,charunicodeescape,commalesslimit,commalessmid,commentbeforeparentheses,concat2concatws,equaltolike,escapequotes,greatest,halfversionedmorekeywords,htmlencode,ifnull2casewhenisnull,ifnull2ifisnull,informationschemacomment,least,lowercase,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,overlongutf8,overlongutf8more,percentage,plus2concat,plus2fnconcat,randomcase,randomcomments,securesphere,sp_password,space2comment,space2dash,space2hash,space2morecomment,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,symboliclogical,unionalltounion,unmagicquotes,uppercase,varnish,versionedkeywords,versionedmorekeywords,xforwardedfor` | 5

---

The last row represents _all of tamper scripts used at once_ score. It looks like, it's not a good idea to use them all at once. 

From tamper scripts that did best in this evaluation, we can point out:
- `nonrecursivereplacement`
- `space2morehash`
- `space2hash`

Although, they had **not been tested** against actual vulnerability, therefore this evalution does not take in account whether SQLMap was able to attack the vulnerability at all.