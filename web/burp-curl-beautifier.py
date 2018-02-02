#!/usr/bin/python

#
# Simple script for making "Copy as curl command" output in system's clipboard a little nicer\
# To use it:
# - firstly right click on request in BurpSuite
# - select "Copy as curl command"
# - then launch this script.
# As a result, you'll have a bit nicer curl command in your clipboard.
#

try:
	import xerox
except ImportError:
	raise ImportError, "`xerox` library not found. Install it using: `pip install xerox`"
import re

data = xerox.paste()
data = re.sub(r"\s+\\\n\s+", ' ', data, re.M)
data = re.sub('curl -i -s -k\s+-X', 'curl -iskX', data)
if "-iskX 'GET'" in data:
	data = data.replace("-iskX 'GET'", '')
else:
	data = re.sub(r"-iskX '([^']+)' ", r"-iskX \1 ", data)

superfluous_headers = {
	'Upgrade-Insecure-Requests':'', 
	'DNT':'', 
	'User-Agent':'',
	'Content-Type':"application/x-www-form-urlencoded",
	'Referer':'',
}

for k, v in superfluous_headers.items():
	val = v
	if not val:
		val = "[^']+"
	rex = r" -H '" + k + ": " + val + "' "
	m = re.search(rex, data)
	if m:
		data = re.sub(rex, ' ', data)

data = re.sub(r"'(http[^']+)'$", r'"\1"', data)
xerox.copy(data)