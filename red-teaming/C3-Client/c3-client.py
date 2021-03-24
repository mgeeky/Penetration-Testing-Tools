#!/usr/bin/python3

import os
import sys
import re
import time
import json
import requests
import subprocess
import argparse
import random
import string
from datetime import datetime 


config = {
    'verbose' : False,  
    'debug' : False,
    'host' : '',
    'command' : '',
    'format' : 'text',
    'httpauth' : '',
}

commands = {
    'list' : [
        'gateways',
        'relays'
    ],
    'get' : [
        'gateway',
        'relay'
    ]
}

# BackendCommons.h: enum class Command : std::uint16_t
commandsMap = {
    'AddDevice' : 0,
    'Close' : 2**16 - 1,
    'UpdateJitter' : 2**16 - 2,
    'CreateRoute' : 2**16 - 3,
    'RemoveRoute' : 2**16 - 4,
    'SetGRC' : 2**16 - 5,
    'Ping' : 2**16 - 6,
    'ClearNetwork' : 2**16 - 7,
}

headers = {
    'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
}

class Logger:
    @staticmethod
    def _out(x): 
        if config['debug'] or config['verbose']: 
            sys.stdout.write(x + '\n')

    @staticmethod
    def dbg(x):
        if config['debug']: 
            sys.stdout.write('[dbg] ' + x + '\n')

    @staticmethod
    def out(x): 
        Logger._out('[.] ' + x)
    
    @staticmethod
    def info(x):
        Logger._out('[?] ' + x)
    
    @staticmethod
    def err(x): 
        sys.stdout.write('[!] ' + x + '\n')
    
    @staticmethod
    def fatal(x): 
        sys.stdout.write('[!] ' + x + '\n')
        sys.exit(1)
    
    @staticmethod
    def fail(x):
        Logger._out('[-] ' + x)
    
    @staticmethod
    def ok(x):  
        Logger._out('[+] ' + x)

def printJson(data):
    print(json.dumps(data, sort_keys=True, indent=4))

def getRequest(url, rawResp = False):
    auth = None
    if config['httpauth']:
        user, _pass = config['httpauth'].split(':')
        Logger.dbg(f'HTTP Basic Auth: {user}:{_pass}')
        auth = requests.HTTPDigestAuth(user, _pass)

    fullurl = config["host"] + url
    Logger.info(f'GET Request: {fullurl}')

    resp = requests.get(fullurl, headers=headers, auth=auth)
    if rawResp:
        return resp

    try:
        ret = resp.json()
    except:
        ret = resp.text

    return ret

def postRequest(url, data=None, contentType = 'application/json', rawResp = False):
    auth = None
    if config['httpauth']:
        user, _pass = config['httpauth'].split(':')
        Logger.dbg(f'HTTP Basic Auth: {user}:{_pass}')
        auth = requests.HTTPDigestAuth(user, _pass)

    fullurl = config["host"] + url
    Logger.info(f'POST Request: {fullurl}')

    resp = None

    if contentType.endswith('/json'):
        resp = requests.post(fullurl, json=data, headers=headers, auth=auth)
    else:
        resp = requests.post(fullurl, data=data, headers=headers, auth=auth)

    if rawResp:
        return resp

    try:
        ret = resp.json()
    except:
        ret = resp.text

    return ret

def printFullGateway(gatewayId):
    gateway = getRequest(f'/api/gateway/{gatewayId}')

    if type(gateway) == str and re.match(r'Gateway with id = \w+ not found', gateway, re.I):
        Logger.err(f'Gateway with ID {gatewayId} was not found.')
        if config['format'] == 'json': print('{}')
        sys.exit(1)

    if config['format'] == 'json':
        printJson(gateway)
    else:
        printGatewayText(gateway)
        indent = '    '

        print()

        print(f'{indent}Connectors:')
        num = 0
        cnum = 0
        for c in gateway['connectors']:
            cnum += 1
            addr = ''
            port = ''

            for d in c['propertiesText']['arguments']:
                if d['type'] == 'ip': 
                    addr = d['value']
                    break
                elif d['type'] == 'uint16': 
                    port = d['value']
                    break

            print(f'{indent}    Host:   {addr}:{port}\n')

        num = 0
        print(f'{indent}Channels:')
        for c in gateway['channels']:
            num += 1
            kind = 'Channel'
            name = ''   # todo

            if 'isNegotiationChannel' in c.keys() and c['isNegotiationChannel']:
                kind = 'Negotiation Channel'

            if 'isReturnChannel' in c.keys() and c['isReturnChannel']:
                kind = 'Gateway Return Channel (GRC)'

            print(f'''{indent}{indent}{kind} {num}:\t{name}
{indent}{indent}    Jitter:      {' ... '.join([str(x) for x in c['jitter']])}
{indent}{indent}    Properties:''')

            for arg in c['propertiesText']['arguments']:
                if type(arg) == list or type(arg) == tuple:
                    for arg1 in arg:
                        print(f'''{indent}{indent}        Name:    {arg1['name']}
{indent}{indent}        Value:   {arg1['value']}
''')
                else:
                    print(f'''{indent}{indent}        Name:    {arg['name']}
{indent}{indent}        Value:   {arg['value']}
''')

        num = 0
        for g in gateway['relays']:
            num += 1
            alive = ''
            elevated = ''

            if g['isActive']:
                alive = '\t\t\t(+)'

            if g['hostInfo']['isElevated']:
                elevated = '\t\t\t(###)'

            print(f'''
{indent}Relay {num}:              {g['name']}
{indent}    Relay ID:         {g['agentId']}
{indent}    Build ID:         {g['buildId']}
{indent}    Is active:        {g['isActive']}{alive}
{indent}    Timestamp:        {datetime.fromtimestamp(g['timestamp'])}
{indent}    Host Info:  
{indent}        Computer:     {g['hostInfo']['computerName']}
{indent}        Domain:       {g['hostInfo']['domain']}
{indent}        User Name:    {g['hostInfo']['userName']}
{indent}        Is elevated:  {g['hostInfo']['isElevated']}{elevated}
{indent}        OS Version:   {g['hostInfo']['osVersion']}
{indent}        Process ID:   {g['hostInfo']['processId']}''')


def onGetGateway(args):
    gateways = getRequest('/api/gateway')
    for g in gateways:
        if args.name.lower() == g['name'].lower():
            print('\n== Relays connected to Gateway ' + g['name'] + ': ')
            printFullGateway(g['agentId'])
            return

    printFullGateway(args.name)

def printFullRelay(r, num = 0, indent='    '):
    alive = ''
    elevated = ''

    if r['isActive']:
        alive = '\t\t\t(+)'

    if r['hostInfo']['isElevated']:
        elevated = '\t\t\t(###)'

    print(f'''{indent}Relay {num}:              {r['name']}
{indent}    Relay ID:         {r['agentId']}
{indent}    Build ID:         {r['buildId']}
{indent}    Is active:        {r['isActive']}{alive}
{indent}    Timestamp:        {datetime.fromtimestamp(r['timestamp'])}
{indent}    Host Info:  
{indent}        Computer:     {r['hostInfo']['computerName']}
{indent}        Domain:       {r['hostInfo']['domain']}
{indent}        User Name:    {r['hostInfo']['userName']}
{indent}        Is elevated:  {r['hostInfo']['isElevated']}{elevated}
{indent}        OS Version:   {r['hostInfo']['osVersion']}
{indent}        Process ID:   {r['hostInfo']['processId']}
''')

    cnum = 0
    print(f'{indent}Channels:')
    for c in r['channels']:
        cnum += 1
        kind = 'Channel'
        name = ''   # todo

        if 'isNegotiationChannel' in c.keys() and c['isNegotiationChannel']:
            kind = 'Negotiation Channel'

        if 'isReturnChannel' in c.keys() and c['isReturnChannel']:
            kind = 'Gateway Return Channel (GRC)'

        print(f'''{indent}{indent}{kind} {cnum}:\t{name}
{indent}{indent}    Jitter:      {' ... '.join([str(x) for x in c['jitter']])}
{indent}{indent}    Properties:''')

        for arg in c['propertiesText']['arguments']:
            if type(arg) == list or type(arg) == tuple:
                for arg1 in arg:
                    print(f'''{indent}{indent}        Name:    {arg1['name']}
{indent}{indent}        Value:   {arg1['value']}
''')
            else:
                print(f'''{indent}{indent}        Name:    {arg['name']}
{indent}{indent}        Value:   {arg['value']}
''')

def onGetRelay(args):
    Logger.dbg('in onListRelays(): ' + str(args))

    relays = collectRelays(args)

    if len(relays) == 0:
        Logger.err('Could not find specified Relay given neither its name nor agentId.')
        if config['format'] == 'json': print('{}')
        sys.exit(1)

    num = 0
    if config['format'] == 'text':
        for gateway, relay in relays:
            num += 1
            printFullRelay(relay, num)

    elif config['format'] == 'json':
        printJson(relays)

def printGatewayText(g, num = 0):
    alive = ''
    if g['isActive']:
        alive = '\t\t\t(+)'
    print(f'''
Gateway {num}:\t{g['name']}
    Gateway ID: {g['agentId']}
    Build ID:   {g['buildId']}
    Is active:  {g['isActive']}{alive}
    Timestamp:  {datetime.fromtimestamp(g['timestamp'])}''')

def onListGateways(args):
    Logger.dbg('in onListGateways(): ' + str(args))
    gateways = getRequest('/api/gateway')
    
    if config['format'] == 'json':
        printJson(gateways)

    elif config['format'] == 'text':
        num = 0
        for g in gateways:
            num += 1
            if args.active:
                if not g['isActive']: continue

            printGatewayText(g, num)

def listGatewayRelays(gatewayId, indent = '', onlyActive = False):
    relays = getRequest(f'/api/gateway/{gatewayId}')

    if type(relays) == str and re.match(r'Gateway with id = \w+ not found', relays, re.I):
        Logger.err(f'Gateway with ID {gatewayId} was not found.')
        if config['format'] == 'json': print('{}')
        sys.exit(1)

    if config['format'] == 'json':
        printJson(relays['relays'])

    elif config['format'] == 'text':
        num = 0
        for g in relays['relays']:
            num += 1
            alive = ''
            elevated = ''

            if onlyActive:
                if not g['isActive']: continue

            if g['isActive']:
                alive = '\t\t\t(+)'

            if g['hostInfo']['isElevated']:
                elevated = '\t\t\t(###)'

            print(f'''
{indent}Relay {num}:\t{g['name']}
{indent}    Gateway ID: {g['agentId']}
{indent}    Build ID:   {g['buildId']}
{indent}    Is active:  {g['isActive']}{alive}
{indent}    Timestamp:  {datetime.fromtimestamp(g['timestamp'])}
{indent}    Host Info:  
{indent}        Computer:     {g['hostInfo']['computerName']}
{indent}        Domain:       {g['hostInfo']['domain']}
{indent}        User Name:    {g['hostInfo']['userName']}
{indent}        Is elevated:  {g['hostInfo']['isElevated']}
{indent}        OS Version:   {g['hostInfo']['osVersion']}
{indent}        Process ID:   {g['hostInfo']['processId']}''')

def onListRelays(args):
    Logger.dbg('in onListRelays(): ')

    if args.gateway_id != None:
        gateways = getRequest('/api/gateway')
        for g in gateways:
            if args.gateway_id == g['name'].lower():
                print('\n== Relays connected to Gateway ' + g['name'] + ': ')
                listGatewayRelays(g['agentId'], onlyActive = args.active)
                return

        listGatewayRelays(args.gateway_id, onlyActive = args.active)

    else:
        gateways = getRequest('/api/gateway')
        num = 0
        relays = {}
        relays['gateways'] = []
        for g in gateways:
            num += 1
            if config['format'] == 'text':
                print(f'''
Gateway {num}:\t{g['name']}''')
                listGatewayRelays(g['agentId'], indent = '    ', onlyActive = args.active)
            else:
                relaysData = getRequest(f'/api/gateway/{g["agentId"]}')
                g['relays'] = relaysData['relays']
                relays['gateways'].append(g)

        if config['format'] == 'json':
            printJson(relays)

def collectRelays(args):
    relays = []
    gateways = getRequest('/api/gateway')

    gateway_id = None
    if hasattr(args, 'gateway_id') and args.gateway_id != None:
        gateway_id = args.gateway_id

    relay_id = None
    if hasattr(args, 'relay_id') and args.relay_id != None:
        relay_id = args.relay_id

    if gateway_id != None:
        gatewayId = ''
        
        for g in gateways:
            if gateway_id.lower() == g['name'].lower():
                gatewayId = g['agentId']
                break
            elif gateway_id.lower() == g['agentId'].lower():
                gatewayId = g['agentId']
                break

        if gatewayId == '':
            Logger.err('Gateway with given Name/ID could not be found.')
            if config['format'] == 'json': print('{}')
            sys.exit(1)

        gateway = getRequest(f'/api/gateway/{gatewayId}')

        if 'relays' not in gateway.keys():
            Logger.err('Specified Gateway did not have any Relay.')
            if config['format'] == 'json': print('{}')
            sys.exit(1)

        if relay_id != None:
            for r in gateway['relays']:
                if relay_id.lower() == r['name'].lower():
                    relays.append((gateway, r))
                elif relay_id.lower() == r['agentId'].lower():
                    relays.append((gateway, r))
        else:
            for r in gateway['relays']:
                relays.append((gateway, r))
    else:
        for g in gateways:
            gr = getRequest(f'/api/gateway/{g["agentId"]}')
            if 'relays' in gr.keys():
                for r in gr['relays']:
                    if relay_id != None:
                        if relay_id.lower() == r['name'].lower():
                            relays.append((g, r))
                        elif relay_id.lower() == r['agentId'].lower():
                            relays.append((g, r))
                    else:
                        relays.append((g, r))

    return relays

def onPing(args):
    if args.keep_pinging > 0:
        while True:
            print(f'[.] Sending a ping every {args.keep_pinging} seconds.')
            _onPing(args)
            time.sleep(args.keep_pinging)
    else:
        print('[.] Pinging only once...')
        _onPing(args)

def _onPing(args):
    relays = collectRelays(args)

    if len(relays) == 0:
        print('[-] No relays found that could be pinged.')
        return

    pinged = 0
    for gateway, relay in relays:
        Logger.info(f'Pinging relay {relay["name"]}...')
        data = {
            'name' : 'RelayCommandGroup',
            'data' : {
                'id' : commandsMap['Ping'],
                'name' : 'Command',
                'command' : 'Ping',
                'arguments' : []
            }
        }

        ret = postRequest(f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/command', data)

        if type(ret) == dict and 'relayAgentId' in ret.keys() and ret['relayAgentId'] == relay['agentId']:
            print(f'[.] Pinged relay: {relay["name"]:10s} from gateway  {gateway["name"]}')
            pinged += 1

    if pinged == 0:
        print('[-] There were no active relays that could be pinged.\n')
    else:
        print(f'[+] Pinged {pinged} active relays.\n')

def getLastGatewayCommandID(gateway, secondOrder = True):
    lastId = 0
    commands = getRequest(f'/api/gateway/{gateway["agentId"]}/command')
    for comm in commands:
        if secondOrder:
            if 'data' in comm.keys():
                if 'id' in comm['data'].keys():
                    if comm['data']['id'] > lastId:
                        lastId = comm['data']['id']
        else:
            if comm['id'] > lastId:
                lastId = comm['id']

    return lastId

def onMattermostPurge(args):
    data = {
        'data' : {
            'arguments' : [],
            'command' : 'Clear all channel messages',
            'id' : 0,
            'name' : 'Mattermost'
        },
        'name' : 'ChannelCommandGroup'
    }

    channels = collectChannelsToSendCommand(args, 'mattermost')

    if len(channels) == 0:
        print('[-] No channels could be found to receive Mattermost purge command.')
        return

    for channel in channels:
        ret = postRequest(channel['url'], data)

        if type(ret) == dict and 'Clear all' in str(ret):
            if 'relay' in channel.keys():
                print(f'[+] Purged all messages from Mattermost C3 channel {channel["channelId"]} on Relay {channel["relay"]["name"]} on gateway {channel["gateway"]["name"]}')
            else:
                print(f'[+] Purged all messages from Mattermost C3 channel {channel["channelId"]} on gateway {channel["gateway"]["name"]}')

def onLDAPClear(args):
    data = {
        'data' : {
            'arguments' : [],
            'command' : 'Clear attribute values',
            'id' : 0,
            'name' : 'LDAP'
        },
        'name' : 'ChannelCommandGroup'
    }

    channels = collectChannelsToSendCommand(args, 'ldap')

    if len(channels) == 0:
        print('[-] No channels could be found to receive LDAP clear attribute command.')
        return

    for channel in channels:
        ret = postRequest(channel['url'], data)

        if type(ret) == dict and 'LDAP' in str(ret):
            if 'relay' in channel.keys():
                print(f'[+] Cleared LDAP attribute value on C3 channel {channel["channelId"]} on Relay {channel["relay"]["name"]} on gateway {channel["gateway"]["name"]}')
            else:
                print(f'[+] Cleared LDAP attribute value on C3 channel {channel["channelId"]} on gateway {channel["gateway"]["name"]}')

def onMSSQLClearTable(args):
    data = {
        'data' : {
            'arguments' : [],
            'command' : 'Clear DB Table',
            'id' : 0,
            'name' : 'MSSQL'
        },
        'name' : 'ChannelCommandGroup'
    }

    channels = collectChannelsToSendCommand(args, 'table name')

    if len(channels) == 0:
        print('[-] No channels could be found to receive MSSQL clear DB table command.')
        return

    for channel in channels:
        ret = postRequest(channel['url'], data)

        if type(ret) == dict and 'MSSQL' in str(ret):
            if 'relay' in channel.keys():
                print(f'[+] Cleared MSSQL Table on C3 channel {channel["channelId"]} on Relay {channel["relay"]["name"]} on gateway {channel["gateway"]["name"]}')
            else:
                print(f'[+] Cleared MSSQL Table value on C3 channel {channel["channelId"]} on gateway {channel["gateway"]["name"]}')

def onUncShareFileClear(args):
    data = {
        'data' : {
            'arguments' : [],
            'command' : 'Remove all message files',
            'id' : 0,
            'name' : 'UncShareFile'
        },
        'name' : 'ChannelCommandGroup'
    }

    channels = collectChannelsToSendCommand(args, 'filesystem path')

    if len(channels) == 0:
        print('[-] No channels could be found to receive UncShareFile remove all message files command.')
        return

    for channel in channels:
        ret = postRequest(channel['url'], data)

        if type(ret) == dict and 'UncShareFile' in str(ret):
            if 'relay' in channel.keys():
                print(f'[+] Cleared UncShareFile message files on C3 channel {channel["channelId"]} on Relay {channel["relay"]["name"]} on gateway {channel["gateway"]["name"]}')
            else:
                print(f'[+] Cleared UncShareFile message files on C3 channel {channel["channelId"]} on gateway {channel["gateway"]["name"]}')

def onDropboxClear(args):
    data = {
        'data' : {
            'arguments' : [],
            'command' : 'Remove All Files',
            'id' : 1,
            'name' : 'Dropbox'
        },
        'name' : 'ChannelCommandGroup'
    }

    channels = collectChannelsToSendCommand(args, 'dropbox token')

    if len(channels) == 0:
        print('[-] No channels could be found to receive Dropbox remove all message files command.')
        return

    for channel in channels:
        ret = postRequest(channel['url'], data)

        if type(ret) == dict and 'Dropbox' in str(ret):
            if 'relay' in channel.keys():
                print(f'[+] Cleared Dropbox message files on C3 channel {channel["channelId"]} on Relay {channel["relay"]["name"]} on gateway {channel["gateway"]["name"]}')
            else:
                print(f'[+] Cleared Dropbox message files on C3 channel {channel["channelId"]} on gateway {channel["gateway"]["name"]}')

def onGithubClear(args):
    data = {
        'data' : {
            'arguments' : [],
            'command' : 'Remove All Files',
            'id' : 1,
            'name' : 'Github'
        },
        'name' : 'ChannelCommandGroup'
    }

    channels = collectChannelsToSendCommand(args, 'github token')

    if len(channels) == 0:
        print('[-] No channels could be found to receive Github remove all message files command.')
        return

    for channel in channels:
        ret = postRequest(channel['url'], data)

        if type(ret) == dict and 'Github' in str(ret):
            if 'relay' in channel.keys():
                print(f'[+] Cleared Github message files on C3 channel {channel["channelId"]} on Relay {channel["relay"]["name"]} on gateway {channel["gateway"]["name"]}')
            else:
                print(f'[+] Cleared Github message files on C3 channel {channel["channelId"]} on gateway {channel["gateway"]["name"]}')

def onGoogleDriveClear(args):
    data = {
        'data' : {
            'arguments' : [],
            'command' : 'Remove All Files',
            'id' : 1,
            'name' : 'GoogleDrive'
        },
        'name' : 'ChannelCommandGroup'
    }

    channels = collectChannelsToSendCommand(args, 'github token')

    if len(channels) == 0:
        print('[-] No channels could be found to receive GoogleDrive remove all message files command.')
        return

    for channel in channels:
        ret = postRequest(channel['url'], data)

        if type(ret) == dict and 'GoogleDrive' in str(ret):
            if 'relay' in channel.keys():
                print(f'[+] Cleared GoogleDrive message files on C3 channel {channel["channelId"]} on Relay {channel["relay"]["name"]} on gateway {channel["gateway"]["name"]}')
            else:
                print(f'[+] Cleared GoogleDrive message files on C3 channel {channel["channelId"]} on gateway {channel["gateway"]["name"]}')

def collectChannelsToSendCommand(args, channelKeyword):
    relays = collectRelays(args)
    gateways = getRequest('/api/gateway')

    channel_id = None
    if hasattr(args, 'channel_id') and args.channel_id != None:
        channel_id = args.channel_id 

    channels = []

    for gateway, relay in relays:
        if 'channels' in relay.keys():
            channel_num = 0

            for c in relay['channels']:
                channel_num += 1
                Logger.dbg(f'Iterating over channel {c["iid"]} on Relay ...')
                if channel_id != None:
                    if c['iid'] == channel_id:
                        Logger.dbg(f'Adding channel {c["iid"]} in Relay {relay["name"]}.')
                        channels.append({
                            'url' : f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/channel/{c["iid"]}/command',
                            'gateway' : gateway,
                            'relay' : relay,
                            'channelId' : c['iid'],
                        })
                        continue
                else:
                    for arg in c['propertiesText']['arguments']:
                        if type(arg) == dict:
                            if channelKeyword in arg['name'].lower() or ("description" in arg.keys() and channelKeyword in arg['description'].lower()):
                                Logger.dbg(f'Adding channel {c["iid"]} in Relay {relay["name"]}.')
                                channels.append({
                                    'url' : f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/channel/{c["iid"]}/command',
                                    'gateway' : gateway,
                                    'relay' : relay,
                                    'channelId' : c['iid'],
                                })
                                break

    for _gateway in gateways:
        gateway = getRequest(f'/api/gateway/{_gateway["agentId"]}')

        if type(gateway) != dict: 
            continue

        if 'channels' in gateway.keys():
            channel_num = 0
            hadGatewayId = False            

            if hasattr(args, 'gateway_id') and args.gateway_id != None:
                hadGatewayId = True
                if (args.gateway_id == gateway['agentId'].lower()) or (args.gateway_id == gateway['name'].lower()):
                    pass
                else:
                    continue

            Logger.dbg(f'Checking channels bound to Gateway {gateway["name"]} / {gateway["agentId"]}')

            for c in gateway['channels']:
                channel_num += 1
                Logger.dbg(f'Iterating over channel {c["iid"]} in Gateway...')
                if channel_id != None:
                    if c['iid'] == channel_id:
                        Logger.dbg(f'Adding channel {c["iid"]} in gateway {gateway["name"]}.')
                        channels.append({
                            'url' : f'/api/gateway/{gateway["agentId"]}/channel/{c["iid"]}/command',
                            'gateway' : gateway,
                            'channelId' : c['iid'],
                        })
                        break
                else:
                    for arg in c['propertiesText']['arguments']:
                        if type(arg) == dict:
                            if channelKeyword in arg['name'].lower() or ("description" in arg.keys() and channelKeyword in arg['description'].lower()):
                                Logger.dbg(f'Adding channel {c["iid"]} in gateway {gateway["name"]}.')
                                channels.append({
                                    'url' : f'/api/gateway/{gateway["agentId"]}/channel/{c["iid"]}/command',
                                    'gateway' : gateway,
                                    'channelId' : c['iid'],
                                })
                                break
    return channels

def shell(cmd, alternative = False, stdErrToStdout = False, surpressStderr = False):
    CREATE_NO_WINDOW = 0x08000000
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE

    outs = ''
    errs = ''
    if not alternative:
        out = subprocess.run(
            cmd, 
            cwd = os.getcwd(),
            shell=True, 
            capture_output=True, 
            startupinfo=si, 
            creationflags=CREATE_NO_WINDOW,
            timeout=60
            )

        outs = out.stdout
        errs = out.stderr
    else:
        proc = subprocess.Popen(
            cmd,
            cwd = cwd,
            shell=True, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=si, 
            creationflags=CREATE_NO_WINDOW
        )
        try:
            outs, errs = proc.communicate(timeout=60)
            proc.wait()

        except TimeoutExpired:
            proc.kill()
            logger.err('WARNING! The command timed-out! Results may be incomplete')
            outs, errs = proc.communicate()

    status = outs.decode(errors='ignore').strip()

    if len(errs) > 0 and not surpressStderr:
        error = '''
Running shell command ({}) failed:

---------------------------------------------
{}
---------------------------------------------
'''.format(cmd, errs.decode(errors='ignore'))

        if stdErrToStdout:
            return error

    return status

def onAlarmRelay(args):
    origRelays = collectRelays(args)
    lastTimestamp = 0

    origRelayIds = set()

    for gateway, relay in origRelays:
        origRelayIds.add(relay['agentId'])
        if relay['timestamp'] > lastTimestamp:
            lastTimestamp = relay['timestamp']

    print('[.] Entering infinite-loop awaiting for new Relays...')

    try:
        while True:
            currRelays = collectRelays(args)
            currRelayIds = set()
            currLastTimestamp = 0
            newestRelay = None

            for gateway, relay in currRelays:
                currRelayIds.add(relay['agentId'])
                if relay['timestamp'] > currLastTimestamp:
                    currLastTimestamp = relay['timestamp']
                    newestRelay = relay

            if currLastTimestamp > lastTimestamp and len(currRelayIds) > len(origRelayIds) and newestRelay['agentId'] not in origRelayIds:
                lastTimestamp = currLastTimestamp
                origRelayIds = currRelayIds

                print('[+] New Relay checked-in!')
                printFullRelay(newestRelay, len(currRelays))

                try:
                    if args.execute != None and len(args.execute) > 0:
                        cmd = args.execute
                        cmd = cmd.replace("<computerName>", newestRelay['hostInfo']['computerName'])
                        cmd = cmd.replace("<isElevated>", str(newestRelay['hostInfo']['isElevated']))
                        cmd = cmd.replace("<osVersion>", newestRelay['hostInfo']['osVersion'])
                        cmd = cmd.replace("<domain>", newestRelay['hostInfo']['domain'])
                        cmd = cmd.replace("<userName>", newestRelay['hostInfo']['userName'])
                        cmd = cmd.replace("<processId>", str(newestRelay['hostInfo']['processId']))
                        cmd = cmd.replace("<relayName>", newestRelay['name'])
                        cmd = cmd.replace("<relayId>", newestRelay['agentId'])
                        cmd = cmd.replace("<buildId>", newestRelay['buildId'])
                        cmd = cmd.replace("<timestamp>", str(datetime.fromtimestamp(newestRelay['timestamp'])))
                        cmd = cmd.replace("<gatewayId>", newestRelay['name'])

                        print(f'[.] Executing command: {cmd}')
                        shell(cmd)

                    if args.webhook != None and len(args.webhook) > 0:
                        data = {
                            "<computerName>", newestRelay['hostInfo']['computerName'],
                            "<isElevated>", newestRelay['hostInfo']['isElevated'],
                            "<osVersion>", newestRelay['hostInfo']['osVersion'],
                            "<domain>", newestRelay['hostInfo']['domain'],
                            "<userName>", newestRelay['hostInfo']['userName'],
                            "<processId>", newestRelay['hostInfo']['processId'],
                            "<relayName>", newestRelay['name'],
                            "<relayId>", newestRelay['agentId'],
                            "<buildId>", newestRelay['buildId'],
                            "<timestamp>", datetime.fromtimestamp(newestRelay['timestamp']),
                            "<gatewayId>", newestRelay['name'],
                        }

                        print(f'[.] Triggering a webhook: {args.webhook}')
                        requests.post(args.webhook, data = data, headers = headears)

                except Exception as e:
                    print(f'[-] Exception occured during New-Relay alarm trigger: {e}')
    
    except KeyboardInterrupt:
        print('[.] New Relay alarm loop was finished.')


def findAgent(agentId):
    gateways = getRequest('/api/gateway')

    for g in gateways:
        if g["agentId"].lower() == agentId.lower() or g["name"].lower() == agentId.lower():
            return g, None

        gateway = getRequest(f'/api/gateway/{g["agentId"]}')
        if 'relays' in gateway.keys():
            for r in gateway['relays']:
                if r["agentId"].lower() == agentId.lower() or r["name"].lower() == agentId.lower():
                    return g, r

    return None

def getValueOrRandom(val, N = 6):
    if val == 'random':
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))
    
    return val

def onMattermostCreate(args):
    server_url = args.server_url
    if server_url.endswith('/'): server_url = server_url[:-1]

    gateway, relay = findAgent(args.agent_id)
    if not relay and not gateway:
        logger.fatal('Could not find agent (Gateway or Relay) which should be used to setup a channel.')

    url = f'/api/gateway/{gateway["agentId"]}/command'

    if relay != None:
        url = f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/command'
        print(f'[.] Will setup a Mattermost channel on a Relay named {relay["name"]} ({relay["agentId"]})')
    else:
        print(f'[.] Will setup a Mattermost channel on a Gateway named {gateway["name"]} ({gateway["agentId"]})')

    secondCommandId = getLastGatewayCommandID(gateway) + 1
    commandId = getLastGatewayCommandID(gateway, False) + 1
    Logger.info(f'Issuing a command with ID = {commandId}')

    data = {
        "name" : "GatewayCommandGroup",
        "data" : {
            "arguments" : [
                {
                    "type" : "string",
                    "name" : "Negotiation Identifier",
                    "value" : getValueOrRandom(args.negotiation_id),
                },
                {
                    "type" : "string",
                    "name" : "Mattermost Server URL",
                    "value" : server_url,
                },
                {
                    "type" : "string",
                    "name" : "Mattermost Team Name",
                    "value" : args.team_name
                },
                {
                    "type" : "string",
                    "name" : "Mattermost Access Token",
                    "value" : args.access_token,
                },
                {
                    "type" : "string",
                    "name" : "Channel name",
                    "value" : getValueOrRandom(args.channel_name),
                },
                {
                    "type" : "string",
                    "name" : "User-Agent Header",
                    "value" : args.user_agent,
                }
            ],
            "command" : "AddNegotiationChannelMattermost",
            "id" : secondCommandId,
            "name" : "Command",
        },
        'id' : commandId,
        'name' : 'GatewayCommandGroup'
    }

    Logger.info('Will create Mattermost channel with following parameters:\n\n' + json.dumps(data, indent = 4))
    
    ret = postRequest(url, data, rawResp = True)

    if ret.status_code == 201:
        print('[+] Channel was created.')
    else:
        print(f'[-] Channel was not created: {ret.text}')


def parseArgs(argv):
    global config

    usage = '\nUsage: ./c3-client.py [options] <host> <command> [...]\n'
    opts = argparse.ArgumentParser(
        prog = argv[0],
        usage = usage
    )

    opts.add_argument('host', help = 'C3 Web API host:port')

    opts.add_argument('-v', '--verbose', action='store_true', help='Display verbose output.')
    opts.add_argument('-d', '--debug', action='store_true', help='Display debug output.')
    opts.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format. Can be JSON or text (default).')
    opts.add_argument('-A', '--httpauth', metavar = 'user:pass', help = 'HTTP Basic Authentication (user:pass)')

    subparsers = opts.add_subparsers(help = 'command help', required = True)

    #
    # Alarm
    #
    alarm = subparsers.add_parser('alarm', help = 'Alarm options')
    alarm_sub = alarm.add_subparsers(help = 'Alarm on what?', required = True)

    alarm_relay = alarm_sub.add_parser('relay', help = 'Trigger an alarm whenever a new Relay checks-in.')
    alarm_relay.add_argument('-e', '--execute', help = 'If new Relay checks in - execute this command. Use following placeholders in your command: <computerName>, <userName>, <domain>, <isElevated>, <osVersion>, <processId>, <relayName>, <relayId>, <buildId>, <timestamp> to customize executed command\'s parameters. Example: powershell -c "Add-Type -AssemblyName System.Speech; $synth = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer; $synth.Speak(\'New Relay just checked-in <domain>/<userName>@<computerName>\')"')
    alarm_relay.add_argument('-x', '--webhook', help = 'Trigger a Webhook (HTTP POST request) to this URL whenever a new Relay checks-in. The request will contain JSON message with all the fields available, mentioned in --execute option.')
    alarm_relay.add_argument('-g', '--gateway-id', metavar='gateway_id', help = 'ID (or Name) of the Gateway which Relays should be returned. If not given, will result all relays from all gateways.')
    alarm_relay.set_defaults(func = onAlarmRelay)

    #
    # List
    # 
    parser_list = subparsers.add_parser('list', help = 'List options')
    parser_list_sub = parser_list.add_subparsers(help = 'List what?', required = True)

    list_gateways = parser_list_sub.add_parser('gateways', help = 'List available gateways.')
    list_gateways.add_argument('-a', '--active', action='store_true', help = 'List only active gateways')
    list_gateways.set_defaults(func = onListGateways)

    list_relays = parser_list_sub.add_parser('relays', help = 'List available relays.')
    list_relays.set_defaults(func = onListRelays)
    list_relays.add_argument('-a', '--active', action='store_true', help = 'List only active relays')
    list_relays.add_argument('-g', '--gateway-id', metavar='gateway_id', help = 'ID (or Name) of the Gateway which Relays should be returned. If not given, will result all relays from all gateways.')

    #
    # Get
    #
    parser_get = subparsers.add_parser('get', help = 'Get options')
    parser_get_sub = parser_get.add_subparsers(help = 'Get what?', required = True)

    get_gateway = parser_get_sub.add_parser('gateway', help = 'Get gateway\'s data.')
    get_gateway.set_defaults(func = onGetGateway)
    get_gateway.add_argument('name', help = 'Gateway Name or ID')

    get_relay = parser_get_sub.add_parser('relay', help = 'Get relay\'s data.')
    get_relay.set_defaults(func = onGetRelay)
    get_relay.add_argument('name', help = 'Relay Name or ID')
    get_relay.add_argument('-g', '--gateway-id', metavar='gateway_id', help = 'ID (or Name) of the Gateway runs specified Relay. If not given, will return all relays matching criteria from all gateways.')

    #
    # Ping
    #
    parser_ping = subparsers.add_parser('ping', help = 'Ping Relays')
    parser_ping.add_argument('-r', '--relay-id', help = 'Specifies which Relay should be pinged. Can be its ID or name.')
    parser_ping.add_argument('-g', '--gateway-id', metavar='gateway_id', help = 'ID (or Name) of the Gateway which Relays should be pinged. If not given, will ping all relays in all gateways.')
    parser_ping.add_argument('-k', '--keep-pinging', metavar='delay', type=int, default=0, help = 'Keep pinging choosen Relays. Will send a ping every "delay" number of seconds. Default: sends ping only once.')
    parser_ping.set_defaults(func = onPing)

    #
    # Channel
    #
    parser_channel = subparsers.add_parser('channel', help = 'Send Channel-specific command')
    parser_channel.add_argument('-c', '--channel-id', help = 'Specifies ID of the channel to commander. If not given - will issue specified command to all channels in a Relay.')
    parser_channel.add_argument('-r', '--relay-id', help = 'Specifies Relay that runs target channel. Can be its ID or name.')
    parser_channel.add_argument('-g', '--gateway-id', metavar='gateway_id', help = 'ID (or Name) of the Gateway which Relays should be pinged. If not given, will ping all relays in all gateways.')
    
    parser_channel_sub = parser_channel.add_subparsers(help = 'Specify channel', required = True)
    
    ## Mattermost
    mattermost = parser_channel_sub.add_parser('mattermost', help = 'Mattermost channel specific commands.')
    mattermost_parser = mattermost.add_subparsers(help = 'Command to send', required = True)

    ### Create
    #mattermost_create = mattermost_parser.add_parser('create', help = 'Setup a Mattermost channel.')
    #mattermost_create.add_argument('agent_id', metavar = 'agent_id', help = 'Gateway or Relay that will be used to setup a channel. Can be ID or Name.')
    #mattermost_create.add_argument('server_url', metavar = 'server_url', help = 'Mattermost Server URL, example: http://192.168.0.100:8888')
    #mattermost_create.add_argument('team_name', metavar = 'team_name', help = 'Mattermost Team name where to create channels.')
    #mattermost_create.add_argument('access_token', metavar = 'access_token', help = 'Personal Access Token value.')
    #mattermost_create.add_argument('--negotiation-id', metavar = 'ID', default='random', help = 'Negotiation Identifier. Will be picked at random if left empty.')
    #mattermost_create.add_argument('--channel-name', metavar = 'CHANNEL', default='random', help = 'Channel name to create. Will be picked at random if left empty.')
    #mattermost_create.add_argument('--user-agent', metavar = 'USERAGENT', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36', 
    #                                help = 'User-Agent string to use in HTTP requests.')
    #mattermost_create.set_defaults(func = onMattermostCreate)

    ### Purge
    mattermost_purge = mattermost_parser.add_parser('clear', help = 'Purge all dangling posts/messages from Mattermost channel.')
    mattermost_purge.set_defaults(func = onMattermostPurge)

    ## LDAP
    ldap = parser_channel_sub.add_parser('ldap', help = 'LDAP channel specific commands.')
    ldap_parser = ldap.add_subparsers(help = 'Command to send', required = True)

    ### clear
    ldap_clear = ldap_parser.add_parser('clear', help = 'Clear LDAP attribute associated with that channel.')
    ldap_clear.set_defaults(func = onLDAPClear)

    ## MSSQL
    mssql = parser_channel_sub.add_parser('mssql', help = 'MSSQL channel specific commands.')
    mssql_parser = mssql.add_subparsers(help = 'Command to send', required = True)

    ### clear
    mssql_clear = mssql_parser.add_parser('clear', help = 'Clear channel\'s DB Table.')
    mssql_clear.set_defaults(func = onMSSQLClearTable)

    ## UncShareFile
    unc = parser_channel_sub.add_parser('uncsharefile', help = 'UncShareFile channel specific commands.')
    unc_parser = unc.add_subparsers(help = 'Command to send', required = True)

    ### clear
    unc_clear = unc_parser.add_parser('clear', help = 'Clear all message files.')
    unc_clear.set_defaults(func = onUncShareFileClear)

    ## Dropbox
    dropbox = parser_channel_sub.add_parser('dropbox', help = 'Dropbox channel specific commands.')
    dropbox_parser = dropbox.add_subparsers(help = 'Command to send', required = True)

    ### clear
    dropbox_clear = dropbox_parser.add_parser('clear', help = 'Clear all files.')
    dropbox_clear.set_defaults(func = onDropboxClear)

    ## Dropbox
    github = parser_channel_sub.add_parser('github', help = 'Github channel specific commands.')
    github_parser = github.add_subparsers(help = 'Command to send', required = True)

    ### clear
    github_clear = github_parser.add_parser('clear', help = 'Clear all files.')
    github_clear.set_defaults(func = onGithubClear)

    ## GoogleDrive
    gdrive = parser_channel_sub.add_parser('googledrive', help = 'GoogleDrive channel specific commands.')
    gdrive_parser = gdrive.add_subparsers(help = 'Command to send', required = True)

    ### clear
    gdrive_clear = gdrive_parser.add_parser('clear', help = 'Clear all files.')
    gdrive_clear.set_defaults(func = onGoogleDriveClear)

    try:
        args = opts.parse_args()
    except TypeError:
        opts.parse_args(argv.append('--help'))
        sys.exit(1)

    config.update(vars(args))
    return args.func(args)

def main(argv):
    print('''
    :: C3 Client - a lightweight automated companion with C3 voyages
    Mariusz B. / mgeeky, <mb@binary-offensive.com>
''')
    parseArgs(argv) 

    if config['format'] == 'text':
        print()

if __name__ == '__main__':
    main(sys.argv)
