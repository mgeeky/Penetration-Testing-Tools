## `gophish-send-mail.py`

This script will connect to your GoPhish instance, adjust HTML template and will send a quick test e-mail wherever you told it to, in attempt to let you quickly test out your HTML code.

1. Firstly you need to come up with YAML configuration file:


These are required parameters:
```
gophish_addr: https://127.0.0.1:3100
token: 1b07b71b0ba50...API_KEY...efe720a1ab79

file: test.html
template_name: existing-template-name

sender: sender@attacker.com
recipient: recipient@contoso.com
```

These are optional parameters:

- `subject`
- `first_name`
- `last_name`
- `position`
- `url`
- `dont_restore`

2. Then prepare your HTML file with message you want to send.

3. And run it.

Sample run:

```
PS > py .\gophish-send-mail.py .\send-mail-with-gophish.yaml

    :: GoPhish Single Mail Send utility
    Helping you embellish your emails by sending them one-by-one
    Mariusz Banach / mgeeky

[+] Template to use:
    ID:      22
    Name:    test-template-1
    Subject: Click Here To Win

[.] Updating it...
[+] Template updated.
[.] Sending e-mail via Campaign -> Send Test Email...
    From: sender@attacker.com
    To:   recipient@contoso.com

[+] Email Sent
[.] Restoring template...
[+] Finished.
```
