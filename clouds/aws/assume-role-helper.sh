#!/bin/bash
#
# This script simply calls `aws sts assume-role` using hardcoded parameters, in order
# to retrieve set of session credentials and reformat it into ~/.aws/credentials file format.
#
# Mariusz Banach, mgeeky '19-20
#


#
# --------------------------
# Configure below variables.
#

# Below two values are REQUIRED
PROFILE_NAME=
ROLE_NAME=

# If left empty, will be deduced from `aws sts get-caller-identity` output.
ACCOUNT_NUMBER=

# If left empty, will use ROLE_NAME
SESSION_NAME=

# If you leave this field empty - it will be deduced from `aws sts get-caller-identity` output
#SERIAL_MFA=arn:aws:iam::<NUMBER>:mfa/<USER-NAME>
SERIAL_MFA=

# Duration in seconds. Values possible range: 900-43200
# 1 hour - 3600, 2 hours - 7200, 3 hours - 10800, 6 hours - 21600, 12 hours - 43200
DURATION=3600

#
# --------------------------
#

# Some times assume-role may return with an Access-Denied if there were no account authenticated
# regular commands sent first.
out=$(aws --profile $PROFILE_NAME sts get-caller-identity)
if [ $? -ne 0 ]; then
    echo "[!] Could not get caller's identity: "
    echo "$out"
    exit 1
fi

if [[ "$SERIAL_MFA" = "" ]]; then
    SERIAL_MFA=$(echo "$out" | python3 -c "import sys,json; foo=json.loads(sys.stdin.read()); print('arn:aws:iam::{}:mfa/{}'.format(foo['Account'], foo['Arn'].split('/')[1]))" )
fi

if [[ "$ACCOUNT_NUMBER" = "" ]]; then
    ACCOUNT_NUMBER=$(echo "$out" | python3 -c "import sys,json; foo=json.loads(sys.stdin.read()); print(foo['Account'])" )
fi

if [[ "$SESSION_NAME" = "" ]]; then
    SESSION_NAME=$ROLE_NAME
fi

ROLE_ARN=arn:aws:iam::$ACCOUNT_NUMBER:role/$ROLE_NAME

echo "[.] Using Role ARN: $ROLE_ARN"

read -p "Type your AWS MFA Code (leave empty if not needed): " code
echo

if [[ "$code" = "" ]] || [[ "$SERIAL_MFA" == "" ]]; then
    echo "[.] MFA not provided, will attempt to assume role without it."
    out=$(aws --profile $PROFILE_NAME sts assume-role --role-arn $ROLE_ARN --role-session-name $SESSION_NAME --duration-seconds $DURATION 2>&1)
else
    echo "[.] Will attempt to assume role with MFA provided."
    out=$(aws --profile $PROFILE_NAME sts assume-role --serial-number $SERIAL_MFA --role-arn $ROLE_ARN --role-session-name $ROLE_NAME --duration-seconds $DURATION --token-code $code 2>&1)
fi

if [ $? -eq 0 ]; then
    valid=$(printf '%dh:%dm:%ds\n' $(($DURATION/3600)) $(($DURATION%3600/60)) $(($DURATION%60)))
    echo "[+] Collected session credentials. They will be valid for: $valid. "
    echo -e "\tPaste below lines to your '~/.aws/credentials' file:"
    echo
    echo "[$PROFILE_NAME-$SESSION_NAME]"
    echo "$out" | python3 -c 'import sys,json; foo=json.loads(sys.stdin.read()); print("aws_access_key_id={}\naws_secret_access_key={}\naws_session_token={}".format(foo["Credentials"]["AccessKeyId"],foo["Credentials"]["SecretAccessKey"],foo["Credentials"]["SessionToken"]))'
    echo
else
    echo "[!] Could not obtain assume-role session credentials:"
    echo "$out"
    echo
    out2=$(env | grep -E 'AWS_[^=]+')
    if [[ "$out2" != "" ]]; then
        echo "[!] Your command could fail because of pre-set AWS-related environment variables."
        echo -e "\tPlease review them, correct any problems and re-launch that script."
        echo
        echo "$out2"
        echo
    fi
    exit 1
fi