#!/bin/bash
#
# This script simply calls `aws sts assume-role` using hardcoded parameters, in order
# to retrieve set of session credentials and reformat it into ~/.aws/credentials file format.
#
# Mariusz B., mgeeky '19
#


#
# Configure below variables.
#
PROFILE_NAME=your-profile-name
ROLE_NAME=Your_Role_Name
ROLE_ARN=arn:aws:iam::<NUMBER>:role/$ROLE_NAME

# If you leave this field empty - one will be deduced from `aws sts get-caller-identity` output
#SERIAL_MFA=arn:aws:iam::<NUMBER>:mfa/<USER-NAME>
SERIAL_MFA=

# Values possible range: 900-43200
DURATION=42000

#
# ------------------------
#

# Some times assume-role may return with an Access-Denied if there were no account authenticated
# regular commands sent first.
out=$(aws sts get-caller-identity)
if [ $? -ne 0 ]; then
	echo "[!] Could not get caller's identity: "
	echo $out
	exit 1
fi

if [[ "$SERIAL_MFA" = "" ]]; then
	SERIAL_MFA=$(echo "$out" | python -c "import sys,json; foo=json.loads(sys.stdin.read()); print('arn:aws:iam::{}:mfa/{}'.format(foo['Account'], foo['Arn'].split('/')[1]))" )
fi

read -p "Type your AWS MFA Code: " code
echo

out=$(aws sts assume-role --serial-number $SERIAL_MFA --role-arn $ROLE_ARN --role-session-name $ROLE_NAME --duration-seconds $DURATION --token-code $code)

if [ $? -eq 0 ]; then
	echo "[$PROFILE_NAME]"
	echo "$out" | python3 -c 'import sys,json; foo=json.loads(sys.stdin.read()); print("aws_access_key_id={}\naws_secret_access_key={}\naws_session_token={}".format(foo["Credentials"]["AccessKeyId"],foo["Credentials"]["SecretAccessKey"],foo["Credentials"]["SessionToken"]))'
	echo
else
	echo "[!] Could not obtain assume-role session credentials:"
	echo $out
	exit 1
fi
