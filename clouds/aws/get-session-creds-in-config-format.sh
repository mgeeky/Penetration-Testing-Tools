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
SERIAL_MFA=arn:aws:iam::<NUMBER>:mfa/<USER-NAME>
ROLE_NAME=Your_Role_Name
ROLE_ARN=arn:aws:iam::<NUMBER>:role/$ROLE_NAME
DURATION=42000

#
# ------------------------
#

read -p "Type your AWS MFA Code: " code
echo

out=$(aws sts assume-role --serial-number $SERIAL_MFA --role-arn $ROLE_ARN --role-session-name $ROLE_NAME --duration-seconds $DURATION --token-code $code)

if [ $? -eq 0 ]; then
	echo "[$PROFILE_NAME]"
	echo "$out" | python3 -c 'import sys,json; foo=json.loads(sys.stdin.read()); print("aws_access_key_id={}\naws_secret_access_key={}\naws_session_token={}".format(foo["Credentials"]["AccessKeyId"],foo["Credentials"]["SecretAccessKey"],foo["Credentials"]["SessionToken"]))'
	echo
else
	echo $out
fi