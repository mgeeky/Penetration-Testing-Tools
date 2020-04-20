#!/bin/bash
#
# This script attempts quickly enumerate some of the exposed resources
# available given a set of AWS credentials.
# Based on excellent work of Scott Piper:
#	https://duo.com/blog/beyond-s3-exposed-resources-on-aws
#

if [ $# -lt 1 ]; then
	echo "Usage: ./find-exposed-resources.sh <profile-name> [region]"
	echo ""
	echo "If region is not specified, will enumerate all regions."
	exit 1
fi

PROFILE=$1
REGION=

if [[ "$2" != "" ]]; then
	REGION="$2"
fi

trap ctrl_c INT

function ctrl_c() {
	echo "[!] User interrupted script execution."
	exit 1
}

function _aws() {
	if [[ "$REGION" != "" ]]; then 
		#echo "aws --region $REGION --profile $PROFILE $@ --no-paginate"
		aws --region $REGION --profile $PROFILE $@ --no-paginate
	else
		#echo "aws --profile $PROFILE $@ --no-paginate"
		aws --profile $PROFILE $@ --no-paginate
	fi
}

function ebs_snapshots() {
	out=$(_aws ec2 describe-snapshots --owner-id self --restorable-by-user-ids all)
	if ! echo "$out" | grep -q '": \[\]'; then
		echo "---[ Public EBS Snapshots"
		echo "$out"
		echo
	fi
}

function rds_snapshots() {
	out=$(_aws rds describe-db-snapshots --snapshot-type public)
	if ! echo "$out" | grep -q '": \[\]'; then
		echo "---[ Public RDS Snapshots"
		echo "$out"
		echo
	fi
}

function ami_images() {
	out=$(_aws ec2 describe-images --owners self --executable-users all)
	if ! echo "$out" | grep -q '": \[\]'; then
		echo "---[ Public AMI Images"
		echo "$out"
		echo
	fi
}

function s3_buckets() {
	echo "---[ Public S3 Buckets"
	for bucket in $(_aws s3api list-buckets --query 'Buckets[*].Name' --output text)
	do 
		pub=$(_aws s3api get-bucket-policy-status --bucket $bucket --query 'PolicyStatus.IsPublic' 2> /dev/null || echo 'false')
		echo -n "IsPublic:"
		if [[ "$pub" == "true" ]]; then 
			echo -en "\e[91m"
		else 
			echo -en "\e[34m"
		fi
		echo -e "$pub\e[39m - Bucket: \e[93m$bucket\e[39m"
	done
	echo
}

regions=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

if [[ "$REGION" == "" ]]; then
	for region in ${regions[@]}
	do
		REGION="$region"
		echo "=================== Region: $region ======================"
		echo
		ebs_snapshots
		rds_snapshots
		ami_images
	done
	echo
else
	echo "=================== Region: $REGION ======================"
	echo
	ebs_snapshots
	rds_snapshots
	ami_images
	echo
fi

s3_buckets
