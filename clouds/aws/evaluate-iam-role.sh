#!/bin/bash

if [ $# -ne 2 ]; then
	echo "Usage: evaluate-iam-role.sh <profile> <role-name>"
	exit 1
fi

PROFILE=$1
ROLE_NAME=$2

known_dangerous_permissions=(
	"iam:CreatePolicyVersion"
	"iam:SetDefaultPolicyVersion"
	"iam:PassRole"
	"ec2:RunInstances"
	"iam:CreateAccessKey"
	"iam:CreateLoginProfile"
	"iam:UpdateLoginProfile"
	"iam:AttachUserPolicy"
	"iam:AttachGroupPolicy"
	"iam:AttachRolePolicy"
	"iam:PutUserPolicy"
	"iam:PutGroupPolicy"
	"iam:PutRolePolicy"
	"iam:AddUserToGroup"
	"iam:UpdateAssumeRolePolicy"
	"sts:AssumeRole"
	"iam:PassRole"
	"lambda:CreateFunction"
	"lambda:InvokeFunction"
	"lambda:CreateEventSourceMapping"
	"lambda:UpdateFunctionCode"
	"glue:CreateDevEndpoint"
	"glue:UpdateDevEndpoint"
	"cloudformation:CreateStack"
	"datapipeline:CreatePipeline"
	"datapipeline:PutPipelineDefinition"
)

role_policy=$(aws --profile $PROFILE iam get-role --role-name $ROLE_NAME)

echo -e "=============== Role: $ROLE_NAME ==============="
echo "$role_policy"

IFS=$'\n'
attached_role_policies=($(aws --profile $PROFILE iam list-attached-role-policies --role-name $ROLE_NAME | jq -r '.AttachedPolicies[].PolicyArn'))

dangerous_permissions=()

for policy in "${attached_role_policies[@]}" ; do
	echo -e "\n=============== Attached Policy Arn: $policy ==============="

	version_id=$(aws --profile $PROFILE iam get-policy --policy-arn $policy | jq -r '.Policy.DefaultVersionId')

	policy_version=$(aws --profile $PROFILE iam get-policy-version --policy-arn $policy --version-id $version_id)
	echo "$policy_version"

	permissions=($(echo "$policy_version" | jq -r '.PolicyVersion.Document.Statement[].Action | if type=="string" then [.] else . end | .[]'))
	effect=$(echo "$policy_version" | jq -r '.PolicyVersion.Document.Statement[].Effect' )

	if [[ "$effect" == "Allow" ]]; then
		for perm in "${permissions[@]}" ; do
			for dangperm in "${known_dangerous_permissions[@]}"; do
				if echo "$dangperm" | grep -iq $perm ; then
					dangerous_permissions+=("$perm")
				fi
			done
		done
	fi
done

if [[ ${#dangerous_permissions[@]} -gt 0 ]]; then
	echo -e "\n\n=============== Detected dangerous permissions granted ==============="
	for dangperm in "${dangerous_permissions[@]}"; do
		echo -e "\t$dangperm"
	done
else
	echo -e "\nNo dangerous permissions were found to be granted."
fi
