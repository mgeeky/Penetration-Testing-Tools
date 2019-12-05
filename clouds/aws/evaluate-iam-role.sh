#!/bin/bash

if [ $# -ne 2 ]; then
	echo "Usage: evaluate-iam-role.sh <profile> <role-name>"
	exit 1
fi

PROFILE=$1
ROLE_NAME=$2

known_potentially_dangerous_permissions=(
	".*:\*"
	".*:.*Attach.*"
	".*:.*Create.*"
	".*:.*Delete.*"
	".*:.*Reboot.*"
	".*:.*Command.*"
	".*:.*Run.*"
	".*:.*Send.*"
	".*:.*Batch.*"
	".*:.*Set.*"
	".*:.*Invoke.*"
	".*:.*Add.*"
	".*:.*Execute.*"
	".*:.*Start.*"
	".*:.*Modify.*"
	".*:.*Register.*"
	".*:.*Replace.*"
	".*:.*Change.*"
	".*:.*Update.*"
	".*:.*Put.*"
)

known_dangerous_permissions=(
	"*:*"
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
potentially_dangerous_permissions=()
all_perms=()

for policy in "${attached_role_policies[@]}" ; do
	echo -e "\n=============== Attached Policy Arn: $policy ==============="

	version_id=$(aws --profile $PROFILE iam get-policy --policy-arn $policy | jq -r '.Policy.DefaultVersionId')

	policy_version=$(aws --profile $PROFILE iam get-policy-version --policy-arn $policy --version-id $version_id)
	echo "$policy_version"

	permissions=($(echo "$policy_version" | jq -r '.PolicyVersion.Document.Statement[] | select(.Effect=="Allow") | if .Action|type=="string" then [.Action] else .Action end | .[]'))

	for perm in "${permissions[@]}" ; do
		all_perms+=("$perm")
		for dangperm in "${known_dangerous_permissions[@]}"; do
			if echo "$dangperm" | grep -iq $perm ; then
				dangerous_permissions+=("$perm")
			fi
		done
		for dangperm in "${known_potentially_dangerous_permissions[@]}"; do
			if echo "$perm" | grep -Piq "$dangperm" ; then
				potentially_dangerous_permissions+=("$perm")
			fi
		done
	done
done

if [[ ${#all_perms[@]} -gt 0 ]]; then
	echo -e "\n\n=============== All permissions granted to this role ==============="
	sorted=($(echo "${all_perms[@]}" | tr ' ' '\n' | sort -u ))
	for perm in "${sorted[@]}"; do
		echo -e "\t$perm"
	done

	if [[ ${#potentially_dangerous_permissions[@]} -gt 0 ]]; then
		echo -e "\n\n=============== Detected POTENTIALLY dangerous permissions granted ==============="
		sorted=($(echo "${potentially_dangerous_permissions[@]}" | tr ' ' '\n' | sort -u ))
		for dangperm in "${sorted[@]}"; do
			echo -e "\t$dangperm"
		done
	else
		echo -e "\nNo potentially dangerous permissions were found to be granted."
	fi

	if [[ ${#dangerous_permissions[@]} -gt 0 ]]; then
		echo -e "\n\n=============== Detected dangerous permissions granted ==============="
		sorted=($(echo "${dangerous_permissions[@]}" | tr ' ' '\n' | sort -u ))
		for dangperm in "${sorted[@]}"; do
			echo -e "\t$dangperm"
		done
	else
		echo -e "\nNo dangerous permissions were found to be granted."
	fi
else
	echo -e "\nNo permissions were found to be granted."
fi

