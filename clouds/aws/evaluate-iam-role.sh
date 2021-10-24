#!/bin/bash
#
# Evaluates specified AWS IAM Role or Policy given their name/Arn.
# Dumps all of the attached policies in case of Role and all of defined
# policy statements. Then goes through allowed permissions to pick all of them out.
# Finally, checks every allowed permission against a list of known troublesome ones.
#
# Mariusz Banach, mgeeky '19, <mb@binary-offensive.com>
# v0.1
#

if [ $# -lt 2 ] ; then
	echo "Usage: evaluate-iam-role.sh [-v] <profile> <role-name|policy-arn>"
	echo
	echo -e "-v\t\t\tVerbose mode. Dumps full roles/policies contents."
	echo -e "profile\t\t\tAWS credentials profile name."
	echo -e "role-name|policy-name\tEither IAM Role name or Policy Arn to evaluate."
	echo -e "\t\t\tIf 'all' was specified, will evaluate ALL used IAM Roles"
	exit 1
fi

VERBOSE=0
if [[ "$1" == "-v" ]]; then
	VERBOSE=1
	shift
fi

PROFILE=$1
ROLE_NAME=$2

known_potentially_dangerous_permissions=(
	".+:\*"
	".*:Add.*"
	".*:Attach.*"
	".*:Batch.*"
	".*:Change.*"
	".*:Command.*"
	".*:Create.*"
	".*:Delete.*"
	".*:Execute.*"
	".*:Invoke.*"
	".*:Modify.*"
	".*:Put.*"
	".*:Reboot.*"
	".*:Register.*"
	".*:Replace.*"
	".*:Run.*"
	".*:Send.*"
	".*:Set.*"
	".*:Start.*"
	".*:Update.*"
)

known_dangerous_permissions=(
	"\*:\*"
	"cloudformation:CreateStack"
	"datapipeline:CreatePipeline"
	"datapipeline:PutPipelineDefinition"
	"ec2:RunInstances"
	"glue:CreateDevEndpoint"
	"glue:UpdateDevEndpoint"
	"iam:\*"
	"iam:AddUserToGroup"
	"iam:AttachGroupPolicy"
	"iam:AttachRolePolicy"
	"iam:AttachUserPolicy"
	"iam:CreateAccessKey"
	"iam:CreateLoginProfile"
	"iam:CreatePolicyVersion"
	"iam:PassRole"
	"iam:PassRole"
	"iam:PutGroupPolicy"
	"iam:PutRolePolicy"
	"iam:PutUserPolicy"
	"iam:SetDefaultPolicyVersion"
	"iam:UpdateAssumeRolePolicy"
	"iam:UpdateLoginProfile"
	"lambda:CreateEventSourceMapping"
	"lambda:CreateFunction"
	"lambda:InvokeFunction"
	"lambda:UpdateFunctionCode"
	"sts:AssumeRole"
)

known_dangerous_aws_managed_policies=(
	"arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
	"arn:aws:iam::aws:policy/service-role/AmazonMachineLearningRoleforRedshiftDataSource"
)

dangerous_permissions=()
potentially_dangerous_permissions=()
all_perms=()
used_bad_policies=()

function examine_policy() {
	policy=$1
	role_name=$2

	out=$(aws --profile $PROFILE iam get-policy --policy-arn $policy)
	version_id=$(echo "$out" | jq -r '.Policy.DefaultVersionId')
	policy_name=$(echo "$out" | jq -r '.Policy.PolicyName')

	policy_version=$(aws --profile $PROFILE iam get-policy-version --policy-arn $policy --version-id $version_id)

	if [[ $VERBOSE == 1 ]]; then
		echo -e "\n------------[ Policy Arn: $policy ]------------"
		echo "$policy_version"
	fi

	permissions=($(echo "$policy_version" | jq -r '.PolicyVersion.Document.Statement[] | select(.Effect=="Allow") | if .Action|type=="string" then [.Action] else .Action end | .[]'))

	path=""
	if [[ "$role_name" != "" ]]; then
		path="$role_name.$policy_name."
	else
		path="$policy_name."
	fi

	if [[ "$ROLE_NAME" != "all" ]] ; then
		path=""
	fi

	for bad_policy in "${known_dangerous_aws_managed_policies[@]}"; do
		if echo "$policy" | grep -iq "$bad_policy" ; then
			used_bad_policies+=("$path$bad_policy")
		fi
	done

	for perm in "${permissions[@]}" ; do
		permadd="$path$perm"
		all_perms+=("$permadd")

		for potdangperm in "${known_potentially_dangerous_permissions[@]}"; do
			if [[ "$perm" == "iam:*" ]]; then continue ; fi
			if echo "$perm" | grep -Piq "$potdangperm" ; then
				potentially_dangerous_permissions+=("$permadd")
			fi
		done

		for dangperm in "${known_dangerous_permissions[@]}"; do
			if echo "$perm" | grep -iq "$dangperm" ; then
				dangerous_permissions+=("$permadd")
			fi
		done
	done
}

function examine_role() {
	role_name=$1

	role_policy=$(aws --profile $PROFILE iam get-role --role-name $role_name)

	if [[ $VERBOSE == 1 ]]; then
		echo -e "------------[ Role: $role_name ]------------"
		echo "$role_policy"
	fi

	attached_role_policies=($(aws --profile $PROFILE iam list-attached-role-policies --role-name $role_name | jq -r '.AttachedPolicies[].PolicyArn'))

	if [[ $VERBOSE == 1 ]]; then
		echo
	fi
	echo "[+] Role ($role_name) has following policies attached:"
	for policy in "${attached_role_policies[@]}" ; do
		echo -e "\t- $policy"
	done

	if [[ $VERBOSE == 1 ]]; then
		echo
	fi

	for policy in "${attached_role_policies[@]}" ; do
		examine_policy $policy $role_name
	done
}

#
#------------------------------------------------------------------
#

IFS=$'\n'

if [[ "$ROLE_NAME" == "all" ]]; then
	echo "[+] Evaluating ALL used IAM Roles"
	echo

	out=($(aws --profile $PROFILE iam list-roles --query 'Roles[*].RoleName' --output text | tr '\t' '\n'))

	for role in "${out[@]}"; do
		examine_role $role
	done

elif echo "$ROLE_NAME" | grep -q "arn:aws:iam:" && echo "$ROLE_NAME" | grep -q ":policy/" ; then
	echo "[+] Working on specified Policy Arn: $ROLE_NAME"
	echo

	examine_policy $ROLE_NAME
else
	echo "[+] Working on specified Role: $ROLE_NAME"
	echo

	examine_role $ROLE_NAME
fi

#------------------------------------------------------------------

if [[ ${#used_bad_policies[@]} -gt 0 ]]; then
	echo -e "\n\n[-] =============== Found AWS Managed Insecure Policies in Use ==============="
	echo
	sorted=($(echo "${used_bad_policies[@]}" | tr ' ' '\n' | sort -u ))
	for pol in "${sorted[@]}"; do
		echo -e "\t$pol"
	done
fi

if [[ ${#all_perms[@]} -gt 0 ]]; then
	echo -e "\n\n[+] =============== Permissions granted ==============="
	echo
	sorted=($(echo "${all_perms[@]}" | tr ' ' '\n' | sort -u ))
	for perm in "${sorted[@]}"; do
		echo -e "\t$perm" | sed -r 's/\./ -> /g'
	done

	if [[ ${#potentially_dangerous_permissions[@]} -gt 0 ]]; then
		echo -e "\n\n[-] =============== Detected POTENTIALLY dangerous permissions granted ==============="
		echo
		sorted=($(echo "${potentially_dangerous_permissions[@]}" | tr ' ' '\n' | sort -u ))
		for dangperm in "${sorted[@]}"; do
			echo -e "\t$dangperm" | sed -r 's/\./ -> /g'
		done
	fi

	if [[ ${#dangerous_permissions[@]} -gt 0 ]]; then
		echo -e "\n\n[!] =============== Detected DANGEROUS permissions granted ==============="
		echo
		sorted=($(echo "${dangerous_permissions[@]}" | tr ' ' '\n' | sort -u ))
		for dangperm in "${sorted[@]}"; do
			echo -e "\t$dangperm" | sed -r 's/\./ -> /g'
		done
	fi
else
	echo -e "\nNo permissions were found to be granted."
fi

echo
