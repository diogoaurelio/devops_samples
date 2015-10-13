#!/usr/bin/python
"""
Version: 0.1
Description: Basic Recipe for provisioning AWS EC2 instances for a Cloudera Cluster lab.
Notes: make sure you have VPC and subnets provisioned before you provision ec2 instances
Improvements: Include Fabric/Ansible to provision the code in the VMs + provision more than one disk per hadoop node
Authors: Diogo

"""

import boto, boto.ec2, boto.vpc, boto.ec2.networkinterface
import collections
import sys
import time

if sys.version < "3":
    from urllib2 import urlopen, Request, HTTPError
else:
    from urllib.request import urlopen, Request
    from urllib.error import HTTPError
    raw_input = input
    xrange = range

############################################## CHANGE THESE VARIABLES HERE TO CHANGE THE SCRIPT #######################################################

#Env - CHANGING THIS WILL ACTUALLY FIRE UP STUFF ON AWS
my_env = "test"

#REGION NAME
region = 'eu-central-1'

#NOTE: for this region only AVZ: A & B available currently!

my_vpc = { 'id' : 'vpc-17eb537e', 'name': 'berlin_smart_data_vpc', 'cidr_block': '172.16.0.0/16' }
my_subnets = { 'A': {
				'id': 'subnet-2d33bd44', 'cidr_block': '172.16.5.0/24', 'availability_zone': region+'a' 
				},
				'B': {
				'id': 'subnet-0f1cb374', 'cidr_block': '172.16.15.0/24', 'availability_zone': region+'b' 
				},
				#'C': {
				#'id': 'new', 'cidr_block': '172.16.25.0/24', 'availability_zone': region+'c' 
				#}
			 } 


#EC2 INSTANCE VARS

###REMINDER: do NOT forget to make sure you HAVE the SSH KEY that you specify...

ec2Group = collections.namedtuple("ec2Group", [ "name", "additional_info", "id", "image_id", "key_name", "instance_type", "security_groups", "subnet_id", "region", "private_ip_address", "monitoring_enabled", "disable_api_termination", "volumes" ])
#NOTE - laziness side-effects gotchas: PAY ATTENTION TO SUBNET STATICALLY ASSIGNED MATCHES SUBNET ID + check AMI specific for Region: https://cloud-images.ubuntu.com/locator/ec2/
#For region eu-west-1: ami => ami-b05101c7, Ubuntu 14.04 LTS (PV), trusty

ec2Instances = [ 
				ec2Group('Cloudera_Manager', 'Cloudera Manager', 'new', 'ami-b6cff2ab', 'bsd_labs_eu_central_1', 'm3.medium', 'bsd_cloudera_manager', my_subnets['A']['id'], region, '172.16.5.10', False, False,  [50]), # Ubuntu 14.04, x64, eu-west-1			
				ec2Group('Cloudera_Node_1', 'Node 1', 'new', 'ami-b6cff2ab', 'bsd_labs_eu_central_1', 'm3.large', 'bsd_cloudera_manager', my_subnets['A']['id'], region, '172.16.5.100', False, False, [60]), # Ubuntu 14.04, x64, eu-west-1
				ec2Group('Cloudera_Node_2', 'Node 2', 'new', 'ami-b6cff2ab', 'bsd_labs_eu_central_1', 'm3.large', 'bsd_cloudera_manager', my_subnets['B']['id'], region, '172.16.15.101', False, False, [60]) # Ubuntu 14.04, x64, eu-west-1
				]

#SECURITY GROUPS

SecurityGroupRule = collections.namedtuple("SecurityGroupRule", [ "ip_protocol", "from_port", "to_port", "cidr_ip", "src_group_name"])


CLOUDERA_RULES = [
    SecurityGroupRule("tcp", "22", "22", "0.0.0.0/0", "bsd_cloudera_manager"),
    SecurityGroupRule("tcp", "7180", "7180", "0.0.0.0/0", "bsd_cloudera_manager"), # Cloudera Manager web console
    SecurityGroupRule("tcp", "7183", "7183", "0.0.0.0/0", "bsd_cloudera_manager"), #Optional web console access via TLS
    SecurityGroupRule("tcp", "7182", "7182", "172.16.0.0/16", "bsd_cloudera_manager"), # Agent heartbeat
    SecurityGroupRule("tcp", "7432", "7432", "172.16.0.0/16", "bsd_cloudera_manager"), #Embedded Postgres
    SecurityGroupRule("icmp", "-1", "-1", "172.16.0.0/16", "bsd_cloudera_manager"), #Ping echo
]
HADOOP_RULES = [
		SecurityGroupRule("tcp", "22", "22", "0.0.0.0/0", "bsd_hadoop_nodes"),
		SecurityGroupRule("tcp", "50070", "50070", "0.0.0.0/0", "bsd_hadoop_nodes"), # NameNode webUI 
		SecurityGroupRule("tcp", "50090", "50090", "0.0.0.0/0", "bsd_hadoop_nodes"), # Secondary NameNode
		SecurityGroupRule("tcp", "8983", "8983", "0.0.0.0/0", "bsd_hadoop_nodes"), #Solr Web UI 
		SecurityGroupRule("tcp", "19888", "19888", "0.0.0.0/0", "bsd_hadoop_nodes"), #History Server Web UI 
		SecurityGroupRule("tcp", "18088", "18088", "0.0.0.0/0", "bsd_hadoop_nodes"), #Spark on YARN Web UI 	
		SecurityGroupRule("tcp", "8088", "8088", "0.0.0.0/0", "bsd_hadoop_nodes"), #YARN Resource Manager Web UI 
		SecurityGroupRule("tcp", "60010", "60010", "0.0.0.0/0", "bsd_hadoop_nodes"), #HBase Web UI 
		SecurityGroupRule("tcp", "25020", "25020", "0.0.0.0/0", "bsd_hadoop_nodes"), #Impala Castalogue Web UI 
		SecurityGroupRule("tcp", "25010", "25010", "0.0.0.0/0", "bsd_hadoop_nodes"), #Impala StateStore Web UI	
		#SecurityGroupRule("tcp", "7182", "7182", "172.16.0.0/16", "bsd_hadoop_nodes"), # Agent heartbeat
		SecurityGroupRule("tcp", "0", "65535", my_vpc['cidr_block'], "bsd_hadoop_nodes"),
    	SecurityGroupRule("icmp", "-1", "-1", my_vpc['cidr_block'], "bsd_hadoop_nodes"), #Ping echo
]


my_security_group = [ 				  
					  ('bsd_hadoop_nodes', 'hadoop nodes', HADOOP_RULES),
					  ('bsd_cloudera_manager', 'Cloudera manager', CLOUDERA_RULES),
					  
					]




############################################## DO NOT CHANGE THE REST OF SCRIPT UNLESS YOU KNOW #######################################################



def get_or_create_security_group(env, vpc, security_groups, group_name, description=""):
    """ Checks from the already existing groups if there is or not intended SG; if not, and env != test, then create new SG
    	args:
    		@env - control var imposed to decide which parts should do dry-run 
    		@vpc - connection object to vpc in aws
    		@security_groups - List of already existing security groups 
    		@group_name - specific Group Name to test if already exists or not
    		@description - optional Group description
    	returns:
    		@group object created
    """
    dryRun = True
    if env != "test":
    	dryRun = False
    print "Group name: " + group_name
    groups = [g for g in security_groups if g.name == group_name]
    group = groups[0] if groups else None
    if not group:
        print "Creating group '%s'..."%(group_name,)
        try:
        	group = vpc.create_security_group(group_name, description, vpc_id = my_vpc['id'], dry_run = dryRun)
        except Exception,e:
        	print e

        if env == "test":
        	print "Since Environment mode is Test, will assign group 'test' just for script to continue.."
        	group = [g for g in security_groups if g.name == "test"][0]
    else:
    	print "Group " + group.name + " already exists."
    return group




def modify_sg(env, c, group, rule, authorize=False, revoke=False):
    """ Method to modify an Security Group Rules (revoke old ones, authorize new ones)
    	args:
    		@env - control var imposed to decide which parts should do dry-run 
    		@c - connection object to aws
    		@group - specific Group to change
    		@description - optional Group description
    	returns:
    		@void
    """
    dryRun = True
    if env != "test":
    	dryRun = False

    src_group = None
    if rule.src_group_name:
        sg_id = [ sg.id for sg in c.get_all_security_groups() if sg.name == group.name ][0]

    if authorize and not revoke:
        print "Authorizing missing rule %s..."%(rule,)
        try:
        	c.authorize_security_group(ip_protocol=rule.ip_protocol,
        				        from_port=rule.from_port,
		                        to_port=rule.to_port,
		                        cidr_ip=rule.cidr_ip,
		                        group_id = sg_id,
		                        dry_run = dryRun)
        except Exception, e:
	    	print e

    elif not authorize and revoke:
        print "Revoking unexpected rule %s..."%(rule,)
        #group.revoke(ip_protocol=rule.ip_protocol,
        try:
        	c.revoke_security_group(ip_protocol=rule.ip_protocol,
        			         from_port=rule.from_port,
		                     to_port=rule.to_port,
		                     cidr_ip=rule.cidr_ip,
		                     group_id = sg_id,
		                     dry_run = dryRun)
        except Exception, e:
        	print e


def authorize(env, c, group, rule):
    """Authorize `rule` on `group`."""
    return modify_sg(env, c, group, rule, authorize=True)


def revoke(env, c, group, rule):
    """Revoke `rule` on `group`."""
    return modify_sg(env, c, group, rule, revoke=True)


def update_security_group(env, c, group, expected_rules):
    """
    """
    print 'Checking if group "%s" needs some updates...'%(group.name,)

    current_rules, count_new_rules = [], 0
    for rule in group.rules:
        if not rule.grants[0].cidr_ip:
            current_rule = SecurityGroupRule(rule.ip_protocol,
                              rule.from_port,
                              rule.to_port,
                              "0.0.0.0/0",
                              group.name)
        else:
            current_rule = SecurityGroupRule(rule.ip_protocol,
                              rule.from_port,
                              rule.to_port,
                              rule.grants[0].cidr_ip,
                              group.name)

        if current_rule not in expected_rules:
        	print "revoking old Rule.. %r"%(current_rule,)
        	revoke(env, c, group, current_rule)
        else:
        	current_rules.append(current_rule)

    for rule in expected_rules:
        if rule not in current_rules:
        	count_new_rules += 1
        	print "Authorizing the following new rule in group: %r"%(str(rule),)
        	authorize(env, c, group, rule)
    if count_new_rules < 1:
    	print "No new rules where updated for Security Group %s."%(group.name)
    else:
    	print "Updated a total of %r new rules in Security Group %r"%(str(count_new_rules), group.name)
    print "Finished updating Security Group %s." % (group.name)


def create_or_update_security_groups(env, conn, vpc, already_existing_sgs):

	for (sg,description, security_rules) in my_security_group:
		group = get_or_create_security_group(env, vpc, already_existing_sgs, sg, description)
		update_security_group(env, conn, group, security_rules)
    	print "Finished Create/Update process for Security group: "+ sg + ", with description: " + description


def get_block_device_mapping(conn, instance_id):
    volumes = conn.get_instance_attribute( instance_id=instance_id, attribute='blockDeviceMapping' )['blockDeviceMapping']
    print volumes
    print [ (k,v) for k,v in volumes.items() ]

def list_all_ec2_instances(env, conn):
	reservations = conn.get_all_reservations()
	existing_instances = [ (ec2.image_id, ec2.key_name, ec2.instance_type, ec2.placement) for res in reservations for ec2 in res.instances ]
	print "Existing instances: " + str(existing_instances)


def get_instance_status(env, conn, ec2Group):
	statuses = conn.get_all_instance_status()



def create_ec2_instance(env, conn, vpc, ec2Group):
	print "Starting Instance creation process.."
	#Launch an instance:
	new_instaces_ids, dryRun  = {}, True
	if env != "test":
		dryRun = False
	for ec2 in ec2Group:
		if ec2.id == "new":
			dev_sda1 = boto.ec2.blockdevicemapping.EBSBlockDeviceType()
			if len(ec2.volumes) <= 1: #instance has only one volume
				#TODO - specify that disk should be deleted on instance termination
				dev_sda1.size = ec2.volumes[0]
				dev_sda1.delete_on_termination=True
				bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping()
				bdm['/dev/sda1'] = dev_sda1
			#TODO increment number of disks provisioned:
			#else:
			#	for in xrange( len(ec2.volumes) -1):
			# 		conn.attach_volume (vol.id, inst.id, "/dev/sdx")
			sg_id = [ sg.id for sg in vpc.get_all_security_groups() if sg.name == ec2.security_groups ]
			if len(sg_id) > 0:
				#print ec2.private_ip_address
				interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(subnet_id = ec2.subnet_id, private_ip_address= ec2.private_ip_address, groups= sg_id, associate_public_ip_address = True)
				interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)
				print "Creating new ec2 instance - " + str(ec2)
				try:
					new_ec2 = conn.run_instances( image_id= ec2.image_id , 
												key_name=ec2.key_name, 
												instance_type=ec2.instance_type, 
												#the following two arguments are provided in the network_interface
                                				#instead at the global level !!
												#security_group_ids=sg_id, 
												#subnet_id = ec2.subnet_id, 
												network_interfaces = interfaces,
												monitoring_enabled=ec2.monitoring_enabled, 
												disable_api_termination= ec2.disable_api_termination, 
												additional_info=ec2.additional_info, 
												block_device_map =bdm, 
												dry_run = dryRun)
					if new_ec2:
						instance = new_ec2.instances[0]
						instance.update()
						while instance.state == 'pending':
							print instance, instance.state
							time.sleep(5)
							instance.update()
						if instance.state == 'running':
							new_instaces_ids[ new_ec2.instances[0] ] = ec2.additional_info
							instance.add_tag(ec2.name, ec2.additional_info)
						else:
							print "There was a problem, and instance could not be created.."
							print instance
				except Exception, e:
					print e
				
			else:
				print "Could not provision ec2 instance %s because SG %s does not exist! (tip: maybe its creation failed!)" % (str(ec2), ec2.security_groups)

	if bool(new_instaces_ids):
		print "Alright, job finished, but you still have work to do!! New instances IDs to upodate"
		print new_instaces_ids
			
	else:
		print "No new instances were provisioned. Alright, job completed!!"

def provision_vpc(env, vpc):
	dryRun = True
	if env != "test":
		dryRun = False
	print "Availability zones: " + str( vpc.get_all_zones() )
	existing_vpcs = [v for v in vpc.get_all_vpcs() if v.id == my_vpc['id'] ]
	existing_subnets = [s.id for s in vpc.get_all_subnets() ]
	print "Info: Existing VPCs: " + str(vpc.get_all_vpcs())
	print "Info: Existing Subnets: " + str(existing_subnets)
	#print my_vpc['id']

	vpc_to_prov = existing_vpcs[0] if existing_vpcs else None
	if not vpc_to_prov:
		print "Starting new VPC provisioning process.."
		new_vpc = vpc.create_vpc(my_vpc['cidr_block'], dry_run = dryRun)
		print "New VPC provisioned, please update its ID: " +str(new_vpc.id)
		provision_subnets(env, vpc, new_vpc.id, existing_subnets)
	else:
		print "vpc already exists, nothing to do here, moving on to subnets.."
		provision_subnets(env, vpc, my_vpc['id'], existing_subnets)
	
	

def provision_subnets(env, vpc, vpc_id, existing_subnets):
	dryRun = True
	if env != "test":
		dryRun = False
	count_new_subnets = 0
	for id, subnet in my_subnets.items():
		print "Checking id: %s and subnet: %s" % (id, subnet)
		if subnet['id'] not in existing_subnets:
			count_new_subnets +=1
			new_subnet = vpc.create_subnet(vpc_id, subnet['cidr_block'], availability_zone= subnet['availability_zone'], dry_run = dryRun)
			print "New Subnet with id %s provisioned, please update its ID." % (str(new_subnet.id), )
		else:
			print "Subnet %s already exists.." % subnet['id']	
	if count_new_subnets < 1:
		print "No new subnets were provisioned"
	else:
		print "A total of %s new subnets were provisioned."%(str(count_new_subnets),)


def boostrapper(env):
	"""
		Main launcher
		@env - fake variable just to distinguish between testing and prod
    """
	#from util import aws_conf
	#conn = boto.ec2.connect_to_region(aws_conf['AWS_REGION'],
    #                              aws_access_key_id=aws_conf['AWS_ACCESS_KEY_ID'],
    #                              aws_secret_access_key=aws_conf['AWS_SECRET_ACCESS_KEY'])

	#Booting up..
	conn = boto.ec2.connect_to_region(region)

	#Make sure VPC exists to bring some order
	vpc = boto.vpc.connect_to_region(region)

	try:
		provision_vpc("production", vpc)
	except Exception, e:
		print e

	#Prepare Security Groups
	already_existing_sgs = vpc.get_all_security_groups()

	#Make sure Security Groups already Exist and/or are up to date
	try:
		create_or_update_security_groups("production", conn, vpc, already_existing_sgs)	
	except Exception, e:
		print e
	#Fire new ec2 instances
	print "Current ec2 instances:"
	list_all_ec2_instances(env, conn)
	create_ec2_instance(env, conn, vpc, ec2Instances)


if __name__=="__main__":
    boostrapper(my_env)
