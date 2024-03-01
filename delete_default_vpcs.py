import boto3
import sys

def delete_default_vpc(session, region):
    print(f"Processing region {region}...")

    ec2 = session.resource('ec2', region_name=region)
    ec2_client = session.client('ec2', region_name=region)

    try:
        vpc = list(ec2.vpcs.filter(Filters=[{'Name': 'isDefault', 'Values': ['true']}]))[0]
        print(f"Found default VPC in region {region} with ID: {vpc.id}")
    except IndexError:
        print(f"No default VPC found in region {region}.")
        return

    try:
        # 1. Terminate EC2 instances in the VPC
        for subnet in vpc.subnets.all():
            for instance in subnet.instances.all():
                print(f"Terminating instance {instance.id}...")
                instance.terminate()
                instance.wait_until_terminated()

        # 2. Delete VPC endpoints
        vpc_endpoints = ec2_client.describe_vpc_endpoints(Filters=[{'Name': 'vpc-id', 'Values': [vpc.id]}])['VpcEndpoints']
        for ep in vpc_endpoints:
            print(f"Deleting VPC endpoint {ep['VpcEndpointId']}...")
            ec2_client.delete_vpc_endpoints(VpcEndpointIds=[ep['VpcEndpointId']])

        # 3. Delete NAT Gateways
        nat_gateways = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc.id]}])['NatGateways']
        for nat in nat_gateways:
            print(f"Deleting NAT Gateway {nat['NatGatewayId']}...")
            ec2_client.delete_nat_gateway(NatGatewayId=nat['NatGatewayId'])

        # 4. Delete Elastic Load Balancers (need 'elbv2' client)
        elbv2_client = session.client('elbv2', region_name=region)
        lbs = elbv2_client.describe_load_balancers()['LoadBalancers']
        for lb in lbs:
            if lb['VpcId'] == vpc.id:
                print(f"Deleting Load Balancer {lb['LoadBalancerArn']}...")
                elbv2_client.delete_load_balancer(LoadBalancerArn=lb['LoadBalancerArn'])

        # 5. Delete Network ACLs
        for acl in vpc.network_acls.all():
            if not acl.is_default:
                print(f"Deleting network ACL {acl.id}...")
                acl.delete()

        # 6. Delete security groups (skip 'default' group)
        for sg in vpc.security_groups.all():
            if sg.group_name != 'default':
                print(f"Deleting security group {sg.id}...")
                sg.delete()

        # 7. Disassociate and delete subnets
        for subnet in vpc.subnets.all():
            print(f"Deleting subnet {subnet.id}...")
            subnet.delete()

        # 8. Delete route tables (skip main)
        for rt in vpc.route_tables.all():
            for association in rt.associations:
                if not association.main:
                    print(f"Deleting route table association {association.id}...")
                    association.delete()
            if not rt.associations:
                print(f"Deleting route table {rt.id}...")
                rt.delete()

        # 9. Delete Network Interfaces (ENIs)
        for eni in ec2.network_interfaces.filter(Filters=[{'Name': 'vpc-id', 'Values': [vpc.id]}]):
            if eni.attachment:
                eni.detach()
            print(f"Deleting network interface {eni.id}...")
            eni.delete()

        # 10. Delete Internet Gateways
        for ig in vpc.internet_gateways.all():
            print(f"Detaching and deleting Internet Gateway {ig.id}...")
            vpc.detach_internet_gateway(InternetGatewayId=ig.id)
            ig.delete()

        # 11. Delete VPC Peering Connections
        for vpc_peer in vpc.accepted_vpc_peering_connections.all():
            print(f"Deleting VPC peering connection {vpc_peer.id}...")
            vpc_peer.delete()
        for vpc_peer in vpc.requested_vpc_peering_connections.all():
            vpc_peer.delete()

        # 12. Delete Elastic IPs (associated with the VPC's ENIs)
        for eip in ec2_client.describe_addresses()['Addresses']:
            if 'VpcId' in eip and eip['VpcId'] == vpc.id:
                print(f"Releasing Elastic IP address {eip['PublicIp']}...")
                ec2_client.release_address(AllocationId=eip['AllocationId'])

        # 13. Finally, delete the VPC
        print(f"Deleting VPC {vpc.id}...")
        vpc.delete()

        print(f"Default VPC in region {region} has been successfully deleted.")
    except Exception as e:
        print(f"Failed to delete default VPC in region {region}. Reason: {str(e)}. Continuing to the next region...")

def main():
    if len(sys.argv) < 2:
        print("Usage: python delete_vpc.py <aws_profile_name>")
        sys.exit(1)

    profile_name = sys.argv[1]
    session = boto3.Session(profile_name=profile_name)

    # Fetch all available regions
    ec2_client = session.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    # Iterate through each region and delete default VPCs
    for region in regions:
        delete_default_vpc(session, region)

if __name__ == "__main__":
    main()
