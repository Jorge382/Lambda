# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import logging
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Optiene todas las regiones de AWS usando el cliente de EC2 (¿se podria filtrar para que solo use regiones con ec2?)
def get_regions():
    try:
        ec2_client = boto3.client("ec2")
        return [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    except ClientError as e:
        print(f"Error obteniendo regiones: {e}")
        return []
    
def update_auto_scaling(region):
    # Bloque de procesado de excepciones en caso de que no haya ningun grupo de autoescalado en esa región
    try:
        ag_client = boto3.client("autoscaling", region_name=region)
        paginator = ag_client.get_paginator('describe_auto_scaling_groups')
        groups = paginator.paginate(PaginationConfig={'PageSize': 100})
        filtered_asgs = groups.search('AutoScalingGroups[] | [?contains(Tags[?Key==`{}`].Value, `{}`)]'.format('Application', 'CCP'))

        for asg in filtered_asgs:
            print(asg['AutoScalingGroupName'])
            ag_client.update_auto_scaling_group(AutoScalingGroupName=asg['AutoScalingGroupName'],DesiredCapacity=0)
    except ClientError as e:
        logger.error(f"Error actualizando escalado en {region}: {e}")  

def stop_instances(region):
    # Bloque de procesado de excepciones en caso de que no haya ninguna instancia en esa región
    try:
        ec2 = boto3.resource("ec2", region_name=region)
        
        filters = [
            {
                'Name': 'instance-state-name', 
                'Values': ['running']
            }
        ]
        
        ec2.instances.filter(Filters=filters).stop()
    except ClientError as e:
        logger.error(f"Error deteniendo instancias en {region}: {e}")        

def lambda_handler(event, context):
    for region in get_regions():
        update_auto_scaling(region)
        stop_instances(region)