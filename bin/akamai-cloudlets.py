"""
Copyright 2020 Akamai Technologies, Inc. All Rights Reserved.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""
from __future__ import annotations

import configparser
import csv
import json
import logging
import os
import sys
import time
from time import gmtime
from time import strftime

import click
import numpy as np
import pandas as pd
import requests
from akamai.edgegrid import EdgeGridAuth
from akamai.edgegrid import EdgeRc
from cloudlet_api_wrapper import Cloudlet
from prettytable import PrettyTable
from rich import print_json
from tabulate import tabulate
from utility import PythonLiteralOption
from utility import Utility

"""
This code leverages Akamai OPEN API to work with Cloudlets.
In case you need quick explanation contact the authors.
Authors: vbhat@akamai.com, kchinnan@akamai.com, aetsai@akamai.com
"""

PACKAGE_VERSION = '1.0.1'

# setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')
log_file = os.path.join('logs', 'cloudlets.log')

# set the format of logging in console and file separately
log_formatter = logging.Formatter(
    '%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s')
console_formatter = logging.Formatter('%(message)s')
root_logger = logging.getLogger()

logfile_handler = logging.FileHandler(log_file, mode='w')
logfile_handler.setFormatter(log_formatter)
root_logger.addHandler(logfile_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(console_formatter)
root_logger.addHandler(console_handler)
# set log level to DEBUG, INFO, WARNING, ERROR, CRITICAL
root_logger.setLevel(logging.INFO)


def init_config(edgerc_file, section):
    if not edgerc_file:
        if not os.getenv('AKAMAI_EDGERC'):
            edgerc_file = os.path.join(os.path.expanduser('~'), '.edgerc')
        else:
            edgerc_file = os.getenv('AKAMAI_EDGERC')

    if not os.access(edgerc_file, os.R_OK):
        root_logger.error("ERROR: Unable to read edgerc file \"%s\"" % edgerc_file)
        exit(1)

    if not section:
        if not os.getenv('AKAMAI_EDGERC_SECTION'):
            section = 'cloudlets'
        else:
            section = os.getenv('AKAMAI_EDGERC_SECTION')

    try:
        edgerc = EdgeRc(edgerc_file)
        base_url = edgerc.get(section, 'host')

        session = requests.Session()
        session.auth = EdgeGridAuth.from_edgerc(edgerc, section)

        return base_url, session
    except configparser.NoSectionError:
        root_logger.error("ERROR: edgerc section \"%s\" not found" % section)
        exit(1)
    except Exception:
        root_logger.info(
            'ERROR: Unknown error occurred trying to read edgerc file (%s)' %
            edgerc_file)
        exit(1)


class Config:
    def __init__(self):
        pass


pass_config = click.make_pass_decorator(Config, ensure=True)


@click.group(context_settings={'help_option_names': ['-h', '--help']})
@click.option('--edgerc', metavar='', default=os.path.join(os.path.expanduser('~'), '.edgerc'), help='Location of the credentials file [$AKAMAI_EDGERC]', required=False)
@click.option('--section', metavar='', help='Section of the credentials file [$AKAMAI_EDGERC_SECTION]', required=False)
@click.option('-a', '--account-key', metavar='', help='Account Key', required=False)
@click.version_option(version=PACKAGE_VERSION)
@pass_config
def cli(config, edgerc, section, account_key):
    '''
    Akamai CLI for Cloudlets
    '''
    config.edgerc = edgerc
    config.section = section
    config.account_key = account_key


@cli.command()
@click.pass_context
def help(ctx):
    '''
    Show help information
    '''
    print(ctx.parent.get_help())


@cli.command(short_help='List policies')
@click.option('--json', 'optjson', metavar='', help='Output the policy details in json format', is_flag=True, required=False)
@click.option('--csv', 'optcsv', metavar='', help='Output the policy details in csv format', is_flag=True, required=False)
@click.option('--cloudlet-type', metavar='', help='Abbreviation code for cloudlet type', required=False)
@click.option('--name-contains', metavar='', help='String to use for searching for policies by name', required=False)
@pass_config
def list(config, optjson, optcsv, cloudlet_type, name_contains):
    '''
    List policies
    '''
    base_url, session = init_config(config.edgerc, config.section)

    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    cloudlet_type = cloudlet_type
    name_contains = name_contains
    if cloudlet_type:
        if cloudlet_type.upper() not in utility_object.do_cloudlet_code_map().keys():
            root_logger.info(f'ERROR: {cloudlet_type} is not a valid cloudlet type code')
            keys = []
            for key in utility_object.do_cloudlet_code_map():
                keys.append(key)
            print(f'Cloudlet Type Codes: {keys}')
            exit(-1)
        else:
            utility_object.do_cloudlet_code_map()[cloudlet_type.upper()]

    root_logger.info('...fetching policy list')
    policies_response = cloudlet_object.list_policies(session)
    if policies_response.status_code == 200:
        policies_data = policies_response.json()
    else:
        root_logger.info('ERROR: Unable to fetch policy list')
        root_logger.info(json.dumps(policies_response.json(), indent=4))
        exit(-1)

    df = pd.DataFrame(policies_data)
    df.rename(columns={'policyId': 'Policy ID', 'name': 'Policy Name', 'cloudletCode': 'Type', 'groupId': 'Group ID'}, inplace=True)
    df = df[['Policy ID', 'Policy Name', 'Type', 'Group ID']]
    df.sort_values('Policy Name', inplace=True, key=lambda col: col.str.lower())
    df.reset_index(drop=True, inplace=True)

    if name_contains:  # check whether user passed a filter
        df = df[df['Policy Name'].str.contains(name_contains, case=False)]
        df.reset_index(drop=True, inplace=True)

    if cloudlet_type:  # only searching by cloudlet type
        df = df[df['Type'] == cloudlet_type.upper()]
        df.reset_index(drop=True, inplace=True)

    if optjson:
        print_json(df.to_json(orient='records'))
    elif optcsv:
        df.to_csv('temp_output.csv', header=True, index=None, sep=',', mode='w')
        with open('temp_output.csv') as f:
            for line in f:
                print(line.rstrip())
        os.remove('temp_output.csv')
    else:
        print(tabulate(df, headers='keys', tablefmt='psql', showindex=False))
    root_logger.info(f'{len(df.index)} policies found')


@cli.command(short_help='List shared policies')
@click.option('--json', 'optjson', metavar='', help='Output the policy details in json format', is_flag=True, required=False)
@click.option('--csv', 'optcsv', metavar='', help='Output the policy details in csv format', is_flag=True, required=False)
@click.option('--cloudlet-type', metavar='', help='Abbreviation code for cloudlet type', required=False)
@click.option('--name-contains', metavar='', help='String to use for searching for policies by name', required=False)
@pass_config
def list_share(config, optjson, optcsv, cloudlet_type, name_contains):
    '''
    List Share Policies
    '''
    base_url, session = init_config(config.edgerc, config.section)

    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    cloudlet_type = cloudlet_type
    name_contains = name_contains
    if cloudlet_type:
        if cloudlet_type.upper() not in utility_object.do_cloudlet_code_map().keys():
            root_logger.info(f'ERROR: {cloudlet_type} is not a valid cloudlet type code')
            keys = []
            for key in utility_object.do_cloudlet_code_map():
                keys.append(key)
            print(f'Cloudlet Type Codes: {keys}')
            exit(-1)
        else:
            utility_object.do_cloudlet_code_map()[cloudlet_type.upper()]

    root_logger.info('...fetching policy list')
    policies_data = cloudlet_object.list_shared_policies(session)
    if not policies_data:
        root_logger.info('ERROR: Unable to fetch policy list')
        root_logger.info(json.dumps(policies_data.json(), indent=4))
        exit(-1)

    df = pd.DataFrame(policies_data)
    df.rename(columns={'id': 'Policy ID', 'name': 'Policy Name', 'cloudletType': 'Type', 'groupId': 'Group ID'}, inplace=True)
    df = df[['Policy ID', 'Policy Name', 'Type', 'Group ID']]
    df.sort_values('Policy Name', inplace=True, key=lambda col: col.str.lower())
    df.reset_index(drop=True, inplace=True)

    if name_contains:  # check whether user passed a filter
        df = df[df['Policy Name'].str.contains(name_contains, case=False)]
        df.reset_index(drop=True, inplace=True)

    if cloudlet_type:  # only searching by cloudlet type
        df = df[df['Type'] == cloudlet_type.upper()]
        df.reset_index(drop=True, inplace=True)

    if optjson:
        print_json(df.to_json(orient='records'))
    elif optcsv:
        df.to_csv('temp_output.csv', header=True, index=None, sep=',', mode='w')
        with open('temp_output.csv') as f:
            for line in f:
                print(line.rstrip())
        os.remove('temp_output.csv')
    else:
        print(tabulate(df, headers='keys', tablefmt='psql', showindex=False, numalign='left'))
    root_logger.info(f'{len(df.index)} shared policies found')


@cli.command(short_help='Show status for a specific policy')
@click.option('--policy-id', metavar='', help='Policy Id', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@pass_config
def status(config, policy_id, policy):
    """
    Show status for a specific policy
    """
    base_url, session = init_config(config.edgerc, config.section)

    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()

    policy_name = policy
    policy_id = policy_id

    if policy_id and policy:
        root_logger.info('Please specify either policy or policy-id.')
        exit(-1)

    if not policy_id and not policy:
        root_logger.info('Please specify either policy or policy-id.')
        exit(-1)

    # get policy
    if policy:
        root_logger.info('...searching for cloudlet policy ' + str(policy_name))
        policy_info = utility_object.get_policy_by_name(session, cloudlet_object, policy_name, root_logger)
    else:
        root_logger.info('...searching for cloudlet policy-id ' + str(policy_id))
        policy_info = utility_object.get_policy_by_id(session, cloudlet_object, policy_id, root_logger)

    try:
        policy_id = policy_info['policyId']
        policy_name = policy_info['name']
        root_logger.info('...found policy-id ' + str(policy_id))
    except:
        root_logger.info('ERROR: Unable to find existing policy')
        exit(-1)

    # setup a table
    table = PrettyTable(['Version', 'Network', 'PM Config', 'PM Version'])

    for every_policy in policy_info['activations']:
        table_row = []
        table_row.append(every_policy['policyInfo']['version'])
        table_row.append(every_policy['network'])
        table_row.append(every_policy['propertyInfo']['name'])
        table_row.append(str(every_policy['propertyInfo']['version']))
        table.add_row(table_row)

    table.align = 'l'
    print(table)


@cli.command(short_help='Show status for a specific shared policy')
@click.option('--policy-id', metavar='', help='Policy Id', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@pass_config
def status_share(config, policy_id, policy):
    base_url, session = init_config(config.edgerc, config.section)

    if policy_id and policy:
        root_logger.info('Please specify either policy or policy-id')
        exit(-1)

    if not policy_id and not policy:
        root_logger.info('Please specify either policy or policy-id')
        exit(-1)

    cloudlet_object = Cloudlet(base_url, config.account_key)
    if policy:
        root_logger.info(f'...searching for cloudlet policy {policy}')
        policy_id, policy_info = cloudlet_object.list_shared_policies_by_name(session, policy_name=policy)
    else:
        root_logger.info(f'...searching for cloudlet policy-id {policy_id}')
        name, policy_info = cloudlet_object.list_shared_policies_by_id(session, policy_id=policy_id)
        print(f'Policy Name: {name}') if name else None

    if not policy_info:
        root_logger.info('Not found')
    else:
        df = pd.DataFrame(policy_info)
        staging = df.loc[df['network'] == 'staging'].iloc[0, 0]
        production = df.loc[df['network'] == 'production'].iloc[0, 0]

        df = cloudlet_object.get_active_properties(session, policy_id)
        df['policy version'] = df.apply(lambda row: fill_column(row, staging, production), axis=1)

        new_header = f'Policy ID ({policy_id}) version'
        df.rename(columns={'policy version': new_header}, inplace=True)
        columns = [new_header, 'network', 'property name', 'property version']
        print(tabulate(df[columns], headers='keys', tablefmt='psql', showindex=False, numalign='center'))


def fill_column(row, staging_version: int, production_version: int):
    if row['network'] == 'staging':
        return staging_version
    return production_version


@cli.command(short_help='Create a new policy')
@click.option('--group-id', metavar='', help='Group Id', required=False)
@click.option('--group-name', metavar='', help='Group Name', required=False)
@click.option('--notes', metavar='', help='Policy Notes', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=True)
@click.option('--cloudlet-type', metavar='', help='Abbreviation code for cloudlet type', required=True)
@pass_config
def create_policy(config, group_id, group_name, notes, policy, cloudlet_type):
    """
    Create a new policy
    """
    base_url, session = init_config(config.edgerc, config.section)

    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    policy_name = policy
    group_id = group_id
    group_name = group_name

    if group_id:
        if group_id.startswith('grp_'):
            group_id = group_id.split('_')[1]
        try:
            group_id = int(group_id)
        except:
            root_logger.info('group-id must be a number or start with grp_')
            exit(-1)

    cloudlet_type = cloudlet_type.upper()
    if notes:
        description = notes
    else:
        # notes not specified, create our own default description
        description = f'{policy_name} (Created by Cloudlet CLI)'

    if group_id and group_name:
        root_logger.info('Please specify either group-id or group-name.')
        exit(-1)

    if group_id is None and group_name is None:
        root_logger.info('Please specify either group-id or group-name.')
        exit(-1)

    # verify valid cloudlet type code
    if cloudlet_type not in utility_object.do_cloudlet_code_map().keys():
        root_logger.info(f'ERROR: {cloudlet_type}is not a valid cloudlet type code')
        keys = []
        for key in utility_object.do_cloudlet_code_map():
            keys.append(key)
        print(f'Cloudlet Type Codes: {keys}')
        exit(-1)
    else:
        cloudlet_id = utility_object.do_cloudlet_code_map()[cloudlet_type]

    # group name passed, so check to see if it exists
    if group_name:
        found_group = False
        root_logger.info(f'...searching for group: {group_name}')
        group_response = cloudlet_object.get_groups(session)
        if group_response.status_code == 200:
            for every_group in group_response.json():
                if every_group['groupName'].upper() == group_name.upper():
                    group_id = every_group['groupId']
                    root_logger.info(f'...found group-id: {every_group["groupId"]}')
                    found_group = True
                    pass
            if not found_group:
                root_logger.info(f'ERROR: Unable to find group: {group_name}')
                exit(-1)

    policy_data = dict()
    policy_data['cloudletId'] = cloudlet_id
    policy_data['groupId'] = group_id
    policy_data['name'] = policy_name
    policy_data['description'] = description

    create_response = cloudlet_object.create_clone_policy(session, json.dumps(policy_data))

    if create_response.status_code == 201:
        print(f'Policy {create_response.json()["policyId"]} created successfully')
        pass
    else:
        root_logger.info('ERROR: Unable to create policy')
        root_logger.info(json.dumps(create_response.json(), indent=4))

    return 0


@cli.command(short_help='Create a new shared policy')
@click.option('-p', '--policy', metavar='', help='Policy Name', required=True)
@click.option('-t', '--cloudlet-type', type=click.Choice(['AS', 'ER', 'FR', 'VWR'], case_sensitive=False),
               help='Abbreviation code for cloudlet type', required=True)
@click.option('-g', '--group-id', metavar='', type=int, help='Group Id without grp_', required=False)
@click.option('--group-name', metavar='', type=str, help='Group Name', required=False)
@click.option('-n', '--notes', metavar='', help='Policy Notes', required=False)
@pass_config
def create_shared_policy(config, policy, cloudlet_type, group_id, group_name, notes):
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)

    if group_id and group_name:
        root_logger.info('Please specify either group-id or group-name.')
        exit(-1)

    if group_id is None and group_name is None:
        root_logger.info('Please specify either group-id or group-name.')
        exit(-1)

    # validate group-name
    if group_name:
        found_group = False
        root_logger.info(f'...searching for group: {group_name}')
        group_response = cloudlet_object.get_groups(session)
        if group_response.status_code == 200:
            for every_group in group_response.json():
                if every_group['groupName'].upper() == group_name.upper():
                    group_id = every_group['groupId']
                    root_logger.info(f'...found group-id: {every_group["groupId"]}')
                    found_group = True
                    pass
            if not found_group:
                root_logger.info(f'ERROR: Unable to find group: {group_name}')
                exit(-1)

    response = cloudlet_object.create_shared_policy(session, name=policy, cloudlet_type=cloudlet_type, group_id=group_id, notes=notes)
    if response.status_code == 201:
        print(f'Policy {response.json()["id"]} created successfully')
    else:
        root_logger.info('ERROR: Unable to create policy')
        root_logger.info(json.dumps(response.json(), indent=4))
        exit(-1)


@cli.command(short_help='Deprecated')
@click.option('--version', metavar='', help='Policy version number', required=False)
@click.option('--policy-id', metavar='', help='Policy Id', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@click.option('--notes', metavar='', help='New Policy Notes', required=False)
@click.option('--new-group-name', metavar='', help='Group Name of new policy', required=False)
@click.option('--new-group-id', metavar='', help='Group Id of new policy', required=False)
@click.option('--new-policy', metavar='', help='New Policy Name', required=True)
@pass_config
def clone_apiv2(config, version, policy_id, policy, notes, new_group_name, new_group_id, new_policy):
    """
    Clone policy from an existing policy
    """
    base_url, session = init_config(config.edgerc, config.section)

    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    policy_name = policy
    policy_id = policy_id
    new_policy_name = new_policy
    group_name = new_group_name
    group_id = new_group_id

    # verify new group id argument
    if new_group_id:
        if group_id.startswith('grp_'):
            group_id = group_id.split('_')[1]
        try:
            group_id = int(group_id)
        except:
            root_logger.info('new-group-id must be a number or start with grp_')
            exit(-1)

    data = dict()

    if policy_id and policy:
        root_logger.info('Please specify either policy or policy-id.')
        exit(-1)

    if not policy_id and not policy:
        root_logger.info('Please specify either policy or policy-id.')
        exit(-1)

    # find existing policy to clone from
    if policy:
        root_logger.info('...searching for cloudlet policy ' + str(policy_name))
        policy_info = utility_object.get_policy_by_name(session, cloudlet_object, policy_name, root_logger)
    else:
        root_logger.info('...searching for cloudlet policy-id ' + str(policy_id))
        policy_info = utility_object.get_policy_by_id(session, cloudlet_object, policy_id, root_logger)

    try:
        policy_id = policy_info['policyId']
        policy_name = policy_info['name']
        cloudlet_id = policy_info['cloudletId']
        group_id = policy_info['groupId']
        root_logger.info('...found policy-id ' + str(policy_id))
    except:
        root_logger.info('ERROR: Unable to find existing policy')
        exit(-1)

    # verify new group name (if passed in)
    if new_group_name:
        found_group = False
        root_logger.info('...searching for group ' + str(group_name))
        group_response = cloudlet_object.get_groups(session)
        if group_response.status_code == 200:
            for every_group in group_response.json():
                if every_group['groupName'].upper() == group_name.upper():
                    group_id = every_group['groupId']
                    root_logger.info('...found group-id ' + str(every_group['groupId']))
                    data['groupId'] = group_id
                    found_group = True
                    pass
            if not found_group:
                root_logger.info('ERROR: Unable to find group')
                exit(-1)
    elif new_group_id:
        # group-id is passed, so use it
        data['groupId'] = int(group_id)
    else:
        # group-id is mandatory, so use the group-id of source policy
        root_logger.info('...using same policy group: ' + str(group_id))
        data['groupId'] = group_id

    if notes:
        description = notes
    else:
        description = 'Cloned from policy: ' + str(policy_name) + ' (Created by Cloudlet CLI)'

    data['description'] = description
    data['name'] = new_policy_name

    if version:
        root_logger.info('Cloning policy ' + str(policy_name) + ' v' + str(version))
        clone_response = cloudlet_object.create_clone_policy(session, json.dumps(data), policy_id, version)
    else:
        root_logger.info('Cloning policy ' + str(policy_name) + ' (latest version)')
        clone_response = cloudlet_object.create_clone_policy(session, json.dumps(data), policy_id, 'optional')

    if clone_response.status_code == 201:
        root_logger.info('Successfully cloned policy as ' + new_policy)
        print(str(clone_response.json()['policyId']))
        pass
    else:
        root_logger.info('ERROR: Unable to clone the policy')
        root_logger.info(json.dumps(clone_response.json(), indent=4))
        exit(-1)

    return 0


@cli.command(short_help='Clone policy from an existing policy using API v3')
@click.option('--policy-id', metavar='', type=int, help='Policy Id', required=True)
@click.option('--version', metavar='', cls=PythonLiteralOption, help='Policy version numbers to be cloned from i.e. [1] or [1,2,3]', default=[], required=False)
@click.option('--group-id', metavar='', type=int, help='Group ID of new policy', required=True)
@click.option('--new-policy', metavar='', help='New Policy Name', required=True)
@pass_config
def clone(config, version, policy_id, group_id, new_policy):
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    if not version:
        response = cloudlet_object.clone_policy(session, name=new_policy, policy_id=policy_id, group_id=group_id)
    else:
        response = cloudlet_object.clone_policy(session, name=new_policy, policy_id=policy_id, group_id=group_id, version=version)
    if response.status_code == 200:
        print(f'Policy {response.json()["id"]} clone successfully')
    else:
        root_logger.info('ERROR: Unable to clone policy')
        root_logger.info(json.dumps(response.json(), indent=4))
        exit(-1)


@cli.command(short_help='Update new policy version with rules')
@click.option('--policy-id', metavar='', help='Policy Id', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@click.option('--notes', metavar='', help='Policy version notes', required=False)
@click.option('--version', metavar='', help='Policy version to update otherwise creates new version', required=False)
@click.option('--file', metavar='', help='JSON file with policy data', required=True)
@pass_config
def update(config, policy_id, policy, notes, version, file):
    """
    Update new policy version with rules
    """
    base_url, session = init_config(config.edgerc, config.section)

    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    policy_name = policy
    policy_id = policy_id
    version = version

    if policy_id and policy:
        root_logger.info('Please specify either policy or policy-id.')
        exit(-1)

    if not policy_id and not policy:
        root_logger.info('Please specify either policy or policy-id.')
        exit(-1)

    # get policy
    if policy:
        root_logger.info('...searching for cloudlet policy ' + str(policy_name))
        policy_info = utility_object.get_policy_by_name(session, cloudlet_object, policy_name, root_logger)
    else:
        root_logger.info('...searching for cloudlet policy-id ' + str(policy_id))
        policy_info = utility_object.get_policy_by_id(session, cloudlet_object, policy_id, root_logger)

    try:
        policy_id = policy_info['policyId']
        policy_name = policy_info['name']
        root_logger.info('...found policy-id ' + str(policy_id))
    except:
        root_logger.info('ERROR: Unable to find existing policy')
        exit(-1)

    try:
        with open(file) as update_content:
            update_json_content = json.load(update_content)
    except:
        root_logger.info('ERROR: unable to read --file')
        exit(-1)

    # if there is no description field in <FILE>, then update it with --notes argument or use default description
    if notes:
        description = notes
    else:
        if 'description' not in update_json_content:
            description = ''
        else:
            description = update_json_content['description']
    update_json_content['description'] = description

    if version:
        # update the provided version
        root_logger.info('Updating policy ' + str(policy_name) + ' v' + str(version))
        update_response = cloudlet_object.update_policy_version(session, policy_id, version, json.dumps(update_json_content))
    else:
        # create and update a new version
        root_logger.info('Updating policy ' + str(policy_name))
        update_response = cloudlet_object.create_clone_policy_version(session, policy_id, json.dumps(update_json_content))

    if update_response.status_code == 201:
        # return version number that was just created
        print(str(update_response.json()['version']))
    elif update_response.status_code == 200:
        root_logger.info('Successfully updated policy version')
    else:
        root_logger.info('ERROR: Unable to update policy')
        root_logger.info(json.dumps(update_response.json(), indent=4))
        exit(-1)

    return 0


@cli.command(short_help='Activate policy version')
@click.option('--policy-id', metavar='', help='Policy Id', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@click.option('--version', metavar='', help='Policy version', required=False)
@click.option('--add-properties', metavar='', help='Property names to be associated to cloudlet policy (comma separated).', required=False)
@click.option('--network', metavar='', help='Akamai network (staging or prod)', required=True)
@pass_config
def activate(config, policy_id, policy, version, add_properties, network):
    """
    Activate a policy version
    """
    base_url, session = init_config(config.edgerc, config.section)

    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    policy_name = policy
    policy_id = policy_id
    network = network.lower()

    if add_properties:
        additionalPropertyNames = add_properties.split(',')
    else:
        additionalPropertyNames = []

    if network not in ['staging', 'prod']:
        root_logger.info("Please specify 'staging' or 'prod' network")
        exit(-1)

    if policy_id and policy:
        root_logger.info('Please specify either policy or policy-id.')
        exit(-1)

    if not policy_id and not policy:
        root_logger.info('Please specify either policy or policy-id.')
        exit(-1)

    # get policy
    if policy:
        root_logger.info('...searching for cloudlet policy ' + str(policy_name))
        policy_info = utility_object.get_policy_by_name(session, cloudlet_object, policy_name, root_logger)
    else:
        root_logger.info('...searching for cloudlet policy-id ' + str(policy_id))
        policy_info = utility_object.get_policy_by_id(session, cloudlet_object, policy_id, root_logger)

    try:
        policy_id = policy_info['policyId']
        policy_name = policy_info['name']
        root_logger.info('...found policy-id ' + str(policy_id))
    except:
        root_logger.info('ERROR: Unable to find existing policy')
        exit(-1)

    if version:
        version = version
    else:
        # version not specified, find latest version to activate
        version = utility_object.get_latest_version(session, cloudlet_object, policy_id, root_logger)

    # associate properties to cloudlet policy if argument passed in
    if len(additionalPropertyNames) > 0:
        root_logger.info('...associating properties: ' + str(additionalPropertyNames))

    root_logger.info('Activating ' + str(policy_name) + ' v' + str(version) + ' to ' + str(network).upper())
    start_time = round(time.time())
    activation_response = cloudlet_object.activate_policy_version(session, policy_id,
                                                                  version, additionalPropertyNames,
                                                                  network)
    if activation_response.status_code == 200:
        root_logger.info('...submitted activation request')
        status = 'pending'
        # check every 30s to see if activation status for version/network is active
        while status != 'active':
            activation_status_response = cloudlet_object.list_policy_activations(session, policy_id, network)
            if activation_status_response.status_code == 200:
                for every_activation in activation_status_response.json():
                    if str(every_activation['policyInfo']['version']) == str(version) \
                        and str(every_activation['network']).lower() == str(network):
                        status = every_activation['policyInfo']['status']
                        if status == 'active':
                            root_logger.info('Successfully activated policy version')
                            end_time = round(time.time())
                            command_time = end_time - start_time
                            root_logger.info('DURATION: ' + str(strftime('%H:%M:%S', gmtime(command_time))) + '\n')
                            break
                        else:
                            pass
            else:
                root_logger.info('ERROR: Unable to retrieve activation status')
                root_logger.info(json.dumps(activation_status_response.json(), indent=4))
                exit(-1)
            if status != 'active':
                root_logger.info('...polling 30s')
                time.sleep(30)

    else:
        root_logger.info('ERROR: Unable to activate policy')
        root_logger.info(json.dumps(activation_response.json(), indent=4))
        exit(-1)
    return 0


@cli.command(short_help='Retrieve policy detail version')
@click.option('--json', 'optjson', metavar='', help='Output the policy details in json format', is_flag=True, required=False)
@click.option('--version', metavar='', help='Policy version number', required=False)
@click.option('--policy-id', metavar='', help='Policy Id', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@click.option('--only-match-rules', metavar='', help='Retrieve only match rules section of policy version', is_flag=True, required=False)
@pass_config
def retrieve(config, optjson, version, policy_id, policy, only_match_rules):
    """
    Retrieve policy version
    """
    base_url, session = init_config(config.edgerc, config.section)

    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    policy_name = policy
    policy_id = policy_id

    if policy_id and policy:
        root_logger.info('Please specify either policy or policy-id.')
        exit(-1)

    if not policy_id and not policy:
        root_logger.info('Please specify either policy or policy-id.')
        exit(-1)

    # get policy
    if policy:
        root_logger.info(f'...searching for cloudlet policy {policy_name}')
        policy_info = utility_object.get_policy_by_name(session, cloudlet_object, policy_name, root_logger)
    else:
        root_logger.info(f'...searching for cloudlet policy-id {policy_id}')
        policy_info = utility_object.get_policy_by_id(session, cloudlet_object, policy_id, root_logger)

    try:
        policy_id = policy_info['policyId']
        policy_name = policy_info['name']
        root_logger.info(f'...found policy-id {policy_id}')
    except:
        root_logger.info('ERROR: Unable to find existing policy')
        exit(-1)

    if version:
        version = version
    else:
        # version not specified, find latest version to use
        version = utility_object.get_latest_version(session, cloudlet_object, policy_id, root_logger)

    root_logger.info(f'Retrieving version: {version}')
    retrieve_response = cloudlet_object.get_policy_version(session, policy_id, version)
    if retrieve_response.status_code == 200:
        if only_match_rules:
            # retrieve only matchRules section and strip out location akaRuleId
            matchRules = []
            try:
                for every_match_rule in retrieve_response.json()['matchRules']:
                    if 'location' in every_match_rule:
                        del every_match_rule['location']
                    if 'akaRuleId' in every_match_rule:
                        del every_match_rule['akaRuleId']
                    matchRules.append(every_match_rule)
                if optjson:
                    print_json(json.dumps({'matchRules': matchRules}))
                else:
                    df = pd.DataFrame(matchRules)
                    columns = ['name', 'statusCode', 'redirectURL', 'useIncomingQueryString', 'useRelativeUrl']  # , 'useIncomingSchemeAndHost' ]
                    matchURL = df['matchURL'].unique().tolist()
                    if len(matchURL) > 1:
                        columns.append('matchURL')
                    print(tabulate(df[columns], headers='keys', tablefmt='psql', showindex=False, numalign='center'))

                    df = pd.DataFrame(matchRules)
                    columns = []
                    id = df['id'].unique().tolist()
                    start = df['start'].unique().tolist()
                    end = df['end'].unique().tolist()
                    if len(id) > 1:
                        columns.append('id')
                    if len(start) > 1:
                        columns.append('start')
                    if len(end) > 1:
                        columns.append('end')
                    columns.append('matches')
                    df.replace(np.nan, '', regex=True, inplace=True)
                    print(tabulate(df[columns], headers='keys', tablefmt='psql', showindex=False, numalign='center'))
            except:
                root_logger.info('ERROR: Unable to retrieve matchRules')
        else:
            if optjson:
                print_json(json.dumps(retrieve_response.json()))
            else:
                df = pd.DataFrame.from_dict(retrieve_response.json(), orient='index')
                transposed_df = df.T
                columns = ['description', 'policyId', 'version', 'lastModifiedBy', 'activations']
                print(tabulate(transposed_df[columns], headers='keys', tablefmt='psql', showindex=False, numalign='center'))
    else:
        root_logger.info('ERROR: Unable to retrieve policy version')
        root_logger.info(json.dumps(retrieve_response.json(), indent=4))
        exit(-1)
    return 0


def get_prog_name():
    prog = os.path.basename(sys.argv[0])
    if os.getenv('AKAMAI_CLI'):
        prog = 'akamai cloudlets'
    return prog


def get_cache_dir():
    if os.getenv('AKAMAI_CLI_CACHE_DIR'):
        return os.getenv('AKAMAI_CLI_CACHE_DIR')
    return os.curdir


if __name__ == '__main__':
    try:
        cli_status = cli(prog_name='akamai cloudlets')
        exit(cli_status)
    except KeyboardInterrupt:
        exit(1)
