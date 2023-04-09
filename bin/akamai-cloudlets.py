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

PACKAGE_VERSION = '1.1.1'

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
@click.option('-e', '--edgerc', metavar='', default=os.path.join(os.path.expanduser('~'), '.edgerc'), help='Location of the credentials file [$AKAMAI_EDGERC]', required=False)
@click.option('-s', '--section', metavar='', help='Section of the credentials file [$AKAMAI_EDGERC_SECTION]', required=False)
@click.option('-a', '--account-key', metavar='', help='Account Key', required=False)
@click.version_option(version=PACKAGE_VERSION)
@pass_config
def cli(config, edgerc, section, account_key):
    '''
    Akamai CLI for Cloudlets 1.1.1
    '''
    config.edgerc = edgerc
    config.section = section
    config.account_key = account_key


@cli.command(short_help='List available cloudlets')
@pass_config
def cloudlets(config):
    """
    List available cloudlets
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    policy_df = cloudlet_object.get_schema(session)
    if not policy_df.empty:
        shared_df = cloudlet_object.available_shared_policies(session)
        if not shared_df.empty:
            shared_df['policy'] = '* shared'
        else:
            exit(-1)

        stack = pd.concat([policy_df, shared_df], axis=0)
        stack.fillna('', inplace=True)
        stack.sort_values(by=['code', 'policy'], inplace=True)
        stack['count'] = stack.groupby('code')['code'].transform('count')

        stack.reset_index(drop=True, inplace=True)
        stack['name'] = stack['name'].str.replace('_', ' ')
        stack['name'] = stack['name'].str.title()

        # combine and if code is duplicated, remove cloudlets that are not shared policy
        df1 = stack[stack['count'] == 1]
        df2 = stack[stack['policy'] == '* shared']
        df3 = pd.concat([df1, df2], axis=0)
        df3.sort_values(by=['code', 'policy'], inplace=True)
        df3.reset_index(drop=True, inplace=True)
        columns = ['name', 'code', 'policy']
        if not df3.empty:
            root_logger.info(tabulate(df3[columns], headers='keys', tablefmt='psql', showindex=False))


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
            print(f'Cloudlet Type Codes: {sorted(keys)}')
            exit(-1)
        else:
            utility_object.do_cloudlet_code_map()[cloudlet_type.upper()]
            cloudlet_object.get_schema(session)

    root_logger.info('...fetching policy list')

    policies_response = cloudlet_object.list_policies(session)
    if policies_response.status_code == 200:
        policies_data = policies_response.json()
        policy_df = pd.DataFrame(policies_data)
        policy_df['Shared Policy'] = pd.Series(dtype='str')
        policy_df.rename(columns={'policyId': 'Policy ID', 'name': 'Policy Name', 'cloudletCode': 'Type', 'groupId': 'Group ID'}, inplace=True)

    shared_policies = cloudlet_object.list_shared_policies(session)
    shared_df = pd.DataFrame(shared_policies)
    shared_df.rename(columns={'id': 'Policy ID', 'name': 'Policy Name', 'cloudletType': 'Type', 'groupId': 'Group ID'}, inplace=True)
    shared_df['Shared Policy'] = '* shared'

    df = pd.concat([policy_df, shared_df], ignore_index=True)
    df.fillna('', inplace=True)
    df = df[['Policy ID', 'Policy Name', 'Type', 'Group ID', 'Shared Policy']]
    df.sort_values('Policy Name', inplace=True, key=lambda col: col.str.lower())
    df.reset_index(drop=True, inplace=True)

    if name_contains:  # check whether user passed a filter
        df = df[df['Policy Name'].str.contains(name_contains, case=False)]
        df.reset_index(drop=True, inplace=True)

    if cloudlet_type:  # only searching by cloudlet type
        df = df[df['Type'] == cloudlet_type.upper()]
        df.reset_index(drop=True, inplace=True)

    if optjson:
        if not df.empty:
            print_json(df.to_json(orient='records'))
    elif optcsv:
        if not df.empty:
            df.to_csv('temp_output.csv', header=True, index=None, sep=',', mode='w')
            with open('temp_output.csv') as f:
                for line in f:
                    print(line.rstrip())
            os.remove('temp_output.csv')
    else:
        if not df.empty:
            print(tabulate(df, headers='keys', tablefmt='psql', showindex=False))

    root_logger.info(f'{len(df.index)} policies found')


@cli.command(short_help='Retrieve policy detail version')
@click.option('--json', 'optjson', metavar='', help='Output the policy details in json format', is_flag=True, required=False)
@click.option('--version', metavar='', help='Policy version number', required=False)
@click.option('--policy-id', metavar='', type=int, help='Policy Id', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@click.option('--only-match-rules', metavar='', help='Retrieve only match rules section of policy version', is_flag=True, required=False)
@pass_config
def retrieve(config, optjson, version, policy_id, policy, only_match_rules):
    """
    Retrieve policy detail version
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    utility_object.check_policy_input(root_logger, policy_name=policy, policy_id=policy_id)
    policy_name = policy
    type, policy_name, policy_id, policy_info = utility_object.validate_policy_arguments(session, root_logger,
                                                               cloudlet_object,
                                                               policy_name=policy_name,
                                                               policy_id=policy_id)
    if not policy_info:
        root_logger.info('ERROR: Unable to find existing policy')
        exit(-1)
    else:
        root_logger.info(f'Found policy-id {policy_id}, cloudlet policy {policy_name}')

    if type == ' ':
        if version:
            response = cloudlet_object.get_policy_version(session, policy_id, version)
        else:
            response = cloudlet_object.list_policy_versions(session, policy_id)
            if response.status_code == 200:
                version = response.json()[0]['version']
                response = cloudlet_object.get_policy_version(session, policy_id, version)

        if response.status_code == 200:
            df = pd.DataFrame.from_dict(response.json(), orient='index')
            transposed_df = df.T
            transposed_df.rename(columns={'description': 'notes', 'lastModifiedBy': 'modifiedBy', 'lastModifiedDate': 'modifiedDate'}, inplace=True)
            if not transposed_df.empty:
                transposed_df['modifiedDate'] = pd.to_datetime(transposed_df['modifiedDate'], unit='ms')
                df = transposed_df
    else:  # 'Shared Policy'
        if version:
            df, response = cloudlet_object.get_shared_policy_version(session, policy_id, version)
        else:
            # shared latest version policy
            _, version = cloudlet_object.list_shared_policy_versions(session, policy_id)
            df, response = cloudlet_object.get_shared_policy_version(session, policy_id, version)

    if optjson:
        summary = response.json()
        del summary['matchRules']
        print_json(data=summary)
    else:
        if not df.empty:
            df.rename(columns={'description': 'notes'}, inplace=True)
            columns = ['policyId', 'version', 'notes', 'modifiedBy', 'modifiedDate']
            root_logger.info(tabulate(df[columns], headers='keys', tablefmt='psql', showindex=False, numalign='center'))

    if only_match_rules:
        matchRules = []
        try:
            df = response.json()['matchRules']
            for every_match_rule in response.json()['matchRules']:
                # retrieve only matchRules section and strip out location akaRuleId
                if 'location' in every_match_rule:
                    del every_match_rule['location']
                if 'akaRuleId' in every_match_rule:
                    del every_match_rule['akaRuleId']
                matchRules.append(every_match_rule)
        except:
            root_logger.info('ERROR: Unable to retrieve matchRules')
            exit(-1)

        if len(matchRules) > 0:
            if optjson:
                print_json(json.dumps({'matchRules': matchRules}))
            else:
                temp_df = pd.DataFrame.from_records(matchRules)
                temp_df.fillna('', inplace=True)

                type, columns = utility_object.proces_matchrules_column(temp_df)
                if 'matches' in columns:
                    columns.remove('matches')
                    new_df = temp_df[columns]
                    matches = temp_df['matches'].tolist()

                    clean_matches = []
                    for x in matches:
                        if x and len(x) > 0:
                            clean_matches.append(x[0])
                        else:
                            clean_matches.append({'matchValue': '',
                                                  'matchOperator': '',
                                                  'negate': '',
                                                  'caseSensitive': '',
                                                  'matchType': ''})
                    matches_df = pd.DataFrame(clean_matches)
                    matches_df.fillna('', inplace=True)

                    combine_df = pd.concat([new_df, matches_df], axis=1)
                    root_logger.info(tabulate(combine_df, headers='keys', tablefmt='psql', showindex=True, numalign='center'))

                file_location = 'policy.xlsx'
                with pd.ExcelWriter(file_location, engine='xlsxwriter') as writer:
                    combine_df.to_excel(writer, sheet_name='Sheet1')
                root_logger.info(f'{file_location=}')

    return 0


@cli.command(short_help='Show policy status with property manager version, if any')
@click.option('--policy-id', metavar='', help='Policy Id', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@pass_config
def status(config, policy_id, policy):
    """
    Show policy status with property manager version, if any
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    utility_object.check_policy_input(root_logger, policy_name=policy, policy_id=policy_id)
    type, policy_name, policy_id, policy_info = utility_object.validate_policy_arguments(session, root_logger,
                                                               cloudlet_object,
                                                               policy_name=policy,
                                                               policy_id=policy_id)

    if not policy_info:
        root_logger.info('ERROR: Unable to find existing policy')
        exit(-1)
    else:
        root_logger.info(f'Found policy-id {policy_id}, cloudlet policy {policy_name}')

    if not policy_info:
        pass
    else:
        if type == ' ':

            # setup a table
            table = PrettyTable(['Version', 'Network', 'PM Config', 'PM Version'])
            if len(policy_info['activations']) > 0:
                for every_policy in policy_info['activations']:
                    table_row = []
                    table_row.append(every_policy['policyInfo']['version'])
                    table_row.append(every_policy['network'])
                    table_row.append(every_policy['propertyInfo']['name'])
                    table_row.append(str(every_policy['propertyInfo']['version']))
                    table.add_row(table_row)
                table.align = 'l'
                print(table)
            else:
                print('no active property')
        else:

            df = pd.DataFrame(policy_info)
            staging = df.loc[df['network'] == 'staging'].iloc[0, 0]
            production = df.loc[df['network'] == 'production'].iloc[0, 0]

            df = cloudlet_object.get_active_properties(session, policy_id)
            if not df.empty:
                df['policy version'] = df.apply(lambda row: utility_object.fill_column(row, staging, production), axis=1)

                new_header = f'Policy ID ({policy_id}) version'
                df.rename(columns={'policy version': new_header}, inplace=True)
                columns = [new_header, 'network', 'property name', 'property version']
                print(tabulate(df[columns], headers='keys', tablefmt='psql', showindex=False, numalign='center'))


@cli.command(short_help='Create a new policy')
@click.option('--group-id', metavar='', type=int, help='Group ID without grp_ prefix', required=False)
@click.option('--group-name', metavar='', help='Group Name', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=True)
@click.option('--cloudlet-type', metavar='', help='Abbreviation code for cloudlet type', required=True)
@click.option('--share', help='Shared policy', is_flag=True, default=False)
@click.option('--notes', metavar='', help='Policy Notes', required=False)
@pass_config
def create_policy(config, group_id, group_name, policy, share, cloudlet_type,
                  notes: str | None = None):
    """
    Create a new policy
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    cloudlet_type = cloudlet_type.upper()
    utility_object.check_group_input(root_logger, group_name=group_name, group_id=group_id)

    if notes:
        description = notes
    else:
        description = 'created by cloudlet CLI'

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

    if share:
        create_response, _, _ = cloudlet_object.create_shared_policy(session,
                                                                     name=policy,
                                                                     type=cloudlet_type,
                                                                     group_id=group_id,
                                                                     notes=notes)
    else:
        policy_data = dict()
        policy_data['cloudletId'] = cloudlet_id
        policy_data['groupId'] = group_id
        policy_data['name'] = policy
        policy_data['description'] = description
        create_response = cloudlet_object.create_clone_policy(session, policy_data)

    if create_response.status_code == 201:
        print(f'Policy {create_response.json()["policyId"]} created successfully')
    else:
        root_logger.info('ERROR: Unable to create policy')
        print_json(data=create_response.json())

    return 0


# @cli.command(short_help='Clone policy using API v2 [Deprecated]')
@click.option('--version', metavar='', help='Policy version number', required=False)
@click.option('--policy-id', metavar='', help='Policy ID', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@click.option('--notes', metavar='', help='New Policy Notes', required=False)
@click.option('--new-group-name', metavar='', help='Group Name of new policy', required=False)
@click.option('--new-group-id', metavar='', help='Group ID of new policy', required=False)
@click.option('--new-policy', metavar='', help='New Policy Name', required=True)
@pass_config
def clone_api_v2(config, version, policy_id, policy, notes, new_group_name, new_group_id, new_policy):
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
    """
    Clone policy from an existing policy using API v3
    """
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
@click.option('--group-id', metavar='', help='Group ID without ctr_ prefix', required=False)
@click.option('--policy-id', metavar='', help='Policy Id', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@click.option('--notes', metavar='', help='Policy version notes', required=False)
@click.option('--version', metavar='', help='Policy version to update otherwise creates new version', required=False)
@click.option('--file', metavar='', help='JSON file with policy data', required=False)
@click.option('--share', help='Shared policy', is_flag=True, default=False)
@pass_config
def update(config, group_id, policy_id, policy, notes, version, file, share):
    """
    Update new policy version with rules
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    utility_object.check_policy_input(root_logger, policy_name=policy, policy_id=policy_id)

    type, policy_name, policy_id, policy_info = utility_object.validate_policy_arguments(session, root_logger,
                                                               cloudlet_object,
                                                               policy_name=policy,
                                                               policy_id=policy_id)
    if share:
        if version:
            update_response = cloudlet_object.update_shared_policy_detail(session, policy_id, version, notes)
            if update_response.status_code == 409:
                root_logger.info(f"{update_response.json()['errors'][0]['detail']}")
            elif update_response.status_code == 200:
                root_logger.info(f'Updating policy {policy_name} v{version}')
            else:
                print_json(data=update_response.json())
                root_logger.info(f'Not able to update policy {policy_name} v{version}')
        else:
            update_response = cloudlet_object.update_shared_policy(session, policy_id, group_id, notes)
            if update_response.status_code == 400:
                print_json(data=update_response.json())
                root_logger.info(f'Not able to update policy {policy_name}')
            else:
                root_logger.info(f'Updating policy {policy_name}')
    else:
        if file:
            with open(file) as update_content:
                update_json_content = json.load(update_content)
        update_json_content = {'description': notes} if notes else {'description': 'update by cloudlets cli'}

        if version:
            # update the provided version
            update_response = cloudlet_object.update_policy_version(session, policy_id, version, data=update_json_content)
            print_json(data=update_response.json())
            if update_response.status_code == 200:
                root_logger.info(f'Updating policy {policy_name} v{version}')
        else:
            # create and update a new version
            update_response = cloudlet_object.create_clone_policy_version(session, policy_id, json.dumps(update_json_content))
            print_json(data=update_response.json())

        if update_response.status_code == 201:
            version = update_response.json()['version']
            root_logger.info(f'create and update a new version {version}')
        elif update_response.status_code == 200:
            root_logger.info('Successfully updated policy version')
        else:
            root_logger.info('ERROR: Unable to update policy')
            exit(-1)

    return 0


@cli.command(short_help='Activate a policy version')
@click.option('--policy-id', metavar='', help='Policy Id', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@click.option('--version', metavar='', help='Policy version', required=False)
@click.option('--add-properties', metavar='', help='Property names to be associated to cloudlet policy (comma separated).', required=False)
@click.option('--network', metavar='', type=click.Choice(['staging', 'production'], case_sensitive=False),
              help='Akamai network (staging or prod)', required=True)
@pass_config
def activate(config, policy_id, policy, version, add_properties, network):
    """
    Activate a policy version
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    utility_object = Utility()
    if network == 'production':
        network = 'prod'

    utility_object.check_policy_input(root_logger, policy_name=policy, policy_id=policy_id)
    type, policy_name, policy_id, policy_info = utility_object.validate_policy_arguments(session, root_logger,
                                                                                         cloudlet_object,
                                                                                         policy_name=policy,
                                                                                         policy_id=policy_id)
    # associate properties to cloudlet policy if argument passed in
    if add_properties:
        additionalPropertyNames = add_properties.split(',')
    else:
        additionalPropertyNames = []
    if len(additionalPropertyNames) > 0:
        root_logger.info(f'...associating properties: {additionalPropertyNames}')

    if not version:
        version = utility_object.get_latest_version(session, cloudlet_object, policy_id, root_logger)
        if not version:
            _, version = cloudlet_object.list_shared_policy_versions(session, policy_id)

    start_time = time.perf_counter()
    if type == ' ':
        root_logger.info(f'x {version} {network} {policy_name} {policy_id}')
        response = cloudlet_object.activate_policy_version(session, policy_id=policy_id,
                                                           version=version, network=network,
                                                           additionalPropertyNames=additionalPropertyNames)
        if response.status_code != 200:
            print(f'{response.json()["errorMessage"]}')
            exit(-1)
        else:
            activation_response = response.json()[0]
            network = network.lower()

    else:
        network = network.upper()
        response = cloudlet_object.activate_shared_policy(session, policy_id=policy_id, version=version, network=network)
        activation_response = response.json()
        activation_response_status_code = response.status_code
        root_logger.info(f'{activation_response_status_code} {network} {policy_name} {policy_id}')
        if activation_response_status_code != 202:
            root_logger.info(f'{activation_response["errorMessage"]}')
            exit(-1)

    try:
        end_time = utility_object.poll_activation(session, cloudlet_object, activation_response, type, network=network)
    except:
        root_logger.info('ERROR: Unable to retrieve activation status')
        exit(-1)
    elapse_time = str(strftime('%H:%M:%S', gmtime(end_time - start_time)))
    root_logger.info(f'Activation Duration: {elapse_time}')
    msg = f'Successfully activate policy id {policy_id} on Akamai {network} network'
    root_logger.info(f'{msg}')

    return 0


@cli.command(short_help='Show activation history status')
@click.option('--policy-id', metavar='', help='Policy Id', required=True)
@click.option('--network', metavar='', type=click.Choice(['staging', 'production'], case_sensitive=False),
              help='Akamai network (staging or production)', required=False)
@pass_config
def activation_status(config, policy_id, network):
    """
    Show activation history status
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    status_code, response = cloudlet_object.list_policy_activation(session, policy_id)
    df = pd.DataFrame()
    if status_code == 200:
        if len(response) == 0:
            root_logger.info('no activation history')
            exit(-1)
        else:
            df = pd.DataFrame(response)
            if network:
                if network == 'production':
                    networks = ['prod']
                else:
                    networks = [network]
            else:
                networks = ['staging', 'prod']
            for network in networks:
                network_temp_df = df[df['network'] == network]
                if network_temp_df.empty:
                    root_logger.info(f'no activation history on {network} network')
                else:
                    policy = network_temp_df['policyInfo'].values.tolist()
                    policy_df = pd.DataFrame(policy)
                    if not policy_df.empty:
                        policy_df['activationDate'] = pd.to_datetime(policy_df['activationDate'], unit='ms')
                        root_logger.info(f'{network} network')
                        root_logger.info(tabulate(policy_df, headers='keys', tablefmt='psql', showindex=False, numalign='center'))
                    '''
                    property = network_df['propertyInfo'].values.tolist()
                    property_df = pd.DataFrame(property)
                    property_df['activationDate'] = pd.to_datetime(property_df['activationDate'], unit='ms')
                    root_logger.info(tabulate(property_df, headers='keys', tablefmt='psql', showindex=False, numalign='center'))
                    '''
    if df.empty:
        shared_policy_response = cloudlet_object.get_activation_status(session, policy_id=policy_id)
        if shared_policy_response.status_code == 200:
            try:
                df = pd.DataFrame(shared_policy_response.json()['content'])
            except:
                print('no activation history')
            if network:
                networks = [network.upper()]
            else:
                networks = ['STAGING', 'PRODUCTION']
            df.rename(columns={'id': 'activationId', 'policyVersion': 'policy version'}, inplace=True)
            columns = ['network', 'policy version', 'operation', 'status', 'activationId', 'finishDate', 'createdBy']
            for network in networks:
                temp_df = df[df['network'] == network.upper()]
                if not temp_df.empty:
                    root_logger.info(f'Share policy {network} network')
                    root_logger.info(tabulate(temp_df[columns], headers='keys', tablefmt='psql', showindex=False, numalign='center'))
                else:
                    root_logger.info(f'no activation history in {network} network')
        else:
            root_logger.info('no activation history')


@cli.command(short_help='Cloudlet policies API endpoints specification')
@click.option('--json', 'optjson', metavar='', help='Output the policy details in json format', is_flag=True, required=False)
@click.option('--cloudlet-type', metavar='', help='cloudlet type', required=False)
@click.option('--template', metavar='', help='ie. update-policy, create-policy, update-nimbus_policy_version-ALB-1.0', required=False)
@pass_config
def policy_endpoint(config, cloudlet_type, template, optjson):
    """
    Cloudlet policies API endpoints specification
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    df, response = cloudlet_object.get_schema(session, cloudlet_type, template)
    if optjson:
        print_json(data=response.json())


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
