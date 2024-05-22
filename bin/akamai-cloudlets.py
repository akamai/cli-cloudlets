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
import platform
import subprocess
import sys
import time
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from time import gmtime
from time import strftime

import click
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

PACKAGE_VERSION = '1.1.3'

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
        root_logger.error(f'ERROR: Unable to read edgerc file {edgerc_file}')
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
    except configparser.NoSectionError:
        root_logger.error(f'ERROR: edgerc section {section} not found')
        exit(1)
    except Exception:
        root_logger.error(f'ERROR: Unknown error occurred trying to read edgerc file ({edgerc_file})')
        exit(1)
    return base_url, session


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
    Akamai CLI for Cloudlets 1.1.3
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


@cli.command(short_help='List available cloudlets')
@pass_config
def cloudlets(config):
    """
    List available cloudlets policy name/code/type for the contract
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    policy, _ = cloudlet_object.get_schema(session)
    shared_policy = cloudlet_object.available_shared_policies(session)
    column_headers = ['code', 'type', 'policy']
    if len(shared_policy) == 0:
        if len(policy) == 0:
            root_logger.info('This account does not have access to any cloudlets')
        else:
            root_logger.info(tabulate(policy, headers=column_headers, tablefmt='github', showindex=False))
    else:
        policy.extend(shared_policy)
        sorted_policy = sorted(policy, key=lambda x: x[0])
        summary = {}
        for entry in sorted_policy:
            code = entry[0]
            name = entry[1].replace('_', ' ')
            if code in summary:
                if entry[2] == '* shared':
                    summary[code] = code, name.title(), entry[2]
            else:
                summary[code] = code, name.title(), entry[2]
        summary_data = []
        for x in summary.values():
            summary_data.append(x)
        print()
        root_logger.info(tabulate(summary_data, headers=column_headers, tablefmt='github', showindex=False))


@cli.command(short_help='List policies')
@click.option('--json', 'optjson', metavar='', help='Output the policy details in json format', is_flag=True, required=False)
@click.option('--csv', 'optcsv', metavar='', help='Output the policy details in csv format', is_flag=True, required=False)
@click.option('--cloudlet-type', metavar='', help='Abbreviation code for cloudlet type', required=False)
@click.option('--name-contains', metavar='', help='String to use for searching for policies by name', required=False)
@click.option('--sortby', metavar='', help='Sort by column name',
              type=click.Choice(['id', 'name', 'type', 'lastmodified'], case_sensitive=True),
              required=False)
@pass_config
def list(config, optjson, optcsv, cloudlet_type, name_contains, sortby):
    '''
    List all cloudlet policies.
    '''
    base_url, session = init_config(config.edgerc, config.section)

    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    utility = Utility()
    cloudlet_type = cloudlet_type
    name_contains = name_contains
    if cloudlet_type:
        if cloudlet_type.upper() not in utility.do_cloudlet_code_map().keys():
            root_logger.info(f'ERROR: {cloudlet_type} is not a valid cloudlet type code')
            keys = []
            for key in utility.do_cloudlet_code_map():
                keys.append(key)
            print(f'Cloudlet Type Codes: {sorted(keys)}')
            exit(-1)
        else:
            utility.do_cloudlet_code_map()[cloudlet_type.upper()]
            cloudlet_object.get_schema(session, cloudlet_type.upper())

    root_logger.info('...fetching policy list')
    policies_response = cloudlet_object.list_policies(session)
    if policies_response is None:
        root_logger.debug('account does not have non-shared (v2) policy')
    else:
        policies_data = []
        if policies_response.ok:
            data = policies_response.json()
            if len(data) > 0:
                for x in data:
                    dt_str = datetime.fromtimestamp(x['lastModifiedDate'] / 1000).strftime('%Y-%m-%d %H:%M:%S')
                    policies_data.append([x['policyId'], x['name'], x['cloudletCode'], x['groupId'], '', dt_str])

    shared_policies = cloudlet_object.list_shared_policies(session)
    if len(shared_policies) > 0:
        shared_policies_data = []
        for x in shared_policies:
            dt_object = datetime.strptime(x['modifiedDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
            dt_str = dt_object.strftime('%Y-%m-%d %H:%M:%S')
            shared_policies_data.append([x['id'], x['name'], x['cloudletType'], x['groupId'], '* shared', dt_str])

    column_headers = ['Policy ID', 'Policy Name', 'Type', 'Group ID', 'Shared Policy', 'lastmodified']
    if not len(policies_data) > 0 or len(shared_policies) > 0:
        policies_data.extend(shared_policies_data)
        if sortby is None:
            policies_data = sorted(policies_data, key=lambda x: x[1].lower())
        else:
            if sortby == 'name':
                policies_data = sorted(policies_data, key=lambda x: x[1].lower())
            elif sortby == 'lastmodified':
                policies_data = sorted(policies_data, key=lambda x: x[5])
            elif sortby == 'type':
                policies_data = sorted(policies_data, key=lambda x: x[2])
            elif sortby == 'id':
                policies_data = sorted(policies_data, key=lambda x: x[1])

    if name_contains and len(policies_data) > 0:  # check whether user passed a filter
        temp = []
        for item in policies_data:
            if name_contains.lower() in item[1].lower():
                temp.append(item)
        policies_data = temp

    if cloudlet_type and len(policies_data) > 0:  # only searching by cloudlet type
        temp = []
        for item in policies_data:
            if cloudlet_type.upper() in item[2]:
                temp.append(item)
        policies_data = temp

    if len(policies_data) > 0:
        if optjson:
            policies = []
            for x in policies_data:
                single_policy = {}
                single_policy['Policy ID'] = x[0]
                single_policy['Policy Name'] = x[1]
                single_policy['Type'] = x[2]
                single_policy['Group ID'] = x[3]
                single_policy['Share Policy'] = x[4]
                single_policy['lastModifiedDate'] = x[5]
                policies.append(single_policy)
            print_json(data=policies)
        elif optcsv:
            if cloudlet_type is None:
                filepath = 'policy.csv'
            else:
                filepath = f'policy_{cloudlet_type}.csv'
                with open(filepath, 'w', newline='') as csvfile:
                    csv_writer = csv.writer(csvfile)
                    csv_writer.writerow(column_headers)
                    csv_writer.writerows(policies_data)
        else:
            print(tabulate(policies_data, headers=column_headers, tablefmt='psql', showindex=False))
    print()
    root_logger.info(f'{len(policies_data)} policies found')

    if optcsv:
        print()
        msg = ''
        if cloudlet_type == 'ALB':
            msg = 'You can use this as an input for alb-download command'
        root_logger.info(f'Output file saved - {filepath:<20} {msg}')


@cli.command(short_help='Retrieve policy detail version')
@click.option('--policy', metavar='', help='Policy Name (please specify either --policy-id or --policy)', required=False)
@click.option('--policy-id', metavar='', type=int, help='Policy Id (please specify either --policy-id or --policy)', required=False)
@click.option('--version', metavar='',
              help='Policy version number  (If not specified, CLI will show the latest version, if exists)',
              required=False)
@click.option('--only-match-rules', metavar='', help='Only return the rules section object  [Optional]', is_flag=True, default=False, required=False)
@click.option('--json', 'optjson', metavar='', help='Output the policy details in json format', is_flag=True, required=False)
@click.option('--show', is_flag=True, default=False,
              help='Automatically launch Microsoft Excel after (Mac OS Only)',
              required=False)
@pass_config
def retrieve(config, optjson, version, policy_id, policy, only_match_rules, show):
    """
    Retrieve policy detail version
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet = Cloudlet(base_url, config.account_key)
    cloudlet.get_account_name(session, config.account_key)
    utility_object = Utility()
    utility_object.check_policy_input(root_logger, policy_name=policy, policy_id=policy_id)
    policy_name = policy
    policy_type, policy_name, policy_id, policy_info = utility_object.validate_policy_arguments(session, root_logger,
                                                               cloudlet,
                                                               policy_name=policy_name,
                                                               policy_id=policy_id)
    if not policy_info:
        root_logger.info('ERROR: Unable to find existing policy')
        exit(-1)
    else:
        print()
        root_logger.info(f'Found policy-id {policy_id}, cloudlet policy {policy_name}')

    if policy_type == ' ':
        if version:
            response = cloudlet.get_policy_version(session, policy_id, version)
        else:
            response = cloudlet.list_policy_versions(session, policy_id)

        # Custom function to extract "status" for "staging" and "production" activations
        def get_activation_status(activations, version, network):
            for activation in activations:
                if activation['policyInfo']['version'] == version and activation['network'] == network:
                    return activation['policyInfo'].get('status')
            return None

        if response.ok:
            if version is None:
                history_response = cloudlet.list_policy_versions_history(session, policy_id)
                data = history_response.json()
            else:
                data = [response.json()]

            columns = ['version', 'lastModifiedDate', 'lastModifiedBy', 'description', 'lastModifiedBy']
            policy_data = []
            for record in data:
                filter_value = []
                policy = {k: record[k] for k in ('version', 'lastModifiedDate', 'lastModifiedBy', 'description')}
                for key, value in policy.items():
                    if key == 'lastModifiedDate':
                        dt_str = datetime.fromtimestamp(value / 1000).strftime('%Y-%m-%d %H:%M:%S')
                        filter_value.append(dt_str)
                    elif isinstance(value, int):
                        filter_value.append(str(value))
                    else:
                        filter_value.append(value)
                policy_data.append(filter_value)

            policy_history = []
            for i, policy in enumerate(data):
                activations = policy.get('activations')
                update_policy = deepcopy(policy_data[i])

                if isinstance(activations, str):
                    update_policy.insert(3, ' ')
                    update_policy.insert(4, ' ')
                else:
                    version = policy.get('version')
                    staging = get_activation_status(activations, version, 'staging')
                    production = get_activation_status(activations, version, 'production')
                    update_policy.insert(3, staging) if staging else update_policy.insert(3, ' ')
                    update_policy.insert(4, production) if production else update_policy.insert(4, ' ')
                policy_history.append(update_policy)
    else:  # 'Shared Policy'
        if version:
            data, response = cloudlet.get_shared_policy_version(session, policy_id, version)
        else:
            # shared latest version policy
            data, version, history_response = cloudlet.list_shared_policy_versions(session, policy_id)
            _, response = cloudlet.get_shared_policy_version(session, policy_id, version)

    if optjson:
        print_json(data=response.json())
    else:
        if len(data) > 0:
            if policy_type == ' ':
                history_columns = ['version', 'last modified', 'last editor', 'staging', 'production', 'notes']
                root_logger.info(tabulate(policy_history, headers=history_columns, maxcolwidths=60, tablefmt='psql', numalign='center'))
            else:
                history_columns = ['description', 'version', 'createdBy', 'createdDate', 'modifiedBy', 'lock']
                root_logger.info(tabulate(data, headers=history_columns, tablefmt='psql'))

    # Writing full json from latest version
    json_file = 'policy.json'
    with open(json_file, 'w') as f:
        json.dump(response.json(), f, indent=4)
    root_logger.info(f'Full policy json is saved at {json_file}')
    print('\n\n')

    if only_match_rules:
        matchRules = []
        try:
            for every_match_rule in response.json()['matchRules']:
                # retrieve only matchRules section and strip out location akaRuleId
                if every_match_rule['type'] == 'igMatchRule':
                    del every_match_rule['matchURL']

                if 'location' in every_match_rule:
                    del every_match_rule['location']
                if 'akaRuleId' in every_match_rule:
                    del every_match_rule['akaRuleId']
                matchRules.append(every_match_rule)
        except:
            root_logger.info('ERROR: Unable to retrieve matchRules, please specify --version')
            exit(-1)

        if len(matchRules) == 0:
            print()
            root_logger.info('no matchrule found')
            exit(-1)
        else:
            print_json(json.dumps({'matchRules': matchRules}))
            # Writing full json
            json_file = 'policy_matchrules.json'
            with open(json_file, 'w') as f:
                json.dump({'matchRules': matchRules}, f, indent=4)
            root_logger.info(f'matchrules policy json is saved at {json_file}')

            '''
            else:
                original_df = pd.DataFrame.from_records(matchRules)

                try:
                    total_rows = original_df.shape[0]
                    if total_rows == original_df['matchURL'].isna().sum():
                        del original_df['matchURL']
                except:
                    pass

                if 'matchURL' in original_df.columns:
                    original_df['match_type'] = ['matchURL' if isinstance(x, str) else 'matchValue' for x in original_df['matchURL']]
                    if 'matches' in original_df.columns:
                        original_df['matchURL'].fillna(original_df['matches'], inplace=True)
                else:
                    original_df['match_type'] = 'matchValue'

                type, columns, match_types = utility_object.proces_matchrules_column(original_df)
                root_logger.info(f'{type=}')
                print()
                root_logger.info('match rules')

                if 'matches' not in columns:
                    # --policy-id 163451
                    sheet1 = original_df[columns]
                    sheet2 = pd.DataFrame()
                    root_logger.info(tabulate(sheet1, headers='keys', tablefmt='psql', showindex=True, numalign='center'))
                else:
                    new_df = original_df
                    new_df = new_df.fillna('')

                    if len(match_types) == 1 and match_types[0] == 'matchValue':
                        # --policy-id 183946, 149103
                        try:
                            del new_df['matchURL']
                            columns.remove('matchURL')
                        except:
                            "columns doesn't exist"

                        columns.remove('match_type')
                        columns.remove('matches')

                        subtracted = ['matchType', 'matchOperator', 'matchValue', 'negate', 'caseSensitive']
                        if 'objectMatchValue' in subtracted:
                            subtracted = subtracted + ['objectMatchValue.type', 'objectMatchValue.Value']
                        original_df['length'] = original_df['matches'].str.len()

                        matches = original_df[['name', 'matches']].to_dict('records')
                        matches_df = pd.json_normalize(matches, 'matches', ['name'])
                        matches_df['match no.'] = matches_df.assign(ind=1).groupby('name')['ind'].cumsum()
                        matched_columns = ['name', 'match no.'] + subtracted

                        member = original_df['length'].unique().tolist()
                        x = matches_df.columns.values.tolist()
                        x.remove('name')
                        x.remove('match no.')

                        if len(member) == 1 and member[0] == 1:
                            matched_columns = x
                            combine_df = pd.concat([original_df[columns], matches_df[matched_columns]], axis=1)
                            sheet1 = combine_df
                            sheet1 = sheet1.fillna('')
                            root_logger.info(tabulate(sheet1, headers='keys', tablefmt='psql', showindex=True, numalign='center'))
                            sheet2 = pd.DataFrame()
                        else:
                            sheet1 = original_df[columns]
                            sheet1 = sheet1.fillna('')
                            root_logger.info(tabulate(sheet1, headers='keys', tablefmt='psql', showindex=True, numalign='center'))

                            print()
                            root_logger.info('matches')
                            matched_columns = ['name', 'match no.'] + x
                            sheet2 = matches_df[matched_columns]
                            sheet2 = sheet2.fillna('')

                            if len(matched_columns) > 7:
                                if len(matched_columns) - 7 > 2:
                                    column_1 = matched_columns[:7]
                                    print(tabulate(sheet2[column_1], headers='keys', showindex=True, tablefmt='psql', maxcolwidths=40))
                                    column_2 = matched_columns[7:]
                                    print(tabulate(sheet2[column_2], headers='keys', showindex=True, tablefmt='psql'))
                                else:
                                    print(tabulate(sheet2[matched_columns], headers='keys', showindex=True, tablefmt='psql', maxcolwidths=20))
                            else:
                                root_logger.info(tabulate(sheet2[matched_columns], headers='keys', tablefmt='psql', showindex=True, numalign='center', maxcolwidths=40))

                    if len(match_types) == 2:
                        # --policy-id 161133, 185769, 163388,  163454
                        root_logger.info('...found both matchURL and matches')
                        new_df = original_df
                        new_df = new_df.fillna('')
                        del new_df['matches']
                        columns.remove('matches')

                        # use .loc and copy() to avoid SettingWithCopyWarning
                        # new_df = original_df[original_df['match_type'] == 'matchValue']
                        new_df = original_df.loc[original_df['match_type'] == 'matchValue'].copy()
                        del new_df['match_type']

                        new_df.rename(columns={'matchURL': 'matches'}, inplace=True)
                        matched_columns = new_df[['matches']].columns.to_list()

                        subtracted = ['matchType', 'matchOperator', 'matchValue', 'negate', 'caseSensitive']
                        if 'objectMatchValue' in subtracted:
                            subtracted = subtracted + ['objectMatchValue.type', 'objectMatchValue.Value']

                        matches = new_df[['name', 'matches']].to_dict('records')
                        matches_df = pd.json_normalize(matches, 'matches', ['name'])

                        matches_df['match no.'] = matches_df.assign(ind=1).groupby('name')['ind'].cumsum()
                        matched_columns = ['name', 'match no.'] + subtracted
                        combine_df = pd.merge(left=original_df[columns], right=matches_df[matched_columns], on='name')
                        sheet1 = original_df[columns]
                        root_logger.info(tabulate(sheet1, headers='keys', tablefmt='psql', showindex=True, numalign='center', maxcolwidths=40))

                        print()
                        root_logger.info('matches')
                        sheet2 = matches_df[matched_columns]
                        root_logger.info(tabulate(sheet2, headers='keys', tablefmt='psql', showindex=True, numalign='center'))

                filename = 'policy_matchrules.xlsx'
                file_location = Path(filename).absolute()
                utility_object.generate_excel(file_location, sheet1, sheet2)
                root_logger.info(f'Matchrules is saved at {file_location}')
                if show:
                    if platform.system() != 'Darwin':
                        root_logger.info('--show argument is supported only on Mac OS')
                    else:
                        subprocess.check_call(['open', '-a', 'Microsoft Excel', file_location])
            '''

    return 0


@cli.command(short_help='Show policy status with property manager version, if any')
@click.option('--policy', metavar='', help='Policy Name (please specify either --policy-id or --policy)', required=False)
@click.option('--policy-id', metavar='', type=int, help='Policy Id (please specify either --policy-id or --policy)', required=False)
@pass_config
def status(config, policy_id, policy):
    """
    Show policy status with property manager version, if any
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
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
        print()
        root_logger.info(f'Found policy-id {policy_id}, cloudlet policy {policy_name}')

    if not policy_info:
        pass
    else:
        if type == ' ':
            # setup a table
            new_header = f'Policy ID ({policy_id}) version'
            columns = [new_header, 'network', 'property name', 'property version']
            combined_data = []
            if len(policy_info['activations']) > 0:
                for every_policy in policy_info['activations']:
                    table_row = []
                    table_row.append(every_policy['policyInfo']['version'])
                    table_row.append(every_policy['network'])
                    table_row.append(every_policy['propertyInfo']['name'])
                    table_row.append(str(every_policy['propertyInfo']['version']))
                    combined_data.append(table_row)
                print(tabulate(combined_data, headers=columns, tablefmt='psql', numalign='center'))
            else:
                print('no active property')
        else:
            properties = cloudlet_object.get_active_properties(session, policy_id)
            new_header = f'Policy ID ({policy_id}) version'
            columns = [new_header, 'network', 'property name', 'property version']
            if len(properties) > 0:
                combined_data = []
                for policy, prop in zip(policy_info, properties):
                    policy.extend(prop[:2])
                    combined_data.append(policy)
                print(tabulate(combined_data, headers=columns, tablefmt='psql', numalign='center'))


@cli.command(short_help='Create a new policy')
@click.option('--policy', metavar='', help='Policy Name', required=True)
@click.option('--cloudlet-type', metavar='', type=click.Choice(['ALB', 'AP', 'AS', 'CD', 'ER', 'FR', 'IG', 'IV', 'MMA', 'MMB', 'VP'], case_sensitive=False),
              help='Abbreviation code for cloudlet type', required=True)
@click.option('--group-id', metavar='', type=int, help='Existing group id without grp_ prefix to be associated with cloudlet policy (please specify either --group-id or --group-name)', required=False)
@click.option('--group-name', metavar='', help='Existing group name to be associated with cloudlet policy (please specify either --group-id or --group-name)', required=False)
@click.option('--share', help='Shared policy [optional]', is_flag=True, default=False)
@click.option('--notes', metavar='', help='Policy Notes [optional]', required=False)
@click.option('--file', metavar='', help='JSON file with policy data', required=False)
@pass_config
def create_policy(config, group_id, group_name, policy, share, cloudlet_type, file, notes):
    """
    Create a new policy
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
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
        if group_response.ok:
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
        if file:
            with open(file) as f:
                match_rules = json.loads(f.read())['matchRules']
        else:
            match_rules = []

        create_response, _, _ = cloudlet_object.create_shared_policy(session,
                                                                     name=policy,
                                                                     type=cloudlet_type,
                                                                     group_id=group_id,
                                                                     matchRules=match_rules,
                                                                     notes=notes)
    else:
        policy_data = dict()
        policy_data['cloudletId'] = cloudlet_id
        policy_data['groupId'] = group_id
        policy_data['name'] = policy
        policy_data['description'] = description
        create_response = cloudlet_object.create_clone_policy(session, policy_data)

    if create_response.ok:
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
@click.option('--new-policy', metavar='', help='New Policy Name', required=True)
@click.option('--group-id', metavar='', type=int, help='Group ID of new policy', required=True)
@click.option('--version', metavar='', cls=PythonLiteralOption, help='Policy version numbers to be cloned from i.e. [1] or [1,2,3]', default=[], required=False)
@pass_config
def clone(config, version, policy_id, group_id, new_policy):
    """
    Clone policy from an existing policy using API v3
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    if not version:
        response = cloudlet_object.clone_policy(session, name=new_policy, policy_id=policy_id, group_id=group_id)
    else:
        response = cloudlet_object.clone_policy(session, name=new_policy, policy_id=policy_id, group_id=group_id, version=version)
    if response.ok:
        print(f'Policy {response.json()["id"]} clone successfully')
    else:
        root_logger.info('ERROR: Unable to clone policy')
        root_logger.info(json.dumps(response.json(), indent=4))
        exit(-1)


@cli.command(short_help='Update new policy version with rules')
@click.option('--group-id', metavar='', help='Group ID without ctr_ prefix', required=False)
@click.option('--policy', metavar='', help='Policy Name', required=False)
@click.option('--policy-id', metavar='', help='Policy Id', required=False)
@click.option('--notes', metavar='', help='Policy version notes', required=False)
@click.option('--version', metavar='', help='Policy version to update otherwise creates new version', required=False)
@click.option('--file', metavar='', help='JSON file with policy data', required=False)
@click.option('--share', help='Shared policy.  This flag is required if you update a share policy', is_flag=True, default=False)
@pass_config
def update(config, group_id, policy_id, policy, notes, version, file, share):
    """
    Update new policy version with rules
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    utility_object = Utility()
    utility_object.check_policy_input(root_logger, policy_name=policy, policy_id=policy_id)

    type, policy_name, policy_id, policy_info = utility_object.validate_policy_arguments(session, root_logger,
                                                               cloudlet_object,
                                                               policy_name=policy,
                                                               policy_id=policy_id)

    if file:
        with open(file) as f:
            update_json_content = json.loads(f.read())
    else:
        update_json_content = {}

    if share:
        if notes:
            update_json_content['description'] = notes
        else:
            update_json_content['description'] = 'update by cloudlets cli'

        if version:
            update_response = cloudlet_object.update_shared_policy_detail(session, policy_id, version,
                                                                          match_rules=update_json_content)
            if update_response.ok:
                root_logger.info(f'Updating policy {policy_name} v{version}')
            elif update_response.status_code == 409:
                root_logger.info(f"{update_response.json()['errors'][0]['detail']}")
            else:
                print_json(data=update_response.json())
                root_logger.info(f'Not able to update policy {policy_name} v{version}')
        else:
            if file is None:
                if group_id is None:
                    root_logger.error('--group_id argument is required')
                    exit(-1)
                else:
                    root_logger.info('only policy description will be updated')
                    response = cloudlet_object.update_shared_policy(session, policy_id, group_id, notes)
                    if response.ok:
                        root_logger.info('policy note is updated')
            else:
                matchRules = update_json_content['matchRules']
                version_response = cloudlet_object.create_shared_policy_version(session, policy_id, matchRules, notes)
                if version_response.ok:
                    version = version_response.json()['version']
                    root_logger.info(f'create a new version {policy_name} v{version}')
                else:
                    root_logger.info('Unable to create a new version')
    else:
        if notes:
            update_json_content['description'] = notes
        else:
            update_json_content['description'] = 'update by cloudlets cli'

        if version:
            # update the provided version
            update_response = cloudlet_object.update_policy_version(session, policy_id, version, data=update_json_content)
        else:
            # create and update a new version
            update_response = cloudlet_object.create_clone_policy_version(session, policy_id, json.dumps(update_json_content))

        if update_response.status_code == 200:
            root_logger.info(f'Successfully updated policy version {policy_name} v{version}')
        elif update_response.status_code == 201:
            version = update_response.json()['version']
            root_logger.info(f'create a new version {version}')
        else:
            print_json(data=update_response.json())
            root_logger.info('ERROR: Unable to update policy')
            exit(-1)

    return 0


@cli.command(short_help='Activate a policy version')
@click.option('--policy', metavar='', help='Policy Name', required=False)
@click.option('--policy-id', metavar='', help='Policy Id', required=False)
@click.option('--version', metavar='', help='Policy version to be activated (Optional: if not specified, latest version will be activated)', required=False)
@click.option('--network', metavar='', type=click.Choice(['staging', 'production'], case_sensitive=False),
              help='Akamai network (staging or prod)', required=True)
@click.option('--add-properties', metavar='', required=False,
              help='Property names to be associated to cloudlet policy (comma separated). (Optional: configurations will be associated to the policy which is necessary for first time activation)')
@pass_config
def activate(config, policy_id, policy, version, add_properties, network):
    """
    Activate a policy version
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    utility_object = Utility()
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
            _, version, _ = cloudlet_object.list_shared_policy_versions(session, policy_id)
    start_time = time.perf_counter()
    if type == ' ':
        if network == 'production':
            network = 'prod'
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
        root_logger.info(f'Activating policy {policy_name}')
        if activation_response_status_code != 202:
            root_logger.info(f'{activation_response["errors"]}')
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
    cloudlet_object.get_account_name(session, config.account_key)
    status_code, response = cloudlet_object.list_policy_activation(session, policy_id, network)

    if status_code == 200:
        if len(response) == 0:
            root_logger.info(f'no activation history for policy {policy_id}')
            exit(-1)
        else:
            if network:
                if network == 'production':
                    networks = ['prod']
                else:
                    networks = [network]
            else:
                networks = ['staging', 'prod']
            for network in networks:
                results = [x for x in response if x['network'] == network]

                sorted_results = sorted(results, key=lambda x: x['policyInfo']['version'], reverse=True)
                results = sorted_results

                if len(results) == 0:
                    print()
                    root_logger.info(f'no activation history on {network} network')
                else:
                    print()
                    root_logger.info(f'{network} network')
                    environment = []

                    prev_version = 0
                    for result in results:
                        res = result['policyInfo']
                        if prev_version == res['version']:
                            continue
                        else:
                            prev_version = res['version']
                            status_detail = res['status']
                            activated_by = res['activatedBy']
                            dt_str = datetime.fromtimestamp(res['activationDate'] / 1000).strftime('%Y-%m-%d %H:%M:%S')
                            environment.append([res['policyId'], res['name'], res['version'],
                                                res['status'], status_detail, activated_by, dt_str])

                    columns = ['policyId', 'name', 'version', 'status', 'statusDetail', 'activatedBy', 'activationDate']
                    root_logger.info(tabulate(environment, headers=columns, tablefmt='psql', numalign='center'))

    if status_code == 404:
        shared_policy_response = cloudlet_object.get_activation_status(session, policy_id=policy_id)
        if not shared_policy_response.ok:
            root_logger.info(f'no activation history for shared policy id {policy_id}')
        else:
            try:
                data = shared_policy_response.json()['content']
            except:
                root_logger.info('shared no activation history')
            if network:
                networks = [network.upper()]
            else:
                networks = ['STAGING', 'PRODUCTION']

            columns = ['network', 'policy version', 'operation', 'status', 'activationId', 'finishDate', 'createdBy']
            for network in networks:
                results = [x for x in data if x['network'] == network.upper()]
                if len(results) > 0:
                    print()
                    root_logger.info(f'Share policy {network} network')
                    environment = []
                    for res in results:
                        environment.append([res['network'], res['policyVersion'], res['operation'], res['status'],
                                            res['id'], res['finishDate'], res['createdBy']])
                    columns = ['network', 'policy version', 'operation', 'status', 'activationId', 'finishDate', 'createdBy']
                    root_logger.info(tabulate(environment, headers=columns, tablefmt='psql', numalign='center'))
                else:
                    root_logger.info(f'no activation history in {network} network')


@cli.command(short_help='Cloudlet policies API endpoints specification')
@click.option('--cloudlet-type', metavar='', help='cloudlet type', required=True)
@click.option('--json', 'optjson', metavar='', help='Output the policy details in json format', is_flag=True, required=False)
@click.option('--template', metavar='', help='ie. update-policy, create-policy, update-nimbus_policy_version-ALB-1.0', required=False)
@pass_config
def policy_endpoint(config, cloudlet_type, template, optjson):
    """
    Cloudlet policies API endpoints specification.  For template, add --template without .json extension
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    _, response = cloudlet_object.get_schema(session, cloudlet_type, template)
    if optjson:
        print_json(data=response.json())
    if template:
        print()
        print(f"Endpoint:              {response.json()['location']}")
        print(f"Version:               {response.json()['version']}")
        print(f"Title:                 {response.json()['title']}")
        print(f"Description:           {response.json()['description']}")
        if 'additionalDescription' in response.json().keys():
            print(f"AdditionalDescription: {response.json()['additionalDescription']}")


@cli.command(short_help='ALB - lookup origins from a single ALB policy')
@click.option('--type', metavar='', help='filter specific type.  Options: "alb", "ns", "customer"',
              default='alb',
              type=click.Choice(['alb', 'ns', 'customer']), required=False)
@click.option('--list', metavar='', help='list all load balancer', is_flag=True, required=False)
@click.option('--name-contains', metavar='', help='String to use for searching for load balance (case insensitive)', required=False)
@click.option('--lb', 'loadbalance', metavar='', help='load balancing name (case sensitive, require exact name match)', required=False)
@click.option('--version', metavar='', help='load balance version', required=False)
@click.option('--json', 'optjson', metavar='', help='Output the load balancing details in json format', is_flag=True, required=False)
@pass_config
def alb_origin(config, type, name_contains, list, loadbalance, version, optjson):
    """
    Lists the Application Load Balancer origins/data centers
    """
    util = Utility()

    if name_contains and list is False:
        sys.exit(root_logger.info('missing --list argument'))

    if type != 'alb' and list is False:
        sys.exit(root_logger.info('missing --list argument'))

    if type == 'alb':
        type = 'APPLICATION_LOAD_BALANCER'
    elif type == 'ns':
        type = 'NETSTORAGE'
    elif type == 'customer':
        type = 'CUSTOMER'
    else:
        type = None
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    lookup_resp = cloudlet_object.list_alb_conditional_origin(session, type)

    if list:
        data = lookup_resp.json()
        if name_contains and len(data) > 0:
            filter_data = [x for x in data if name_contains.lower() in x['originId'].lower()]
        else:
            filter_data = data
        if len(filter_data) > 0:
            result = []
            for x in filter_data:
                try:
                    descr = x['description']
                except:
                    descr = ' '
                result.append([x['originId'], x['type'], descr])
            columns = ['Load Balancing ID', 'type', 'description']
            sorted_result = sorted(result, key=lambda x: x[0].lower())
            root_logger.info(tabulate(sorted_result, headers=columns, tablefmt='psql', showindex=True))
        else:
            root_logger.info('not found')

    if loadbalance and version is None:
        if type != 'APPLICATION_LOAD_BALANCER':
            sys.exit(root_logger.info('Search only works with "ALB" type'))
        lookup_resp = cloudlet_object.list_load_balancing_version(session, loadbalance)
        data = lookup_resp.json()
        if len(data) == 0:
            sys.exit(f'{loadbalance} not found')
        else:
            result = []
            for x in data:
                try:
                    descr = x['description']
                except KeyError:
                    descr = ' '
                result.append([x['originId'], x['version'], x['immutable'], x['lastModifiedDate'], x['lastModifiedBy'], descr, x['deleted']])

        activation_resp = cloudlet_object.list_load_balancing_config_activation(session, loadbalance)
        activation_data = activation_resp.json()

        if activation_resp.ok:
            if len(activation_data) == 0:
                root_logger.info('\nno activation history')
        if len(activation_data) > 0:
            staging_status = ' '
            production_status = ' '
            for x in result:
                temp_version = x[1]
                network = [y for y in activation_data if y['version'] == temp_version]
                if len(network) == 0:
                    pass
                elif network[0]['network'] == 'STAGING':
                    staging_status = network[0]['status']
                else:
                    production_status = network[0]['status']
                x.insert(6, staging_status)
                x.insert(7, production_status)
            result_with_activation = result

            columns = ['Load Balancing ID', 'version', 'lock', 'Last Modified', 'Last Editor', 'Version Notes', 'STAGING', 'PRODUCTION', 'deleted']
            root_logger.info(tabulate(result_with_activation, headers=columns, numalign='center', tablefmt='psql', showindex=False))
        else:
            version_columns = ['Load Balancing ID', 'version', 'lock', 'Last Modified', 'Last Editor', 'Version Notes', 'deleted']
            root_logger.info(tabulate(result, headers=version_columns, numalign='center', tablefmt='psql', maxcolwidths=30))

    if loadbalance and version:
        version_resp = cloudlet_object.get_load_balancing_version(session, loadbalance, version)

        if not version_resp.ok:
            root_logger.info(version_resp.json()['detail'])
            exit(-1)

        if isinstance(version_resp.json(), dict):
            data = version_resp.json()
            if 'livenessSettings' in data.keys():
                data.pop('livenessSettings')

        if optjson:
            print_json(data=version_resp.json())
        else:
            sections = []
            sections.append(['Load Balancing ID', 'version', 'deleted', 'immutable',
                             'createdBy', 'createdDate', 'lastModifiedBy', 'lastModifiedDate'])
            sections.append(['dataCenters'])
            sections.append(['livenessSettings'])
            sections.append(['warnings'])

            for section in sections:
                print()

                if len(section) == 1:
                    sectn = section[0]

                    if sectn == 'dataCenters':
                        datacenter_columns = ['Data Center', 'percent', 'city',
                                                'cloudServerHostHeaderOverride', 'cloudService',
                                                'continent', 'country', 'hostname', 'latitude', 'longitude']
                        jsonkeys = ['originId', 'percent', 'city', 'cloudServerHostHeaderOverride', 'cloudService', 'continent', 'country', 'hostname', 'latitude', 'longitude']
                        dc_output = []
                        lh_output = []
                        lh = False
                        for temp_dc in data['dataCenters']:
                            dc = [temp_dc[k] for k in jsonkeys if k in temp_dc]
                            str_dc = util.dict_to_list(dc)
                            dc_output.append(str_dc)
                            if 'livenessHosts' in temp_dc.keys():
                                lh_output.append(temp_dc['livenessHosts'])
                                lh = True
                        root_logger.info(sectn)
                        root_logger.info(tabulate(dc_output, headers=datacenter_columns, numalign='center', tablefmt='psql'))

                        if lh:
                            print()
                            root_logger.info('livenessHosts')
                            root_logger.info(tabulate(lh_output, numalign='center', tablefmt='psql', showindex=False))

                    if sectn == 'livenessSettings':
                        if 'livenessSettings' in version_resp.json().keys():
                            live_data = version_resp.json()['livenessSettings']
                            output = util.dict_to_list_2(live_data.values())
                            columns = util.dict_to_list(live_data.keys())
                            print(sectn)
                            root_logger.info(tabulate(output, headers=columns, numalign='center', tablefmt='psql'))

                    if sectn == 'warnings':
                        warnings_output = []
                        headers = ['detail', 'title', 'type', 'jsonPointer']
                        if 'warnings' in data.keys():
                            for i, x in enumerate(data['warnings'], start=1):
                                temp = util.dict_to_list(x.values())
                                temp.insert(0, i)
                                warnings_output.append(temp)
                            print(sectn)
                            root_logger.info(tabulate(warnings_output, headers=headers, numalign='center', tablefmt='psql'))
                else:
                    try:
                        jsonkeys = ['originId', 'version', 'deleted', 'immutable',
                                    'createdBy', 'createdDate',
                                    'lastModifiedBy', 'lastModifiedDate']
                        if 'description' in data.keys():
                            section.insert(4, 'description')
                            jsonkeys.insert(4, 'description')
                        if 'balancingType' in data.keys():
                            section.insert(3, 'balancingType')
                            jsonkeys.insert(3, 'balancingType')
                        main_output = [[data[k] for k in jsonkeys if k in data]]
                        root_logger.info(tabulate(main_output, headers=section, numalign='center', tablefmt='psql'))
                    except:
                        print_json(data=data)
                        root_logger.error('exception')


@cli.command(short_help='ALB - Update load balancing description')
@click.option('--lb', 'loadbalance', metavar='', help='load balancing name (case sensitive, require exact name match)', required=True)
@click.option('--descr', metavar='', help='description', required=True)
@pass_config
def alb_update(config, loadbalance, descr):
    """
    Update load balancing description
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    response = cloudlet_object.update_load_balancing_config(session, loadbalance, descr)
    if response.status_code == 200:
        msg = f"Update load balancing '{response.json()['originId']}'"
        msg = f"{msg} description to '{response.json()['description']}' succesfully"
        root_logger.info(msg)
    else:
        print_json(data=response.json())


@cli.command(short_help='Remove policy')
@click.option('--policy-id', metavar='', help='policyId', required=False)
@click.option('--input', metavar='', help='csv input file contains policyID per line without header', required=False)
@pass_config
def delete_policy(config, policy_id, input):
    """
    Delete cloudlet policy
    """
    if policy_id and input:
        sys.exit(root_logger.info('Please use either policy-id or input, not both'))

    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    if policy_id:
        response_msg = cloudlet_object.delete_policy(session, policy_id)
        root_logger.info(response_msg)

    if input:
        with open(input, newline='\n') as file:
            csv_readers = csv.reader(file)
        for row in csv_readers:
            response_msg = cloudlet_object.delete_policy(session, row)
            root_logger.info(response_msg)


@cli.command(short_help='ALB - download all origins/data centers')
@click.option('--input', metavar='', help='csv input file', required=True)
@click.option('--csv', 'optcsv', metavar='', help='Output the policy details in csv format', is_flag=True, required=False)
@pass_config
def alb_download(config, input, optcsv):
    """ Retrieve all data centers from ALB policy based on an input CSV file.\n
        This only pulls ALB policies with activation history
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    utility_object = Utility()

    policies = []
    with open(input, newline='\n') as file:
        rows = csv.reader(file, delimiter=',')
        next(rows)  # skip header row
        for row in rows:
            policies.append(row)

    # print(*policies, sep='\n')
    policies_output = []
    lb_list = []
    for policy in policies:
        policy_id = policy[0]
        _, policy_name, _, policy_info = utility_object.validate_policy_arguments(session, root_logger, cloudlet_object, policy_id=policy_id)

        if policy_name is None or len(policy_info['activations']) == 0:
            policy.extend([' ', ' ', ' ', ' '])
            policies_output.append(policy)
            continue

        latest = str(utility_object.get_latest_version(session, cloudlet_object, policy_id, root_logger))
        policy.append(latest) if latest else policy.append(' ')

        staging_version = ' '
        production_version = ' '
        for act in policy_info['activations']:
            if act['network'] == 'staging':
                staging_version = act['policyInfo']['version']
            if act['network'] == 'prod':
                production_version = act['policyInfo']['version']

        activations_version = [str(staging_version), str(production_version)]
        policy.extend(activations_version)

        if staging_version:
            albMatchRule = cloudlet_object.get_policy_version(session, policy_id=policy_id, version=staging_version).json()
        if production_version:
            albMatchRule = cloudlet_object.get_policy_version(session, policy_id=policy_id, version=production_version).json()

        try:
            loadbalance = [x['forwardSettings']['originId'] for x in albMatchRule['matchRules']]
            policy.append(loadbalance)
            lb_list.extend(loadbalance)
        except KeyError:
            loadbalance = []

        policies_output.append(policy)

    columns = ['Policy ID', 'Policy Name', 'Type', 'Group ID', 'Shared Policy', 'lastModifiedDate', 'LATEST', 'STAGING', 'PRODUCTION', 'Load Balancing ID']
    root_logger.info(tabulate(policies_output, headers=columns, numalign='center', tablefmt='psql', showindex=False))

    if optcsv:
        file = 'alb_policy_with_lb.csv'
        with open(file, mode='w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',')
            csvwriter.writerow(columns)
            for row in policies_output:
                csvwriter.writerow(row)
        root_logger.info(f'\nOutput file saved - {file}')

        file = 'lb.csv'
        columns = ['Load Balancing ID']
        with open(file, mode='w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',')
            csvwriter.writerow(columns)
            for row in lb_list:
                csvwriter.writerow([row])
        root_logger.info(f'Output file saved - {file:<30}  You can use this file as an input for alb-origin-bulk command.')


@cli.command(short_help='ALB - lookup origins from multiple ALB policies')
@click.option('--input', metavar='', help='csv input file', required=True)
@click.option('--version', metavar='', help='Fetch version.  Options = ["production", "staging", "latest"]',
              type=click.Choice(['production', 'staging', 'latest']), multiple=False, required=True)
@click.option('--csv', 'optcsv', metavar='', help='Output the policy details in csv format', is_flag=True, required=False)
@pass_config
def alb_origin_bulk(config, input, version, optcsv):
    """Lookup origins from multiple ALB policies\n
       You can retrieve a list of all load balancing IDs from alb-download command.
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    utility_object = Utility()
    df = pd.read_csv(input, names=['loadbalance'], skiprows=1)

    df['version'] = df['loadbalance'].apply(lambda x: utility_object.alb_active_version(session, cloudlet_object, root_logger, x, version))
    df = df.query('version.notna()')
    df = df.sort_values(by='version', ascending=False)
    df = df.reset_index(drop=True)
    root_logger.debug(tabulate(df, headers='keys', tablefmt='psql', numalign='center', showindex=True))

    df['dataCenters'] = df.apply(lambda row: utility_object.fetch_data_centers(session, cloudlet_object, row), axis=1)
    df_exploded = pd.json_normalize(df['dataCenters'])
    df_exploded['dataCenter'] = df_exploded.apply(utility_object.extract_loadbalaner_fields, axis=1)
    df_exploded = df_exploded.reset_index(drop=True)
    df_normalized_datacenter = pd.json_normalize(df_exploded['dataCenter'])
    df = df.drop(['dataCenters'], axis=1)

    # rebuild column name based on number of datacenters
    num_datacenters = len(df_normalized_datacenter.columns)
    new_columns = [f'datacenter_{i+1}' for i in range(num_datacenters)]
    df_normalized_datacenter.columns = new_columns
    result_df = pd.concat([df, df_normalized_datacenter], axis=1)
    result_df = result_df.rename(columns={'loadbalance': 'Load Balancing ID'})
    root_logger.info(tabulate(result_df, headers='keys', tablefmt='psql', numalign='center', showindex=True))
    if optcsv:
        file = 'alb_origin_detail.csv'
        result_df.to_csv(file, index=False)
        root_logger.info(f'Output file saved - {file}')


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
