"""
Copyright 2020 Akamai Technologies, Inc. All Rights Reserved..

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
from pathlib import Path
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
    policy_df, _ = cloudlet_object.get_schema(session)

    shared_df = cloudlet_object.available_shared_policies(session)
    if shared_df.empty:
        if policy_df.empty:
            root_logger.info('This account does not have access to any cloudlets')
        else:
            root_logger.info(tabulate(policy_df, headers='keys', tablefmt='psql', showindex=False))
    else:
        shared_df['policy'] = '* shared'

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
        root_logger.info(tabulate(df3[columns], headers='keys', tablefmt='github', showindex=False))


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
            cloudlet_object.get_schema(session, cloudlet_type.upper())

    root_logger.info('...fetching policy list')

    policies_response = cloudlet_object.list_policies(session)
    policy_df = pd.DataFrame()
    if policies_response is None:
        root_logger.debug('account does not have non-shared (v2) policy')
    else:
        if policies_response.ok:
            policies_data = policies_response.json()
            if len(policies_data) > 0:
                policy_df = pd.DataFrame(policies_data)
                policy_df['Shared Policy'] = pd.Series(dtype='str')
                policy_df.rename(columns={'policyId': 'Policy ID', 'name': 'Policy Name', 'cloudletCode': 'Type', 'groupId': 'Group ID'}, inplace=True)
                policy_df['lastModifiedDate'] = pd.to_datetime(policy_df['lastModifiedDate'], unit='ms')
                policy_df['lastModifiedDate'] = policy_df['lastModifiedDate'].dt.strftime('%Y-%m-%d %H:%M:%S').fillna('')

    shared_policies = cloudlet_object.list_shared_policies(session)
    if len(shared_policies) == 0:
        shared_df = pd.DataFrame()
    else:
        shared_df = pd.DataFrame(shared_policies)
        shared_df.rename(columns={'id': 'Policy ID', 'name': 'Policy Name',
                                'cloudletType': 'Type',
                                'groupId': 'Group ID'}, inplace=True)
        shared_df['lastModifiedDate'] = shared_df['modifiedDate'].apply(utility_object.convert_datetime_format)
        shared_df['Shared Policy'] = '* shared'

    df = pd.DataFrame()
    if not policy_df.empty or not shared_df.empty:
        df = pd.concat([policy_df, shared_df], ignore_index=True)
        df = df.fillna('')
        df = df[['Policy ID', 'Policy Name', 'Type', 'Group ID', 'Shared Policy', 'lastModifiedDate']]
        if sortby is None:
            df.sort_values(by=['Policy Name'], inplace=True, key=lambda col: col.str.lower())
        else:
            if sortby == 'name':
                sort_by = 'Policy Name'
                df.sort_values(sort_by, inplace=True, key=lambda col: col.str.lower())
            elif sortby == 'lastmodified':
                sort_by = 'lastModifiedDate'
                df = df.sort_values(sort_by, ascending=False)
            else:
                if sortby == 'type':
                    sort_by = 'Type'
                if sortby == 'id':
                    sort_by = 'Policy ID'
                df = df.sort_values(sort_by, ascending=True)
        df.reset_index(drop=True, inplace=True)

    if name_contains and not df.empty:  # check whether user passed a filter
        df = df[df['Policy Name'].str.contains(name_contains, case=False)]
        df.reset_index(drop=True, inplace=True)

    if cloudlet_type and not df.empty:  # only searching by cloudlet type
        df = df[df['Type'] == cloudlet_type.upper()]
        df.reset_index(drop=True, inplace=True)

    if optjson:
        if not df.empty:
            print_json(df.to_json(orient='records'))
    elif optcsv:
        if not df.empty:
            if cloudlet_type is None:
                filepath = 'policy.csv'
            else:
                filepath = f'policy_{cloudlet_type}.csv'
            df.to_csv(filepath, header=True, index=None, sep=',', mode='w')
            with open(filepath) as f:
                for line in f:
                    print(line.rstrip())
    else:
        if not df.empty:
            print(tabulate(df, headers='keys', tablefmt='psql', showindex=False))

    root_logger.info(f'{len(df.index)} policies found')

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
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
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
        print()
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

            history_response = cloudlet_object.list_policy_versions_history(session, policy_id)

            # Normalize the JSON data excluding the "activations" field
            history_df = pd.json_normalize(history_response.json(),
                                   meta=['policyId', 'version', 'description',
                                         'lastModifiedBy', 'lastModifiedDate'])
            history_df = history_df.rename(columns={'description': 'notes',
                                                    'lastModifiedDate': 'last modified',
                                                    'lastModifiedBy': 'last editor',
                                                    'activation_staging': 'staging',
                                                    'activation_production': 'production'})

            # Custom function to extract "status" for "staging" and "production" activations
            def get_activation_status(activations, version, network):
                for activation in activations:
                    if activation['policyInfo']['version'] == int(version) and activation['network'] == network:
                        return activation['policyInfo'].get('status')
                return None

            history_df['staging'] = history_df.apply(lambda row: get_activation_status(row['activations'], row['version'], 'staging'), axis=1)
            history_df['production'] = history_df.apply(lambda row: get_activation_status(row['activations'], row['version'], 'prod'), axis=1)
            history_df.drop(columns=['activations'], inplace=True)
            columns = ['version', 'notes', 'last editor', 'last modified', 'staging', 'production']
            history_df['last modified'] = pd.to_datetime(history_df['last modified'], unit='ms')

    else:  # 'Shared Policy'
        if version:
            df, response = cloudlet_object.get_shared_policy_version(session, policy_id, version)
        else:
            # shared latest version policy
            df, version, history_response = cloudlet_object.list_shared_policy_versions(session, policy_id)
            _, response = cloudlet_object.get_shared_policy_version(session, policy_id, version)

    if optjson:
        print_json(data=response.json())
    else:
        if not df.empty:
            if type == ' ':
                history_columns = ['version', 'last modified', 'last editor', 'staging', 'production', 'notes']
                history_df = history_df.fillna('')
                root_logger.info(tabulate(history_df[history_columns], headers=history_columns, maxcolwidths=60,
                                        tablefmt='psql', showindex=False, numalign='center'))
            else:
                # df.rename(columns={'description': 'notes'}, inplace=True)
                # columns = ['policyId', 'version', 'notes', 'modifiedBy', 'modifiedDate']
                # root_logger.info(tabulate(df[columns], headers='keys', tablefmt='psql', showindex=False, numalign='center'))
                history_df = df.copy()
                history_columns = ['version', 'lock', 'last modified', 'last editor', 'notes']
                history_df = history_df.rename(columns={'modifiedDate': 'last modified',
                                                        'createdBy': 'last editor',
                                                        'version notes': 'notes'})

                root_logger.info(tabulate(history_df[history_columns], headers=history_columns, tablefmt='psql', showindex=False, numalign='center'))
    # Writing full json from latest version
    json_file = 'policy.json'
    with open(json_file, 'w') as f:
        json.dump(response.json(), f, indent=4)
    root_logger.info(f'Full policy json is saved at {json_file}')
    print('\n\n')

    if only_match_rules:
        matchRules = []
        try:
            df = response.json()['matchRules']
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
            root_logger.info('ERROR: Unable to retrieve matchRules')
            exit(-1)

        if len(matchRules) == 0:
            print()
            root_logger.info('no matchrule found')
            exit(-1)
        else:
            if optjson:
                print_json(json.dumps({'matchRules': matchRules}))

                # Writing full json
                json_file = 'policy_matchrules.json'
                with open(json_file, 'w') as f:
                    json.dump({'matchRules': matchRules}, f, indent=4)
                root_logger.info(f'matchrules policy json is saved at {json_file}')

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
    if response.status_code == 200:
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
            if update_response.status_code == 409:
                root_logger.info(f"{update_response.json()['errors'][0]['detail']}")
            elif update_response.status_code == 200:
                root_logger.info(f'Updating policy {policy_name} v{version}')
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
                    if response.status_code == 200:
                        root_logger.info('policy note is updated')
            else:
                matchRules = update_json_content['matchRules']
                version_response = cloudlet_object.create_shared_policy_version(session, policy_id, matchRules, notes)
                if version_response.status_code == 201:
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
        # if optjson:
        #    print_json(data=lookup_resp.json())
        df = pd.DataFrame(lookup_resp.json())
        df = df.rename(columns={'originId': 'Load Balancing ID'})
        if name_contains and not df.empty:
            df = df[df['Load Balancing ID'].str.contains(name_contains, case=False)]

        df = df.sort_values(by='Load Balancing ID', key=lambda col: col.str.lower())
        df = df.fillna('')
        df = df.reset_index(drop=True)
        if not df.empty:
            del df['akamaized']
            del df['checksum']
            root_logger.info(tabulate(df, headers='keys', tablefmt='psql', showindex=True))
        else:
            root_logger.info('not found')

    if loadbalance and version is None:
        if type != 'APPLICATION_LOAD_BALANCER':
            sys.exit(root_logger.info('Search only works with "ALB" type'))
        lookup_resp = cloudlet_object.list_load_balancing_version(session, loadbalance)
        if len(lookup_resp.json()) == 0:
            sys.exit(f'{loadbalance} not found')
        else:
            version_df = pd.DataFrame(lookup_resp.json())
            version_df = version_df.rename(columns={'originId': 'Load Balancing ID', 'immutable': 'lock',
                                                    'lastModifiedDate': 'Last Modified', 'lastModifiedBy': 'Last Editor',
                                                    'description': 'Version Notes'})
            version_columns = ['Load Balancing ID', 'version', 'deleted', 'lock', 'createdBy', 'createdDate', 'Last Editor', 'Last Modified']
            version_df = version_df.fillna('')
            if 'Version Notes' in version_df.columns:
                version_columns.insert(2, 'Version Notes')

        activation_resp = cloudlet_object.list_load_balancing_config_activation(session, loadbalance)
        activation_df = pd.DataFrame()
        if activation_resp.status_code == 200:
            if len(activation_resp.json()) == 0:
                root_logger.info('\nno activation history')
            else:
                df = pd.DataFrame(activation_resp.json())
                df = df.rename(columns={'originId': 'Load Balancing ID', 'immutable': 'lock',
                                        'lastModifiedDate': 'Last Modified', 'lastModifiedBy': 'Last Editor',
                                        'description': 'Version Notes'})
                activation_df = df.pivot(index=['Load Balancing ID', 'version'], columns='network', values='status').reset_index()
                activation_df = activation_df.fillna('')
                activation_df = activation_df.sort_values(by='version', ascending=False)
                activation_df = activation_df.reset_index(drop=True)

        if not activation_df.empty:
            merged_df = pd.merge(version_df, activation_df, on=['Load Balancing ID', 'version'], how='left')
            merged_df = merged_df.fillna('')
            columns = ['Load Balancing ID', 'version', 'lock', 'Last Modified', 'Last Editor', 'deleted']
            if 'Version Notes' in merged_df.columns:
                columns.insert(5, 'Version Notes')
            if 'STAGING' in merged_df.columns:
                columns.insert(6, 'STAGING')
            if 'PRODUCTION' in merged_df.columns:
                columns.insert(6, 'PRODUCTION')
            root_logger.info(tabulate(merged_df[columns], headers=columns, numalign='center', tablefmt='psql', showindex=False))
        else:
            root_logger.info(tabulate(version_df[version_columns], headers=version_columns, numalign='center', tablefmt='psql', showindex=False, maxcolwidths=30))

    if loadbalance and version:
        version_resp = cloudlet_object.get_load_balancing_version(session, loadbalance, version)

        if version_resp.status_code != 200:
            root_logger.info(version_resp.json()['detail'])

            lookup_resp = cloudlet_object.list_load_balancing_version(session, loadbalance)
            df = pd.DataFrame(lookup_resp.json())
            df = df.rename(columns={'originId': 'Load Balancing ID'})
            columns = ['Load Balancing ID', 'version', 'deleted', 'immutable', 'createdBy', 'createdDate', 'lastModifiedBy', 'lastModifiedDate']
            df = df.fillna('')
            if 'description' in df.columns:
                columns.insert(2, 'description')

            root_logger.info(tabulate(df[columns], headers=columns, numalign='center', tablefmt='psql', showindex=True, maxcolwidths=30))
            sys.exit()

        if isinstance(version_resp.json(), dict):
            data = version_resp.json()
            if 'livenessSettings' in data.keys():
                data.pop('livenessSettings')
            df = pd.DataFrame.from_dict(data)
            df = df.rename(columns={'originId': 'Load Balancing ID'})
        elif isinstance(version_resp.json(), list):
            df = pd.DataFrame(version_resp.json())
        else:
            pass

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
                    if section[0] == 'livenessSettings':
                        if 'livenessSettings' in version_resp.json().keys():
                            print(section[0])
                            live = version_resp.json()['livenessSettings']
                            # print_json(data=live)
                            live_df = pd.DataFrame([live])
                            root_logger.info(tabulate(live_df, headers='keys', numalign='center', tablefmt='psql', showindex=False))
                    try:
                        section_data = pd.json_normalize(df[section[0]])
                        columns = section_data.columns.tolist()
                        if section[0] == 'dataCenters':
                            print(section[0])
                            section_data = section_data.rename(columns={'originId': 'Data Center'})
                            datacenter_columns = ['Data Center', 'percent', 'city',
                                                  'cloudServerHostHeaderOverride', 'cloudService',
                                                  'continent', 'country', 'hostname', 'latitude', 'longitude']
                            if 'livenessHosts' in section_data.columns:
                                columns.remove('livenessHosts')
                                root_logger.info(tabulate(section_data[datacenter_columns], headers=datacenter_columns, numalign='center', tablefmt='psql', showindex=False))
                                print()
                                root_logger.info('livenessHosts')
                                root_logger.info(tabulate(section_data['livenessHosts'], numalign='center', tablefmt='psql', showindex=False))
                            else:
                                root_logger.info(tabulate(section_data[datacenter_columns], headers=datacenter_columns, numalign='center', tablefmt='psql', showindex=False))
                        else:
                            print(section[0])
                            root_logger.info(tabulate(section_data, headers='keys', numalign='center', tablefmt='psql', showindex=False))
                    except KeyError:
                        pass
                else:
                    try:
                        if 'description' in df.columns:
                            section.insert(3, 'description')
                        if 'balancingType' in df.columns:
                            section.insert(3, 'balancingType')
                        root_logger.info(tabulate(df[section], headers=section, numalign='center', tablefmt='psql', showindex=False))
                    except:
                        root_logger.info(tabulate(df, headers='keys', numalign='center', tablefmt='psql', showindex=False))


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


# adding alb_update_lb_info as part of GitHub issue #29 (GH29 branch)
# Get a load balancing version
@cli.command(short_help='ALB - Get load balancing information')
@click.option('--lb', 'loadbalance', metavar='', help='load balancing name (case sensitive, require exact name match)', required=True)
@click.option('--version', metavar='', help='description', type=int, required=True)
@pass_config
def alb_lb_get_info(config, loadbalance, version):
    """
    Get load balancing information
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    response = cloudlet_object.get_load_balancing_version(session, loadbalance, version)  # create new one in api wrapped for this.
    if response.status_code == 200:
        msg = f"'{response.json()}'"
        msg = json.dumps(msg, indent=4)  # Bug: Format better in output
        # print(msg)  # Bug fix how to output this better
        root_logger.info(msg)
    else:
        print_json(data=response.json())


# adding alb_update_lb_info as part of GitHub issue #29 (GH29 branch)
# List load balancing version
@cli.command(short_help='ALB - List version for a load balancing policy')
@click.option('--lb', 'loadbalance', metavar='', help='load balancing name (case sensitive, require exact name match)', required=True)
@pass_config
def alb_list_lb_version(config, loadbalance):
    """
    List load balancing version
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    response = cloudlet_object.list_load_balancing_version(session, loadbalance)  # create new one in api wrapped for this.
    if response.status_code == 200:
        msg = f"'{response.json()}'"
        msg = json.dumps(msg, indent=4)  # Bug: Format better in output
        # print(msg)  # Bug fix how to output this better
        root_logger.info(msg)
    else:
        print_json(data=response.json())


# adding alb_update_lb_info as part of GitHub issue #29 (GH29 branch)
# Clone from existing valid load balancing version.
@cli.command(short_help='ALB - Clone new version from existing valid load balancing policy')
@click.option('--lb', 'loadbalance', metavar='', help='load balancing name (case sensitive, require exact name match)', required=True)
@click.option('--version', 'version', metavar='', help='Load balancing version to activate', type=int, required=True)  # version
@click.option('--numbers', 'numbers', help='List of DC percentage values to update separated by space adding up to 100', required=True)  # version
@click.option('--descr', metavar='', help='description', required=True)
@pass_config
def alb_clone_lb(config, loadbalance, version, numbers, descr):
    """
    Clone from existing valid load balancing version.
    """
    try:
        # Split the input string into a list of integers
        int_list = [int(num) for num in numbers.split()]
        total_sum = sum(int_list)
        if total_sum == 100:
            root_logger.info(f' {int_list}')
            base_url, session = init_config(config.edgerc, config.section)
            cloudlet_object = Cloudlet(base_url, config.account_key)
            cloudlet_object.get_account_name(session, config.account_key)
            response = cloudlet_object.get_load_balancing_version(session, loadbalance, version)  # create new one in api wrapped for this.
            if response.status_code == 200:
                response = response.json()
                del response['createdBy']
                del response['createdDate']
                for counter, data_center in enumerate(response['dataCenters']):
                    data_center['percent'] = int_list[counter]
                if response.get('livenessSettings') is not None:
                    response = cloudlet_object.manage_load_balancing_version(session, loadbalance, response['balancingType'], response['dataCenters'], descr, response['livenessSettings'])
                    if response.status_code == 200:
                        msg = f"'{response.json()}'"
                        msg = json.dumps(msg, indent=4)  # formatting the json for better output
                        root_logger.info(msg)
                    else:
                        print_json(data=response.json())
                else:
                    response = cloudlet_object.manage_load_balancing_version(session, loadbalance, response['balancingType'], response['dataCenters'], descr, '')
                    if response.status_code == 200:
                        msg = f"'{response.json()}'"
                        msg = json.dumps(msg, indent=4)  # formatting the json for better output
                        root_logger.info(msg)
                    else:
                        print_json(data=response.json())
            else:
                print_json(data=response.json())
    except ValueError:
        print('Error: Please provide a valid list of integers separated by space adding upto 100')


# adding alb_update_lb_list_versions as part of GitHub issue #29 (GH29 branch)
# List current activations version for a Load balancing configuration
@cli.command(short_help='ALB - List current activations version for a Load balancing configuration')
@click.option('--lb', 'loadbalance', metavar='', help='load balancing name (case sensitive, require exact name match)', required=True)
@pass_config
def alb_lb_activate_version(config, loadbalance):
    """
    List current activations version for a Load balancing configuration
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    response = cloudlet_object.list_load_balancing_config_activation(session, loadbalance)
    if response.status_code == 200:
        msg = f"'{response.json()}'"
        msg = json.dumps(msg, indent=4)  # formatting the json for better output
        # print(msg)  # Bug fix how to output this better
        root_logger.info(msg)
    else:
        print_json(data=response.json())


# adding alb_update_lb_list_versions as part of GitHub issue #29 (GH29 branch)
# Activate Load balancing policies
@cli.command(short_help='ALB - Activate LB')
@click.option('--lb', 'loadbalance', metavar='', help='load balancing name (case sensitive, require exact name match)', required=True)  # check
@click.option('--network', metavar='', help='Specify Akamai network - Staging/Production', required=True)  # network
@click.option('--dryrun', metavar='', type=bool, default=False, help='dryrun - If true, the operation validates the configuration, but does not activate the load balancing version. Default is false', required=False)  # dryrun
@click.option('--version', 'version', metavar='', help='Load balancing version to activate', type=int, required=True)  # version
@pass_config
def alb_lb_activate(config, loadbalance, network, dryrun, version):
    """
    Activate load balancing policy
    """
    base_url, session = init_config(config.edgerc, config.section)
    cloudlet_object = Cloudlet(base_url, config.account_key)
    cloudlet_object.get_account_name(session, config.account_key)
    response = cloudlet_object.activation_load_balancing_config_version(session, loadbalance, version, network, dryrun)  # create new one in api wrapped for this.
    if response.status_code == 200:
        if (dryrun):
            msg = f"Load balancing policy '{response.json()['originId']}' was successfully tested with dryrun. Please run as --dryrun False to activate "
        else:
            msg = f"load balancing policy '{response.json()['originId']}' is on its way to Akamai {network} network"  # Fix bug - Activate version already active
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
        df = pd.read_csv(input, names=['id'])
        df['delete_message'] = df['id'].apply(lambda id: cloudlet_object.delete_policy(session, id))

        df = df.rename(columns={'id': 'Policy ID'})
        root_logger.info(tabulate(df, headers='keys', tablefmt='psql', numalign='center'))


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

    df = pd.read_csv(input, names=['Policy ID', 'Policy Name', 'Type', 'Group ID', 'Shared Policy', 'lastModifiedDate'], skiprows=1)
    df['version'] = df['Policy ID'].apply(lambda x: utility_object.validate_policy_arguments(session, root_logger, cloudlet_object, policy_id=x)[3]['activations'])

    nohistory = df.query('version.str.len() == 0')
    nohistory = nohistory.fillna('')
    nohistory = nohistory.reset_index(drop=True)
    if not nohistory.empty:
        root_logger.info('\nALB policy without activation history')
        del nohistory['version']
        root_logger.info(tabulate(nohistory, headers='keys', tablefmt='psql', numalign='center', showindex=True))

    df = df.query('version.str.len() > 0')
    df = df.fillna('')
    df = df.reset_index(drop=True)

    df['LATEST'] = df['Policy ID'].apply(lambda x: utility_object.get_latest_version(session, cloudlet_object, x, root_logger))
    df['PRODUCTION'] = df['Policy ID'].apply(lambda x: utility_object.get_production_version(session, root_logger, cloudlet_object, policy_id=x))
    df['STAGING'] = df['Policy ID'].apply(lambda x: utility_object.get_staging_version(session, root_logger, cloudlet_object, policy_id=x))
    df['PRODUCTION'] = df['PRODUCTION'].apply(utility_object.convert_df_float_to_int)
    df['STAGING'] = df['STAGING'].apply(utility_object.convert_df_float_to_int)
    df['albMatchRule'] = df.apply(lambda row: cloudlet_object.get_policy_version(session, policy_id=row['Policy ID'], version=row['PRODUCTION']
                                                                                 if row['PRODUCTION'] else row['STAGING']).json()['matchRules'], axis=1)
    df['loadbalance'] = df['albMatchRule'].apply(lambda x: [rule['forwardSettings']['originId']
                                                            for rule in x if x is not None] if x else [])
    df = df.query('loadbalance.str.len() > 0')
    df = df.fillna('')
    df = df.reset_index(drop=True)
    del df['albMatchRule']
    del df['version']
    df['loadbalance'] = df['loadbalance'].apply(lambda x: set(x))
    df['loadbalance'] = df['loadbalance'].apply(lambda x: sorted(x))
    df = df.rename(columns={'loadbalance': 'Load Balancing ID'})
    combined_all_lbs = sorted(df['Load Balancing ID'].explode().tolist())
    alb_df = pd.DataFrame(combined_all_lbs, columns=['Load Balancing ID'])

    if optcsv:
        file = 'alb_policy_with_lb.csv'
        df.to_csv(file, header=True, index=None, sep=',', mode='w')
        root_logger.info(f'\nOutput file saved - {file}')
        file = 'lb.csv'
        alb_df.to_csv(file, header=True, index=None, sep=',', mode='w')
        root_logger.info(f'Output file saved - {file:<30}  You can use this file as an input for alb-origin-bulk command.')
    else:
        columns = ['Policy ID', 'Policy Name', 'Shared Policy', 'LATEST', 'STAGING', 'PRODUCTION', 'Load Balancing ID']
        root_logger.info('\nALB policy with activation history')
        root_logger.info(tabulate(df[columns], headers=columns, tablefmt='psql', numalign='center', showindex=True, maxcolwidths=70))
        root_logger.info('\nAll load balancing IDs')
        root_logger.info(tabulate(alb_df, headers='keys', tablefmt='psql', numalign='center', showindex=True))


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
