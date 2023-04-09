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

import ast
import json
import time

import click
import pandas as pd
from openpyxl import load_workbook
from pandas.io.formats.excel import ExcelFormatter
from rich.live import Live
from rich.table import Table
from tabulate import tabulate


class Utility:

    def do_cloudlet_code_map(self):
        """
        Function to map cloudlet abbreviations to code/id

        Parameters
        -----------

        Returns
        -------
        cloudlet_code : cloudlet_code
            (cloudlet_code) string with cloudlet code
        """
        cloudlet_code = {'ER': 0, 'VP': 1, 'FR': 3, 'IG': 4,
                         'AP': 5, 'AS': 6, 'CD': 7, 'IV': 8, 'ALB': 9}
        return cloudlet_code

    def get_policy_by_name(self, session, cloudlet_object, policy_name: str, root_logger):
        """Function to fetch policy details"""
        policy_info = dict()
        cloudlet_policies_response = cloudlet_object.list_policies(session)

        if cloudlet_policies_response.status_code != 200:
            root_logger.info('ERROR: Unable to fetch policies')
            root_logger.info(json.dumps(cloudlet_policies_response.json(), indent=4))
            exit(-1)

        try:
            num_policies = int(cloudlet_policies_response.headers['x-total-count'])
        except:
            num_policies = 0

        if num_policies > 1000:
            root_logger.info(f'...more than 1000 policies found ({num_policies}): may take additional time')

            # the first response already returns the first 1000
            root_logger.info('...searching policies: 1-1000')
            for policy in cloudlet_policies_response.json():
                if policy_name is not None:
                    if (str(policy['name'].lower()) == str(policy_name).lower()):
                        policy_info = policy
                        return policy_info

            # figure out how many more api calls need to make and loop until we find it
            max_calls = int(num_policies / 1000) + 1
            for i in range(1, max_calls):
                offset = i * 1000
                start_label = offset + 1
                end_label = start_label + 999
                root_logger.info(f'...searching policies: {start_label}-{end_label}')
                cloudlet_policies_response = cloudlet_object.list_policies_offset(session, offset, 1000)
                for policy in cloudlet_policies_response.json():
                    if policy_name is not None:
                        if (str(policy['name'].lower()) == str(policy_name).lower()):
                            policy_info = policy
                            return policy_info

        else:
            for policy in cloudlet_policies_response.json():
                if policy_name:
                    if (str(policy['name'].lower()) == str(policy_name).lower()):
                        policy_info = policy
                        return policy_info

        # If policy_info is empty, we check for not null after return
        return policy_info

    def get_policy_by_id(self, session, cloudlet_object, policy_id: int, root_logger):
        """Function to fetch policy details"""
        policy_info = dict()
        policy_response = cloudlet_object.get_policy(session, policy_id)
        if policy_response.status_code == 200:
            policy_info = policy_response.json()
        return policy_info

    def get_latest_version(self, session, cloudlet_object, policy_id: int, root_logger):
        """Function to fetch latest version"""
        policy_versions_response = cloudlet_object.list_policy_versions(session, policy_id, page_size=1)
        if policy_versions_response.status_code == 200:
            # If for some reason, can't find a version
            if len(policy_versions_response.json()) > 0:
                version = policy_versions_response.json()[0]['version']
                return version
            else:
                root_logger.info('ERROR: Unable to find latest version. Check if version exists')

    def check_group_input(self, root_logger,
                                group_name: str | None = None,
                                group_id: int | None = None) -> None:

        if group_id and group_name:
            root_logger.info('Please specify either group-id or group-name.')
            exit(-1)

        if not group_id and not group_name:
            root_logger.info('Please specify either group-id or group-name.')
            exit(-1)

    def check_policy_input(self, root_logger,
                                 policy_name: str | None = None,
                                 policy_id: int | None = None) -> None:

        if policy_id and policy_name:
            root_logger.info('Please specify either policy or policy-id.')
            exit(-1)

        if not policy_id and not policy_name:
            root_logger.info('Please specify either policy or policy-id.')
            exit(-1)

    def validate_policy_arguments(self, session, root_logger,
                                  cloudlet_object,
                                  policy_name: str | None = None,
                                  policy_id: int | None = None) -> tuple:

        if policy_name:
            policy_info = self.get_policy_by_name(session, cloudlet_object, policy_name, root_logger)
        else:
            policy_info = self.get_policy_by_id(session, cloudlet_object, policy_id, root_logger)

        if not policy_info:
            type = 'shared'
            policy_name, policy_id, policy_info = self.validate_shared_policy_arguments(session, root_logger,
                                                                                        cloudlet_object,
                                                                                        policy_name=policy_name,
                                                                                        policy_id=policy_id)
        else:
            type = ' '
            policy_name = policy_info['name']
            policy_id = policy_info['policyId']
        return type, policy_name, policy_id, policy_info

    def validate_shared_policy_arguments(self, session, root_logger, cloudlet_object,
                                         policy_name: str | None = None,
                                         policy_id: int | None = None) -> tuple:

        if policy_name:
            id, policy_info, _ = cloudlet_object.list_shared_policies_by_name(session, policy_name=policy_name)
            policy_name, policy_info, _ = cloudlet_object.list_shared_policies_by_id(session, policy_id=id)
        else:
            id = policy_id
            policy_name, policy_info, _ = cloudlet_object.list_shared_policies_by_id(session, policy_id=id)
        return policy_name, id, policy_info

    def retrieve_shared_policy(self, session, root_logger, cloudlet_object,
                               policy_name: str | None = None,
                               policy_id: int | None = None) -> tuple:

        if policy_name:
            root_logger.info(f'...searching for cloudlet policy {policy_name}')
            id, policy_info, full_policy_detail = cloudlet_object.list_shared_policies_by_name(session, policy_name=policy_name)
        else:
            id = policy_id
            root_logger.info(f'...searching for cloudlet policy-id {id}')
            policy_name, policy_info, full_policy_detail = cloudlet_object.list_shared_policies_by_id(session, policy_id=id)
            print(f'Policy Name: {policy_name}') if policy_name else None

        df = pd.json_normalize(full_policy_detail)

        df.rename(columns={'id': 'policyId',
                           'modifiedBy': 'lastModifiedBy'}, inplace=True)
        columns = ['name', 'policyType', 'policyId', 'description', 'lastModifiedBy']
        print(tabulate(df[columns], headers='keys', tablefmt='psql', showindex=False))

        if not policy_info:
            root_logger.info('Not found')
        else:
            df = pd.DataFrame(policy_info)
            staging = df.loc[df['network'] == 'staging'].iloc[0, 0]
            production = df.loc[df['network'] == 'production'].iloc[0, 0]
            df = cloudlet_object.get_active_properties(session, policy_id=id)
            if not df.empty:
                df['policy version'] = df.apply(lambda row: self.fill_column(row, staging, production), axis=1)
                new_header = f'Policy ID ({policy_id}) version'
                df.rename(columns={'policy version': new_header}, inplace=True)
                columns = [new_header, 'network', 'property name', 'property version']
                print(tabulate(df[columns], headers='keys', tablefmt='psql', showindex=False, numalign='center'))
                return df, policy_name, id, policy_info

        print(f'{df} {policy_name} {id} {policy_info}')

        return df, policy_name, id, policy_info

    def fill_column(self, row, staging_version: int, production_version: int):
        if row['network'] == 'staging':
            return staging_version
        return production_version

    def activation_table(self, policy) -> Table:
        """Make a new table."""
        table = Table()
        table.add_column('policy id')
        table.add_column('version')
        table.add_column('network')

        try:
            if policy['id']:
                table.add_column('activation id')
        except:
            pass

        table.add_column('status')

        try:
            status = policy['status']
        except:
            status = policy['policyInfo']['status']

        try:
            if policy['id']:
                table.add_row(f"{policy['policyId']}", f"{policy['policyVersion']}", f"{policy['network']}",
                              f"{policy['id']}",
                              f'[red]{status}' if status == 'IN_PROGRESS' else '[green]SUCCESS'
                             )
        except:
            table.add_row(f"{policy['policyInfo']['policyId']}", f"{policy['policyInfo']['version']}", f"{policy['network']}",
                          f'[red]{status}' if status == 'pending' else '[green]active'
                          )
        return table

    def poll_activation(self, session, cloudlet_object, json_response, type, network: str | None = None):

        try:
            policy_id = json_response['policyId']
        except:
            policy_id = json_response['policyInfo']['policyId']

        try:
            activation_id = json_response['id']
        except:
            activation_id = 0
            msg = 'API v2 do not have activation_id'

        with Live(self.activation_table(json_response), refresh_per_second=1) as live:
            in_progress = True
            while in_progress:
                # determine to use API v2 or v3
                if type == ' ':
                    status_code, temp_response = cloudlet_object.list_policy_activation(session,
                                                                                    policy_id,
                                                                                    network=network)

                    if isinstance(temp_response, list):
                        response = temp_response[0]
                    else:
                        response = temp_response
                    if status_code == 200:
                        if response['policyInfo']['status'] != 'pending':
                            in_progress = False
                            end_time = time.perf_counter()
                else:
                    status_code, temp_response = cloudlet_object.list_shared_policy_activation(session,
                                                                                    policy_id,
                                                                                    activation_id)
                    response = temp_response
                    if status_code == 200:
                        if temp_response['status'] != 'IN_PROGRESS':
                            in_progress = False
                            end_time = time.perf_counter()
                time.sleep(30)
                live.update(self.activation_table(response))
                print('Polling every 30 seconds...')

            return end_time

    def proces_matchrules_column(self, df):
        columns = df.columns.tolist()
        new_columns = []
        for column in columns:
            if column == 'type':
                type = df['type'].unique().tolist()[0]
            if column == 'match_type':
                match_types = df['match_type'].unique().tolist()
            col = df[column].astype(str).unique().tolist()
            if isinstance(col, (list, tuple)):
                if len(col) > 1:
                    new_columns.append(column)
                elif len(col) == 1 and col[0] not in [type, '0', 'None', '']:
                    new_columns.append(column)
        return type, new_columns, match_types

    def generate_excel(self, filename: str, df1: pd.DataFrame, df2: pd.DataFrame | None = None) -> None:
        if df2.empty:
            df_dict = {'match_rules': df1}
        else:
            df_dict = {'match_rules': df1, 'match_value': df2}
        writer = pd.ExcelWriter(filename, engine='xlsxwriter')
        for sheetname, df in df_dict.items():
            df.to_excel(writer, sheet_name=sheetname)
            df.columns = df.columns.str.upper()
            workbook = writer.book
            worksheet = writer.sheets[sheetname]

            header_format = workbook.add_format({'bold': True,
                                                'text_wrap': False,
                                                'valign': 'top',
                                                'align': 'middle',
                                                'fg_color': '#FFC588',  # orange
                                                'border': 1,
                                                })
            index_format = workbook.add_format({'bold': True,
                                                'text_wrap': False,
                                                'valign': 'top',
                                                'align': 'left'
                                                })
            # format table headers
            for col_num, value in enumerate(df.columns.values, 1):
                worksheet.write(0, col_num, value, header_format)

            # format index column
            for i, value in enumerate(df.index.values, 1):
                worksheet.write(i, 0, value, index_format)

            worksheet.freeze_panes(1, 2)
            worksheet.autofit()
        writer.close()


class PythonLiteralOption(click.Option):

    def type_cast_value(self, ctx, value):
        try:
            return ast.literal_eval(value)
        except:
            return None
