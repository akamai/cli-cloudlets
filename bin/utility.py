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

import click
import pandas as pd
from tabulate import tabulate


class Utility:

    def do_cloudlet_code_map(self):
        """
        Function to map cloudlet abbrevations to code/id

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

    def check_policy_input(self, root_logger,
                                 policy_name: str | None = None,
                                 policy_id: int | None = None) -> tuple:

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


class PythonLiteralOption(click.Option):

    def type_cast_value(self, ctx, value):
        try:
            return ast.literal_eval(value)
        except:
            return None
