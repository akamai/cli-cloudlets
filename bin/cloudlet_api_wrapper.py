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

import json
import sys

import pandas as pd
from rich import print_json
from tabulate import tabulate


class Cloudlet:
    def __init__(self, access_hostname, account_switch_key):
        self.access_hostname = access_hostname
        if account_switch_key is not None:
            self.account_switch_key = '&accountSwitchKey=' + account_switch_key
        else:
            self.account_switch_key = ''

    def get_account_name(self, session, account_id: str | None = None) -> None:
        if account_id:
            account_id = account_id.split(':')
            url = f'https://{self.access_hostname}/identity-management/v3/api-clients/self/account-switch-keys?search={account_id[0]}'
            resp = session.get(url)
            try:
                account_name = resp.json()[0]['accountName']
                print(f'\nAccount Name: {account_name} {account_id}')
            except:
                print(f'\nInvalid account key: {account_id}')
                sys.exit()

    def get_groups(self, session):
        cloudlet_group_url = f'https://{self.access_hostname}/cloudlets/api/v2/group-info'
        cloudlet_group_response = session.get(self.form_url(cloudlet_group_url))
        return cloudlet_group_response

    def list_policies(self, session):
        policies_response = None
        headers = {'accept': 'application/json'}
        policies_url = f'https://{self.access_hostname}/cloudlets/api/v2/policies'
        policies_response = session.get(self.form_url(policies_url), headers=headers)
        return policies_response

    def list_shared_policies(self, session) -> list:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies'
        response = session.get(self.form_url(url))
        if response.status_code == 200:
            return response.json()['content']
        else:
            return response

    def list_shared_policies_by_name(self, session, policy_name: str) -> tuple:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies'
        response = session.get(self.form_url(url))
        if response.status_code == 200:
            data = response.json()['content']
            df = pd.DataFrame(data)
            df = df[df['name'] == policy_name]
            if not df.empty:
                id = df['id'].values[0]
                _, policy_info, full_policy_detail = self.list_shared_policies_by_id(session, policy_id=id)
                return id, policy_info, full_policy_detail
        return None, None, None

    def list_shared_policies_by_id(self, session, policy_id: int) -> tuple:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}'
        response = session.get(self.form_url(url))
        name = None
        policy_info = []
        full_policy_detail = {}
        if response.status_code == 200:
            full_policy_detail = response.json()
            try:
                staging = full_policy_detail['currentActivations']['staging']['latest']['policyVersion']
            except:
                staging = 0
            try:
                production = full_policy_detail['currentActivations']['production']['latest']['policyVersion']
            except:
                production = 0
            name = full_policy_detail['name']
            header = f'Policy ID ({policy_id}) version'
            policy_info.append({header: staging, 'network': 'staging'})
            policy_info.append({header: production, 'network': 'production'})
        return name, policy_info, full_policy_detail

    def list_shared_policy_versions(self, session, policy_id: int) -> tuple:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/versions'
        response = session.get(self.form_url(url))

        if response.status_code == 200:
            data = response.json()['content']
            df = pd.DataFrame(data)
            df.rename(columns={'description': 'version notes',
                               'immutable': 'lock'}, inplace=True)
            columns = ['version', 'version notes', 'createdBy', 'modifiedDate', 'lock']
            df.sort_values(by='version', ascending=False, inplace=True)
            version = response.json()['content'][0]['version']
            return df[columns], version, response

    def get_active_properties(self, session, policy_id) -> pd.DataFrame:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/properties'
        response = session.get(self.form_url(url))
        if response.status_code == 200:
            data = response.json()['content']
            if data:
                columns = ['network', 'property name', 'property version']
                df = pd.DataFrame(data)
                df['network'] = df['network'].apply(str.lower)
                df.sort_values(by='network', ascending=False, inplace=True)
                df.rename(columns={'name': 'property name',
                                   'version': 'property version'}, inplace=True)
                return df[columns]
            else:
                print('no active property')
                return pd.DataFrame()

    def list_policies_offset(self, session, offset, page_size):
        """ Function to fetch policies from offset and page size"""
        policies_response = None
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies?offset={offset}&pageSize={page_size}'
        policies_response = session.get(self.form_url(url))
        return policies_response

    def clone_policy(self, session, name: str, policy_id: int, group_id: int, version: list | None = None):
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/clone'
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'}
        payload = {}
        if version:
            payload['additionalVersions'] = version
        payload['newName'] = name
        payload['groupId'] = group_id
        response = session.post(self.form_url(url), json=payload, headers=headers)
        return response

    def create_clone_policy(self, session, data, clone_policy_id='optional', version='optional'):
        """Function to clone a policy version"""
        headers = {'accept': 'application/json',
                   'Content-Type': 'application/json'}
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/'
        if clone_policy_id != 'optional':
            url = f'{url}?clonePolicyId={clone_policy_id}'
        if version != 'optional':
            symbol = '?'
            if '?' in url:
                symbol = '&'
                url = f'{url}{symbol}version={version}'
        cloudlet_policy_create_response = session.post(self.form_url(url), data=json.dumps(data), headers=headers)
        return cloudlet_policy_create_response

    def create_shared_policy(self, session, name: str, type: str,
                             group_id: int,
                             matchRules: list | None = None,
                             notes: str | None = None):
        url = f'https://{self.access_hostname}/cloudlets/v3/policies'
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'}
        if notes is None:
            notes = 'Created by Cloudlet CLI'
        payload = {'name': name,
                   'cloudletType': type,
                   'groupId': group_id,
                   'description': notes,
                   'policyType': 'SHARED'
                  }
        response = session.post(self.form_url(url), json=payload, headers=headers)
        if response.status_code == 201:
            policy_id = response.json()['id']
            version_response = self.create_shared_policy_version(session, policy_id, matchRules, notes)
            if version_response.status_code == 201:
                try:
                    policy_version = version_response.json()['version']
                    return version_response, policy_id, policy_version
                except:
                    return version_response, policy_id, None
            else:
                return version_response, policy_id, None
        return response, None, None

    def create_shared_policy_version(self, session, policy_id: int, matchRules: list, notes: str | None = None):
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/versions'
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'}
        if notes is None:
            notes = 'Created by Cloudlet CLI'
        payload = {'description': notes,
                   'matchRules': matchRules
                   }
        version_response = session.post(self.form_url(url), json=payload, headers=headers)
        return version_response

    def delete_shared_policy(self, session, policy_id: int):
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}'
        headers = {'accept': 'application/problem+json'}
        response = session.delete(self.form_url(url), headers=headers)
        if response.status_code == 204:
            return True
        else:
            print_json(data=response.json())
            return False

    def get_policy(self, session, policy_id: int):
        """ Function to fetch a cloudlet policy detail"""
        headers = {'accept': 'application/json'}
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}'
        policy_response = session.get(self.form_url(url), headers=headers)
        return policy_response

    def list_policy_versions(self, session, policy_id: int, page_size='optional'):
        """Function to fetch a cloudlet policy versions"""
        if page_size == 'optional':
            url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions?includeRules=true'
        else:
            url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions?includeRules=true&pageSize={page_size}'
        cloudlet_policy_versions_response = session.get(self.form_url(url))
        return cloudlet_policy_versions_response

    def list_policy_versions_history(self, session, policy_id: int):
        """Function to fetch a cloudlet policy versions history"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions?includeActivations=true'
        cloudlet_policy_versions_response = session.get(self.form_url(url))
        return cloudlet_policy_versions_response

    def get_policy_version(self, session, policy_id, version):
        """Function to fetch a cloudlet policy detail"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions/{version}?omitRules=false'
        policy_version_response = session.get(self.form_url(url))
        return policy_version_response

    def get_shared_policy_version(self, session, policy_id: int, version: int):
        """Function to fetch a cloudlet policy detail"""
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/versions/{version}'
        policy_version_response = session.get(self.form_url(url))
        transposed_df = pd.DataFrame()
        if policy_version_response.status_code == 200:
            policy_version = policy_version_response.json()
            policy = {k: policy_version[k] for k in ('policyId', 'version', 'description', 'modifiedBy', 'modifiedDate')}
            df = pd.DataFrame.from_dict(policy, orient='index')
            df.rename(columns={'description': 'notes'}, inplace=True)
            transposed_df = df.T
        return transposed_df, policy_version_response

    def create_clone_policy_version(self, session, policy_id, data=dict(), clone_version: int | None = None):
        """Function to create a policy version"""
        headers = {'Content-Type': 'application/json'}
        if clone_version is None:
            url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions?includeRules=true'
        else:
            url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions?includeRules=true&cloneVersion={clone_version}'
        cloudlet_policy_create_response = session.post(self.form_url(url), data, headers=headers)
        return cloudlet_policy_create_response

    def update_policy_version(self, session, policy_id, version, data: dict):
        """
        Function to update a policy version
        Only unlock version can be updated
        """
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'
                  }
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions/{version}'
        update_policy_version_response = session.put(self.form_url(url), json=data, headers=headers)
        return update_policy_version_response

    def update_shared_policy(self, session, policy_id: int, group_id: int, notes: str | None = None):
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}'
        if notes is None:
            notes = 'CLI cloudlet update'

        payload = {
            'groupId': group_id,
            'description': notes
        }
        headers = {
            'accept': 'application/json',
            'content-type': 'application/json'
        }

        response = session.put(self.form_url(url), json=payload, headers=headers)
        return response

    def update_shared_policy_detail(self, session, policy_id: int, version: int, match_rules: dict):
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/versions/{version}'
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'
                  }
        response = session.put(self.form_url(url), json=match_rules, headers=headers)
        return response

    def get_schema(self, session, cloudlet_type: str | None = None, template: str | None = None) -> pd.DataFrame:
        headers = {'accept': 'application/json'}

        url = f'https://{self.access_hostname}/cloudlets/api/v2/cloudlet-info'
        response = session.get(self.form_url(url), headers=headers)
        if response.status_code == 200:
            df = pd.DataFrame(response.json())
            if not df.empty:
                df.rename(columns={'cloudletName': 'name', 'cloudletCode': 'code'}, inplace=True)
            else:
                return pd.DataFrame(), response
        else:
            return pd.DataFrame(), response

        if cloudlet_type:
            url = f'https://{self.access_hostname}/cloudlets/api/v2/schemas?cloudletType={cloudlet_type}'
            response = session.get(self.form_url(url), headers=headers)
            schemas_df = pd.DataFrame(response.json()['schemas'])
            schemas_df.rename(columns={'title': 'action', 'location': 'endpoint'}, inplace=True)
            df = df[df['code'] == cloudlet_type]

        columns = ['name', 'code']
        if cloudlet_type:
            if not schemas_df.empty:
                columns = ['action', 'endpoint']
                # no need to display
                # print(tabulate(schemas_df[columns], headers='keys', showindex=True, tablefmt='psql'))

        if template:
            url = f'https://{self.access_hostname}/cloudlets/api/v2/schemas/{template}.json'
            response = session.get(self.form_url(url), headers=headers)

            # print_json(data= response.json())
            if 'properties' in response.json().keys():
                print('\n\nFields information')
                property = response.json()['properties']
                property_df = pd.DataFrame(property)
                property_df.fillna('', inplace=True)
                columns = property_df.columns.values.tolist()
                print(tabulate(property_df[columns], headers='keys', showindex=True, tablefmt='psql', maxcolwidths=30))

            if 'definitions' in response.json().keys():
                try:
                    matchRuleType = response.json()['definitions']['matchRuleType']['properties']
                    matchrule_df = pd.DataFrame(matchRuleType)
                    matchrule_df.fillna('', inplace=True)
                    if not matchrule_df.empty:
                        print('\n\nmatchRuleType')
                        columns = matchrule_df.columns.values.tolist()
                        if len(columns) > 7:
                            if len(columns) - 7 > 4:
                                column_1 = columns[:7]
                                print(tabulate(matchrule_df[column_1], headers='keys', showindex=True, tablefmt='psql', maxcolwidths=40))
                                column_2 = columns[7:]
                                print(tabulate(matchrule_df[column_2], headers='keys', showindex=True, tablefmt='psql', maxcolwidths=40))
                            else:
                                print(tabulate(matchrule_df[columns], headers='keys', showindex=True, tablefmt='psql', maxcolwidths=20))
                        else:
                            print(tabulate(matchrule_df[columns], headers='keys', showindex=True, tablefmt='psql', maxcolwidths=10))
                except:
                    print('no matchRuleType')

                try:
                    matchCriteriaType = response.json()['definitions']['matchCriteriaType']['properties']
                    criteria_df = pd.DataFrame(matchCriteriaType)
                    criteria_df.fillna('', inplace=True)
                    if not criteria_df.empty:
                        print('\n\nmatchCriteriaType')
                        columns = criteria_df.columns.values.tolist()
                        print(tabulate(criteria_df[columns], headers='keys', showindex=True, tablefmt='psql', maxcolwidths=30))
                except:
                    print('no matchCriteriaType')
        return df, response

    def available_shared_policies(self, session) -> pd.DataFrame:
        url = f'https://{self.access_hostname}/cloudlets/v3/cloudlet-info'
        response = session.get(self.form_url(url))
        if response.status_code == 200:
            df = pd.DataFrame(data=response.json())
            if not df.empty:
                df.rename(columns={'cloudletType': 'code',
                                    'cloudletName': 'name'}, inplace=True)
                return df[['name', 'code']]
        return pd.DataFrame()

    def activate_policy_version(self, session, policy_id, version, network: str, additionalPropertyNames: list | None = None):
        """Function to activate a policy version"""
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'}
        data = dict()
        data['network'] = network
        if additionalPropertyNames:
            data['additionalPropertyNames'] = additionalPropertyNames
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions/{version}/activations?async=true'
        response = session.post(self.form_url(url), json=data, headers=headers)
        return response

    def activate_shared_policy(self, session, network: str, policy_id: int, version: int | None = None) -> pd.DataFrame:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/activations'
        payload = {'network': network,
                   'operation': 'ACTIVATION',
                   'policyVersion': version}
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'}
        response = session.post(self.form_url(url), json=payload, headers=headers)
        # print_json(data=response.json())
        return response

    def list_policy_activation(self, session, policy_id: int, network: str | None = None):
        """Function to fetch activation details of policy"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/activations'
        if network:
            if network == 'production':
                network = 'prod'
                url = f'{url}?network={network}&offset=0&pageSize=100'
        headers = {'accept': 'application/json'}
        response = session.get(self.form_url(url), headers=headers)
        return response.status_code, response.json()

    def list_shared_policy_activation(self, session, policy_id: int, activation_id: int):
        """Function to fetch activation details of shared policy"""
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/activations/{activation_id}'
        response = session.get(self.form_url(url))
        return response.status_code, response.json()

    def get_activation_status(self, session, policy_id: int) -> pd.DataFrame:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/activations/'
        headers = {'accept': 'application/json'}
        response = session.get(self.form_url(url), headers=headers)
        return response

    def form_url(self, url):
        # This is to ensure accountSwitchKey works for internal users
        if '?' in url:
            url = url + self.account_switch_key
        else:
            # Replace & with ? if there is no query string in URL
            account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&', '?'))
            url = url + account_switch_key
        return url

    def delete_policy(self, session, policy_id: str):
        """delete cloudlet policy"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}'

        response = session.delete(self.form_url(url))
        if response.status_code == 204:
            msg = 'remove success'
        else:
            msg = response.json()['errorMessage']
        return msg

    def list_alb_conditional_origin(self, session, type: str | None = None):
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins'
        if type:
            url = f'{url}?type={type}'
        headers = {'accept': 'application/json'}
        response = session.get(self.form_url(url), headers=headers)
        return response

    def get_alb_conditional_origin(self, session, origin_id: str):
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins/{origin_id}'
        headers = {'accept': 'application/json'}
        response = session.get(self.form_url(url), headers=headers)
        return response

    def create_load_balancing_config(self, session, origin_id: str, description: str):
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins'
        headers = {'accept': 'application/json'}
        payload = {
            'description': description,
            'originId': origin_id
        }
        response = session.post(self.form_url(url), json=payload, headers=headers)
        return response

    def update_load_balancing_config(self, session, origin_id: str, description: str | None = None):
        """Update description only"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins/{origin_id}'
        headers = {'accept': 'application/json'}

        if description:
            payload = {}
            payload['description'] = description
            response = session.put(self.form_url(url), json=payload, headers=headers)
            return response

    def list_load_balancing_version(self, session, origin_id: str):
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins/{origin_id}/versions'
        headers = {'accept': 'application/json'}
        response = session.get(self.form_url(url), headers=headers)
        return response

    def get_load_balancing_version(self, session, origin_id: str, version: int):
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins/{origin_id}/versions/{version}?validate=true'
        headers = {'accept': 'application/json'}
        response = session.get(self.form_url(url), headers=headers)
        return response

    def manage_load_balancing_version(self, session, origin_id: str,
                                      balancing_type: str,
                                      datacenters: list,
                                      note: str | None = None,
                                      livenessSettings: dict | None = None):
        """create or delete load balancing version"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins/{origin_id}/versions'
        headers = {'accept': 'application/json'}
        payload = {'balancingType': balancing_type}
        if note:
            payload['description'] = note
        if datacenters:
            payload['dataCenters'] = datacenters
        if livenessSettings is None:
            print('No liveness setting found')
        else:
            payload['livenessSettings'] = livenessSettings
        if origin_id:
            payload['originId'] = origin_id
        response = session.post(self.form_url(url), json=payload, headers=headers)
        return response

    def update_load_balancing_version(self, session, origin_id: str,
                                      version: int,
                                      action: bool,
                                      balancing_type: str,
                                      datacenters: list,
                                      description: str,
                                      livenessSettings: dict):
        """update a selected load balancer version, not yet activated"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins/{origin_id}/versions/{version}'
        headers = {'accept': 'application/json'}
        payload = {'balancingType': balancing_type}
        if action:
            payload['deleted'] = action
        if description:
            payload['description'] = description
        if datacenters:
            payload['dataCenters'] = datacenters
        if livenessSettings:
            payload['livenessSettings'] = livenessSettings
        if origin_id:
            payload['originId'] = origin_id
        response = session.put(self.form_url(url), json=payload, headers=headers)
        return response

    def list_all_load_balancing_activation(self, session):
        """list all the current load balancing activations"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins/currentActivations'
        headers = {'accept': 'application/json'}
        response = session.get(self.form_url(url), headers=headers)
        return response

    def list_load_balancing_config_activation(self, session, origin_id: str):
        """list all the current load balancing activations"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins/{origin_id}/activations?latestOnly=true'
        headers = {'accept': 'application/json'}
        response = session.get(self.form_url(url), headers=headers)
        return response

    def activation_load_balancing_config_version(self, session, origin_id: str, version: int, network: str, dryrun: bool):
        """Activate the selected load balancing version.
        The load balancing version status is either active or inactive."""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins/{origin_id}/activations?async=true'
        headers = {'accept': 'application/json'}
        payload = {
            'network': network,
            'version': version
        }
        if dryrun:
            payload['dryrun'] = True
        response = session.post(self.form_url(url), json=payload, headers=headers)
        return response
