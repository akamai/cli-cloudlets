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
        if response.ok:
            data = response.json()['content']
            policy = [x for x in data if x['name'] == policy_name][0]
            if policy:
                id = policy['id']
                _, policy_info, full_policy_detail = self.list_shared_policies_by_id(session, policy_id=id)
                return id, policy_info, full_policy_detail

    def list_shared_policies_by_id(self, session, policy_id: int) -> tuple:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}'
        response = session.get(self.form_url(url))
        name = None
        policy_info = []
        full_policy_detail = {}
        if response.ok:
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
            policy_info.append([staging, 'staging'])
            policy_info.append([production, 'production'])
        return name, policy_id, policy_info

    def list_shared_policy_versions(self, session, policy_id: int) -> tuple:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/versions'
        response = session.get(self.form_url(url))

        if response.ok:
            data = response.json()['content']
            version = response.json()['content'][0]['version']
            columns = ['description', 'version', 'createdBy', 'createdDate', 'modifiedBy', 'immutable']
            all_policies = []
            for record in data:
                filtered_values = []
                for key, value in record.items():
                    if key in columns:
                        filtered_values.append(value)
                all_policies.append(filtered_values)
            return all_policies, version, response

    def get_active_properties(self, session, policy_id) -> pd.DataFrame:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/properties'
        response = session.get(self.form_url(url))
        if response.ok:
            data = response.json()['content']
            if data:
                properties = []
                for x in data:
                    properties.append([x['name'], str(x['version']), x['network'].lower()])
                sorted_properties = sorted(properties, key=lambda item: item[2] != 'staging')
                return sorted_properties
            else:
                print('no active property')

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
        if response.ok:
            policy_id = response.json()['id']
            version_response = self.create_shared_policy_version(session, policy_id, matchRules, notes)
            if version_response.ok:
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
        if policy_version_response.ok:
            policy_version = policy_version_response.json()
            policy = {k: policy_version[k] for k in ('description', 'version', 'createdBy', 'createdDate', 'modifiedBy', 'immutable')}
            policy_data = []
            filter_value = []
            for _, value in policy.items():
                if isinstance(value, int):
                    filter_value.append(str(value))
                else:
                    filter_value.append(value)
            policy_data.append(filter_value)
            return policy_data, policy_version_response

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
        schemas_data = []
        if response.ok:
            for x in response.json():
                schemas_data.append([x['cloudletCode'], x['cloudletName'], ''])

        if cloudlet_type:
            url = f'https://{self.access_hostname}/cloudlets/api/v2/schemas?cloudletType={cloudlet_type}'
            response = session.get(self.form_url(url), headers=headers)
            schemas_data = response.json()['schemas']
            # print_json(data=schemas_data)
            print('\nAvailable endpoints')
            for x in schemas_data:
                endpoint = x['location'].split('/')[-1].rstrip('.json')
                print(f'   {endpoint}')

        if template:
            print(f'\nChosen template: {template}')
            url = f'https://{self.access_hostname}/cloudlets/api/v2/schemas/{template}.json'
            response = session.get(self.form_url(url), headers=headers)
            if response.ok:
                keys = response.json().keys()
                columns = []
                for key in keys:
                    columns.append(key)
                columns.insert(0, '')

            if 'properties' in columns:
                schema = response.json()['properties']
                rows = [['type'] + [s.get('type', '') for s in schema.values()],
                        ['pattern'] + [s.get('pattern', '') for s in schema.values()],
                        ['maxLength'] + [s.get('maxLength', '') for s in schema.values()]]
                print('\nFields information')
                print(tabulate(rows, headers=columns, tablefmt='psql', maxcolwidths=30))

            if 'definitions' in columns:
                try:
                    matchRuleType = response.json()['definitions']['matchRuleType']['properties']
                    keys = matchRuleType.keys()
                    columns = []
                    for key in keys:
                        columns.append(key)
                    columns.insert(0, '')

                    rows = [['type'] + [s.get('type', '') for s in matchRuleType.values()],
                            ['maxLength'] + [s.get('maxLength', '') for s in matchRuleType.values()],
                            ['enum'] + [s.get('enum', '') for s in matchRuleType.values()],
                            ['minimum'] + [s.get('minimum', '') for s in matchRuleType.values()],
                            ['items'] + [s.get('items', '') for s in matchRuleType.values()]]
                    print(tabulate(rows, headers=columns, tablefmt='psql', maxcolwidths=30))
                except:
                    print('no matchRuleType')

                try:
                    matchCriteriaType = response.json()['definitions']['matchCriteriaType']['properties']
                    keys = matchCriteriaType.keys()
                    columns = []
                    for key in keys:
                        columns.append(key)
                    columns.insert(0, '')

                    print('\n\nmatchCriteriaType')
                    rows = [['type'] + [s.get('type', '') for s in matchRuleType.values()],
                            ['minLength'] + [s.get('minLength', '') for s in matchRuleType.values()],
                            ['maxLength'] + [s.get('maxLength', '') for s in matchRuleType.values()],
                            ['enum'] + [s.get('enum', '') for s in matchRuleType.values()],
                            ['$ref'] + [s.get('$ref', '') for s in matchRuleType.values()]]
                    print(tabulate(rows, headers=columns, tablefmt='psql', maxcolwidths=30))
                except:
                    print('no matchCriteriaType')
        return schemas_data, response

    def available_shared_policies(self, session) -> pd.DataFrame:
        url = f'https://{self.access_hostname}/cloudlets/v3/cloudlet-info'
        response = session.get(self.form_url(url))
        cloudlets = []
        if response.ok:
            for x in response.json():
                cloudlets.append([x['cloudletType'], x['cloudletName'], '* shared'])
        return cloudlets

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
        if response.ok:
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
                                      action: bool,
                                      balancing_type: str,
                                      datacenters: list,
                                      description: str,
                                      livenessSettings: dict):
        """create or delete load balancing version"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/origins/{origin_id}/versions'
        headers = {'accept': 'application/json'}
        payload = {'balancingType': balancing_type,
                   'delete': action}
        if description:
            payload['description'] = description
        if datacenters:
            payload['dataCenters'] = datacenters
        if livenessSettings:
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
