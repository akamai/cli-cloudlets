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

    def get_groups(self, session):
        cloudlet_group_url = f'https://{self.access_hostname}/cloudlets/api/v2/group-info'
        cloudlet_group_response = session.get(self.form_url(cloudlet_group_url))
        return cloudlet_group_response

    def list_policies(self, session):
        policies_response = None
        policies_url = f'https://{self.access_hostname}/cloudlets/api/v2/policies'
        policies_response = session.get(self.form_url(policies_url))
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

    def list_shared_policy_versions(self, session, policy_id: int) -> pd.DataFrame:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/versions'
        response = session.get(self.form_url(url))
        if response.status_code == 200:
            df = pd.DataFrame(data=response.json()['content'])
            columns = ['id', 'description', 'version', 'modifiedDate']
            df.sort_values(by='version', ascending=False, inplace=True)
            return df[columns]

    def list_shared_policy_activations(self, session, policy_id: int) -> pd.DataFrame:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/activations'
        response = session.get(self.form_url(url))
        if response.status_code == 200:
            df = pd.DataFrame(data=response.json()['content'])
            columns = ['operation', 'policyVersion', 'network', 'createdDate']
            df.sort_values(by='createdDate', ascending=False, inplace=True)
            return df[columns]

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
        headers = {'Content-Type': 'application/json'}
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/'
        if clone_policy_id != 'optional':
            url = f'{url}?clonePolicyId={clone_policy_id}'
        if version != 'optional':
            symbol = '?'
            if '?' in url:
                symbol = '&'
                url = f'{url}{symbol}version={version}'
        cloudlet_policy_create_response = session.post(self.form_url(url), data=data, headers=headers)
        return cloudlet_policy_create_response

    def create_shared_policy(self, session, name: str, type: str,
                             group_id: int,
                             notes: str):
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
            version_response = self.create_shared_policy_version(session, policy_id, type)
            if version_response.status_code == 201:
                try:
                    policy_version = version_response.json()['version']
                    return None, policy_id, policy_version
                except:
                    return version_response, policy_id, policy_version
            else:
                return version_response, policy_id, None
        return response, None, None

    def create_shared_policy_version(self, session, policy_id: int, name: str, notes: str | None = None):
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/versions'
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'}
        if notes is None:
            notes = 'Created by Cloudlet CLI'
        payload = {'configuration': {'originNewVisitorLimit': 1000},
                   'description': notes,
                   'matchRules': [{'type': 'erMatchRule',
                                    'disabled': False,
                                    'matchesAlways': True,
                                    'redirectURL': 'none',
                                    'statusCode': 307,
                                    'useIncomingQueryString': True,
                                    'useIncomingSchemeAndHost': True,
                                    'useRelativeUrl': 'relative_url'
                                   }
                                  ]
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

    def get_policy(self, session, policy_id):
        """ Function to fetch a cloudlet policy detail"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}'
        policy_response = session.get(self.form_url(url))
        return policy_response

    def list_policy_versions(self, session, policy_id, page_size='optional'):
        """Function to fetch a cloudlet policy versions"""
        if page_size == 'optional':
            url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions?includeRules=true'
        else:
            url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions?includeRules=true&pageSize={page_size}'
        cloudlet_policy_versions_response = session.get(self.form_url(url))
        return cloudlet_policy_versions_response

    def get_policy_version(self, session, policy_id, version):
        """Function to fetch a cloudlet policy detail"""
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions/{version}?omitRules=false'
        policy_version_response = session.get(self.form_url(url))
        return policy_version_response

    def create_clone_policy_version(self, session, policy_id, data=dict(), clone_version='optional'):
        """Function to create a policy version"""
        headers = {'Content-Type': 'application/json'}
        if clone_version == 'optional':
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

    def update_shared_policy_detail(self, session, policy_id: int, version: int, notes: str | None = None):
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/versions/{version}'
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'
                  }
        if notes is None:
            notes = 'CLI cloudlet update'

        payload = {'configuration': {'originNewVisitorLimit': 1000},
                   'description': notes,
                   'matchRules': [{'type': 'erMatchRule',
                                   'disabled': False,
                                   'end': 0,
                                   'name': 'Redirect images',
                                   'matchURL': '/images/*',
                                   'redirectURL': '/static/images/*',
                                   'start': 0,
                                   'statusCode': 302,
                                   'useIncomingQueryString': True,
                                   'useRelativeUrl': 'relative_url'
                                  }
                                 ],
                  }
        response = session.put(self.form_url(url), json=payload, headers=headers)
        return response

    def get_schema(self, session, cloudlet_type: str | None = None) -> pd.DataFrame:
        headers = {'accept': 'application/json'}

        url = f'https://{self.access_hostname}/cloudlets/api/v2/cloudlet-info'
        response = session.get(self.form_url(url), headers=headers)
        df = pd.DataFrame(response.json())

        df.rename(columns={'cloudletName': 'name', 'cloudletCode': 'code'}, inplace=True)
        columns = ['name', 'code']
        # print(tabulate(df[columns], headers='keys', tablefmt='psql', showindex=False, numalign='center'))

        if cloudlet_type:
            url = f'https://{self.access_hostname}/cloudlets/api/v2/schemas?cloudletType={cloudlet_type}'
            response = session.get(self.form_url(url), headers=headers)
            schemas_df = pd.DataFrame(response.json()['schemas'])

            schemas_df.rename(columns={'title': 'action', 'location': 'endpoint'}, inplace=True)
            columns = ['action', 'endpoint']
            print(tabulate(schemas_df[columns], headers='keys', tablefmt='psql', showindex=False, numalign='center'))

            url = f'https://{self.access_hostname}/cloudlets/api/v2/schemas/update-nimbus_policy_version-ER-1.0.json'
            response = session.get(self.form_url(url), headers=headers)
            spec_df = pd.DataFrame(response.json())
            spec_df = spec_df[spec_df['properties'].notna()]
            print(tabulate(spec_df[['properties']], headers='keys', showindex=True, tablefmt='psql'))

            return df[['name', 'code']], schemas_df[['action', 'endpoint']], spec_df[['properties']]

        return df[['name', 'code']], None, None

    def available_shared_policies(self, session) -> pd.DataFrame:
        url = f'https://{self.access_hostname}/cloudlets/v3/cloudlet-info'
        response = session.get(self.form_url(url))
        if response.status_code == 200:
            df = pd.DataFrame(data=response.json())
            df.rename(columns={'cloudletType': 'code',
                                'cloudletName': 'name'}, inplace=True)
            return df[['name', 'code']]

    def activate_policy_version(self, session, policy_id, version, additionalPropertyNames=[], network='staging'):
        """Function to activate a policy version"""
        headers = {'Content-Type': 'application/json'}
        data = dict()
        data['network'] = network
        data['additionalPropertyNames'] = additionalPropertyNames
        url = f'https://{self.access_hostname}/cloudlets/api/v2/policies/{policy_id}/versions/{version}/activations'
        cloudlet_policy_activate_response = session.post(self.form_url(url), json.dumps(data), headers=headers)
        return cloudlet_policy_activate_response

    def list_policy_activations(self, session, policy_id, network):
        """Function to fetch activation details of policy"""
        url = f'https:///cloudlets/api/v2/policies/{policy_id}/activations?network={network}'
        policy_activations_response = session.get(self.form_url(url))
        return policy_activations_response

    def activate_shared_policy(self, session, network: str, policy_id: int, version: int) -> pd.DataFrame:
        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/activations'
        payload = {'network': network,
                   'operation': 'ACTIVATION',
                   'policyVersion': version
                  }
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'
                  }
        response = session.post(self.form_url(url), json=payload, headers=headers)
        if response.status_code == 202:
            df = pd.DataFrame(data=response.json())
            return df
        else:
            print(response.status_code)
            print_json(data=response.json())

    def get_activation_status(self, session, policy_id: int, activation_id: int):

        url = f'https://{self.access_hostname}/cloudlets/v3/policies/{policy_id}/activations/{activation_id}'

        headers = {'accept': 'application/json'}
        response = session.get(self.form_url(url), headers=headers)
        if response.status_code == 200:
            df = pd.DataFrame(data=response.json())
            return df  # ['Policy ID', 'Policy Version', 'network' ,'operation', 'createdBy', 'Activation ID']
        else:
            print(response.text)

    def form_url(self, url):
        # This is to ensure accountSwitchKey works for internal users
        if '?' in url:
            url = url + self.account_switch_key
        else:
            # Replace & with ? if there is no query string in URL
            account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&', '?'))
            url = url + account_switch_key
        return url
