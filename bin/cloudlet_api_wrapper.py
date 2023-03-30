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

    def list_policies_offset(self,
                      session,
                      offset,
                      page_size):
        """
        Function to fetch policies from offset and page size

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        policies_response : policies_response
            Policies of cloudlet Id
        """
        policies_response = None
        policies_url = 'https://' + self.access_hostname + \
                           '/cloudlets/api/v2/policies?offset=' + str(offset) + '&pageSize=' + str(page_size)

        policies_response = session.get(self.form_url(policies_url))
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

    def create_clone_policy(
            self,
            session,
            data,
            clone_policy_id='optional',
            version='optional'):
        """
        Function to clone a policy version

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudlet_policy_create_response : cloudlet_policy_create_response
            Json object details of created cloudlet policy version
        """
        headers = {
            'Content-Type': 'application/json'
        }

        cloudlet_policy_create_url = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/'

        if clone_policy_id != 'optional':
            cloudlet_policy_create_url = cloudlet_policy_create_url + '?clonePolicyId=' + str(clone_policy_id)

        if version != 'optional':
            symbol = '?'
            if '?' in cloudlet_policy_create_url:
                symbol = '&'
                cloudlet_policy_create_url = cloudlet_policy_create_url + symbol + 'version=' + str(version)

        cloudlet_policy_create_response = session.post(self.form_url(cloudlet_policy_create_url), data=data, headers=headers)
        return cloudlet_policy_create_response

    def create_shared_policy(self, session, name: str, cloudlet_type: str,
                             group_id: int,
                             notes: str):
        url = f'https://{self.access_hostname}/cloudlets/v3/policies'
        headers = {'accept': 'application/json',
                   'content-type': 'application/json'}
        if notes is None:
            notes = 'Created by Cloudlet CLI'
        payload = {'name': name,
                   'cloudletType': cloudlet_type,
                   'groupId': group_id,
                   'description': notes,
                   'policyType': 'SHARED'
                  }
        response = session.post(self.form_url(url), json=payload, headers=headers)
        return response

    def get_policy(self,
                   session,
                   policy_id):
        """
        Function to fetch a cloudlet policy detail

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudlet_policy_response : cloudlet_policy_response
            Json object details of specific cloudlet policy
        """

        policy_url = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/' + \
                              str(policy_id)

        policy_response = session.get(self.form_url(policy_url))
        return policy_response

    def list_policy_versions(self,
                            session,
                            policy_id,
                            page_size='optional'):
        """
        Function to fetch a cloudlet policy versions

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudletPolicyResponse : cloudletPolicyResponse
            Json object details of specific cloudlet policy versions
        """
        if page_size == 'optional':
            cloudlet_policy_versions_url = 'https://' + self.access_hostname + \
                                           '/cloudlets/api/v2/policies/' + str(
                                               policy_id) + '/versions?includeRules=true'
        else:
            cloudlet_policy_versions_url = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/' + \
                                           str(policy_id) + '/versions?includeRules=true&pageSize=' + str(page_size)

        cloudlet_policy_versions_response = session.get(self.form_url(cloudlet_policy_versions_url))
        return cloudlet_policy_versions_response

    def get_policy_version(self,
                           session,
                           policy_id,
                           version):
        """
        Function to fetch a cloudlet policy detail

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudlet_policy_response : cloudlet_policy_response
            Json object details of specific cloudlet policy
        """

        policy_version_url = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/' + \
                              str(policy_id) + '/versions/' + str(version) + '?omitRules=false'

        policy_version_response = session.get(self.form_url(policy_version_url))
        return policy_version_response

    def create_clone_policy_version(
            self,
            session,
            policy_id,
            data=dict(),
            clone_version='optional'):
        """
        Function to create a policy version

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudlet_policy_create_response : cloudlet_policy_create_response
            Json object details of created cloudlet policy version
        """
        headers = {
            'Content-Type': 'application/json'
        }
        if clone_version == 'optional':
            cloudlet_policy_create_url = 'https://' + self.access_hostname + \
                '/cloudlets/api/v2/policies/' + str(policy_id) + '/versions' + '?includeRules=true'
        else:
            cloudlet_policy_create_url = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/' + \
                str(policy_id) + '/versions' + '?includeRules=true&cloneVersion=' + clone_version

        cloudlet_policy_create_response = session.post(self.form_url(cloudlet_policy_create_url), data, headers=headers)
        return cloudlet_policy_create_response

    def update_policy_version(
            self,
            session,
            policy_id,
            version,
            data=dict()):
        """
        Function to update a policy version

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        update_policy_version_response : update_policy_version_response
            Json object details of updated cloudlet policy version
        """
        headers = {
            'Content-Type': 'application/json'
        }

        update_policy_version_url = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/' + \
            str(policy_id) + '/versions/' + str(version)

        update_policy_version_response = session.put(self.form_url(update_policy_version_url), data, headers=headers)
        return update_policy_version_response

    def activate_policy_version(
            self,
            session,
            policy_id,
            version,
            additionalPropertyNames=[],
            network='staging'):
        """
        Function to activate a policy version

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudlet_policy_activate_response : cloudlet_policy_activate_response
            Json object details of activated cloudlet policy version
        """
        headers = {
            'Content-Type': 'application/json'
        }

        data = dict()
        data['network'] = network
        data['additionalPropertyNames'] = additionalPropertyNames

        cloudlet_policy_activate_url = 'https://' + self.access_hostname + \
            '/cloudlets/api/v2/policies/' + str(policy_id) + '/versions/' + str(version) + '/activations'

        cloudlet_policy_activate_response = session.post(self.form_url(cloudlet_policy_activate_url), json.dumps(data), headers=headers)
        return cloudlet_policy_activate_response

    def list_policy_activations(self,
                           session,
                           policy_id,
                           network):
        """
        Function to fetch activation details of policy

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object
        policy_id : <integer>
            A policy Id
        network : <string>
            staging pr production
        Returns
        -------
        policy_activations_response : policy_activations_response
            Json object details of activation history
        """

        policy_activations_url = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/' + \
                              str(policy_id) + '/activations?network=' + str(network)

        policy_activations_response = session.get(self.form_url(policy_activations_url))
        return policy_activations_response

    def form_url(self, url):
        # This is to ensure accountSwitchKey works for internal users
        if '?' in url:
            url = url + self.account_switch_key
        else:
            # Replace & with ? if there is no query string in URL
            account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&', '?'))
            url = url + account_switch_key
        return url
