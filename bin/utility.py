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

import json


class Utility(object):

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
        cloudlet_code= {'ER': 0, 'VP': 1,'FR': 3, 'IG' : 4,
                        'AP': 5, 'AS': 6, 'CD': 7, 'IV': 8, 'ALB': 9}
        return cloudlet_code

    def get_policy_by_name(self, session, cloudlet_object, policy_name, root_logger):
        """
        Function to fetch policy details

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object
            cloudlet_object: <object>
            policy_name: <string>
        Returns
        -------
        policy_info : policy_info
            (policy_info) Dictionary containing all the details of policy
        """
        policy_info = dict()
        cloudlet_policies_response = cloudlet_object.list_policies(session)
        if cloudlet_policies_response.status_code == 200:
            for policy in cloudlet_policies_response.json():
                if policy_name is not None:
                    if(str(policy["name"].lower()) == str(policy_name).lower()):
                        policy_info = policy
        else:
            root_logger.info('ERROR: Unable to fetch policies')
            root_logger.info(json.dumps(cloudlet_policies_response.json(), indent=4))
            exit(-1)

        #If policy_info is empty, we check for not null after return
        return policy_info

    def get_policy_by_id(self, session, cloudlet_object, policy_id, root_logger):
        """
        Function to fetch policy details

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object
            cloudlet_object: <object>
            policy_id: <int>
        Returns
        -------
        policy_info : policy_info
            (policy_info) Dictionary containing all the details of policy
        """
        policy_info = dict()
        policy_response = cloudlet_object.get_policy(session,policy_id)
        if policy_response.status_code == 200:
            policy_info = policy_response.json()
        else:
            root_logger.info('ERROR: Unable to find existing policy')
            root_logger.info(json.dumps(policy_response.json(), indent=4))
            exit(-1)        

        #If policy_info is empty, we check for not null after return
        return policy_info


    def get_latest_version(self, session, cloudlet_object, policy_id, root_logger):
        """
        Function to fetch latest version

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object
            cloudlet_object: <object>
            policy_id: <int>
        Returns
        -------
        policy_version : policy_version
            (policy_version) integer (latest policy version)
        """
        policy_versions_response = cloudlet_object.list_policy_versions(session, policy_id, page_size=1)
        if policy_versions_response.status_code ==200:
            #If for some reason, can't find a version
            if len(policy_versions_response.json()) > 0:
                version = str(policy_versions_response.json()[0]['version'])
            else:
                root_logger.info('ERROR: Unable to find latest version. Check if version exists')
                exit(-1)
        else:
            root_logger.info('ERROR: Unable to fetch policy versions')
            root_logger.info(json.dumps(policy_versions_response.json(), indent=4))
            exit(-1)

        return version
