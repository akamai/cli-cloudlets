# cli-cloudlets

Provides a way to interact with the Akamai Cloudlets via Open APIs. Provides various functionality such as searching policies, retrieving, updating, and activating policy versions.

## Akamai CLI Install

```bash
%  akamai install cloudlets
```

## Requirements

- Python 3+
- pip install edgegrid-python

## Prerequisites - Setup API Credentials

In order to use this module, you need to:

- Set up your credential `.edgerc` files as described in the [Create authentication credentials](https://techdocs.akamai.com/developer/docs/set-up-authentication-credentials)
- When working through this process you need to give your API credential the `Cloudlets Policy Manager` grant. The section in your configuration file should be called `cloudlets`.
- If you wish to override, you may also use the `--section <section_name>` to use the specific section credentials from your `.edgerc` file

```
[cloudlets]
client_secret = [CLIENT_SECRET]
host = [HOST]
access_token = [ACCESS_TOKEN_HERE]
client_token = [CLIENT_TOKEN_HERE]
```

## Functionality

Here is a summary of the current functionality:

- List available cloudlet types based on account
- List all cloudlet policies (search by name and/or cloudlet-type)
- Retrieve cloudlet policy version rules
- Update policy version rules
- Activate policy version to staging or production network
- Create a cloudlet policy
- Clone a cloudlet policy (from an existing one)
- Get policy endpoints schema

## Cloudlet Types

Here is the list of cloudlets and cloudlet type codes. Please reference appropriate cloudlet type code in _[list](#list)_ or _[create-policy](#create-policy)_ commands

| name                      | code | policy    |
| ------------------------- | ---- | --------- |
| Application Load Balancer | ALB  |           |
| API Prioritization        | AP   | \* shared |
| Audience Segmentation     | AS   | \* shared |
| Phased Release            | CD   | \* shared |
| Edge Redirector           | ER   | \* shared |
| Forward Rewrite           | FR   | \* shared |
| Request Control           | IG   | \* shared |
| Input Validation          | IV   |           |
| Media Math Advanced       | MMA  |           |
| Media Math Basic          | MMB  |           |
| Visitor Prioritization    | VP   |           |

## akamai-cloudlets

Main program file that wraps this functionality in a command line utility:

- [list](#list)
- [retrieve](#retrieve)
- [update](#update)
- [activate](#activate)
- [create-policy](#create-policy)
- [clone](#clone)
- [status](#status)
- cloudlets TBD
- activation-status TBD
- policy-endpoint TBD

## Global Flags

- `--edgerc value` — Location of the credentials file (default: "/Users/username/.edgerc") [$AKAMAI_EDGERC]
- `--section value` — Section of the credentials file (default: "cloudlets" default:") [$AKAMAI_EDGERC_SECTION]
- `--help`, `-h` — show help
- `--version`, `-v` — print the version

```bash
%  akamai cloudlets --section section_name list
```

### list

List all cloudlet policies. Result is sorted by policy name (case insensitive)
Also search by --name-contains or --cloudlet-type (optional)
Output can be piped to json or csv format (optional)

```xml
%  akamai cloudlets list
%  akamai cloudlets list --name-contains namestring
%  akamai cloudlets list --cloudlet-type ER
%  akamai cloudlets list --name-contains namestring --cloudlet-type ALB
%  akamai cloudlets list --json
%  akamai cloudlets list --csv > sample.csv
```

### retrieve

Retrieves policy version. Please specify either --policy or --policy-id
By default, policy will be saved to file `policy.json`
With argument `--only-match-rules`, information will be displayed in table and saved as `policy_matchrules.xlsx`
If json format is preferred, you can `--json` argument

```xml
%  akamai cloudlets retrieve --policy-id 12345
%  akamai cloudlets retrieve --policy sample_name
%  akamai cloudlets retrieve --policy-id 12345 --version 7
%  akamai cloudlets retrieve --policy-id 12345 --only-match-rules
%  akamai cloudlets retrieve --policy-id 12345 --only-match-rules --json
```

Argument Details:

```xml
--version            Policy version number  (If not specified, CLI will show the latest version, if exists)
--policy             Policy name
--policy-id          Policy id
--only-match-rules   Only return the rules section object  (Optional)
--json               Output the policy details in json format
--show               Automatically launch Microsoft Excel after (Mac OS Only)
```

### update

Update a specific policy with json rules. Please specify either --policy or --policy-id. Specify a version number otherwise a new policy version will be created and its new version number will be returned.

```xml
%  akamai cloudlets update --policy sample_name --file rules.json
%  akamai cloudlets update --policy-id 12345 --file rules.json
%  akamai cloudlets update --policy sample_name --file rules.json --notes "sample notes about the change"
```

Argument Details:

```xml
--policy                     Cloudlet policy name
--policy-id                  Cloudlet policy id
--file                       File that contains cloudlet policy rules (json format)
--notes                      Notes to be associated to the policy version (Optional: if not specified will use value in rules json file)
--version                    Policy version to be updated (Optional: if not specified, a new policy version will be created with specified rules)
```

### activate

Activate a cloudlet policy version to Akamai staging or production network.

```xml
%  akamai cloudlets activate --policy-id 12345 --network staging
%  akamai cloudlets activate --policy sample_name --network staging --version 7
%  akamai cloudlets activate --policy-id 12345 --network staging --version 1 --add-properties property1_name,property2_name
%  akamai cloudlets activate --policy sample_name --network prod
```

Argument Details:

```xml
--policy                     Cloudlet policy name
--policy-id                  Cloudlet policy id
--network                    Either *staging* or *prod*
--version                    Cloudlet policy version to be activated (Optional: if not specified, latest version will be activated)
--add-properties             Comma separated list of property manager configuration names (Optional: configurations will be associated to the policy which is necessary for first time activation
```

### create-policy

Creates a new cloudlet policy

```xml
%  akamai cloudlets create-policy --policy sample_name --group-id 12345 --cloudlet-type ER
%  akamai cloudlets create-policy --policy sample_name --group-name existinggroupname --cloudlet-type AS
%  akamai cloudlets create-policy --policy sample_name --group-id 12345 --cloudlet-type ER --notes "sample create notes"
```

Argument Details:

```xml
--policy                      Cloudlet policy name
--group-id                    Existing group id to be associated with cloudlet policy (please specify either --group-id or --group-name)
--group-name                  Existing group name to be associated with cloudlet policy (please specify either --group-id or --group-name)
--cloudlet-type               Cloudlet type (One of ER, VP, FR, IG, AP, AS, CD, IV, ALB)
--notes                       Notes for cloudlet policy (Optional)
```

### clone

Create a new cloudlet policy by cloning from an existing one.

```xml
%  akamai cloudlets clone --policy-id 67890 --new-policy newname --new-group-id 12345
%  akamai cloudlets clone --policy existingpolicyname --new-policy newname --new-group-name groupname
%  akamai cloudlets clone --policy-id 67890 --version 5 --new-policy newname
%  akamai cloudlets clone --policy existingpolicyname --version 5 --new-policy newname --notes "sample notes"
```

Argument Details:

```xml
--policy                     Cloudlet policy name cloning from (please specify either --policy or --policy-id)
--policy-id                  Cloudlet policy id cloning from (please specify either --policy or --policy-id)
--version                    Version of existing cloudlet policy (Optional: if not specified, will use the latest)
--new-policy                 Name of new cloudlet policy
--new-group-id               Existing group id to be associated with new cloudlet policy (Optional: will use same group if not specified)
--new-group-name             Existing group name to be associated with cloudlet policy (Optional: will use same group if not specified)
--notes                      Policy notes for new cloudlet policy (Optional)
```

### status

Shows current status of policy. Please specify either --policy or --policy-id. Displays which version is active on staging and production and associated property manager configurations.

```xml
%  akamai cloudlets status --policy sample_name
%  akamai cloudlets status --policy-id 12345
```

Argument Details:

```xml
--policy                     Cloudlet policy name
--policy-id                  Cloudlet policy id
```

# Contribution

By submitting a contribution (the “Contribution”) to this project, and for good and valuable consideration, the receipt and sufficiency of which are hereby acknowledged, you (the “Assignor”) irrevocably convey, transfer, and assign the Contribution to the owner of the repository (the “Assignee”), and the Assignee hereby accepts, all of your right, title, and interest in and to the Contribution along with all associated copyrights, copyright registrations, and/or applications for registration and all issuances, extensions and renewals thereof (collectively, the “Assigned Copyrights”). You also assign all of your rights of any kind whatsoever accruing under the Assigned Copyrights provided by applicable law of any jurisdiction, by international treaties and conventions and otherwise throughout the world.

## Local Install

- Minimum python 3.6 `git clone https://github.com/akamai/cli-cloudlets.git`
- Create python virtual environment `python3 -m venv .venv`
- Install required packages `pip3 install -r requirements.txt`
- If testing another branch run, for example, `git switch shared-policy`
- Run as Akamai CLI, first uninstall `akamai uninstall cloudlets`
- Run `pwd` to get current directory i.e `/Users/Documents/cli-onboard`
- Install from local repo
  For MAC OS
  `akamai install file:///Users/Documents/cli-cloudlets` please note there is 3 slashes
  For Window
  `akamai install file://C:/Users/sample/cli-cloudlets` only 2 slashes

# Notice

Copyright 2020 – Akamai Technologies, Inc.

All works contained in this repository, excepting those explicitly otherwise labeled, are the property of Akamai Technologies, Inc.
