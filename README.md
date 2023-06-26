# cli-cloudlets

Provides a way to interact with the Akamai Cloudlets via Open APIs. Provides various functionality such as searching policies, retrieving, updating, and activating policy versions.

## Akamai CLI Install

```bash
%  akamai install cloudlets
```

## Requirements

- Python 3+

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

- Display available cloudlet types based on account
- List all cloudlet policies (search by name and/or cloudlet-type)
- Get policy endpoints schema
- Retrieve cloudlet policy version rules
- Get status of cloudlet policy version on each network and associated property manager
- Update policy version rules
- Clone a cloudlet policy (from an existing one)
- Create a cloudlet policy
- Activate policy version to staging or production network
- View activation history of the policy version to staging or production network

## Cloudlet Types

Here is the list of cloudlets and cloudlet type codes. Please reference appropriate cloudlet type code in _[cloudlets](#cloudlets)_, _[list](#list)_, or _[create-policy](#create-policy)_ commands

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

- [cloudlets](#cloudlets)
- [list](#list)
- [policy-endpoint](#policy-endpoint)
- [retrieve](#retrieve)
- [status](#status)
- [update](#update)
- [clone](#clone)
- [create-policy](#create-policy)
- [activate](#activate)
- [activation-status](#activation-status)

## Global Flags

- `--edgerc value` — Location of the credentials file (default: "/Users/username/.edgerc") [$AKAMAI_EDGERC]
- `--section value` — Section of the credentials file (default: "cloudlets" default:") [$AKAMAI_EDGERC_SECTION]
- `--help`, `-h` — show help
- `--version`, `-v` — print the version

```bash
%  akamai cloudlets --section section_name list
```

### cloudlets

Display cloudlet policy types available for the account. Display name, code, and policy type

```xml
%  akamai cloudlets cloudlets
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

Argument Details:

```xml
  --json            Output the policy details in json format
  --csv             Output the policy details in csv format
  --cloudlet-type   Abbreviation code for cloudlet type
  --name-contains   String to use for searching for policies by name
```

### policy-endpoint

Provide API specification for each cloudlet type.

```xml
%  akamai cloudlets policy-endpoint --cloudlet-type VP
%  akamai cloudlets policy-endpoint --cloudlet-type VP --template update-policy
%  akamai cloudlets policy-endpoint --cloudlet-type VP --template create-nimbus_policy_version-VP-1.0 --json
```

Argument Details:

```xml
  --cloudlet-type   cloudlet type  [required]
  --json            Output the policy details in json format
  --template        ie. update-policy, create-policy, update-nimbus_policy_version-ALB-1.0
```

### retrieve

Retrieves policy version.

- By default, policy will be saved to file `policy.json`
- With argument `--only-match-rules` information will be displayed in table and saved to file `policy_matchrules.xlsx`
- If json format is preferred, you can provide `--json` argument

```xml
%  akamai cloudlets retrieve --policy-id 12345
%  akamai cloudlets retrieve --policy sample_name
%  akamai cloudlets retrieve --policy-id 12345 --version 7
%  akamai cloudlets retrieve --policy-id 12345 --only-match-rules
%  akamai cloudlets retrieve --policy-id 12345 --only-match-rules --json
%  akamai cloudlets retrieve --policy-id 12345 --only-match-rules --show
```

Argument Details:

```xml
  --policy            Policy Name (please specify either --policy-id or --policy)
  --policy-id         Policy Id (please specify either --policy-id or --policy)
  --version           Policy version number  (If not specified, CLI will show the latest version, if exists)
  --only-match-rules  Only return the rules section object  (Optional)
  --json              Output the policy details in json format
  --show              Automatically launch Microsoft Excel after (Mac OS Only)
```

### status

Shows current status of policy. Displays which version is active on staging and production and associated property manager configurations.

```xml
%  akamai cloudlets status --policy sample_name
%  akamai cloudlets status --policy-id 12345
```

Argument Details:

```xml
  --policy      Policy Name (please specify either --policy-id or --policy)
  --policy-id   Policy Id (please specify either --policy-id or --policy)
```

### update

Update a specific policy with json rules. Please specify either `--policy` or `--policy-id`. Specify a version number otherwise a new policy version will be created and its new version number will be returned.
See [policy-endpoint](#polcy-endpoint) for correct json upload file

```xml
%  akamai cloudlets update --policy sample_name --file rules.json
%  akamai cloudlets update --policy-id 12345 --file rules.json
%  akamai cloudlets update --policy sample_name --file rules.json --notes "sample notes about the change"
%  akamai cloudlets update --policy-id 162485 --share --version 2 --file policy.json
%  akamai cloudlets update --policy-id 162485 --share --group-id 47580 --notes "sample note #2"
```

Argument Details:

```xml
  --group-id    Group ID without ctr_ prefix
  --policy      Policy Name
  --policy-id   Policy Id
  --notes       Policy version notes
  --version     Policy version to update, otherwise creates new version
  --file        JSON file with policy data
  --share       Shared policy.  This flag is required if you update a share policy
```

### clone

Clone policy from an existing policy using API v3

```xml
%  akamai cloudlets clone --policy-id 67890 --new-policy newname --group-id 12345
%  akamai cloudlets clone --policy-id 67890 --new-policy newname --group-id 12345 --version 5
%  akamai cloudlets clone --policy-id 67890 --new-policy newname --group-id 12345 --version [1,13,14,15]
```

Argument Details:

```xml
  --policy-id    Policy Id  [required]
  --new-policy   New Policy Name  [required]
  --group-id     Group ID of new policy  [required]
  --version      Policy version numbers to be cloned from i.e. [1] or [1,2,3]
```

### create-policy

Creates a new cloudlet policy
See [cloudlets](#cloudlets) for correct cloudlet types

```xml
%  akamai cloudlets create-policy --policy sample_name --group-id 12345 --cloudlet-type ER
%  akamai cloudlets create-policy --policy sample_name --group-id 12345 --cloudlet-type ER --share
%  akamai cloudlets create-policy --policy sample_name --group-name existinggroupname --cloudlet-type AS
%  akamai cloudlets create-policy --policy sample_name --group-id 12345 --cloudlet-type ER --notes "sample create notes"
```

Argument Details:

```xml
  --policy          Policy Name  [required]
  --cloudlet-type   Abbreviation code for cloudlet type  [required]
                    one of ALB, AP, AS, CD, ER, FR, IG, IV, MMA, MMB, VP
  --group-id        Existing group id without grp_ prefix to be associated with cloudlet policy
                    (please specify either --group-id or --group-name)
  --group-name      Existing group name to be associated with cloudlet policy
                    (please specify either --group-id or --group-name)
  --share           Shared policy [optional]
  --notes           Policy Notes [optional]
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
  --policy           Policy Name
  --policy-id        Policy Id
  --version          Policy version to be activated (Optional: if not specified, latest version will be activated)
  --network          Akamai network (**staging** or **prod**)  [required]
  --add-properties   Property names to be associated to cloudlet policy (comma separated).
                     (Optional: configurations will be associated to the policy which is necessary for first time activation)
```

### activation-status

Show activation history status of the policy id on each network, if specified

```xml
%  akamai cloudlets activation-status --policy-id 162485
%  akamai cloudlets activation-status --policy-id 162485 --network staging
```

Argument Details:

```xml
  --policy-id   Policy Id  [required]
  --network     Akamai network (staging or production)
```

# Contribution

By submitting a contribution (the “Contribution”) to this project, and for good and valuable consideration, the receipt and sufficiency of which are hereby acknowledged, you (the “Assignor”) irrevocably convey, transfer, and assign the Contribution to the owner of the repository (the “Assignee”), and the Assignee hereby accepts, all of your right, title, and interest in and to the Contribution along with all associated copyrights, copyright registrations, and/or applications for registration and all issuances, extensions and renewals thereof (collectively, the “Assigned Copyrights”). You also assign all of your rights of any kind whatsoever accruing under the Assigned Copyrights provided by applicable law of any jurisdiction, by international treaties and conventions and otherwise throughout the world.

## Local Install

- Minimum python 3.6 `git clone https://github.com/akamai/cli-cloudlets.git`
- cd into cli-cloudlets directory `cd cli-onboard`
- Create python virtual environment `python3 -m venv .venv`
- Install required packages `pip3 install -r requirements.txt`
- If testing another branch run, for example, `git checkout -b shared-policy`
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
