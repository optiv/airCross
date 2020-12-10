# airCross
This tool represents a communication framework for navigating the various WMWare AirWatch authentication endpoints, allowing for enumeration and single-factor authentication attacks.

```
Usage:
  airCross <method> [OPTIONS] <dom/endpoint> <file>
  airCross -h | -help
  airCross -v

Global Options:
  -h, -help              Show usage
  -a                     User-Agent for request [default: Agent/20.08.0.23/Android/11]
  -t                     Application threads [default: 10]
  -u                     Airwatch username
  -p                     AirWatch password
  -d                     Enable debug output
  -r                     Disable randomize device ID
  -udid                  Device UDID value
  -dom                   Domain to Execute discovery against
  -email                 User email used for enumeration
  -gid                   AirWatch GroupID Value
  -sgid                  AirWatch sub-GroupID Value
  -sint                  AirWatch sub-GroupID INT value (Associated to multiple groups)

  <endpoint>             AirWatch endpoint FQDN
  <dom>                  Discovery domain
  <file>                 Line divided file containing GroupID or UserID values

Methods:
  gid-disco              GroupID discovery query
  gid-val                GroupID validation query
  gid-brute              GroupID brute-force enumeration
  auth-boxer             Boxer single-factor authentication attack
  auth-reg               Boxer registration single-factor authentication attack
  auth-val               AirWatch single-factor credential validation attack
  auth-gid               Boxer authentication across multi-group tenants
```

## Attack Methods
airCross offers a variable selector of methods that can be leveraged against an AirWatch solution. These leverage and/or enumerate an authentication GroupID and perform authentication attacks against a list of provided usernames.

### gid-disco
This is a discovery process to automatically enumerate and collect the authentication endpoint and GroupID information for a specific domain.

This method will query the following APIs:
* https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v1/domainlookup/<domain>
* https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v2/domainlookup/<domain>
* https://<endpoint>/DeviceManagement/Enrollment/EmailDiscovery

Examples:
To perform discovery against AirWatch's discovery API:
```
airCross gid-disco <domain> ""
```

To perfom HTML disclosure of GroupID details from a known endpoint:
```
airCross gid-disco -email test@<domain> -u test -p test <endpoint> ""
```

### gid-val
This method collects validation details of the discovered GroupID. GroupID authentication has been observed to be performed against a single production value or, in some circumstances, authentication is performed against a list of sub-domain groups. This method will identify the presence of multiple sub-groups and/or provide validation details of the GroupID value.
```
[*] Endpoint <endpoint> contains X groups
[*] Run gid-val method for full listing
```
Executing the gid-val request against the discovered GroupID and endpoint will list all defined sub-groups. Additionally, long/summarized GroupID names will be provided.

This method will query the following API:
* https://<endpoint>/deviceservices/enrollment/airwatchenroll.aws/validategroupidentifier
* https://<endpoint>/deviceservices/enrollment/airwatchenroll.aws/validategroupselector

Examples:
To validate a specific GroupID:
```
airCross gid-val -gid <GroupID> <endpoint> ""
```

Some GroupID values contain sub-groupings across various security groups. To validate this information run gid-val against a target sub-group:
```
airCross gid-val -gid <GroupID> -sgid <SubGroup> -sint <SubGroup-INT> <endpoint> ""
```
SubGroup listings from gid-val are denoted with an integer value attributed to the subGroup that would additionally need to be provided in the options request.

### gid-brute
This method allows brute forcing GroupID values against a known AirWatch endpoint.

This method will query the following API:
* https://<endpoint>/deviceservices/authenticationendpoint.aws

Examples:
Execution of gid-brute requires a line delminiated file containing GroupID values to attempt to validate against a known AirWatch endpoint.
```
airCross gid-brute -u <username> -p <password> <endpoint> <GroupID-file>
```

### auth-boxer
This method allows brute forcing user authentication requests, targeting a known AirWatch endpoint and GroupID, against the AirWatch Boxer API.

This method will query the following API:
* https://<endpoint>/deviceservices/authenticationendpoint.aws

Examples:
Execution of auth-boxer requires a line delminiated file containing username values to attempt to validate against a known AirWatch endpoint.
```
airCross auth-boxer -gid <GroupID> -p <password>  <endpoint> <Username-file>
```

In a configuration including sub-groups, the sub-group shortname would be supplied under the GID option.
```
airCross auth-boxer -gid <subGroup-short> -p <password>  <endpoint> <Username-file>
```
Sub-group listings from gid-val are denoted with an integer value attributed to the sub-group that would additionally need to be provided in the options request.

### auth-reg
This method allows brute forcing user authentication requests, targeting a known AirWatch endpoint and GroupID, against the AirWatch Boxer API.

This method will query the following API:
* https://<endpoint>/deviceservices/authenticationendpoint.aws

Examples:
Execution of auth-boxer requires a line delminiated file containing username values to attempt to validate against a known AirWatch endpoint.
```
airCross auth-reg -gid <GroupID> -p <password>  <endpoint> <Username-file>
```

In a configuration including sub-groups, the sub-group shortname would be supplied under the GID option.
```
airCross auth-reg -gid <subGroup-short> -p <password>  <endpoint> <Username-file>
```
Sub-group listings from gid-val are denoted with an integer value attributed to the sub-group that would additionally need to be provided in the options request.

### auth-val
This method allows brute forcing user authentication requests, targeting a known AirWatch endpoint and GroupID, against the AirWatch HUB registration API.

This method will query the following API:
* https://<endpoint>/deviceservices/enrollment/airwatchenroll.aws/validatelogincredentials

Examples:
Execution of auth-val requires a line delminiated file containing username values to attempt to validate against a known AirWatch endpoint.
```
airCross auth-val -gid <GroupID> -p <password>  <endpoint> <Username-file>
```

In a configuration including sub-groups, the sub-group shortname would be supplied under the GID option.
```
airCross auth-val -gid <GroupID> -sgid <SubGroup> -sint <SubGroup-INT> <endpoint> -p <password> <Username-file>
```
Sub-group listings from gid-val are denoted with an integer value attributed to the sub-group that would additionally need to be provided in the options request.

### auth-gid
This method allows single account authentication checks against each sub-group definition. This method can be used to validate user access and/or registration permissions to each sub-group attributed to the primary GroupID.

This method will query the following API:
* https://<endpoint>/deviceservices/authenticationendpoint.aws

Examples:
Execution of auth-gid requires a username/password combinations to leverage as an authentication attempt to each sub-group.
```
airCross.go auth-gid -gid <GroupID> -u <user> -p <password> <endpoint> ""
```
