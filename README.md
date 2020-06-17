# find-guardduty-user

## Description

`find-guardduty-user` is used to search CloudTrial to find users that triggered GuardDuty alerts

This script will look up all GuardDuty findings and for each one will
pull out the access key, search for that access key in CloudTrail to find
the AssumedRole event.  That event will then provide the ARN of the role
which can be looked up in CloudTrail again to find the username of the
person that triggered the event.

## Installation

TBD

## Usage

TBD

## Examples

Run the command like this:

```sh
find-guardduty-user
```
