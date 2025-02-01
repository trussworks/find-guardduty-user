# find-guardduty-user

## Description

`find-guardduty-user` is used to search CloudTrial to find users that triggered GuardDuty alerts

This script will look up all GuardDuty findings and for each one will
pull out the access key, search for that access key in CloudTrail to find
the AssumedRole event. That event will then provide the ARN of the role
which can be looked up in CloudTrail again to find the username of the
person that triggered the event.

## Installation

For OSX Homebrew:

```sh
brew tap trussworks/tap
brew install find-guardduty-user
```

## Usage

```sh
Description
    Easily identify IAM users that have triggered GuardDuty findings.

Usage:
  find-guardduty-user find [flags]

Flags:
  -p    --aws-guardduty-partition string AWS partition ('aws' or 'aws-us-gov') used for inspecting guardduty (default "aws")
  -r    --aws-guardduty-region string   AWS region used for inspecting guardduty (default "us-west-2")
  -a, --archived                      Show archived findings instead of current findings
  -o, --output string                 Whether to print output as 'text' or 'json' (default "text")
  -v, --debug-logging                 log messages at the debug level.
  -h, --help                          help for find
```

## Examples

Run the command like this:

```sh
find-guardduty-user find
```

Run the command in GovCloud like this:

```sh
find-guardduty-user find -p aws-us-gov -r us-gov-west-1
```

Review archived findings:

```sh
find-guardduty-user find -a
```

Look at the output in JSON format:

```sh
find-guardduty-user find -o json
```
