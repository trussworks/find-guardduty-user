package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// FindingDetail captures the data from a guard duty finding
type FindingDetail struct {
	ID             *string `json:"id"`
	CreatedAt      *string `json:"createdAt"`
	AccessKeyID    *string `json:"accessKeyID,omitempty"`
	PrincipalID    *string `json:"principalID,omitempty"`
	AssumedRoleARN *string `json:"assumeRoleARN"`
	Username       *string `json:"username"`
	IPAddress      *string `json:"ipAddress,omitempty"`
	ServiceName    *string `json:"serviceName,omitempty"`
	API            *string `json:"api,omitempty"`
	City           *string `json:"city,omitempty"`
	Country        *string `json:"country,omitempty"`
}

// PrintJSON will log JSON-formatted output
func (fd *FindingDetail) PrintJSON(logger *log.Logger) error {
	fdJSON, err := json.Marshal(fd)
	if err != nil {
		return fmt.Errorf("Unable to marshal FindingDetail to JSON: %w", err)

	}
	logger.Println(string(fdJSON))
	return nil
}

// Print will log plain-text output
func (fd *FindingDetail) Print(logger *log.Logger) {
	template := `
Finding ID:         %s
Finding Created At: %s
Access Key ID:      %s
Principal ID:       %s
Assumed Role ARN:   %s
Username:           %s
IPv4:               %s
Service Name:       %s
API:                %s
City, Country:      %s, %s`

	logger.Println(fmt.Sprintf(template,
		aws.StringValue(fd.ID),
		aws.StringValue(fd.CreatedAt),
		aws.StringValue(fd.AccessKeyID),
		aws.StringValue(fd.PrincipalID),
		aws.StringValue(fd.AssumedRoleARN),
		aws.StringValue(fd.Username),
		aws.StringValue(fd.IPAddress),
		aws.StringValue(fd.ServiceName),
		aws.StringValue(fd.API),
		aws.StringValue(fd.City),
		aws.StringValue(fd.Country),
	))
}

type errInvalidPartition struct {
	Partition string
}

func (e *errInvalidPartition) Error() string {
	return fmt.Sprintf("invalid partition %s", e.Partition)
}

type errInvalidRegion struct {
	Region string
}

func (e *errInvalidRegion) Error() string {
	return fmt.Sprintf("invalid region %s", e.Region)
}

type errInvalidOutput struct {
	Output string
}

func (e *errInvalidOutput) Error() string {
	return fmt.Sprintf("invalid output %s", e.Output)
}

// version is the published version of the utility
var version string

const (
	// AWSGuardDutyPartitionFlag is the AWS Guard Duty Partition Flag
	AWSGuardDutyPartitionFlag = "aws-guardduty-partition"
	// AWSGuardDutyRegionFlag is the AWS GuardDuty Region Flag
	AWSGuardDutyRegionFlag = "aws-guardduty-region"
	// ArchivedFlag is the Archive Flag
	ArchivedFlag = "archived"
	// OutputFlag is the Output Flag
	OutputFlag = "output"
	// VerboseFlag is the Verbose Flag
	VerboseFlag string = "debug-logging"
)

func initFlags(flag *pflag.FlagSet) {

	flag.StringP(AWSGuardDutyPartitionFlag, "p", "aws", "AWS partition used for inspecting guardduty")
	flag.StringP(AWSGuardDutyRegionFlag, "r", "us-west-2", "AWS region used for inspecting guardduty")
	flag.BoolP(ArchivedFlag, "a", false, "Show archived findings instead of current findings")
	flag.StringP(OutputFlag, "o", "json", "Whether to print output as 'text' or 'json'")

	// Verbose
	flag.BoolP(VerboseFlag, "v", false, "log messages at the debug level.")

	flag.SortFlags = false
}

func checkRegion(v *viper.Viper) error {

	regions, ok := endpoints.RegionsForService(endpoints.DefaultPartitions(), v.GetString(AWSGuardDutyPartitionFlag), endpoints.GuarddutyServiceID)
	if !ok {
		return fmt.Errorf("could not find regions for service %s", endpoints.GuarddutyServiceID)
	}

	p := v.GetString(AWSGuardDutyPartitionFlag)
	if len(p) == 0 {
		return fmt.Errorf("%s is invalid: %w", AWSGuardDutyPartitionFlag, &errInvalidPartition{Partition: p})
	}

	r := v.GetString(AWSGuardDutyRegionFlag)
	if len(r) == 0 {
		return fmt.Errorf("%s is invalid: %w", AWSGuardDutyRegionFlag, &errInvalidRegion{Region: r})
	}

	if _, ok := regions[r]; !ok {
		return fmt.Errorf("%s is invalid: %w", AWSGuardDutyRegionFlag, &errInvalidRegion{Region: r})
	}

	return nil
}

func checkOutput(v *viper.Viper) error {

	outputs := map[string]string{"text": "text", "json": "json"}

	o := v.GetString(OutputFlag)
	if _, ok := outputs[o]; !ok {
		return fmt.Errorf("%s is invalid: %w", OutputFlag, &errInvalidOutput{Output: o})
	}

	return nil
}

func checkConfig(v *viper.Viper) error {

	err := checkRegion(v)
	if err != nil {
		return fmt.Errorf("Region check failed: %w", err)
	}

	err = checkOutput(v)
	if err != nil {
		return fmt.Errorf("Output check failed: %w", err)
	}

	return nil
}

// LookupEvent searches CloudTrail for event smatching a key-value pair
func LookupEvent(key *string, value *string, serviceCloudTrail *cloudtrail.CloudTrail) (*cloudtrail.Event, error) {
	lookupAttribute := cloudtrail.LookupAttribute{
		AttributeKey:   key,
		AttributeValue: value,
	}
	maxResults := int64(1)
	lookupEventsInput := cloudtrail.LookupEventsInput{
		LookupAttributes: []*cloudtrail.LookupAttribute{&lookupAttribute},
		MaxResults:       &maxResults,
	}
	events, err := serviceCloudTrail.LookupEvents(&lookupEventsInput)
	if err != nil {
		return nil, fmt.Errorf("LookupEvents failed with Attribute Key '%s' and Attribute Value '%s': %w", *key, *value, err)
	}
	if len(events.Events) != 1 {
		return nil, fmt.Errorf("Expected exactly one event, got %d", len(events.Events))
	}
	return events.Events[0], nil
}

// GetRoleAndUser tries to use an access key or principal id to find a role arn and username
func GetRoleAndUser(key *string, value *string, serviceCloudTrail *cloudtrail.CloudTrail) (*string, *string, error) {
	event, err := LookupEvent(key, value, serviceCloudTrail)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to find CloudTrail event for %s %s: %w", *key, *value, err)
	}

	// The CloudTrailEvent is a JSON object of unknown format
	dataStr := aws.StringValue(event.CloudTrailEvent)
	var data map[string]interface{}
	err = json.Unmarshal([]byte(dataStr), &data)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to unmarshal JSON data from CloudTrail event: %w", err)
	}
	userIdentity, ok := data["userIdentity"].(map[string]interface{})
	if !ok {
		return nil, nil, errors.New("Could not retrieve userIdentity from JSON object")
	}
	roleArn, ok := userIdentity["arn"].(string)
	if !ok {
		return nil, nil, errors.New("Could not retrieve arn from JSON object")
	}
	username, _ := userIdentity["userName"].(string)
	return &roleArn, &username, nil
}

// GetUser uses a roleArn to find a given user
func GetUser(roleArn *string, serviceCloudTrail *cloudtrail.CloudTrail) (*string, error) {
	key := "ResourceName"
	event, err := LookupEvent(&key, roleArn, serviceCloudTrail)
	if err != nil {
		return nil, fmt.Errorf("Unable to find CloudTrail event for role arn %s: %w", *roleArn, err)
	}

	// The CloudTrailEvent is a JSON object of unknown format
	username := aws.StringValue(event.Username)
	return &username, nil
}

func main() {
	root := cobra.Command{
		Use:   "find-guardduty-user [flags]",
		Short: "Find Users that triggered GuardDuty findings",
		Long:  "Find Users that triggered GuardDuty findings",
	}

	completionCommand := &cobra.Command{
		Use:   "completion",
		Short: "Generates bash completion scripts",
		Long:  "To install completion scripts run:\nfind-guardduty-user completion > /usr/local/etc/bash_completion.d/find-guardduty-user",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenBashCompletion(os.Stdout)
		},
	}
	root.AddCommand(completionCommand)

	findGuardDutyUserCommand := &cobra.Command{
		Use:                   "find [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Find Users that triggered GuardDuty findings",
		Long: `Description
    Easily identify IAM users that have triggered GuardDuty findings.`,
		RunE: findGuardDutyUserFunction,
	}
	initFlags(findGuardDutyUserCommand.Flags())
	root.AddCommand(findGuardDutyUserCommand)

	findGuardDutyVersionCommand := &cobra.Command{
		Use:                   "version",
		DisableFlagsInUseLine: true,
		Short:                 "Print the version",
		Long:                  "Print the version",
		RunE:                  findGuardDutyVersionFunction,
	}
	root.AddCommand(findGuardDutyVersionCommand)

	if err := root.Execute(); err != nil {
		panic(err)
	}
}

func findGuardDutyVersionFunction(cmd *cobra.Command, args []string) error {
	if len(version) == 0 {
		fmt.Println("development")
		return nil
	}
	fmt.Println(version)
	return nil
}

func findGuardDutyUserFunction(cmd *cobra.Command, args []string) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()

	err := cmd.ParseFlags(args)
	if err != nil {
		return err
	}

	flag := cmd.Flags()

	v := viper.New()
	bindErr := v.BindPFlags(flag)
	if bindErr != nil {
		return bindErr
	}
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	// Create the logger
	// Remove the prefix and any datetime data
	logger := log.New(os.Stdout, "", log.LstdFlags)

	verbose := v.GetBool(VerboseFlag)
	if !verbose {
		// Disable any logging that isn't attached to the logger unless using the verbose flag
		log.SetOutput(ioutil.Discard)
		log.SetFlags(0)

		// Remove the flags for the logger
		logger.SetFlags(0)
	}

	// Check the config and exit with usage details if there is a problem
	checkConfigErr := checkConfig(v)
	if checkConfigErr != nil {
		return checkConfigErr
	}

	// Get credentials from environment
	awsRegion := v.GetString(AWSGuardDutyRegionFlag)

	awsConfig := &aws.Config{
		Region: aws.String(awsRegion),
	}

	// Attempt to retrieve AWS creds from envar, if not move to aws-vault
	creds := credentials.NewEnvCredentials()
	_, credsGetErr := creds.Get()
	if credsGetErr != nil {
		logger.Fatal(fmt.Errorf("error creating aws config: %w", credsGetErr))
	}
	// we have creds for envars return them
	awsConfig.CredentialsChainVerboseErrors = aws.Bool(verbose)
	awsConfig.Credentials = creds

	session, errorSession := awssession.NewSession(awsConfig)
	if errorSession != nil {
		logger.Fatal(fmt.Errorf("error creating aws session: %w", errorSession))
	}

	// GuardDuty has the findings
	serviceGuardDuty := guardduty.New(session)

	// CloudTrail has information on who caused the event
	serviceCloudTrail := cloudtrail.New(session)

	// List Detectors
	listDetectorsInput := guardduty.ListDetectorsInput{}
	detectors, err := serviceGuardDuty.ListDetectors(&listDetectorsInput)
	if err != nil {
		logger.Fatal(fmt.Errorf("Unable to list Guard Duty detectors: %w", err))
	}

	// Walk through detectors
	for _, detectorID := range detectors.DetectorIds {

		// The token for paging through findings
		var listFindingsNextToken *string

		for {
			// Define the service condition to list findings
			archived := "false"
			if v.GetBool(ArchivedFlag) {
				archived = "true"
			}
			serviceCondition := guardduty.Condition{}
			serviceCondition.SetEq([]*string{&archived})

			findingCriteria := guardduty.FindingCriteria{
				Criterion: map[string]*guardduty.Condition{
					"service.archived": &serviceCondition,
				},
			}
			listFindingsInput := guardduty.ListFindingsInput{
				DetectorId:      detectorID,
				FindingCriteria: &findingCriteria,
				NextToken:       listFindingsNextToken,
			}

			findingList, err := serviceGuardDuty.ListFindings(&listFindingsInput)
			if err != nil {
				logger.Println(fmt.Errorf("Unable to list Guard Duty findings: %w", err))
				continue
			}

			// Set the next token to page for
			listFindingsNextToken = findingList.NextToken

			// If we've run out of findings then quit
			if len(findingList.FindingIds) == 0 {
				break
			}
			getFindingsInput := guardduty.GetFindingsInput{
				DetectorId: detectorID,
				FindingIds: findingList.FindingIds,
			}
			findings, err := serviceGuardDuty.GetFindings(&getFindingsInput)
			if err != nil {
				logger.Println(fmt.Errorf("Unable to retrieve Guard Duty findings: %w", err))
			}

			// Walk through each finding
			for _, finding := range findings.Findings {
				if finding == nil {
					continue
				}

				// Not all events are from humans and in those cases we skip
				if finding.Resource.AccessKeyDetails == nil {
					if verbose {
						logger.Println(fmt.Sprintf("\nSkipping Non User Finding ID: %s", aws.StringValue(finding.Id)))
					}
					continue
				}

				fd := FindingDetail{
					ID:          finding.Id,
					CreatedAt:   finding.CreatedAt,
					AccessKeyID: finding.Resource.AccessKeyDetails.AccessKeyId,
					PrincipalID: finding.Resource.AccessKeyDetails.PrincipalId,
				}

				// If the Service is missing then these items can't be used
				if finding.Service != nil {
					fd.IPAddress = finding.Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4
					fd.ServiceName = finding.Service.Action.AwsApiCallAction.ServiceName
					fd.API = finding.Service.Action.AwsApiCallAction.Api
					fd.City = finding.Service.Action.AwsApiCallAction.RemoteIpDetails.City.CityName
					fd.Country = finding.Service.Action.AwsApiCallAction.RemoteIpDetails.Country.CountryName
				}

				var roleArn *string
				var username *string

				// Get Assumed Role ARN and Username details based on Access Key or Principal IDs
				if fd.AccessKeyID != nil && *fd.AccessKeyID != "" && *fd.AccessKeyID != "GeneratedFindingAccessKeyId" {
					var err error
					key := "AccessKeyId"
					roleArn, username, err = GetRoleAndUser(&key, fd.AccessKeyID, serviceCloudTrail)
					if err != nil {
						logger.Println(fmt.Errorf("Unable to find role arn and username from access key in finding: %w", err))
						continue
					}
				} else if fd.PrincipalID != nil && *fd.PrincipalID != "" && *fd.PrincipalID != "GeneratedFindingPrincipalId" {
					var err error
					key := "ResourceName"
					roleArn, username, err = GetRoleAndUser(&key, fd.PrincipalID, serviceCloudTrail)
					if err != nil {
						logger.Println(fmt.Errorf("Unable to find role arn and username from principal ID in finding: %w", err))
						continue
					}
				} else {
					continue
				}

				if roleArn == nil || *roleArn == "" {
					continue
				}
				fd.AssumedRoleARN = roleArn

				// If previous queries did not return username try again using the assumed role arn
				if username == nil || *username == "" {
					var err error
					username, err = GetUser(roleArn, serviceCloudTrail)
					if err != nil {
						logger.Println(fmt.Errorf("Unable to find role username from role arn: %w", err))
						continue
					}
				}
				fd.Username = username

				// Print output in desired format
				if output := v.GetString(OutputFlag); output == "json" {
					err := fd.PrintJSON(logger)
					if err != nil {
						logger.Println(fmt.Errorf("Unable to marshal finding detail to JSON: %w", err))
					}
				} else {
					fd.Print(logger)
				}
			}

			// If the next token is nil or an empty string then there are no more results to page through
			if listFindingsNextToken == nil || *listFindingsNextToken == "" {
				break
			}
		}
	}
	return nil
}
