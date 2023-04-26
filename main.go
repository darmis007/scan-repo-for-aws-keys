package main

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"os"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

func main() {
	// scan the input for github repository url
	fmt.Print("Enter GitHub repository URL: ")
	var repoUrl string
	fmt.Scanln(&repoUrl)

	// remove https:// from the url
	repoUrl = strings.Replace(repoUrl, "https://github.com/", "", 1)
	// split the url to get the owner and repo name
	parts := strings.Split(repoUrl, "/")
	owner, repo := parts[0], parts[1]

	// set up the GitHub client
	ctx := context.Background()
	var client *github.Client
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		tc := oauth2.NewClient(ctx, ts)
		client = github.NewClient(tc)
	} else {
		client = github.NewClient(nil)
	}

	// get all the commits for the repository
	commits, _, err := client.Repositories.ListCommits(ctx, owner, repo, nil)
	if err != nil {
		log.Fatal(err)
	}

	// compile the AWS key regex pattern
	awsKeyRegex := regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)
	awsSecretKeyRegex := regexp.MustCompile(`([a-zA-Z0-9+/]{40})`)
	// set up a wait group to ensure all goroutines complete before exiting
	var wg sync.WaitGroup

	// iterate through all the commits
	for _, commit := range commits {
		// get the commit details
		commitSha := commit.GetSHA()
		commitMsg := commit.GetCommit().GetMessage()

		// get the tree for the commit
		tree, _, err := client.Git.GetTree(ctx, owner, repo, commitSha, true)
		if err != nil {
			log.Fatal(err)
		}

		// iterate through all the tree entries
		for _, entry := range tree.Entries {
			if *entry.Type == "blob" {
				wg.Add(1)
				go func(entry github.TreeEntry) {
					defer wg.Done()
					// get the contents of the file
					content, _, _, err := client.Repositories.GetContents(ctx, owner, repo, *entry.Path, &github.RepositoryContentGetOptions{Ref: commitSha})
					if err != nil {
						log.Fatal(err)
					}
					fmt.Printf("Processing file: %s\n", *entry.Path)

					// check if the file contains AWS keys
					fileContent, _ := content.GetContent()
					matched := awsKeyRegex.MatchString(fileContent)
					if matched {
						// check if the AWS key is authentic
						match := awsKeyRegex.FindAllStringSubmatch(fileContent, 2)
						matchSecret := awsSecretKeyRegex.FindAllStringSubmatch(fileContent, 2)
						accessKey, secretKey := "", ""
						if len(match) > 0 {
							accessKey = match[0][0]
						}
						if len(matchSecret) > 0 {
							secretKey = matchSecret[0][0]
						}
						if checkAwsKeyValidity(accessKey, secretKey) {
							fmt.Printf("Found authentic AWS key in commit %s: %s - %s\n", commitSha, commitMsg, *entry.Path)
						} else {
							fmt.Printf("Found AWS key in commit %s: %s - %s, but it is not authentic.\n", commitSha, commitMsg, *entry.Path)
						}
					}
				}(*entry)
			}
		}
	}

	wg.Wait()
}

// checkAwsKeyValidity checks if an AWS key is authentic by making a request to the AWS API
func checkAwsKeyValidity(accessKey string, secretKey string) bool {
	fmt.Println(accessKey, secretKey)
	if accessKey == "" && secretKey == ""{
		return false
	}
	if accessKey == "" {
		accessKey = secretKey
	}
	if secretKey == "" {
		secretKey = accessKey
	}
	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, ""),
	})
	if err != nil {
		fmt.Println("Invalid AWS credentials key")
		return false
	}

	// create a new STS client
	svc := sts.New(sess)

	// get the caller identity
	result, err := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Println("Invalid AWS key")
		return false
	}

	// print the caller identity
	fmt.Printf("AWS Account ID: %s\n", *result.Account)
	fmt.Printf("AWS User ARN: %s\n", *result.Arn)
	return true
}