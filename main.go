// Copyright 2020 Ben Kehoe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var Version string = "0.4"

type innerError struct {
	Code    string
	Message string
}

type errorBody struct {
	Error innerError
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	log.Printf("Error %d: %s %s\n", status, code, message)

	w.Header().Add("Content-type", "application/json")
	w.WriteHeader(http.StatusMethodNotAllowed)
	errorBody := errorBody{
		Error: innerError{
			Code:    code,
			Message: message,
		},
	}
	bodyBytes, err := json.Marshal(errorBody)
	if err != nil {
		log.Fatal(err)
	}
	w.Write(bodyBytes)
}

type Config struct {
	secret        []byte
	AwsConfig     aws.Config
	PrincipalArn  string
	PrincipalName string
	Debug         bool
}

func NewConfig(awsCfg aws.Config) *Config {
	secretBytes := make([]byte, 32)
	_, err := rand.Read(secretBytes)
	if err != nil {
		log.Fatal(err)
	}

	stsClient := sts.NewFromConfig(awsCfg)

	resp, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatalf("Call to GetCallerIdentity failed, %v", err)
	}
	arn := resp.Arn
	arnParts := strings.Split(*arn, ":")
	nameParts := strings.Split(arnParts[len(arnParts)-1], "/")
	nameType := nameParts[0]
	var principalName string
	if nameType == "user" {
		principalName = nameParts[len(nameParts)-1]
	} else {
		principalName = nameParts[1]
	}

	return &Config{
		secret:        secretBytes,
		AwsConfig:     awsCfg,
		PrincipalArn:  *arn,
		PrincipalName: principalName,
	}
}

func (cfg *Config) EncodeToken(ttl time.Duration) []byte {
	now := time.Now().UTC()
	expiration := now.Add(ttl)
	expirationBytes, err := expiration.MarshalText()
	if err != nil {
		log.Fatal(err)
	}
	encodedExpirationStr := base64.URLEncoding.EncodeToString(expirationBytes)

	mac := hmac.New(sha256.New, cfg.secret)
	mac.Write(expirationBytes)

	macBytes := mac.Sum(nil)
	macStr := base64.URLEncoding.EncodeToString(macBytes)

	token := make([]byte, 0, len(encodedExpirationStr)+len(macStr)+1)

	token = append(token, encodedExpirationStr...)
	token = append(token, "."...)
	token = append(token, macStr...)

	return token
}

func (cfg *Config) ValidateToken(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errors.New("The IMDSv2 token is invalid")
	}
	encodedExpirationStr := parts[0]
	macStr := parts[1]

	expirationBytes, err := base64.URLEncoding.DecodeString(encodedExpirationStr)
	if err != nil {
		return errors.New("The IMDSv2 token is invalid")
	}

	var expiration time.Time
	err = expiration.UnmarshalText(expirationBytes)
	if err != nil {
		return errors.New("The IMDSv2 token is invalid")
	}

	macBytes, err := base64.URLEncoding.DecodeString(macStr)
	if err != nil {
		return errors.New("The IMDSv2 token is invalid")
	}

	mac := hmac.New(sha256.New, cfg.secret)
	mac.Write(expirationBytes)

	expectedMacBytes := mac.Sum(nil)
	if !hmac.Equal(expectedMacBytes, macBytes) {
		return errors.New("The IMDSv2 token is invalid")
	}

	now := time.Now().UTC()
	if expiration.Before(now) {
		return errors.New("The IMDSv2 token has expired")
	}

	return nil
}

func (cfg *Config) handleTokenRequest(w http.ResponseWriter, req *http.Request) {
	if cfg.Debug {
		log.Println("Request headers in handleTokenRequest:")
		for name, values := range req.Header {
			for _, value := range values {
				log.Println("-", name, "=", value)
			}
		}
	}

	if req.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Token must be obtained with PUT")
		return
	}

	forwardedFor := req.Header.Get("x-forwarded-for")
	if forwardedFor != "" {
		writeError(w, http.StatusUnauthorized, "InvalidHeader", "Token requests can't contain X-Forwarded-For")
		return
	}

	ttlStr := req.Header.Get("x-aws-ec2-metadata-token-ttl-seconds")
	if ttlStr == "" {
		writeError(w, http.StatusUnauthorized, "MissingTTL", "The IMDSv2 token expiration header is missing")
		return
	}
	ttlInt, err := strconv.Atoi(ttlStr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "InvalidTTL", "The IMDSv2 token expiration is invalid")
		return
	}
	if ttlInt <= 0 || ttlInt > 21600 {
		writeError(w, http.StatusUnauthorized, "InvalidTTL", "The IMDSv2 token expiration is invalid")
		return
	}
	ttl := time.Second * time.Duration(ttlInt)

	bodyBytes := cfg.EncodeToken(ttl)
	// Go SDK V2 requires the response to have this header
	// https://github.com/aws/aws-sdk-go-v2/blob/787a81828a3812407a6d90036f07449d77a0f070/feature/ec2/imds/api_op_GetToken.go#L80
	w.Header().Add("x-aws-ec2-metadata-token-ttl-seconds", ttlStr)
	w.Header().Add("Content-type", "text/plain")
	w.Write(bodyBytes)

	if cfg.Debug {
		log.Println("Response from handleTokenRequest:")
		log.Println(string(bodyBytes))
		log.Println("Completed handleTokenRequest")
	}
}

func (cfg *Config) handleRequest(w http.ResponseWriter, req *http.Request) {
	if cfg.Debug {
		log.Println("Request headers of handleRequest:")
		for name, values := range req.Header {
			for _, value := range values {
				log.Println("-", name, "=", value)
			}
		}
	}

	if req.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
		return
	}

	token := req.Header.Get("x-aws-ec2-metadata-token")
	if token == "" {
		writeError(w, http.StatusUnauthorized, "MissingToken", "The IMDSv2 token header is missing")
		return
	}
	if err := cfg.ValidateToken(token); err != nil {
		writeError(w, http.StatusUnauthorized, "InvalidToken", err.Error())
		return
	}

	if req.URL.Path == "/latest/meta-data/iam/security-credentials/" {
		cfg.handleRoleRequest(w, req)
	} else {
		role := req.URL.Path[len("/latest/meta-data/iam/security-credentials/"):]
		cfg.handleCredentialRequest(w, req, role)
	}

	if cfg.Debug {
		log.Println("Completed handleRequest")
	}
}

func (cfg *Config) handleRoleRequest(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-type", "text/plain")
	io.WriteString(w, cfg.PrincipalName)

	if cfg.Debug {
		log.Println("Response from handleRoleRequest:")
		log.Println(cfg.PrincipalName)
		log.Println("Completed handleRoleRequest")
	}
}

// This is based on the example output in the IMDS documentation:
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials
type Response struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      string
	// Go SDK V2 requires the status to be set and the value to be equal to "Success"
	// https://github.com/aws/aws-sdk-go-v2/blob/787a81828a3812407a6d90036f07449d77a0f070/credentials/ec2rolecreds/provider.go#L220
	Code        string
	LastUpdated string
	Type        string
}

func generateResponseWithTemporaryCredentials(awsConfig aws.Config) (Response, error) {
	response := Response{}
	stsClient := sts.NewFromConfig(awsConfig)
	sessionCreds, err := stsClient.GetSessionToken(context.TODO(), &sts.GetSessionTokenInput{})
	if err != nil {
		return response, err
	}

	// time.Time has a method of .String() but it returns it in a format we can't use.
	sessionExpiration, err := sessionCreds.Credentials.Expiration.MarshalText()
	if err != nil {
		return response, err
	}

	lastUpdatedTime := time.Now().UTC()
	lastUpdated, err := lastUpdatedTime.MarshalText()
	if err != nil {
		return response, err
	}

	response = Response{
		AccessKeyId:     *sessionCreds.Credentials.AccessKeyId,
		SecretAccessKey: *sessionCreds.Credentials.SecretAccessKey,
		Token:           *sessionCreds.Credentials.SessionToken,
		Expiration:      string(sessionExpiration),
		Code:            "Success",
		LastUpdated:     string(lastUpdated),
		Type:            "AWS-HMAC",
	}

	return response, nil
}

func (cfg *Config) GenerateResponse() (Response, error) {
	response := Response{}
	awsCreds, err := cfg.AwsConfig.Credentials.Retrieve(context.TODO())
	if err != nil {
		return response, err
	}

	if awsCreds.SessionToken == "" {
		// Convert static credentials to temporary credentials so the return value
		// always has a session token and expiration
		return generateResponseWithTemporaryCredentials(cfg.AwsConfig)
	}

	// Make sure there's an expiration (even if it's wrong)
	var expirationTime time.Time
	if !awsCreds.Expires.IsZero() {
		expirationTime = awsCreds.Expires
	} else {
		expirationTime = time.Now().Add(time.Hour)
	}

	// time.Time has a method of .String() but it returns it in a format we can't use.
	expiration, err := expirationTime.MarshalText()
	if err != nil {
		return response, err
	}

	lastUpdatedTime := time.Now().UTC()
	lastUpdated, err := lastUpdatedTime.MarshalText()
	if err != nil {
		return response, err
	}

	response = Response{
		AccessKeyId:     awsCreds.AccessKeyID,
		SecretAccessKey: awsCreds.SecretAccessKey,
		Token:           awsCreds.SessionToken,
		Expiration:      string(expiration),
		LastUpdated:     string(lastUpdated),
		Code:            "Success",
		Type:            "AWS-HMAC",
	}

	return response, nil
}

func (cfg *Config) handleCredentialRequest(w http.ResponseWriter, req *http.Request, role string) {
	response, err := cfg.GenerateResponse()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "InternalServerError", "Something went wrong")
		return
	}

	bodyBytes, err := json.Marshal(response)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "InternalServerError", "Something went wrong")
		return
	}

	w.Header().Add("Content-type", "application/json")
	w.Write(bodyBytes)

	if cfg.Debug {
		log.Println("Response from handleCredentialRequest:")
		log.Println(string(bodyBytes))
		log.Println("Completed handleCredentialRequest")
	}
}

/*
PUT /latest/api/token -> token
GET /latest/meta-data/iam/security-credentials/ -> role name
GET /latest/meta-data/iam/security-credentials/{role_name} -> creds
*/
func (cfg *Config) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Println(req.Method, req.URL.Path)
	if req.URL.Path == "/latest/api/token" {
		cfg.handleTokenRequest(w, req)
	} else if strings.HasPrefix(req.URL.Path, "/latest/meta-data/iam/security-credentials/") {
		cfg.handleRequest(w, req)
	} else {
		writeError(w, http.StatusNotFound, "InvalidPath", "Invalid path")
	}
}

func main() {
	var spec, profile string
	var debug bool
	flag.StringVar(&spec, "port", "", "[HOST:]PORT, can provide as a positional arg")
	flag.StringVar(&profile, "profile", "", "A config profile to use")
	flag.BoolVar(&debug, "verbose", debug, "Show debug output, exposes sensitive information")
	flag.Parse()

	if spec == "" {
		spec = flag.Arg(0)
	}
	if spec == "" {
		log.Fatalln("Error: Port not specified")
	}
	if spec == "version" {
		log.Println(Version)
		os.Exit(0)
	}
	_, err := strconv.Atoi(spec)
	if err == nil {
		spec = ":" + spec
	}
	if strings.HasPrefix(spec, ":") {
		spec = "localhost" + spec
	}

	awsConfig, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(profile))
	if err != nil {
		log.Fatal(err)
	}

	config := NewConfig(awsConfig)
	config.Debug = debug

	log.Printf("Identity: %s\n", config.PrincipalArn)

	log.Fatal(http.ListenAndServe(spec, config))
}
