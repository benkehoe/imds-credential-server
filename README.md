# imds-credential-server
**Provide AWS credentials to a container from the host**

This CLI tool runs a server compliant with the [EC2 IMDSv2 interface](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) in order to vend AWS credentials, primarily to export credentials into locally-run containers.

This is better than mounting your `~/.aws` directory into a container as a) it allows for mechanisms that only work on the host, e.g., custom credential processes and b) it only vends one set of (refreshable) credentials to the container rather than providing access to all your credentials.

## Quickstart

Install from source or with `go install`.
[`go install` will install to `$GOBIN` or `$GOPATH/bin` or `$HOME/go/bin`](https://pkg.go.dev/cmd/go#hdr-Compile_and_install_packages_and_dependencies), so ensure that directory is on your `$PATH`.


```bash
$ go install github.com/benkehoe/imds-credential-server@main
```

Run the server, and then use it with a container:

```
# in one terminal
$ imds-credential-server 8081

# in a separate terminal
# note the trailing slash on the URL
$ docker run --rm -p 8081:8081 -e AWS_EC2_METADATA_SERVICE_ENDPOINT=http://host.docker.internal:8081/
amazon/aws-cli sts get-caller-identity
{
    "UserId": "AROAXXXXXXXXXXXXXXXXX:SessionName",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/SomeRole/SessionName"
}
```

## Details

You must provide a port (or optionally a full address) for the server.
Then map the port from the host to the container, and set the environment variable `AWS_EC2_METADATA_SERVICE_ENDPOINT` to `http://host.docker.internal:MAPPED_PORT/` with the approporiate port and **remember to include the trailing slash.**

AWS SDKs run inside the container should just work.

You can use `imds-credential-server version` to get the version.
