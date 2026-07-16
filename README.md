# CSR Inspector

CSR Inspector is an open-source web application for decoding and validating PKCS#10 Certificate Signing Requests.

The application accepts certificate signing requests in PEM format, displays their contents in a readable form, verifies their signatures, and reports potentially invalid or insecure parameters.

## Planned Features

* Parse PKCS#10 certificate signing requests in PEM format
* Display the complete subject distinguished name
* Display Subject Alternative Names
* Inspect public key parameters
* Display the CSR signature algorithm
* Verify the CSR signature
* Display requested X.509 extensions
* Detect potentially insecure or invalid parameters
* Provide validation warnings and recommendations
* Provide a JSON API
* Process certificate signing requests without persistent storage

## Supported Input Format

CSR Inspector accepts only a complete PEM-encoded certificate signing request.

Supported PEM headers:

```pem
-----BEGIN CERTIFICATE REQUEST-----
MIIC...
-----END CERTIFICATE REQUEST-----
```

The following alternative header may also be supported:

```pem
-----BEGIN NEW CERTIFICATE REQUEST-----
MIIC...
-----END NEW CERTIFICATE REQUEST-----
```

Raw Base64 input without PEM headers is not supported.

## Requirements

* Go
* Docker and Docker Compose — optional for local development

## Local Development

Run the application locally:

```bash
go run ./cmd/server
```

The server listens on port `8080` by default.

Check the health endpoint:

```bash
curl http://localhost:8080/health
```

Expected response:

```json
{
  "status": "ok"
}
```

## Configuration

The application is configured through environment variables.

| Variable                |  Default | Description                        |
| ----------------------- | -------: | ---------------------------------- |
| `HTTP_ADDRESS`          |  `:8080` | HTTP server listen address         |
| `HTTP_MAX_REQUEST_SIZE` | `131072` | Maximum request body size in bytes |

An example configuration is available in `.env.example`.

To create a local configuration file:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

The `.env` file must not be committed to the repository.


## Security

Certificate signing requests are processed in memory and are not intended to be stored persistently.

A legitimate CSR contains a public key but does not contain a private key.

Never submit private keys or files containing private keys.

The application should not log complete CSR contents because a CSR may contain internal domain names, organization names, email addresses, IP addresses, and other infrastructure-related information.

## Running Checks

Format the source code:

```bash
go fmt ./...
```

Run static analysis:

```bash
go vet ./...
```

Run tests:

```bash
go test ./...
```

Run all basic checks through Make:

```bash
make check
```

## License

This project is licensed under the MIT License.
