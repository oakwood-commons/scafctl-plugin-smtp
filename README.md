# scafctl-plugin-smtp

SMTP email provider plugin for scafctl. Sends emails via SMTP with optional STARTTLS
encryption and authentication.

## Names

This plugin uses the following names across different surfaces:

| Surface | Value |
|---------|-------|
| Repository | `scafctl-plugin-smtp` |
| Go module | `github.com/oakwood-commons/scafctl-plugin-smtp` |
| Binary | `scafctl-plugin-smtp` |
| Provider name | `smtp` |
| Catalog artifact | `smtp` |

The **provider name** is what users reference in solutions (`provider: smtp`).
It comes from the RPC contract (`GetProviders` / `GetProviderDescriptor`), not from
the binary filename.

## Installation

```bash
# Build from source
task build

# Or download from releases
gh release download --repo github.com/oakwood-commons/scafctl-plugin-smtp
```

## Usage

Register this plugin in your scafctl configuration, then reference
the **smtp** provider in your solutions:

```yaml
actions:
  notify-team:
    run:
      with:
        - provider: smtp
          inputs:
            host: smtp.example.com
            port: "587"
            from: alerts@example.com
            to:
              - oncall@example.com
              - team-lead@example.com
            subject: "Deployment Complete"
            body: "The production deployment finished successfully."
            username: alerts@example.com
            password:
              fromEnv: SMTP_PASSWORD
            starttls: true
```

### Inputs

| Name | Required | Description |
|------|----------|-------------|
| `host` | yes | SMTP server hostname |
| `port` | no | SMTP port (default: `587`) |
| `from` | yes | Sender email address |
| `to` | yes | Recipient email address(es) |
| `subject` | yes | Email subject line |
| `body` | yes | Email body content |
| `contentType` | no | `text/plain` or `text/html` (default: `text/plain`) |
| `cc` | no | CC recipient(s) |
| `bcc` | no | BCC recipient(s) |
| `username` | no | SMTP auth username |
| `password` | no | SMTP auth password (sensitive) |
| `starttls` | no | Enable STARTTLS (default: `true` when credentials provided) |

### Output

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Whether the email was sent |
| `recipients` | integer | Total recipients (to + cc + bcc) |
| `data` | object | Additional send details |

## Development

```bash
# Run tests
task test

# Run linter
task lint

# Build
task build

# Full CI pipeline (lint + test + build)
task ci
```

## Local Testing

After building, verify the plugin works end-to-end through the host:

```bash
# 1. Build the binary
task build

# 2. Package as a local catalog artifact
task release:local VERSION=0.1.0

# 3. Run the sample solution to verify host registration
scafctl run solution -f ./examples/solution.yaml
```

The full local loop (build, package, install, run) is the most reliable way to
verify that the host registers the provider correctly.

## Release

### Publishing to a catalog

A tagged release should publish both the plugin artifact and refresh the
catalog index:

```bash
# Publish the plugin artifact
scafctl catalog push smtp --version v1.0.0

# Refresh the catalog index so the plugin is discoverable
scafctl catalog index push --catalog oci://ghcr.io/<REGISTRY_OWNER>
```

Both steps are required. Publishing the artifact alone does not make the
plugin appear in catalog listings.

### CI release workflow

The release workflow needs two kinds of authentication:

1. **Container registry auth** for OCI push operations (`docker login` or equivalent).
2. **scafctl auth** for catalog operations (`scafctl auth login github --flow pat --registry ghcr.io --write-registry-auth`).

Standard `docker login` is not sufficient for `scafctl catalog index push`.

### Required secrets

| Secret | Scopes | Purpose |
|--------|--------|---------|
| `GITHUB_TOKEN` | Default | Build, test, create release |
| `CATALOG_PUSH_TOKEN` | `repo`, `read:packages`, `write:packages` | Publish artifact and refresh catalog index |

Create the publishing secret at the org or repo level:

```bash
gh secret set CATALOG_PUSH_TOKEN --org <ORG> --repos scafctl-plugin-example --body "$TOKEN"
```

### Token strategy

For official providers, use a machine account or GitHub App for the publishing
token rather than a personal account. This avoids tying release capability to
an individual developer.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.