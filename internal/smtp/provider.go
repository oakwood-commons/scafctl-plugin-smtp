// Package smtp implements the smtp provider plugin.
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/google/jsonschema-go/jsonschema"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
	sdkhelper "github.com/oakwood-commons/scafctl-plugin-sdk/provider/schemahelper"
)

const (
	// ProviderName is the unique identifier for this provider.
	ProviderName = "smtp"

	// Version is the provider version.
	Version = "0.1.0"

	// defaultPort is the standard SMTP submission port with STARTTLS.
	defaultPort = "587"

	// dialTimeout is the TCP connection timeout.
	dialTimeout = 30 * time.Second

	// retryBaseDelay is the initial backoff duration for retries.
	retryBaseDelay = 1 * time.Second

	// retryMaxDelay caps the exponential backoff.
	retryMaxDelay = 30 * time.Second
)

// Dialer abstracts SMTP connection establishment for testing.
type Dialer interface {
	Dial(addr string) (Client, error)
}

// Client abstracts the net/smtp.Client for testing.
type Client interface {
	StartTLS(config *tls.Config) error
	Auth(a smtp.Auth) error
	Mail(from string) error
	Rcpt(to string) error
	Data() (DataWriter, error)
	Quit() error
	Close() error
}

// DataWriter abstracts the io.WriteCloser returned by smtp.Client.Data().
type DataWriter interface {
	Write(p []byte) (int, error)
	Close() error
}

// netDialer implements Dialer using the standard net/smtp package.
type netDialer struct {
	timeout time.Duration
}

func (d *netDialer) Dial(addr string) (Client, error) {
	conn, err := net.DialTimeout("tcp", addr, d.timeout)
	if err != nil {
		return nil, fmt.Errorf("dialing SMTP server: %w", err)
	}
	host, _, _ := net.SplitHostPort(addr)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("creating SMTP client: %w", err)
	}
	return &clientWrapper{c: c}, nil
}

// clientWrapper adapts *smtp.Client to the Client interface.
type clientWrapper struct {
	c *smtp.Client
}

func (w *clientWrapper) StartTLS(config *tls.Config) error { return w.c.StartTLS(config) }
func (w *clientWrapper) Auth(a smtp.Auth) error            { return w.c.Auth(a) }
func (w *clientWrapper) Mail(from string) error            { return w.c.Mail(from) }
func (w *clientWrapper) Rcpt(to string) error              { return w.c.Rcpt(to) }
func (w *clientWrapper) Quit() error                       { return w.c.Quit() }
func (w *clientWrapper) Close() error                      { return w.c.Close() }
func (w *clientWrapper) Data() (DataWriter, error)         { return w.c.Data() }

// Plugin implements the scafctl ProviderPlugin interface.
type Plugin struct {
	// Dialer is the SMTP dialer used for connections. Injected for testing.
	Dialer Dialer
}

// dialer returns the configured Dialer or the default net dialer.
func (p *Plugin) dialer() Dialer {
	if p.Dialer != nil {
		return p.Dialer
	}
	return &netDialer{timeout: dialTimeout}
}

// GetProviders returns the list of providers exposed by this plugin.
//
//nolint:revive // ctx required by interface
func (p *Plugin) GetProviders(_ context.Context) ([]string, error) {
	return []string{ProviderName}, nil
}

// GetProviderDescriptor returns the descriptor for the named provider.
//
//nolint:revive // ctx required by interface
func (p *Plugin) GetProviderDescriptor(_ context.Context, providerName string) (*sdkprovider.Descriptor, error) {
	if providerName != ProviderName {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	return &sdkprovider.Descriptor{
		Name:        ProviderName,
		DisplayName: "SMTP Email",
		Description: "Sends emails via SMTP with optional STARTTLS and authentication",
		APIVersion:  "v1",
		Version:     semver.MustParse(Version),
		Category:    "notification",
		Tags:        []string{"email", "smtp", "notification", "alert"},
		Capabilities: []sdkprovider.Capability{
			sdkprovider.CapabilityAction,
		},
		SensitiveFields: []string{"password"},
		Schema: sdkhelper.ObjectSchema(
			[]string{"host", "from", "to", "subject", "body"},
			map[string]*jsonschema.Schema{
				"host": sdkhelper.StringProp(
					"SMTP server hostname",
					sdkhelper.WithExample("smtp.example.com"),
				),
				"port": sdkhelper.StringProp(
					"SMTP server port",
					sdkhelper.WithDefault(defaultPort),
					sdkhelper.WithExample("587"),
				),
				"from": sdkhelper.StringProp(
					"Sender email address",
					sdkhelper.WithFormat("email"),
					sdkhelper.WithExample("noreply@example.com"),
				),
				"to": sdkhelper.ArrayProp(
					"Recipient email addresses",
					sdkhelper.WithItems(sdkhelper.StringProp("email address", sdkhelper.WithFormat("email"))),
					sdkhelper.WithMinItems(1),
				),
				"subject": sdkhelper.StringProp(
					"Email subject line",
					sdkhelper.WithExample("Alert: deployment completed"),
				),
				"body": sdkhelper.StringProp(
					"Email body content",
					sdkhelper.WithExample("Deployment to production completed successfully."),
				),
				"contentType": sdkhelper.StringProp(
					"Body content type",
					sdkhelper.WithDefault("text/plain"),
					sdkhelper.WithEnum("text/plain", "text/html"),
				),
				"cc": sdkhelper.ArrayProp(
					"CC recipient email addresses",
					sdkhelper.WithItems(sdkhelper.StringProp("email address", sdkhelper.WithFormat("email"))),
				),
				"bcc": sdkhelper.ArrayProp(
					"BCC recipient email addresses",
					sdkhelper.WithItems(sdkhelper.StringProp("email address", sdkhelper.WithFormat("email"))),
				),
				"username": sdkhelper.StringProp(
					"SMTP authentication username",
				),
				"password": sdkhelper.StringProp(
					"SMTP authentication password",
					sdkhelper.WithWriteOnly(),
				),
				"starttls": sdkhelper.BoolProp(
					"Enable STARTTLS encryption (defaults to true when credentials are provided)",
				),
				"maxRetries": sdkhelper.IntProp(
					"Maximum number of retry attempts for transient failures (default: 0, no retries)",
					sdkhelper.WithDefault(0),
					sdkhelper.WithMinimum(0),
					sdkhelper.WithMaximum(50),
					sdkhelper.WithExample(30),
				),
			},
		),
		OutputSchemas: map[sdkprovider.Capability]*jsonschema.Schema{
			sdkprovider.CapabilityAction: sdkhelper.ObjectSchema(nil, map[string]*jsonschema.Schema{
				"success":    sdkhelper.BoolProp("Whether the email was sent successfully"),
				"recipients": sdkhelper.IntProp("Total number of recipients (to + cc + bcc)"),
				"data": sdkhelper.ObjectProp("Additional send details", nil, map[string]*jsonschema.Schema{
					"attempts": sdkhelper.IntProp("Number of send attempts made"),
				}),
			}),
		},
		WriteOperations: []string{"send"},
		Examples: []sdkprovider.Example{
			{
				Name:        "Plain text alert",
				Description: "Sends a notification email via an internal relay",
				YAML: `provider: smtp
inputs:
  host: smtp.internal.example.com
  port: "25"
  from: alerts@example.com
  to:
    - oncall@example.com
  subject: "Deployment Complete"
  body: "The production deployment finished successfully."`,
			},
			{
				Name:        "Authenticated HTML email",
				Description: "Sends an email using SMTP credentials and STARTTLS",
				YAML: `provider: smtp
inputs:
  host: smtp.example.com
  port: "587"
  from: noreply@example.com
  to:
    - admin@example.com
  subject: "Weekly Report"
  body: "<h1>Report</h1><p>All systems nominal.</p>"
  contentType: text/html
  username: noreply@example.com
  password:
    fromEnv: SMTP_PASSWORD
  starttls: true`,
			},
		},
	}, nil
}

// ExecuteProvider sends an email via SMTP.
func (p *Plugin) ExecuteProvider(ctx context.Context, providerName string, input map[string]any) (*sdkprovider.Output, error) {
	if providerName != ProviderName {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	params, err := parseInput(input)
	if err != nil {
		return nil, fmt.Errorf("smtp: %w", err)
	}

	attempts, err := p.sendMail(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("smtp: %w", err)
	}

	totalRecipients := len(params.to) + len(params.cc) + len(params.bcc)
	return &sdkprovider.Output{
		Data: map[string]any{
			"success":    true,
			"recipients": totalRecipients,
			"data": map[string]any{
				"attempts": attempts,
			},
		},
	}, nil
}

// DescribeWhatIf returns a description of what the provider would do.
//
//nolint:revive // ctx required by interface
func (p *Plugin) DescribeWhatIf(_ context.Context, providerName string, input map[string]any) (string, error) {
	if providerName != ProviderName {
		return "", fmt.Errorf("unknown provider: %s", providerName)
	}

	host, _ := input["host"].(string)
	to := extractRecipients(input["to"])
	subject, _ := input["subject"].(string)
	maxRetries := extractInt(input["maxRetries"])

	var sb strings.Builder
	sb.WriteString("Would send email")
	if subject != "" {
		fmt.Fprintf(&sb, " with subject %q", subject)
	}
	if len(to) > 0 {
		fmt.Fprintf(&sb, " to %s", strings.Join(to, ", "))
	}
	if host != "" {
		fmt.Fprintf(&sb, " via %s", host)
	}
	if maxRetries > 0 {
		sb.WriteString(fmt.Sprintf(" (up to %d retries)", maxRetries))
	}
	return sb.String(), nil
}

// ConfigureProvider stores host-side configuration.
//
//nolint:revive // ctx and cfg required by interface
func (p *Plugin) ConfigureProvider(_ context.Context, providerName string, _ sdkplugin.ProviderConfig) error {
	if providerName != ProviderName {
		return fmt.Errorf("unknown provider: %s", providerName)
	}
	return nil
}

// ExecuteProviderStream is not supported by the SMTP provider.
//
//nolint:revive // all params required by interface
func (p *Plugin) ExecuteProviderStream(_ context.Context, providerName string, _ map[string]any, _ func(sdkplugin.StreamChunk)) error {
	if providerName != ProviderName {
		return fmt.Errorf("unknown provider: %s", providerName)
	}
	return sdkplugin.ErrStreamingNotSupported
}

// ExtractDependencies returns resolver keys this input depends on.
//
//nolint:revive // all params required by interface
func (p *Plugin) ExtractDependencies(_ context.Context, providerName string, _ map[string]any) ([]string, error) {
	if providerName != ProviderName {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}
	return nil, nil
}

// StopProvider performs cleanup for the named provider.
//
//nolint:revive // all params required by interface
func (p *Plugin) StopProvider(_ context.Context, providerName string) error {
	if providerName != ProviderName {
		return fmt.Errorf("unknown provider: %s", providerName)
	}
	return nil
}

// smtpParams holds validated SMTP parameters extracted from input.
type smtpParams struct {
	host        string
	port        string
	from        string
	to          []string
	cc          []string
	bcc         []string
	subject     string
	body        string
	contentType string
	username    string
	password    string
	startTLS    bool
	maxRetries  int
}

// parseInput validates and extracts SMTP parameters from the input map.
func parseInput(input map[string]any) (*smtpParams, error) {
	host, _ := input["host"].(string)
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}

	from, _ := input["from"].(string)
	if from == "" {
		return nil, fmt.Errorf("from is required")
	}
	if containsCRLF(from) {
		return nil, fmt.Errorf("from contains invalid characters")
	}

	to := extractRecipients(input["to"])
	if len(to) == 0 {
		return nil, fmt.Errorf("to is required (at least one recipient)")
	}
	for _, addr := range to {
		if containsCRLF(addr) {
			return nil, fmt.Errorf("to address contains invalid characters")
		}
	}

	subject, _ := input["subject"].(string)
	if subject == "" {
		return nil, fmt.Errorf("subject is required")
	}
	if containsCRLF(subject) {
		return nil, fmt.Errorf("subject contains invalid characters")
	}

	body, _ := input["body"].(string)
	if body == "" {
		return nil, fmt.Errorf("body is required")
	}

	port := extractPort(input["port"])

	contentType, _ := input["contentType"].(string)
	if contentType == "" {
		contentType = "text/plain"
	}

	username, _ := input["username"].(string)
	password, _ := input["password"].(string)

	// Default STARTTLS to true when credentials are provided.
	startTLS := username != ""
	if v, ok := input["starttls"].(bool); ok {
		startTLS = v
	}

	maxRetries := extractInt(input["maxRetries"])

	cc := extractRecipients(input["cc"])
	for _, addr := range cc {
		if containsCRLF(addr) {
			return nil, fmt.Errorf("cc address contains invalid characters")
		}
	}

	bcc := extractRecipients(input["bcc"])
	for _, addr := range bcc {
		if containsCRLF(addr) {
			return nil, fmt.Errorf("bcc address contains invalid characters")
		}
	}

	return &smtpParams{
		host:        host,
		port:        port,
		from:        from,
		to:          to,
		cc:          cc,
		bcc:         bcc,
		subject:     subject,
		body:        body,
		contentType: contentType,
		username:    username,
		password:    password,
		startTLS:    startTLS,
		maxRetries:  maxRetries,
	}, nil
}

// sendMail connects to the SMTP server and sends the email with retry support.
func (p *Plugin) sendMail(ctx context.Context, params *smtpParams) (int, error) {
	var lastErr error
	attempts := 0

	for attempt := range params.maxRetries + 1 {
		attempts = attempt + 1

		err := p.trySend(params)
		if err == nil {
			return attempts, nil
		}
		lastErr = err

		// Do not retry on the last attempt or permanent errors.
		if attempt >= params.maxRetries || !isTransient(err) {
			break
		}

		// Exponential backoff: 1s, 2s, 4s, 8s... capped at retryMaxDelay.
		delay := time.Duration(math.Min(
			float64(retryBaseDelay)*math.Pow(2, float64(attempt)),
			float64(retryMaxDelay),
		))

		select {
		case <-ctx.Done():
			return attempts, fmt.Errorf("cancelled during retry: %w", ctx.Err())
		case <-time.After(delay):
		}
	}

	return attempts, lastErr
}

// trySend performs a single SMTP send attempt.
func (p *Plugin) trySend(params *smtpParams) error {
	addr := net.JoinHostPort(params.host, params.port)
	client, err := p.dialer().Dial(addr)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if params.startTLS {
		tlsCfg := &tls.Config{
			ServerName: params.host,
			MinVersion: tls.VersionTLS12,
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starting TLS: %w", err)
		}
	}

	if params.username != "" && params.password != "" {
		auth := smtp.PlainAuth("", params.username, params.password, params.host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authenticating: %w", err)
		}
	}

	if err := client.Mail(params.from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}

	allRecipients := make([]string, 0, len(params.to)+len(params.cc)+len(params.bcc))
	allRecipients = append(allRecipients, params.to...)
	allRecipients = append(allRecipients, params.cc...)
	allRecipients = append(allRecipients, params.bcc...)

	for _, rcpt := range allRecipients {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}

	msg := buildMessage(params)
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("writing message: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("closing message: %w", err)
	}

	return client.Quit()
}

// buildMessage constructs an RFC 5322 email message from parameters.
func buildMessage(params *smtpParams) []byte {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z)))
	sb.WriteString(fmt.Sprintf("Message-ID: <%d.%s>\r\n", time.Now().UnixNano(), params.from))
	sb.WriteString(fmt.Sprintf("From: %s\r\n", params.from))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(params.to, ", ")))
	if len(params.cc) > 0 {
		sb.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(params.cc, ", ")))
	}
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", params.subject))
	sb.WriteString(fmt.Sprintf("Content-Type: %s; charset=UTF-8\r\n", params.contentType))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(params.body)
	return []byte(sb.String())
}

// extractRecipients normalizes recipient input to a string slice.
// Accepts: string, []string, []any (with string elements).
func extractRecipients(input any) []string {
	if input == nil {
		return nil
	}
	switch v := input.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}

// extractPort normalizes port input to a string.
func extractPort(input any) string {
	switch v := input.(type) {
	case string:
		if v != "" {
			return v
		}
	case int:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%d", int(v))
	}
	return defaultPort
}

// extractInt extracts an integer from input (int, float64, or nil → 0).
func extractInt(input any) int {
	switch v := input.(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

// isTransient returns true if the error is likely transient and worth retrying.
// Dial failures and temporary network errors are retried; auth failures and
// permanent SMTP rejections (5xx) are not.
func isTransient(err error) bool {
	if err == nil {
		return false
	}

	msg := err.Error()

	// Do not retry authentication or permanent failures.
	if strings.Contains(msg, "authenticating") {
		return false
	}

	// Dial/connection errors are transient.
	if strings.Contains(msg, "dialing SMTP server") {
		return true
	}
	if strings.Contains(msg, "starting TLS") {
		return true
	}

	// Check for net.Error temporary flag.
	var netErr net.Error
	return errors.As(err, &netErr)
}

// containsCRLF reports whether s contains CR or LF characters.
// These are invalid in SMTP header values and could enable header injection.
func containsCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}
