package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
)

// --- Test doubles ---

type mockClient struct {
	startTLSCalled bool
	authCalled     bool
	mailFrom       string
	rcptTo         []string
	dataWritten    []byte
	quitCalled     bool

	startTLSErr error
	authErr     error
	mailErr     error
	rcptErr     error
	dataErr     error
	writeErr    error
	closeErr    error
	quitErr     error
}

func (m *mockClient) StartTLS(_ *tls.Config) error {
	m.startTLSCalled = true
	return m.startTLSErr
}

func (m *mockClient) Auth(_ smtp.Auth) error {
	m.authCalled = true
	return m.authErr
}

func (m *mockClient) Mail(from string) error {
	m.mailFrom = from
	return m.mailErr
}

func (m *mockClient) Rcpt(to string) error {
	m.rcptTo = append(m.rcptTo, to)
	return m.rcptErr
}

func (m *mockClient) Data() (DataWriter, error) {
	if m.dataErr != nil {
		return nil, m.dataErr
	}
	return &mockWriter{client: m}, nil
}

func (m *mockClient) Quit() error {
	m.quitCalled = true
	return m.quitErr
}

func (m *mockClient) Close() error { return nil }

type mockWriter struct {
	client *mockClient
}

func (w *mockWriter) Write(p []byte) (int, error) {
	if w.client.writeErr != nil {
		return 0, w.client.writeErr
	}
	w.client.dataWritten = append(w.client.dataWritten, p...)
	return len(p), nil
}

func (w *mockWriter) Close() error { return w.client.closeErr }

type mockDialer struct {
	client  *mockClient
	dialErr error

	// For retry testing: fail the first N dials, then succeed.
	failCount   int
	dialAttempt int
}

func (d *mockDialer) Dial(_ string) (Client, error) {
	d.dialAttempt++
	if d.failCount > 0 && d.dialAttempt <= d.failCount {
		return nil, d.dialErr
	}
	if d.dialErr != nil && d.failCount == 0 {
		return nil, d.dialErr
	}
	return d.client, nil
}

// --- Provider lifecycle tests ---

func TestGetProviders(t *testing.T) {
	p := &Plugin{}
	providers, err := p.GetProviders(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{ProviderName}, providers)
}

func TestGetProviderDescriptor(t *testing.T) {
	p := &Plugin{}

	t.Run("known provider", func(t *testing.T) {
		desc, err := p.GetProviderDescriptor(context.Background(), ProviderName)
		require.NoError(t, err)
		assert.Equal(t, ProviderName, desc.Name)
		assert.Equal(t, "SMTP Email", desc.DisplayName)
		assert.NotEmpty(t, desc.Description)
		assert.NotNil(t, desc.Schema)
		assert.NotEmpty(t, desc.Capabilities)
		assert.Contains(t, desc.Capabilities, sdkprovider.CapabilityAction)
		assert.NotNil(t, desc.OutputSchemas, "OutputSchemas must be present")
		for _, cap := range desc.Capabilities {
			assert.Contains(t, desc.OutputSchemas, cap, "OutputSchemas must include capability %s", cap)
		}
		assert.Contains(t, desc.SensitiveFields, "password")
	})

	t.Run("unknown provider", func(t *testing.T) {
		_, err := p.GetProviderDescriptor(context.Background(), "unknown")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})
}

// --- ExecuteProvider tests ---

func TestExecuteProvider_Success(t *testing.T) {
	client := &mockClient{}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	out, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":    "smtp.example.com",
		"port":    "587",
		"from":    "sender@example.com",
		"to":      []any{"recipient@example.com"},
		"subject": "Test Email",
		"body":    "Hello, World!",
	})

	require.NoError(t, err)
	data, ok := out.Data.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, data["success"])
	assert.Equal(t, 1, data["recipients"])

	dataField, ok := data["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, 1, dataField["attempts"])

	assert.Equal(t, "sender@example.com", client.mailFrom)
	assert.Equal(t, []string{"recipient@example.com"}, client.rcptTo)
	assert.True(t, client.quitCalled)
	assert.Contains(t, string(client.dataWritten), "Subject: Test Email")
	assert.Contains(t, string(client.dataWritten), "Hello, World!")
}

func TestExecuteProvider_WithAuth(t *testing.T) {
	client := &mockClient{}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	out, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":     "smtp.example.com",
		"port":     "587",
		"from":     "sender@example.com",
		"to":       []any{"recipient@example.com"},
		"subject":  "Test",
		"body":     "Body",
		"username": "user",
		"password": "pass",
	})

	require.NoError(t, err)
	assert.NotNil(t, out)
	assert.True(t, client.startTLSCalled, "STARTTLS should be used when auth is provided")
	assert.True(t, client.authCalled)
}

func TestExecuteProvider_ExplicitStartTLS(t *testing.T) {
	tests := []struct {
		name           string
		starttls       bool
		username       string
		expectStartTLS bool
	}{
		{
			name:           "explicit true without auth",
			starttls:       true,
			expectStartTLS: true,
		},
		{
			name:           "explicit false with auth",
			starttls:       false,
			username:       "user",
			expectStartTLS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockClient{}
			p := &Plugin{Dialer: &mockDialer{client: client}}

			inputs := map[string]any{
				"host":     "smtp.example.com",
				"from":     "sender@example.com",
				"to":       []any{"r@example.com"},
				"subject":  "Test",
				"body":     "Test",
				"starttls": tt.starttls,
			}
			if tt.username != "" {
				inputs["username"] = tt.username
				inputs["password"] = "pass"
			}

			_, err := p.ExecuteProvider(context.Background(), ProviderName, inputs)
			require.NoError(t, err)
			assert.Equal(t, tt.expectStartTLS, client.startTLSCalled)
		})
	}
}

func TestExecuteProvider_MultipleRecipients(t *testing.T) {
	client := &mockClient{}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	out, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":    "smtp.example.com",
		"from":    "sender@example.com",
		"to":      []any{"u1@example.com", "u2@example.com"},
		"cc":      "cc@example.com",
		"bcc":     []any{"bcc1@example.com", "bcc2@example.com"},
		"subject": "Test Email",
		"body":    "Hello everyone!",
	})

	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, 5, data["recipients"])
	assert.Equal(t, []string{
		"u1@example.com",
		"u2@example.com",
		"cc@example.com",
		"bcc1@example.com",
		"bcc2@example.com",
	}, client.rcptTo)
}

func TestExecuteProvider_HTMLContent(t *testing.T) {
	client := &mockClient{}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":        "smtp.example.com",
		"from":        "sender@example.com",
		"to":          []any{"r@example.com"},
		"subject":     "HTML Email",
		"body":        "<h1>Hello</h1>",
		"contentType": "text/html",
	})

	require.NoError(t, err)
	assert.Contains(t, string(client.dataWritten), "Content-Type: text/html")
}

func TestExecuteProvider_PortVariants(t *testing.T) {
	tests := []struct {
		name string
		port any
	}{
		{"string port", "587"},
		{"int port", 587},
		{"float port", 587.0},
		{"no port defaults to 587", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockClient{}
			p := &Plugin{Dialer: &mockDialer{client: client}}

			inputs := map[string]any{
				"host":    "smtp.example.com",
				"from":    "s@example.com",
				"to":      []any{"r@example.com"},
				"subject": "Test",
				"body":    "Test",
			}
			if tt.port != nil {
				inputs["port"] = tt.port
			}

			_, err := p.ExecuteProvider(context.Background(), ProviderName, inputs)
			require.NoError(t, err)
		})
	}
}

func TestExecuteProvider_MissingRequired(t *testing.T) {
	tests := []struct {
		name   string
		inputs map[string]any
		errMsg string
	}{
		{
			name:   "missing host",
			inputs: map[string]any{"from": "a@b.c", "to": []any{"x@y.z"}, "subject": "s", "body": "b"},
			errMsg: "host is required",
		},
		{
			name:   "missing from",
			inputs: map[string]any{"host": "h", "to": []any{"x@y.z"}, "subject": "s", "body": "b"},
			errMsg: "from is required",
		},
		{
			name:   "missing to",
			inputs: map[string]any{"host": "h", "from": "a@b.c", "subject": "s", "body": "b"},
			errMsg: "to is required",
		},
		{
			name:   "empty to list",
			inputs: map[string]any{"host": "h", "from": "a@b.c", "to": []any{}, "subject": "s", "body": "b"},
			errMsg: "to is required",
		},
		{
			name:   "missing subject",
			inputs: map[string]any{"host": "h", "from": "a@b.c", "to": []any{"x@y.z"}, "body": "b"},
			errMsg: "subject is required",
		},
		{
			name:   "missing body",
			inputs: map[string]any{"host": "h", "from": "a@b.c", "to": []any{"x@y.z"}, "subject": "s"},
			errMsg: "body is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Plugin{}
			_, err := p.ExecuteProvider(context.Background(), ProviderName, tt.inputs)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestExecuteProvider_UnknownProvider(t *testing.T) {
	p := &Plugin{}
	_, err := p.ExecuteProvider(context.Background(), "unknown", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

// --- SMTP error path tests ---

func TestExecuteProvider_DialError(t *testing.T) {
	p := &Plugin{Dialer: &mockDialer{dialErr: errors.New("connection refused")}}

	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":    "smtp.example.com",
		"from":    "s@example.com",
		"to":      []any{"r@example.com"},
		"subject": "Test",
		"body":    "Test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestExecuteProvider_StartTLSError(t *testing.T) {
	client := &mockClient{startTLSErr: errors.New("TLS handshake failed")}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":     "smtp.example.com",
		"from":     "s@example.com",
		"to":       []any{"r@example.com"},
		"subject":  "Test",
		"body":     "Test",
		"username": "u",
		"password": "p",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "starting TLS")
}

func TestExecuteProvider_AuthError(t *testing.T) {
	client := &mockClient{authErr: errors.New("invalid credentials")}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":     "smtp.example.com",
		"from":     "s@example.com",
		"to":       []any{"r@example.com"},
		"subject":  "Test",
		"body":     "Test",
		"username": "u",
		"password": "p",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authenticating")
}

func TestExecuteProvider_MailFromError(t *testing.T) {
	client := &mockClient{mailErr: errors.New("sender rejected")}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":    "smtp.example.com",
		"from":    "s@example.com",
		"to":      []any{"r@example.com"},
		"subject": "Test",
		"body":    "Test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MAIL FROM")
}

func TestExecuteProvider_RcptError(t *testing.T) {
	client := &mockClient{rcptErr: errors.New("recipient rejected")}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":    "smtp.example.com",
		"from":    "s@example.com",
		"to":      []any{"r@example.com"},
		"subject": "Test",
		"body":    "Test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RCPT TO")
}

func TestExecuteProvider_DataError(t *testing.T) {
	client := &mockClient{dataErr: errors.New("data not accepted")}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":    "smtp.example.com",
		"from":    "s@example.com",
		"to":      []any{"r@example.com"},
		"subject": "Test",
		"body":    "Test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DATA")
}

func TestExecuteProvider_WriteError(t *testing.T) {
	client := &mockClient{writeErr: errors.New("write failed")}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":    "smtp.example.com",
		"from":    "s@example.com",
		"to":      []any{"r@example.com"},
		"subject": "Test",
		"body":    "Test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "writing message")
}

func TestExecuteProvider_CloseError(t *testing.T) {
	client := &mockClient{closeErr: errors.New("close failed")}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":    "smtp.example.com",
		"from":    "s@example.com",
		"to":      []any{"r@example.com"},
		"subject": "Test",
		"body":    "Test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closing message")
}

func TestExecuteProvider_NonStringToElements(t *testing.T) {
	client := &mockClient{}
	p := &Plugin{Dialer: &mockDialer{client: client}}

	// []any with only non-string elements yields empty recipients list.
	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":    "smtp.example.com",
		"from":    "s@example.com",
		"to":      []any{123, true},
		"subject": "Test",
		"body":    "Test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "to is required")
}

// --- DescribeWhatIf tests ---

func TestDescribeWhatIf(t *testing.T) {
	p := &Plugin{}

	t.Run("with full inputs", func(t *testing.T) {
		desc, err := p.DescribeWhatIf(context.Background(), ProviderName, map[string]any{
			"host":    "smtp.example.com",
			"to":      []any{"admin@example.com"},
			"subject": "Alert",
		})
		require.NoError(t, err)
		assert.Contains(t, desc, "Alert")
		assert.Contains(t, desc, "admin@example.com")
		assert.Contains(t, desc, "smtp.example.com")
	})

	t.Run("empty inputs", func(t *testing.T) {
		desc, err := p.DescribeWhatIf(context.Background(), ProviderName, map[string]any{})
		require.NoError(t, err)
		assert.Contains(t, desc, "Would send email")
	})

	t.Run("with maxRetries", func(t *testing.T) {
		desc, err := p.DescribeWhatIf(context.Background(), ProviderName, map[string]any{
			"host":       "smtp.example.com",
			"to":         []any{"admin@example.com"},
			"subject":    "Alert",
			"maxRetries": 3,
		})
		require.NoError(t, err)
		assert.Contains(t, desc, "up to 3 retries")
	})

	t.Run("unknown provider", func(t *testing.T) {
		_, err := p.DescribeWhatIf(context.Background(), "unknown", map[string]any{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})
}

// --- Known/unknown provider consistency tests ---

func TestConfigureProvider_KnownProvider(t *testing.T) {
	p := &Plugin{}
	err := p.ConfigureProvider(context.Background(), ProviderName, sdkplugin.ProviderConfig{})
	assert.NoError(t, err)
}

func TestExecuteProviderStream_KnownProvider(t *testing.T) {
	p := &Plugin{}
	err := p.ExecuteProviderStream(context.Background(), ProviderName, nil, nil)
	assert.ErrorIs(t, err, sdkplugin.ErrStreamingNotSupported)
}

func TestExtractDependencies_KnownProvider(t *testing.T) {
	p := &Plugin{}
	deps, err := p.ExtractDependencies(context.Background(), ProviderName, nil)
	assert.NoError(t, err)
	assert.Nil(t, deps)
}

func TestStopProvider_KnownProvider(t *testing.T) {
	p := &Plugin{}
	err := p.StopProvider(context.Background(), ProviderName)
	assert.NoError(t, err)
}

func TestConfigureProvider_UnknownProvider(t *testing.T) {
	p := &Plugin{}
	err := p.ConfigureProvider(context.Background(), "unknown", sdkplugin.ProviderConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestExecuteProviderStream_UnknownProvider(t *testing.T) {
	p := &Plugin{}
	err := p.ExecuteProviderStream(context.Background(), "unknown", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestExtractDependencies_UnknownProvider(t *testing.T) {
	p := &Plugin{}
	_, err := p.ExtractDependencies(context.Background(), "unknown", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestStopProvider_UnknownProvider(t *testing.T) {
	p := &Plugin{}
	err := p.StopProvider(context.Background(), "unknown")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

// --- Header injection tests ---

func TestExecuteProvider_HeaderInjection(t *testing.T) {
	tests := []struct {
		name   string
		inputs map[string]any
		errMsg string
	}{
		{
			name: "newline in subject",
			inputs: map[string]any{
				"host":    "smtp.example.com",
				"from":    "s@example.com",
				"to":      []any{"r@example.com"},
				"subject": "Test\r\nBcc: evil@attacker.com",
				"body":    "body",
			},
			errMsg: "subject contains invalid characters",
		},
		{
			name: "newline in from",
			inputs: map[string]any{
				"host":    "smtp.example.com",
				"from":    "s@example.com\r\nBcc: evil@attacker.com",
				"to":      []any{"r@example.com"},
				"subject": "Test",
				"body":    "body",
			},
			errMsg: "from contains invalid characters",
		},
		{
			name: "newline in to",
			inputs: map[string]any{
				"host":    "smtp.example.com",
				"from":    "s@example.com",
				"to":      []any{"r@example.com\r\nBcc: evil@attacker.com"},
				"subject": "Test",
				"body":    "body",
			},
			errMsg: "to address contains invalid characters",
		},
		{
			name: "newline in cc",
			inputs: map[string]any{
				"host":    "smtp.example.com",
				"from":    "s@example.com",
				"to":      []any{"r@example.com"},
				"cc":      "cc@example.com\nBcc: evil@attacker.com",
				"subject": "Test",
				"body":    "body",
			},
			errMsg: "cc address contains invalid characters",
		},
		{
			name: "LF only in subject",
			inputs: map[string]any{
				"host":    "smtp.example.com",
				"from":    "s@example.com",
				"to":      []any{"r@example.com"},
				"subject": "Test\nInjected: header",
				"body":    "body",
			},
			errMsg: "subject contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Plugin{}
			_, err := p.ExecuteProvider(context.Background(), ProviderName, tt.inputs)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// --- Helper function tests ---

func TestExtractRecipients(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected []string
	}{
		{"nil", nil, nil},
		{"empty string", "", nil},
		{"single string", "a@b.c", []string{"a@b.c"}},
		{"string slice", []string{"a@b.c", "x@y.z"}, []string{"a@b.c", "x@y.z"}},
		{"any slice", []any{"a@b.c", "x@y.z"}, []string{"a@b.c", "x@y.z"}},
		{"any slice with empty", []any{"a@b.c", "", "x@y.z"}, []string{"a@b.c", "x@y.z"}},
		{"empty any slice", []any{}, nil},
		{"unsupported type", 123, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRecipients(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractPort(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{"string", "587", "587"},
		{"empty string", "", defaultPort},
		{"int", 587, "587"},
		{"float", 587.0, "587"},
		{"nil", nil, defaultPort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPort(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildMessage(t *testing.T) {
	params := &smtpParams{
		from:        "sender@example.com",
		to:          []string{"u1@example.com", "u2@example.com"},
		cc:          []string{"cc@example.com"},
		subject:     "Test Subject",
		body:        "Hello, World!",
		contentType: "text/plain",
	}

	msg := string(buildMessage(params))
	assert.Contains(t, msg, "Date: ")
	assert.Contains(t, msg, "Message-ID: <")
	assert.Contains(t, msg, ".sender@example.com>\r\n")
	assert.Contains(t, msg, "From: sender@example.com\r\n")
	assert.Contains(t, msg, "To: u1@example.com, u2@example.com\r\n")
	assert.Contains(t, msg, "Cc: cc@example.com\r\n")
	assert.Contains(t, msg, "Subject: Test Subject\r\n")
	assert.Contains(t, msg, "Content-Type: text/plain; charset=UTF-8\r\n")
	assert.Contains(t, msg, "MIME-Version: 1.0\r\n")
	assert.Contains(t, msg, "\r\n\r\nHello, World!")
}

func TestBuildMessage_NoCc(t *testing.T) {
	params := &smtpParams{
		from:        "sender@example.com",
		to:          []string{"r@example.com"},
		subject:     "Test",
		body:        "Body",
		contentType: "text/plain",
	}

	msg := string(buildMessage(params))
	assert.NotContains(t, msg, "Cc:")
}

// --- Benchmark ---

func BenchmarkExecuteProvider(b *testing.B) {
	client := &mockClient{}
	p := &Plugin{Dialer: &mockDialer{client: client}}
	input := map[string]any{
		"host":    "smtp.example.com",
		"from":    "s@example.com",
		"to":      []any{"r@example.com"},
		"subject": "Bench",
		"body":    "Benchmark body",
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _ = p.ExecuteProvider(ctx, ProviderName, input)
	}
}

// --- Retry tests ---

func TestExecuteProvider_RetrySuccess(t *testing.T) {
	client := &mockClient{}
	dialer := &mockDialer{
		client:    client,
		dialErr:   errors.New("dialing SMTP server: connection refused"),
		failCount: 2, // Fail first 2 attempts, succeed on 3rd.
	}
	p := &Plugin{Dialer: dialer}

	out, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":       "smtp.example.com",
		"from":       "s@example.com",
		"to":         []any{"r@example.com"},
		"subject":    "Test",
		"body":       "Test",
		"maxRetries": 5,
	})

	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, true, data["success"])
	dataField := data["data"].(map[string]any)
	assert.Equal(t, 3, dataField["attempts"])
}

func TestExecuteProvider_RetryExhausted(t *testing.T) {
	dialer := &mockDialer{
		dialErr:   errors.New("dialing SMTP server: connection refused"),
		failCount: 10, // Always fail.
	}
	p := &Plugin{Dialer: dialer}

	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":       "smtp.example.com",
		"from":       "s@example.com",
		"to":         []any{"r@example.com"},
		"subject":    "Test",
		"body":       "Test",
		"maxRetries": 3,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	assert.Equal(t, 4, dialer.dialAttempt) // 1 initial + 3 retries
}

func TestExecuteProvider_NoRetryOnAuthError(t *testing.T) {
	client := &mockClient{authErr: errors.New("authenticating: invalid credentials")}
	dialer := &mockDialer{client: client}
	p := &Plugin{Dialer: dialer}

	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{
		"host":       "smtp.example.com",
		"from":       "s@example.com",
		"to":         []any{"r@example.com"},
		"subject":    "Test",
		"body":       "Test",
		"username":   "u",
		"password":   "p",
		"maxRetries": 5,
	})

	require.Error(t, err)
	assert.Equal(t, 1, dialer.dialAttempt, "should not retry auth failures")
}

func TestExecuteProvider_RetryContextCancellation(t *testing.T) {
	dialer := &mockDialer{
		dialErr:   errors.New("dialing SMTP server: connection refused"),
		failCount: 10,
	}
	p := &Plugin{Dialer: dialer}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := p.ExecuteProvider(ctx, ProviderName, map[string]any{
		"host":       "smtp.example.com",
		"from":       "s@example.com",
		"to":         []any{"r@example.com"},
		"subject":    "Test",
		"body":       "Test",
		"maxRetries": 5,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cancelled during retry")
}

// --- isTransient tests ---

func TestIsTransient(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil", nil, false},
		{"dial error", errors.New("dialing SMTP server: connection refused"), true},
		{"TLS error", errors.New("starting TLS: handshake failure"), true},
		{"auth error", errors.New("authenticating: bad credentials"), false},
		{"random error", errors.New("something else"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isTransient(tt.err))
		})
	}
}

// --- extractInt tests ---

func TestExtractInt(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected int
	}{
		{"int", 30, 30},
		{"float64", 30.0, 30},
		{"nil", nil, 0},
		{"string", "30", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractInt(tt.input))
		})
	}
}
