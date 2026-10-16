// Package oob implements a minimal, dependency-free Interactsh client for
// out-of-band (OOB) interaction testing. It speaks the public ProjectDiscovery
// Interactsh wire protocol directly (RSA-OAEP key exchange + AES-CTR encrypted
// poll payloads) so the framework can confirm blind vulnerabilities such as
// SSRF, blind XSS and blind XXE without shelling out to an external binary.
package oob

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultCIDLength is the length of the correlation-id preamble. It must
	// match the server's configured length (20 by default).
	DefaultCIDLength = 20
	// DefaultNonceLength is the length of the per-payload nonce.
	DefaultNonceLength = 13

	alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// ErrNotRegistered is returned by Poll when the server no longer knows the
// session's correlation id (e.g. after a server restart or eviction). Callers
// should re-register and retry.
var ErrNotRegistered = errors.New("interactsh correlation id not registered")

// Interaction is a single decoded out-of-band interaction.
type Interaction struct {
	Protocol      string `json:"protocol"`
	UniqueID      string `json:"unique-id"`
	FullID        string `json:"full-id"`
	QType         string `json:"q-type"`
	RawRequest    string `json:"raw-request"`
	RawResponse   string `json:"raw-response"`
	RemoteAddress string `json:"remote-address"`
	Timestamp     string `json:"timestamp"`
	SmtpFrom      string `json:"smtp-from"`
}

// Client is a single registered Interactsh session against one server.
type Client struct {
	server      string
	scheme      string
	token       string
	nonceLength int
	cid         string
	secret      string
	privateKey  *rsa.PrivateKey
	http        *http.Client
}

// NewClient creates a client bound to the given server hostname (a bare host
// such as "oast.pro", or a URL). A fresh RSA keypair, correlation id and poll
// secret are generated; call Register to complete the handshake.
func NewClient(server, token string) (*Client, error) {
	server = strings.TrimSpace(server)
	scheme := "https"
	if strings.HasPrefix(server, "http://") {
		scheme = "http"
	}
	server = strings.TrimPrefix(server, "https://")
	server = strings.TrimPrefix(server, "http://")
	server = strings.TrimSuffix(server, "/")
	if server == "" {
		return nil, errors.New("interactsh server is required")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	cid, err := randomString(DefaultCIDLength)
	if err != nil {
		return nil, err
	}
	secret, err := randomUUID()
	if err != nil {
		return nil, err
	}

	return &Client{
		server:      server,
		scheme:      scheme,
		token:       token,
		nonceLength: DefaultNonceLength,
		cid:         cid,
		secret:      secret,
		privateKey:  priv,
		http:        &http.Client{Timeout: 20 * time.Second},
	}, nil
}

// Domain returns the server hostname (without scheme).
func (c *Client) Domain() string { return c.server }

// CorrelationID returns the session correlation id.
func (c *Client) CorrelationID() string { return c.cid }

func (c *Client) url(path string) string {
	return c.scheme + "://" + c.server + path
}

// Register performs the Interactsh registration handshake.
func (c *Client) Register() error {
	der, err := x509.MarshalPKIXPublicKey(&c.privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	body, err := json.Marshal(map[string]string{
		"public-key":     base64.StdEncoding.EncodeToString(pubPEM),
		"secret-key":     c.secret,
		"correlation-id": c.cid,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.url("/register"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()

	var parsed struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&parsed)

	if resp.StatusCode != http.StatusOK {
		if parsed.Error != "" {
			return fmt.Errorf("register failed (http %d): %s", resp.StatusCode, parsed.Error)
		}
		return fmt.Errorf("register failed: http %d", resp.StatusCode)
	}
	if !strings.Contains(strings.ToLower(parsed.Message), "registration successful") {
		return fmt.Errorf("register failed: unexpected response %q", parsed.Message)
	}
	return nil
}

// Poll retrieves and decrypts any interactions captured since the last poll.
func (c *Client) Poll() ([]Interaction, error) {
	values := url.Values{}
	values.Set("id", c.cid)
	values.Set("secret", c.secret)

	req, err := http.NewRequest(http.MethodGet, c.url("/poll?"+values.Encode()), nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll request: %w", err)
	}
	defer resp.Body.Close()

	var parsed struct {
		AESKey string   `json:"aes_key"`
		Data   []string `json:"data"`
		Error  string   `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode poll response: %w", err)
	}

	if resp.StatusCode == http.StatusBadRequest &&
		strings.Contains(strings.ToLower(parsed.Error), "correlation-id from cache") {
		return nil, ErrNotRegistered
	}
	if resp.StatusCode != http.StatusOK {
		if parsed.Error != "" {
			return nil, fmt.Errorf("poll failed (http %d): %s", resp.StatusCode, parsed.Error)
		}
		return nil, fmt.Errorf("poll failed: http %d", resp.StatusCode)
	}
	if len(parsed.Data) == 0 {
		return nil, nil
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privateKey, b64decode(parsed.AESKey), nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt aes key: %w", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	out := make([]Interaction, 0, len(parsed.Data))
	for _, entry := range parsed.Data {
		raw := b64decode(entry)
		blockSize := block.BlockSize()
		if len(raw) <= blockSize {
			continue
		}
		iv, ct := raw[:blockSize], raw[blockSize:]
		stream := cipher.NewCTR(block, iv)
		plaintext := make([]byte, len(ct))
		stream.XORKeyStream(plaintext, ct)
		plaintext = bytes.TrimRight(plaintext, "\n")

		var interaction Interaction
		if err := json.Unmarshal(plaintext, &interaction); err != nil {
			continue
		}
		out = append(out, interaction)
	}
	return out, nil
}

// GenerateLabel returns a fresh, unique hostname label (correlation id + nonce).
func (c *Client) GenerateLabel() (string, error) {
	nonce, err := randomString(c.nonceLength)
	if err != nil {
		return "", err
	}
	return c.cid + nonce, nil
}

// Hostname returns the fully-qualified OOB hostname for a label.
func (c *Client) Hostname(label string) string {
	return label + "." + c.server
}

func b64decode(s string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return decoded
}

func randomString(n int) (string, error) {
	if n <= 0 {
		return "", nil
	}
	max := big.NewInt(int64(len(alphabet)))
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[idx.Int64()]
	}
	return string(b), nil
}

func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
