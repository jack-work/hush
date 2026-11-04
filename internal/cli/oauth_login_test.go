package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A failed code exchange is printed to the terminal, and a login run inside an
// aria's pty would put that line in its transcript: it must not echo the code.
func TestAFailedCodeExchangeDoesNotEchoTheRequest(t *testing.T) {
	const code, verifier, state = "code-0123456789abcdefghij", "verifier-0123456789abcdefghij0123456789", "state-0123456789"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"rejected ` + code + ` ` + verifier + `","echo":` + string(body) + `}`))
	}))
	defer srv.Close()

	_, err := exchangeCode(srv.URL, "client-1", code, state, "http://localhost/cb", verifier)
	if err == nil {
		t.Fatal("exchange succeeded against a refusing endpoint")
	}
	for _, secret := range []string{code, verifier, state} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error echoes %q: %v", secret, err)
		}
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error lost the RFC 6749 code: %v", err)
	}
}
