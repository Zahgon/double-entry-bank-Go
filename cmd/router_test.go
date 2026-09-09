package main

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PaulBabatuyi/Double-Entry-Bank-Go/internal/api"
	"github.com/PaulBabatuyi/Double-Entry-Bank-Go/internal/db"
	"github.com/PaulBabatuyi/Double-Entry-Bank-Go/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testJWTSecret = "fV7sliKV3qn657I60wEFtw/Auk/0bNU9zdp30wFzfDg="

// newTestServer starts the real router on a real socket. These tests pin the
// wire contract of the routing layer, so an in-process handler call would not
// prove what they claim: status lines, header casing, charset parameters and
// trailing bytes are decided by the server, not by the handler.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	require.NoError(t, api.InitTokenAuth(testJWTSecret))

	// newRouter reads the allowed-origin list from CORS_ALLOWED_ORIGINS, so pin
	// it here. A seam test has to control its own inputs: without this the CORS
	// assertions below are a function of whatever the ambient environment sets
	// rather than of the middleware, and they fail wherever a deployment config
	// is exported. t.Setenv restores the previous value when the test ends.
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,https://golangbank.app")

	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		dbURL = "postgresql://root:secret@localhost:5432/simple_ledger?sslmode=disable"
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	require.NoError(t, err)
	store := db.NewStore(sqlDB)
	h := api.NewHandler(service.NewLedgerService(store), store)

	srv := httptest.NewServer(newRouter(h, time.Now()))
	t.Cleanup(srv.Close)
	return srv
}

// do issues a request without following redirects, so a router that silently
// redirects instead of answering is visible rather than hidden.
func do(t *testing.T, srv *httptest.Server, method, path string, mutate func(*http.Request)) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	require.NoError(t, err)
	if mutate != nil {
		mutate(req)
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(body)
}

func bearer(t *testing.T) func(*http.Request) {
	t.Helper()
	token, err := api.GenerateToken(uuid.New())
	require.NoError(t, err)
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

// --- routing table ----------------------------------------------------------

// TestRoutesAreMounted fails if any route moved, lost its path parameter or was
// never registered: an unmounted path answers 404, a mounted one answers 401.
func TestRoutesAreMounted(t *testing.T) {
	srv := newTestServer(t)

	protected := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/accounts"},
		{http.MethodGet, "/accounts"},
		{http.MethodGet, "/accounts/" + uuid.NewString()},
		{http.MethodPost, "/accounts/" + uuid.NewString() + "/deposit"},
		{http.MethodPost, "/accounts/" + uuid.NewString() + "/withdraw"},
		{http.MethodPost, "/transfers"},
		{http.MethodGet, "/accounts/" + uuid.NewString() + "/entries"},
		{http.MethodGet, "/accounts/" + uuid.NewString() + "/reconcile"},
		{http.MethodGet, "/transactions/" + uuid.NewString()},
	}
	for _, route := range protected {
		resp, _ := do(t, srv, route.method, route.path, nil)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%s %s", route.method, route.path)
	}

	// Public routes answer without a token.
	resp, _ := do(t, srv, http.MethodPost, "/register", nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp, _ = do(t, srv, http.MethodPost, "/login", nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestPathParameterReachesHandler fails if the path parameter is declared under
// a name the handlers do not read: the id would arrive empty and parse as a bad
// request rather than reaching the not-found branch.
func TestPathParameterReachesHandler(t *testing.T) {
	srv := newTestServer(t)

	resp, body := do(t, srv, http.MethodGet, "/accounts/not-a-uuid", bearer(t))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "{\"error\":\"invalid account ID\"}\n", body)

	resp, body = do(t, srv, http.MethodGet, "/transactions/not-a-uuid", bearer(t))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "{\"error\":\"invalid transaction ID\"}\n", body)
}

// --- framework error envelopes ---------------------------------------------

func TestUnknownRouteEnvelope(t *testing.T) {
	srv := newTestServer(t)

	for _, path := range []string{"/definitely-not-a-route", "/accounts/x/y/z/nope", "/"} {
		resp, body := do(t, srv, http.MethodGet, path, nil)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, path)
		assert.Equal(t, "404 page not found\n", body, path)
		assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"), path)
		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"), path)
	}
}

// TestWrongMethodEnvelope pins a 405 with an empty body and one Allow header per
// permitted method. Gin answers 404 unless method mismatch is enabled, and joins
// the methods into a single header unless they are split back apart.
func TestWrongMethodEnvelope(t *testing.T) {
	srv := newTestServer(t)

	resp, body := do(t, srv, http.MethodPut, "/health", nil)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	assert.Empty(t, body)
	assert.Equal(t, []string{"GET"}, resp.Header.Values("Allow"))
	assert.Empty(t, resp.Header.Get("Content-Type"))

	resp, body = do(t, srv, http.MethodDelete, "/transfers", nil)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	assert.Empty(t, body)
	assert.Equal(t, []string{"POST"}, resp.Header.Values("Allow"))

	// A path serving two methods reports both, one header each.
	resp, _ = do(t, srv, http.MethodOptions, "/accounts", nil)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	assert.Equal(t, []string{"POST", "GET"}, resp.Header.Values("Allow"))

	// HEAD is not registered anywhere, so it is a method mismatch too.
	resp, _ = do(t, srv, http.MethodHead, "/health", nil)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	assert.Equal(t, []string{"GET"}, resp.Header.Values("Allow"))
}

// TestTrailingSlashIsNotRedirected fails if the router redirects to the
// slash-less form, which Gin does by default and the previous router never did.
func TestTrailingSlashIsNotRedirected(t *testing.T) {
	srv := newTestServer(t)

	for _, path := range []string{"/health/", "/accounts/", "/accounts//"} {
		resp, body := do(t, srv, http.MethodGet, path, nil)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, path)
		assert.Equal(t, "404 page not found\n", body, path)
	}
}

// --- authentication seam ----------------------------------------------------

// TestAuthEnvelope pins the plain-text 401 bodies, which differ per reason and
// are not JSON like the handlers' own errors.
func TestAuthEnvelope(t *testing.T) {
	srv := newTestServer(t)

	cases := []struct {
		name   string
		mutate func(*http.Request)
		body   string
	}{
		{"no token", nil, "no token found\n"},
		{"garbage token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer not.a.jwt") }, "token is unauthorized\n"},
		{"empty bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }, "no token found\n"},
		{"wrong scheme", func(r *http.Request) { r.Header.Set("Authorization", "Basic abcdef") }, "no token found\n"},
		{"header too short", func(r *http.Request) { r.Header.Set("Authorization", "Bearer") }, "no token found\n"},
	}
	for _, tc := range cases {
		resp, body := do(t, srv, http.MethodGet, "/accounts", tc.mutate)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, tc.name)
		assert.Equal(t, tc.body, body, tc.name)
		assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"), tc.name)
		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"), tc.name)
	}
}

// TestTokenLookupOrder pins where a token may be presented: the Authorization
// header with a case-insensitive BEARER prefix, or a "jwt" cookie. A query
// parameter is not a lookup source and must stay unauthenticated.
//
// The accepted cases assert "not 401" rather than "200" on purpose. The seam
// under test is the middleware's token lookup, and the middleware's only
// rejection is 401; what the handler goes on to do with the request belongs to
// a different seam. Asserting 200 would additionally require a reachable
// database, coupling an auth-wiring test to infrastructure without pinning
// anything extra: dropping either lookup source still surfaces here as a 401.
func TestTokenLookupOrder(t *testing.T) {
	srv := newTestServer(t)
	token, err := api.GenerateToken(uuid.New())
	require.NoError(t, err)

	resp, _ := do(t, srv, http.MethodGet, "/accounts", func(r *http.Request) {
		r.Header.Set("Authorization", "bearer "+token)
	})
	assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode)

	resp, _ = do(t, srv, http.MethodGet, "/accounts", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "jwt", Value: token})
	})
	assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode)

	resp, body := do(t, srv, http.MethodGet, "/accounts?jwt="+token, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "no token found\n", body)
}

// --- response encoding seam -------------------------------------------------

// TestJSONResponsesKeepWireFormat pins the media type without a charset
// parameter and the trailing newline. Gin's own JSON renderer emits
// "application/json; charset=utf-8" and no newline.
func TestJSONResponsesKeepWireFormat(t *testing.T) {
	srv := newTestServer(t)

	resp, body := do(t, srv, http.MethodGet, "/health", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.True(t, strings.HasSuffix(body, "\n"), "health body must end with a newline")
	assert.Contains(t, body, `"status":"healthy"`)
	assert.Contains(t, body, `"version":"0.1.0"`)

	resp, body = do(t, srv, http.MethodPost, "/register", nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "{\"error\":\"invalid input\"}\n", body)
}

// --- CORS seam --------------------------------------------------------------

// TestCORSActualRequest pins that Vary is emitted even without an Origin, that
// an allowed origin is echoed with the credentials and exposed-header flags, and
// that a disallowed origin is served normally rather than rejected.
func TestCORSActualRequest(t *testing.T) {
	srv := newTestServer(t)

	resp, _ := do(t, srv, http.MethodGet, "/health", nil)
	assert.Equal(t, []string{"Origin"}, resp.Header.Values("Vary"))
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))

	resp, _ = do(t, srv, http.MethodGet, "/health", func(r *http.Request) {
		r.Header.Set("Origin", "http://localhost:3000")
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "http://localhost:3000", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "Link", resp.Header.Get("Access-Control-Expose-Headers"))

	resp, _ = do(t, srv, http.MethodGet, "/health", func(r *http.Request) {
		r.Header.Set("Origin", "http://evil.example")
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

// TestCORSPreflight pins the preflight answer: status 200 with an empty body,
// three separate Vary headers, and the requested method and headers echoed back.
func TestCORSPreflight(t *testing.T) {
	srv := newTestServer(t)

	resp, body := do(t, srv, http.MethodOptions, "/accounts", func(r *http.Request) {
		r.Header.Set("Origin", "http://localhost:3000")
		r.Header.Set("Access-Control-Request-Method", "POST")
		r.Header.Set("Access-Control-Request-Headers", "Authorization,Content-Type")
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, body)
	assert.Equal(t,
		[]string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"},
		resp.Header.Values("Vary"))
	assert.Equal(t, "http://localhost:3000", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "POST", resp.Header.Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Authorization, Content-Type", resp.Header.Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "300", resp.Header.Get("Access-Control-Max-Age"))

	// Preflight is answered before routing, so an unknown path answers too.
	resp, _ = do(t, srv, http.MethodOptions, "/nope", func(r *http.Request) {
		r.Header.Set("Origin", "http://localhost:3000")
		r.Header.Set("Access-Control-Request-Method", "POST")
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "http://localhost:3000", resp.Header.Get("Access-Control-Allow-Origin"))

	// An OPTIONS request without the preflight header is not a preflight.
	resp, _ = do(t, srv, http.MethodOptions, "/accounts", func(r *http.Request) {
		r.Header.Set("Origin", "http://localhost:3000")
	})
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// --- swagger seam -----------------------------------------------------------

// TestSwaggerIsMounted fails if the wildcard mount was dropped or renamed.
func TestSwaggerIsMounted(t *testing.T) {
	srv := newTestServer(t)

	resp, body := do(t, srv, http.MethodGet, "/swagger/doc.json", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, "Double-Entry Bank Ledger API")

	resp, _ = do(t, srv, http.MethodGet, "/swagger/index.html", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
