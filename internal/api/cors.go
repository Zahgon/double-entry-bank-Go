package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSOptions configures the CORS middleware.
type CORSOptions struct {
	// AllowedOrigins is the list of origins allowed to perform cross-domain
	// requests. A "*" entry allows every origin; an entry may contain a single
	// "*" wildcard, e.g. "https://*.example.com".
	AllowedOrigins []string
	// AllowedMethods is the list of methods allowed for cross-domain requests.
	AllowedMethods []string
	// AllowedHeaders is the list of request headers a client may send.
	AllowedHeaders []string
	// ExposedHeaders is the list of response headers exposed to the client.
	ExposedHeaders []string
	// AllowCredentials indicates whether the request may include credentials.
	AllowCredentials bool
	// MaxAge is the number of seconds a preflight result may be cached.
	MaxAge int
}

type corsWildcard struct {
	prefix string
	suffix string
}

func (w corsWildcard) match(s string) bool {
	return len(s) >= len(w.prefix)+len(w.suffix) &&
		strings.HasPrefix(s, w.prefix) && strings.HasSuffix(s, w.suffix)
}

type corsHandler struct {
	allowedOrigins  []string
	allowedWOrigins []corsWildcard
	allowedMethods  []string
	allowedHeaders  []string
	exposedHeaders  []string

	maxAge            int
	allowedOriginsAll bool
	allowedHeadersAll bool
	allowCredentials  bool
}

// CORS returns middleware applying the CORS specification to every request.
func CORS(options CORSOptions) gin.HandlerFunc {
	c := newCORSHandler(options)
	return c.handle
}

func newCORSHandler(options CORSOptions) *corsHandler {
	c := &corsHandler{
		exposedHeaders:   canonicalizeHeaders(options.ExposedHeaders),
		allowCredentials: options.AllowCredentials,
		maxAge:           options.MaxAge,
	}

	// Origins are matched case-insensitively; "*" collapses the whole list.
	if len(options.AllowedOrigins) == 0 {
		c.allowedOriginsAll = true
	} else {
		for _, origin := range options.AllowedOrigins {
			origin = strings.ToLower(origin)
			if origin == "*" {
				c.allowedOriginsAll = true
				c.allowedOrigins = nil
				c.allowedWOrigins = nil
				break
			}
			if i := strings.IndexByte(origin, '*'); i >= 0 {
				c.allowedWOrigins = append(c.allowedWOrigins, corsWildcard{origin[:i], origin[i+1:]})
				continue
			}
			c.allowedOrigins = append(c.allowedOrigins, origin)
		}
	}

	// Origin is always accepted because browsers send it during preflight.
	if len(options.AllowedHeaders) == 0 {
		c.allowedHeaders = []string{"Origin", "Accept", "Content-Type"}
	} else {
		c.allowedHeaders = canonicalizeHeaders(append(append([]string{}, options.AllowedHeaders...), "Origin"))
		for _, h := range options.AllowedHeaders {
			if h == "*" {
				c.allowedHeadersAll = true
				c.allowedHeaders = nil
				break
			}
		}
	}

	if len(options.AllowedMethods) == 0 {
		c.allowedMethods = []string{http.MethodGet, http.MethodPost, http.MethodHead}
	} else {
		for _, m := range options.AllowedMethods {
			c.allowedMethods = append(c.allowedMethods, strings.ToUpper(m))
		}
	}

	return c
}

func (c *corsHandler) handle(ctx *gin.Context) {
	r := ctx.Request
	// An empty Origin header still counts as a CORS request.
	_, hasOrigin := r.Header["Origin"]

	if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" && hasOrigin {
		c.handlePreflight(ctx)
		// Preflight requests stand alone: no downstream handler may run, because
		// they carry no credentials and would be rejected by authentication.
		ctx.Status(http.StatusOK)
		ctx.Writer.WriteHeaderNow()
		ctx.Abort()
		return
	}

	c.handleActualRequest(ctx)
	ctx.Next()
}

func (c *corsHandler) handlePreflight(ctx *gin.Context) {
	headers := ctx.Writer.Header()
	origin := ctx.Request.Header.Get("Origin")

	// A preflight is answered here, not by the router, so drop the Allow header
	// the router adds when it finds no handler for OPTIONS.
	headers.Del("Allow")

	// Vary is always emitted so caches never serve one origin's response to another.
	headers.Add("Vary", "Origin")
	headers.Add("Vary", "Access-Control-Request-Method")
	headers.Add("Vary", "Access-Control-Request-Headers")

	if !c.isOriginAllowed(origin) {
		return
	}

	reqMethod := ctx.Request.Header.Get("Access-Control-Request-Method")
	if !c.isMethodAllowed(reqMethod) {
		return
	}

	reqHeaders := parseCORSHeaderList(ctx.Request.Header.Get("Access-Control-Request-Headers"))
	if !c.areHeadersAllowed(reqHeaders) {
		return
	}

	if c.allowedOriginsAll {
		headers.Set("Access-Control-Allow-Origin", "*")
	} else {
		headers.Set("Access-Control-Allow-Origin", origin)
	}

	// Echoing the requested method and headers keeps the response bounded.
	headers.Set("Access-Control-Allow-Methods", strings.ToUpper(reqMethod))
	if len(reqHeaders) > 0 {
		headers.Set("Access-Control-Allow-Headers", strings.Join(reqHeaders, ", "))
	}
	if c.allowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}
	if c.maxAge > 0 {
		headers.Set("Access-Control-Max-Age", strconv.Itoa(c.maxAge))
	}
}

func (c *corsHandler) handleActualRequest(ctx *gin.Context) {
	headers := ctx.Writer.Header()
	_, hasOrigin := ctx.Request.Header["Origin"]

	headers.Add("Vary", "Origin")

	if !hasOrigin {
		return
	}

	// A disallowed origin is not an error: the request proceeds without CORS
	// headers and the browser refuses to hand the response to the page.
	origin := ctx.Request.Header.Get("Origin")
	if !c.isOriginAllowed(origin) {
		return
	}
	if !c.isMethodAllowed(ctx.Request.Method) {
		return
	}

	if c.allowedOriginsAll {
		headers.Set("Access-Control-Allow-Origin", "*")
	} else {
		headers.Set("Access-Control-Allow-Origin", origin)
	}
	if len(c.exposedHeaders) > 0 {
		headers.Set("Access-Control-Expose-Headers", strings.Join(c.exposedHeaders, ", "))
	}
	if c.allowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}
}

func (c *corsHandler) isOriginAllowed(origin string) bool {
	if c.allowedOriginsAll {
		return true
	}
	origin = strings.ToLower(origin)
	for _, o := range c.allowedOrigins {
		if o == origin {
			return true
		}
	}
	for _, w := range c.allowedWOrigins {
		if w.match(origin) {
			return true
		}
	}
	return false
}

func (c *corsHandler) isMethodAllowed(method string) bool {
	if len(c.allowedMethods) == 0 {
		return false
	}
	method = strings.ToUpper(method)
	if method == http.MethodOptions {
		// Preflight is always permitted; the requested method is checked separately.
		return true
	}
	for _, m := range c.allowedMethods {
		if m == method {
			return true
		}
	}
	return false
}

func (c *corsHandler) areHeadersAllowed(requestedHeaders []string) bool {
	if c.allowedHeadersAll || len(requestedHeaders) == 0 {
		return true
	}
	for _, header := range requestedHeaders {
		header = http.CanonicalHeaderKey(header)
		found := false
		for _, h := range c.allowedHeaders {
			if h == header {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func canonicalizeHeaders(headers []string) []string {
	out := make([]string, 0, len(headers))
	for _, h := range headers {
		out = append(out, http.CanonicalHeaderKey(h))
	}
	return out
}

// parseCORSHeaderList tokenizes and normalizes an Access-Control-Request-Headers value.
func parseCORSHeaderList(headerList string) []string {
	if strings.TrimSpace(headerList) == "" {
		return nil
	}
	parts := strings.Split(headerList, ",")
	headers := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			headers = append(headers, http.CanonicalHeaderKey(trimmed))
		}
	}
	return headers
}
