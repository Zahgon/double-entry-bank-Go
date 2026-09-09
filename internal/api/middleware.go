package api

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/lestrrat-go/jwx/v3/transform"
)

// JWTAuth signs and verifies the JSON Web Tokens used by the API.
type JWTAuth struct {
	signKey interface{}
	alg     jwa.SignatureAlgorithm
}

var (
	// TokenAuth holds the JWT authenticator used by the API package.
	TokenAuth *JWTAuth
)

// Reasons a request may be refused by Authenticator. The text of each error is
// written verbatim to the client, so it is part of the API contract.
var (
	// ErrUnauthorized is returned when a token cannot be decoded or verified.
	ErrUnauthorized = errors.New("token is unauthorized")
	// ErrExpired is returned when a token carries an "exp" claim in the past.
	ErrExpired = errors.New("token is expired")
	// ErrNBFInvalid is returned when a token is not valid yet.
	ErrNBFInvalid = errors.New("token nbf validation failed")
	// ErrIATInvalid is returned when a token was issued in the future.
	ErrIATInvalid = errors.New("token iat validation failed")
	// ErrNoTokenFound is returned when the request carries no token at all.
	ErrNoTokenFound = errors.New("no token found")
)

// Keys under which Verifier records its result for the rest of the chain.
const (
	tokenCtxKey = "jwt.token"
	errorCtxKey = "jwt.error"
)

// newJWTAuth constructs a JWTAuth for the given algorithm and signing key.
func newJWTAuth(alg string, signKey interface{}) *JWTAuth {
	sigAlg, _ := jwa.LookupSignatureAlgorithm(alg)
	return &JWTAuth{alg: sigAlg, signKey: signKey}
}

// InitTokenAuthFromEnv initializes JWT auth using the JWT_SECRET environment variable.
func InitTokenAuthFromEnv() error {
	// Keep bootstrap simple: this function is called once from main().
	secret := os.Getenv("JWT_SECRET")
	return InitTokenAuth(secret)
}

// InitTokenAuth initializes JWT auth with the provided secret.
func InitTokenAuth(secret string) error {
	// Fail fast if JWT configuration is insecure or missing.
	if secret == "" {
		return errors.New("JWT_SECRET environment variable is required")
	}

	if len(secret) < 32 {
		return errors.New("JWT_SECRET must be at least 32 characters")
	}

	TokenAuth = newJWTAuth("HS256", []byte(secret))
	return nil
}

// GenerateToken creates a signed JWT for the given user ID.
func GenerateToken(userID uuid.UUID) (string, error) {
	if TokenAuth == nil {
		return "", errors.New("token auth is not initialized")
	}

	// Include user identity and expiry in signed JWT claims.
	claims := map[string]interface{}{
		"user_id": userID.String(),
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}
	_, tokenString, err := TokenAuth.Encode(claims)
	return tokenString, err
}

// Encode mints a signed token carrying the given claims.
func (ja *JWTAuth) Encode(claims map[string]interface{}) (jwt.Token, string, error) {
	t := jwt.New()
	for k, v := range claims {
		if err := t.Set(k, v); err != nil {
			return nil, "", err
		}
	}

	payload, err := jwt.Sign(t, jwt.WithKey(ja.alg, ja.signKey))
	if err != nil {
		return nil, "", err
	}
	return t, string(payload), nil
}

// Decode parses and signature-checks a token without applying claim validation.
func (ja *JWTAuth) Decode(tokenString string) (jwt.Token, error) {
	// Validation is applied separately so its failures can be reported distinctly.
	return jwt.Parse([]byte(tokenString), jwt.WithKey(ja.alg, ja.signKey), jwt.WithValidate(false))
}

// Verifier returns middleware that looks for a token on the request and records
// the result for Authenticator, searching in this order:
//
//  1. 'Authorization: BEARER T' request header
//  2. Cookie 'jwt' value
//
// It never rejects a request itself, so a downstream handler is free to treat an
// unauthenticated caller differently.
func Verifier(ja *JWTAuth) gin.HandlerFunc {
	return Verify(ja, TokenFromHeader, TokenFromCookie)
}

// Verify returns middleware that extracts a token using the given lookup
// functions, stopping at the first one that yields a non-empty string.
func Verify(ja *JWTAuth, findTokenFns ...func(r *http.Request) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := verifyRequest(ja, c.Request, findTokenFns...)
		c.Set(tokenCtxKey, token)
		c.Set(errorCtxKey, err)
		c.Next()
	}
}

func verifyRequest(ja *JWTAuth, r *http.Request, findTokenFns ...func(r *http.Request) string) (jwt.Token, error) {
	var tokenString string

	// Stop at the first lookup that produces something.
	for _, fn := range findTokenFns {
		tokenString = fn(r)
		if tokenString != "" {
			break
		}
	}
	if tokenString == "" {
		return nil, ErrNoTokenFound
	}

	return verifyToken(ja, tokenString)
}

func verifyToken(ja *JWTAuth, tokenString string) (jwt.Token, error) {
	token, err := ja.Decode(tokenString)
	if err != nil {
		return token, errorReason(err)
	}

	if token == nil {
		return nil, ErrUnauthorized
	}

	if validateErr := jwt.Validate(token); validateErr != nil {
		return token, errorReason(validateErr)
	}

	return token, nil
}

// errorReason normalizes the underlying JWT library's errors into the small set
// of reasons this API reports.
func errorReason(err error) error {
	switch {
	case errors.Is(err, jwt.TokenExpiredError()):
		return ErrExpired
	case errors.Is(err, jwt.InvalidIssuedAtError()):
		return ErrIATInvalid
	case errors.Is(err, jwt.TokenNotYetValidError()):
		return ErrNBFInvalid
	default:
		return ErrUnauthorized
	}
}

// Authenticator returns middleware that refuses any request Verifier could not
// authenticate and passes the good ones through.
func Authenticator() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, _, err := FromContext(c)

		if err != nil {
			http.Error(c.Writer, err.Error(), http.StatusUnauthorized)
			c.Abort()
			return
		}

		if token == nil {
			http.Error(c.Writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			c.Abort()
			return
		}

		// Token is authenticated, pass it through
		c.Next()
	}
}

// FromContext returns the token, its claims and the verification error recorded
// by Verifier for the current request.
func FromContext(c *gin.Context) (jwt.Token, map[string]interface{}, error) {
	token, _ := c.Value(tokenCtxKey).(jwt.Token)

	var err error
	claims := map[string]interface{}{}
	if token != nil {
		if err = transform.AsMap(token, claims); err != nil {
			return token, nil, err
		}
	}

	err, _ = c.Value(errorCtxKey).(error)

	return token, claims, err
}

// TokenFromCookie tries to retrieve the token string from a cookie named "jwt".
func TokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("jwt")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// TokenFromHeader tries to retrieve the token string from the "Authorization"
// request header: "Authorization: BEARER T".
func TokenFromHeader(r *http.Request) string {
	// Get token from authorization header.
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:7]) == "BEARER " {
		return bearer[7:]
	}
	return ""
}
