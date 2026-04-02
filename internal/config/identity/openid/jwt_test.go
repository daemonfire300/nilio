// Copyright (c) 2015-2022 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package openid

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v4"
	"github.com/minio/minio/internal/arn"
	"github.com/minio/minio/internal/config"
	jwtm "github.com/minio/minio/internal/jwt"
	xnet "github.com/minio/pkg/v3/net"
)

// newTestOpenIDConfig simulates MinIO's already-loaded OpenID provider config
// just before Console calls MinIO STS with a provider-issued id_token.
func newTestOpenIDConfig(t *testing.T, clientID, clientSecret string) Config {
	t.Helper()

	provider := &providerCfg{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}

	return Config{
		Enabled: true,
		pubKeys: publicKeys{
			RWMutex: &sync.RWMutex{},
			pkMap:   map[string]any{},
		},
		arnProviderCfgsMap: map[arn.ARN]*providerCfg{
			DummyRoleARN: provider,
		},
		ProviderCfgs: map[string]*providerCfg{
			"1": provider,
		},
		closeRespFn: func(rc io.ReadCloser) {
			rc.Close()
		},
		transport: http.DefaultTransport,
	}
}

// signV4Token stands in for the id_token the OIDC provider has already issued
// after the browser redirect and authorization-code exchange have completed.
func signV4Token(t *testing.T, method jwtgo.SigningMethod, key any, kid string, claims jwtgo.MapClaims) string {
	t.Helper()

	token := jwtgo.NewWithClaims(method, claims)
	token.Header["kid"] = kid

	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return tokenString
}

// initRSAJWKSServer stands in for the provider JWKS endpoint MinIO consults
// when it verifies the signature on the id_token received through STS.
func initRSAJWKSServer(t *testing.T, publicKey *rsa.PublicKey, kid string) *httptest.Server {
	t.Helper()

	enc := base64.RawURLEncoding
	e := big.NewInt(int64(publicKey.E))
	jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q}]}`,
		kid,
		enc.EncodeToString(publicKey.N.Bytes()),
		enc.EncodeToString(e.Bytes()),
	)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwks))
	}))
}

func requireValidationErrorContains(t *testing.T, err error, want string) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
		t.Fatalf("expected error containing %q, got %v", want, err)
	}
}

// TestRegressionValidateRejectsFutureIATWithoutClockSkew documents the original
// regression where MinIO rejected an otherwise valid OIDC id_token solely
// because iat was slightly in the future. This models the exact server-side
// validation step hit after Console has already finished the browser redirect
// and posts the returned id_token to MinIO STS.
func TestRegressionValidateRejectsFutureIATWithoutClockSkew(t *testing.T) {
	now := time.Now().UTC()
	clientID := "strict-iat-client"
	clientSecret := "strict-iat-secret"
	token := signV4Token(t, jwtgo.SigningMethodHS256, []byte(clientSecret), clientID, jwtgo.MapClaims{
		"aud": clientID,
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Add(2 * time.Minute).Unix(),
	})

	parser := jwtgo.NewParser(jwtgo.WithValidMethods([]string{jwtgo.SigningMethodHS256.Alg()}))
	claims := jwtgo.MapClaims{}
	_, err := parser.ParseWithClaims(token, &claims, func(*jwtgo.Token) (any, error) {
		return []byte(clientSecret), nil
	})
	requireValidationErrorContains(t, err, "used before issued")
}

// TestRegressionValidateRejectsFutureNBFWithoutClockSkew documents the
// pre-fix no-leeway behavior for nbf. This covers the same post-browser,
// pre-STS-credential validation point in MinIO without needing the browser or
// authorization-code exchange itself.
func TestRegressionValidateRejectsFutureNBFWithoutClockSkew(t *testing.T) {
	now := time.Now().UTC()
	clientID := "strict-nbf-client"
	clientSecret := "strict-nbf-secret"
	token := signV4Token(t, jwtgo.SigningMethodHS256, []byte(clientSecret), clientID, jwtgo.MapClaims{
		"aud": clientID,
		"exp": now.Add(10 * time.Minute).Unix(),
		"nbf": now.Add(2 * time.Minute).Unix(),
	})

	parser := jwtgo.NewParser(jwtgo.WithValidMethods([]string{jwtgo.SigningMethodHS256.Alg()}))
	claims := jwtgo.MapClaims{}
	_, err := parser.ParseWithClaims(token, &claims, func(*jwtgo.Token) (any, error) {
		return []byte(clientSecret), nil
	})
	requireValidationErrorContains(t, err, "not valid yet")
}

// TestRegressionValidateAcceptsFutureIATWithinSkew verifies the clock-skew fix
// for the exact point where Console has already exchanged the browser auth code
// for an id_token and MinIO is validating that token in OpenIDConfig.Validate.
// It intentionally skips only the browser redirect and code-exchange steps.
func TestRegressionValidateAcceptsFutureIATWithinSkew(t *testing.T) {
	now := time.Now().UTC()
	clientID := "future-iat-client"
	clientSecret := "future-iat-secret"
	cfg := newTestOpenIDConfig(t, clientID, clientSecret)
	cfg.pubKeys.add(clientID, []byte(clientSecret))

	token := signV4Token(t, jwtgo.SigningMethodHS256, []byte(clientSecret), clientID, jwtgo.MapClaims{
		"aud": clientID,
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Add(2 * time.Minute).Unix(),
	})

	claims := map[string]any{}
	if err := cfg.Validate(t.Context(), DummyRoleARN, token, "", "", claims); err != nil {
		t.Fatalf("expected future iat within skew to validate, got %v", err)
	}
}

// TestRegressionValidateAcceptsFutureNBFWithinSkew verifies that mild skew on
// nbf is accepted at the same MinIO validation point reached immediately after
// Console sends the provider-issued id_token to STS. It intentionally skips the
// browser and provider code-exchange layers.
func TestRegressionValidateAcceptsFutureNBFWithinSkew(t *testing.T) {
	now := time.Now().UTC()
	clientID := "future-nbf-client"
	clientSecret := "future-nbf-secret"
	cfg := newTestOpenIDConfig(t, clientID, clientSecret)
	cfg.pubKeys.add(clientID, []byte(clientSecret))

	token := signV4Token(t, jwtgo.SigningMethodHS256, []byte(clientSecret), clientID, jwtgo.MapClaims{
		"aud": clientID,
		"exp": now.Add(10 * time.Minute).Unix(),
		"nbf": now.Add(4 * time.Minute).Unix(),
	})

	claims := map[string]any{}
	if err := cfg.Validate(t.Context(), DummyRoleARN, token, "", "", claims); err != nil {
		t.Fatalf("expected future nbf within skew to validate, got %v", err)
	}
}

// TestRegressionValidateRejectsFutureNBFBeyondSkew verifies that the fix only
// tolerates mild clock skew and still rejects materially future nbf values at
// the same post-browser MinIO token-validation point.
func TestRegressionValidateRejectsFutureNBFBeyondSkew(t *testing.T) {
	now := time.Now().UTC()
	clientID := "future-nbf-beyond-client"
	clientSecret := "future-nbf-beyond-secret"
	cfg := newTestOpenIDConfig(t, clientID, clientSecret)
	cfg.pubKeys.add(clientID, []byte(clientSecret))

	token := signV4Token(t, jwtgo.SigningMethodHS256, []byte(clientSecret), clientID, jwtgo.MapClaims{
		"aud": clientID,
		"exp": now.Add(10 * time.Minute).Unix(),
		"nbf": now.Add(6 * time.Minute).Unix(),
	})

	claims := map[string]any{}
	err := cfg.Validate(t.Context(), DummyRoleARN, token, "", "", claims)
	requireValidationErrorContains(t, err, "not valid yet")
}

// TestRegressionValidateAcceptsRecentExpiryWithinSkew verifies that mild
// negative skew on exp is tolerated when MinIO validates the id_token Console
// has already received from the provider. It intentionally skips browser and
// code-exchange mechanics to isolate the STS validation regression.
func TestRegressionValidateAcceptsRecentExpiryWithinSkew(t *testing.T) {
	now := time.Now().UTC()
	clientID := "recent-exp-client"
	clientSecret := "recent-exp-secret"
	cfg := newTestOpenIDConfig(t, clientID, clientSecret)
	cfg.pubKeys.add(clientID, []byte(clientSecret))

	token := signV4Token(t, jwtgo.SigningMethodHS256, []byte(clientSecret), clientID, jwtgo.MapClaims{
		"aud": clientID,
		"exp": now.Add(-2 * time.Minute).Unix(),
	})

	claims := map[string]any{}
	if err := cfg.Validate(t.Context(), DummyRoleARN, token, "", "", claims); err != nil {
		t.Fatalf("expected recently expired token within skew to validate, got %v", err)
	}
}

// TestRegressionValidateRejectsExpiryBeyondSkew verifies that tokens outside
// the allowed leeway still map to ErrTokenExpired, which is the contract the
// STS handler uses when surfacing real login failures back to Console.
func TestRegressionValidateRejectsExpiryBeyondSkew(t *testing.T) {
	now := time.Now().UTC()
	clientID := "expired-client"
	clientSecret := "expired-secret"
	cfg := newTestOpenIDConfig(t, clientID, clientSecret)
	cfg.pubKeys.add(clientID, []byte(clientSecret))

	token := signV4Token(t, jwtgo.SigningMethodHS256, []byte(clientSecret), clientID, jwtgo.MapClaims{
		"aud": clientID,
		"exp": now.Add(-6 * time.Minute).Unix(),
	})

	claims := map[string]any{}
	err := cfg.Validate(t.Context(), DummyRoleARN, token, "", "", claims)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

// TestRegressionValidateRetryKeepsValidMethods verifies the retry-path
// regression where a JWKS refresh could otherwise weaken signing-method
// validation. This still models the same MinIO-side id_token verification step
// reached after Console has already obtained the token from the provider.
func TestRegressionValidateRetryKeepsValidMethods(t *testing.T) {
	now := time.Now().UTC()
	clientID := "retry-valid-methods-client"
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	jwksServer := initRSAJWKSServer(t, &privateKey.PublicKey, clientID)
	defer jwksServer.Close()

	cfg := newTestOpenIDConfig(t, clientID, "unused-secret")
	jwksURL, err := xnet.ParseHTTPURL(jwksServer.URL)
	if err != nil {
		t.Fatalf("parse jwks url: %v", err)
	}
	cfg.arnProviderCfgsMap[DummyRoleARN].JWKS.URL = jwksURL
	cfg.ProviderCfgs["1"].JWKS.URL = jwksURL

	token := signV4Token(t, jwtgo.SigningMethodPS256, privateKey, clientID, jwtgo.MapClaims{
		"aud": clientID,
		"exp": now.Add(10 * time.Minute).Unix(),
	})

	claims := map[string]any{}
	err = cfg.Validate(t.Context(), DummyRoleARN, token, "", "", claims)
	requireValidationErrorContains(t, err, "signing method")
}

func TestUpdateClaimsExpiry(t *testing.T) {
	testCases := []struct {
		exp             any
		dsecs           string
		expectedFailure bool
	}{
		{"", "", true},
		{"-1", "0", true},
		{"-1", "900", true},
		{"1574812326", "900", false},
		{1574812326, "900", false},
		{int64(1574812326), "900", false},
		{int(1574812326), "900", false},
		{uint(1574812326), "900", false},
		{uint64(1574812326), "900", false},
		{json.Number("1574812326"), "900", false},
		{1574812326.000, "900", false},
		{time.Duration(3) * time.Minute, "900", false},
	}

	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			claims := map[string]any{}
			claims["exp"] = testCase.exp
			err := updateClaimsExpiry(testCase.dsecs, claims)
			if err != nil && !testCase.expectedFailure {
				t.Errorf("Expected success, got failure %s", err)
			}
			if err == nil && testCase.expectedFailure {
				t.Error("Expected failure, got success")
			}
		})
	}
}

func initJWKSServer() *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const jsonkey = `{"keys":
       [
         {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }`
		w.Write([]byte(jsonkey))
	}))
	return server
}

func TestJWTHMACType(t *testing.T) {
	server := initJWKSServer()
	defer server.Close()

	jwt := &jwtgo.Token{
		Method: jwtgo.SigningMethodHS256,
		Claims: jwtgo.StandardClaims{
			ExpiresAt: 253428928061,
			Audience:  "76b95ae5-33ef-4283-97b7-d2a85dc2d8f4",
		},
		Header: map[string]any{
			"typ": "JWT",
			"alg": jwtgo.SigningMethodHS256.Alg(),
			"kid": "76b95ae5-33ef-4283-97b7-d2a85dc2d8f4",
		},
	}

	token, err := jwt.SignedString([]byte("WNGvKVyyNmXq0TraSvjaDN9CtpFgx35IXtGEffMCPR0"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(token)

	u1, err := xnet.ParseHTTPURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	pubKeys := publicKeys{
		RWMutex: &sync.RWMutex{},
		pkMap:   map[string]any{},
	}
	pubKeys.add("76b95ae5-33ef-4283-97b7-d2a85dc2d8f4", []byte("WNGvKVyyNmXq0TraSvjaDN9CtpFgx35IXtGEffMCPR0"))

	if len(pubKeys.pkMap) != 1 {
		t.Fatalf("Expected 1 keys, got %d", len(pubKeys.pkMap))
	}

	provider := providerCfg{
		ClientID:     "76b95ae5-33ef-4283-97b7-d2a85dc2d8f4",
		ClientSecret: "WNGvKVyyNmXq0TraSvjaDN9CtpFgx35IXtGEffMCPR0",
	}
	provider.JWKS.URL = u1
	cfg := Config{
		Enabled: true,
		pubKeys: pubKeys,
		arnProviderCfgsMap: map[arn.ARN]*providerCfg{
			DummyRoleARN: &provider,
		},
		ProviderCfgs: map[string]*providerCfg{
			"1": &provider,
		},
		closeRespFn: func(rc io.ReadCloser) {
			rc.Close()
		},
	}

	claims := jwtgo.MapClaims{}
	if err = cfg.Validate(t.Context(), DummyRoleARN, token, "", "", claims); err != nil {
		t.Fatal(err)
	}
}

func TestJWT(t *testing.T) {
	const jsonkey = `{"keys":
       [
         {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }`

	pubKeys := publicKeys{
		RWMutex: &sync.RWMutex{},
		pkMap:   map[string]any{},
	}
	err := pubKeys.parseAndAdd(bytes.NewBuffer([]byte(jsonkey)))
	if err != nil {
		t.Fatal("Error loading pubkeys:", err)
	}
	if len(pubKeys.pkMap) != 1 {
		t.Fatalf("Expected 1 keys, got %d", len(pubKeys.pkMap))
	}

	u1, err := xnet.ParseHTTPURL("http://127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}

	provider := providerCfg{}
	provider.JWKS.URL = u1
	cfg := Config{
		Enabled: true,
		pubKeys: pubKeys,
		arnProviderCfgsMap: map[arn.ARN]*providerCfg{
			DummyRoleARN: &provider,
		},
		ProviderCfgs: map[string]*providerCfg{
			"1": &provider,
		},
	}

	u, err := url.Parse("http://127.0.0.1:8443/?Token=invalid")
	if err != nil {
		t.Fatal(err)
	}

	claims := jwtgo.MapClaims{}
	if err = cfg.Validate(t.Context(), DummyRoleARN, u.Query().Get("Token"), "", "", claims); err == nil {
		t.Fatal(err)
	}
}

func TestDefaultExpiryDuration(t *testing.T) {
	testCases := []struct {
		reqURL    string
		duration  time.Duration
		expectErr bool
	}{
		{
			reqURL:   "http://127.0.0.1:8443/?Token=xxxxx",
			duration: time.Duration(60) * time.Minute,
		},
		{
			reqURL:    "http://127.0.0.1:8443/?DurationSeconds=9s",
			expectErr: true,
		},
		{
			reqURL:    "http://127.0.0.1:8443/?DurationSeconds=31536001",
			expectErr: true,
		},
		{
			reqURL:    "http://127.0.0.1:8443/?DurationSeconds=800",
			expectErr: true,
		},
		{
			reqURL:   "http://127.0.0.1:8443/?DurationSeconds=901",
			duration: time.Duration(901) * time.Second,
		},
	}

	for i, testCase := range testCases {
		u, err := url.Parse(testCase.reqURL)
		if err != nil {
			t.Fatal(err)
		}
		d, err := GetDefaultExpiration(u.Query().Get("DurationSeconds"))
		gotErr := (err != nil)
		if testCase.expectErr != gotErr {
			t.Errorf("Test %d: Expected %v, got %v with error %s", i+1, testCase.expectErr, gotErr, err)
		}
		if d != testCase.duration {
			t.Errorf("Test %d: Expected duration %d, got %d", i+1, testCase.duration, d)
		}
	}
}

func TestExpCorrect(t *testing.T) {
	signKey, _ := base64.StdEncoding.DecodeString("NTNv7j0TuYARvmNMmWXo6fKvM4o6nv/aUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiT/qJACs1J0apruOOJCg/gOtkjB4c=")

	claimsMap := jwtm.NewMapClaims()
	claimsMap.SetExpiry(time.Now().Add(time.Minute))
	claimsMap.SetAccessKey("test-access")
	if err := updateClaimsExpiry("3600", claimsMap.MapClaims); err != nil {
		t.Error(err)
	}
	// Build simple token with updated expiration claim
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claimsMap)
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Error(err)
	}

	// Parse token to be sure it is valid
	err = jwtm.ParseWithClaims(tokenString, claimsMap, func(*jwtm.MapClaims) ([]byte, error) {
		return signKey, nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestKeycloakProviderInitialization(t *testing.T) {
	testConfig := providerCfg{
		DiscoveryDoc: DiscoveryDoc{
			TokenEndpoint: "http://keycloak.test/token/endpoint",
		},
	}
	testKvs := config.KVS{}
	testKvs.Set(Vendor, "keycloak")
	testKvs.Set(KeyCloakRealm, "TestRealm")
	testKvs.Set(KeyCloakAdminURL, "http://keycloak.test/auth/admin")
	cfgGet := func(param string) string {
		return testKvs.Get(param)
	}

	if testConfig.provider != nil {
		t.Errorf("Empty config cannot have any provider!")
	}

	if err := testConfig.initializeProvider(cfgGet, http.DefaultTransport); err != nil {
		t.Error(err)
	}

	if testConfig.provider == nil {
		t.Errorf("keycloak provider must be initialized!")
	}
}
