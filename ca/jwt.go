package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/jack-work/hush/spiffeid"
)

const (
	JWTTTL    = 5 * time.Minute
	MaxJWTTTL = time.Hour
)

type JWTClaims struct {
	Subject  string   `json:"sub"`
	Audience []string `json:"aud"`
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func IssueJWTSVID(key *ecdsa.PrivateKey, kid string, id spiffeid.ID, audience []string, now time.Time, ttl time.Duration) (string, time.Time, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return "", time.Time{}, errors.New("jwt-svid: want an ECDSA P-256 key")
	}
	if kid == "" {
		return "", time.Time{}, errors.New("jwt-svid: the key needs a kid")
	}
	if id.IsZero() {
		return "", time.Time{}, errors.New("jwt-svid: no subject")
	}
	if node, _, ok := strings.Cut(kid, ":"); !ok || !id.Under(node) {
		return "", time.Time{}, fmt.Errorf("jwt-svid: key %q may not speak for %s", kid, id)
	}
	if len(audience) == 0 {
		return "", time.Time{}, errors.New("jwt-svid: at least one audience")
	}
	for _, a := range audience {
		if a == "" {
			return "", time.Time{}, errors.New("jwt-svid: an empty audience")
		}
	}
	exp := now.Add(ClampTTL(ttl, JWTTTL, time.Minute, MaxJWTTTL))
	h, err := json.Marshal(jwtHeader{Alg: "ES256", Typ: "JWT", Kid: kid})
	if err != nil {
		return "", time.Time{}, err
	}
	c, err := json.Marshal(JWTClaims{Subject: id.String(), Audience: audience, Expiry: exp.Unix(), IssuedAt: now.Unix()})
	if err != nil {
		return "", time.Time{}, err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", time.Time{}, err
	}
	if n := key.Curve.Params().N; s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s.Sub(n, s)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + enc.EncodeToString(sig), time.Unix(exp.Unix(), 0), nil
}

func JWTKeyID(node string, pub *ecdsa.PublicKey) (string, error) {
	if _, err := spiffeid.Node("x", node); err != nil {
		return "", err
	}
	raw, err := pub.Bytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return node + ":" + base64.RawURLEncoding.EncodeToString(sum[:12]), nil
}
