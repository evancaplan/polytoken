package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"polytoken/internal/jwks"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	typ := flag.String("type", "hs256", "hs256 or rs256")
	iss := flag.String("iss", "https://test.local", "issuer")
	kid := flag.String("kid", "test-key-1", "key id (rs256)")
	sub := flag.String("sub", "test-user", "subject")
	secret := flag.String("secret", "", "HMAC secret (hs256)")
	expHours := flag.Int("exp-hours", 1, "hours until expiry")
	roles := flag.String("roles", "", "comma separated list of roles")
	scope := flag.String("scope", "read write", "comma separated list of scopes")
	flag.Parse()

	if typ == nil || (*typ != "hs256" && *typ != "rs256") {
		log.Fatal("mint token: type must be hs256 or rs256")
	}

	if *typ == "hs256" {

		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims(iss, sub, expHours, scope, getRoles(roles)))

		s, err := tok.SignedString([]byte(*secret))
		if err != nil {
			log.Fatalf("mint token: %v", err)
		}

		fmt.Println(s)
	}

	if *typ == "rs256" {
		r := getRoles(roles)

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("mint token: %v", err)
		}

		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims(iss, sub, expHours, scope, r))
		tok.Header["kid"] = *kid

		s, err := tok.SignedString(key)
		if err != nil {
			log.Fatalf("mint token: %v", err)
		}

		var doc = jwks.JwksDoc{
			Keys: []jwks.JwkKey{{
				Kty: "RSA",
				Kid: *kid,
				N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}},
		}

		fmt.Println("TOKEN:")
		fmt.Println(s)

		jwksJSON, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			log.Fatalf("mint token: %v", err)
		}
		fmt.Println("\nJWKS:")
		fmt.Println(string(jwksJSON))
	}

}

func getRoles(roles *string) []string {
	var r []string

	if *roles != "" {
		r = strings.Split(*roles, ",")
	} else {
		r = []string{}
	}
	return r
}

func claims(iss *string, sub *string, expHours *int, scope *string, r []string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   *iss,
		"sub":   *sub,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Duration(*expHours) * time.Hour).Unix(),
		"scope": *scope,
		"roles": r,
	}
}
