package main

import (
	"context"
	"errors"

	fbase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
)

// FirebaseAuth implements AuthProvider interface.
type FirebaseAuth struct {
	client *auth.Client
}

// Token implements TokenProvider interface.
type Token struct {
	token *auth.Token
}

// NewFirebaseAuth is the factory function to create a new FirebaseAuth.
func NewFirebaseAuth() (*FirebaseAuth, error) {
	// NewApp is able to authenticate to Firebase using service account credentials.
	// For local dev, ensure GOOGLE_APPLICATION_CREDENTIALS env var is set.
	// For prod, cloud engineers must ensure GOOGLE_APPLICATION_CREDENTIALS env var is set in Kubernetes.
	app, err := fbase.NewApp(context.Background(), nil)
	if err != nil {
		return nil, err
	}

	client, err := app.Auth(context.Background())
	if err != nil {
		return nil, err
	}

	f := &FirebaseAuth{client: client}
	return f, nil
}

// VerifyToken checks the given ID Token.
func (f *FirebaseAuth) VerifyToken(idToken string) (TokenProvider, error) {
	token, err := f.client.VerifyIDToken(context.Background(), idToken)
	if err != nil {
		return nil, err
	}
	ftoken := &Token{token: token}
	return ftoken, nil
}

// SetCustomClaims sets a given role to the given uid using custom claims.
func (f *FirebaseAuth) SetCustomClaims(uid string, role string) error {
	var claims map[string]interface{}
	claims = make(map[string]interface{}, 1)
	claims["role"] = role

	err := f.client.SetCustomUserClaims(context.Background(), uid, claims)
	return err
}

// GetRole returns the custom claim "role" specified in the token.
// If the claim is not present in the token, GetRole returns empty string.
func (t *Token) GetRole() string {
	role, ok := t.token.Claims["role"]
	if !ok {
		return ""
	}

	return role.(string)
}

// GetUID returns the UID of a given token.
func (t *Token) GetUID() (string, error) {
	if t.token == nil {
		return "", errors.New("Auth token not initialized")
	}

	return t.token.UID, nil
}
