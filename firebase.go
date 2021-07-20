package auth

import (
	"context"
	"errors"
	"fmt"

	fbase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
)

// FirebaseAuth implements AuthProvider interface.
type FirebaseAuth struct {
	client *auth.Client
}

// Token implements TokenProvider interface.
type FirebaseToken struct {
	token *auth.Token
}

// remove finds a string & removes it from the array (Used to Unset roles)
func remove(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
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
func (f *FirebaseAuth) VerifyToken(idToken string) (Token, error) {
	token, err := f.client.VerifyIDToken(context.Background(), idToken)
	if err != nil {
		return nil, err
	}
	ftoken := &FirebaseToken{token: token}
	return ftoken, nil
}

// SetRoles sets a given role to the given uid using custom claims.
func (f *FirebaseAuth) SetRoles(uid string, role []string) error {
	var claims map[string]interface{}
	claims = make(map[string]interface{}, 1)
	claims["role"] = role

	err := f.client.SetCustomUserClaims(context.Background(), uid, claims)
	return err
}

// AddRole adds a given role to the given uid using custom claims.
func (f *FirebaseAuth) AddRole(uid string, role string) error {

	// Retreive user details from uid
	user, err := f.client.GetUser(context.Background(), uid)
	if err != nil {
		return err
	}
	// Convert claim []interface to []string
	old_claim := make([]string, len(user.CustomClaims))
	for i, v := range old_claim {
		old_claim[i] = fmt.Sprint(v)
	}

	// Append the new role to the []string of roles
	updated_roles := append(old_claim, role)

	// Convert new_claim string[] to []interface
	new_claim := make(map[string]interface{}, 1)
	new_claim["role"] = updated_roles

	err = f.client.SetCustomUserClaims(context.Background(), uid, new_claim)
	return err
}

// UnsetRoles sets a given role to the given uid using custom claims.
func (f *FirebaseAuth) UnsetRoles(uid string, role string) error {

	// Retreive user details from uid
	user, err := f.client.GetUser(context.Background(), uid)
	if err != nil {
		return err
	}

	// Convert claim []interface to []string
	old_claim := make([]string, len(user.CustomClaims))
	for i, v := range old_claim {
		old_claim[i] = fmt.Sprint(v)
	}

	// Remove the role from the []string of roles
	updated_roles := remove(old_claim, role)

	// Convert new_claim string[] to []interface
	new_claim := make(map[string]interface{}, 1)
	new_claim["role"] = updated_roles

	err = f.client.SetCustomUserClaims(context.Background(), uid, new_claim)
	return err
}

// GetRoles returns the custom claim "role" specified in the token.
// If the claim is not present in the token, GetRole returns empty string.
func (t *FirebaseToken) GetRoles() ([]string, bool) {
	role, ok := t.token.Claims["role"]
	if !ok {
		return nil, !ok
	}

	return role.([]string), ok
}

// GetUID returns the UID of a given token.
func (t *FirebaseToken) GetUID() (string, error) {
	if t.token == nil {
		return "", errors.New("Auth token not initialized")
	}

	return t.token.UID, nil
}
