package main

// AuthProvider defines the functions an auth implemention must support.
type AuthProvider interface {
	// VerifyToken checks if the token is valid.
	VerifyToken(token string) (Token, error)
	// SetCustomClaims sets a given role to the given uid.
	SetCustomClaims(uid string, role string) error
}

// Token defines the functions an auth token implementation must support.
type TokenProvider interface {
	// GetRole returns the custom claim "role" specified in the token.
	// If the claim is not present in the token, GetRole returns empty string.
	GetRole() string
	// GetUID returns the UID specified in the token.
	GetUID() (string, error)
}
