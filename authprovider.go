package auth

// AuthProvider defines the functions an auth implemention must support.
type AuthProvider interface {
	// VerifyToken checks if the token is valid.
	VerifyToken(token string) (Token, error)
	// SetRoles sets a given role to the given uid.
	SetRoles(uid string, role []string) error
	// UnsetRoles unsets a given role to the given uid.
	UnsetRole(uid string, role string) error
	// AddRoles adds a given role to the existing roles list to the given uid.
	AddRole(uid string, role string) error
}

// Token defines the functions an auth token implementation must support.
type Token interface {
	// GetRole returns the custom claim "role" specified in the token.
	// If the claim is not present in the token, GetRole returns empty string.
	GetRoles() ([]string, bool)
	// GetUID returns the UID specified in the token.
	GetUID() (string, error)
}
