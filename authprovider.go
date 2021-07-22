package auth

// AuthProvider defines the functions an auth implemention must support.
type AuthProvider interface {
	// CreateUser creates a user in underlying auth provider system and returns the UID and error.
	CreateUser(Email string, DisplayName string) (string, error)
	// VerifyToken checks if the token is valid.
	VerifyToken(token string) (Token, error)
	// SetRoles sets given roles to the given uid.
	SetRoles(uid string, role []string) error
	// UnsetRoles unsets given roles to the given uid.
	UnsetRoles(uid string, role []string) error
	// AddRoles adds given roles to the existing roles list to the given uid.
	AddRoles(uid string, role []string) error
}

// Token defines the functions an auth token implementation must support.
type Token interface {
	// GetRole returns the custom claim "role" specified in the token.
	// If the claim is not present in the token, GetRole returns empty string.
	GetRoles() ([]string, bool)
	// GetUID returns the UID specified in the token.
	GetUID() (string, error)
}
