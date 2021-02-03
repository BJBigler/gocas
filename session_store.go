package gocas

// SessionStore provides an interface for storing and retrieving session data.
type SessionStore interface {
	// Read returns the AuthenticationResponse data associated with a ticket identifier.
	Read(key string) (string, error)

	// Write stores the AuthenticationResponse data received from a ticket validation.
	Write(key, value string) error

	// Delete removes the AuthenticationResponse data associated with a ticket identifier.
	Delete(key string) error

	// Clear removes all of the AuthenticationResponse data from the store.
	Clear() error

	DeleteFromTicket(ticket string) error
}
