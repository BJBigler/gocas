package gocas

import (
	"fmt"
	"sync"
)

// SessionMemoryStore implements the SessionStore interface storing ticket data in memory.
type SessionMemoryStore struct {
	mu    sync.RWMutex
	store map[string]string
}

// Read returns the AuthenticationResponse for a ticket
func (s *SessionMemoryStore) Read(key string) (string, error) {

	s.mu.RLock()

	if s.store == nil {
		s.mu.RUnlock()
		return "", fmt.Errorf("session store invalid")
	}

	t, ok := s.store[key]
	s.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("session store invalid")
	}

	return t, nil
}

// Write stores the AuthenticationResponse for a ticket
func (s *SessionMemoryStore) Write(key, value string) error {

	s.mu.Lock()
	if s.store == nil {
		s.store = make(map[string]string)
	}

	s.store[key] = value
	s.mu.Unlock()
	return nil
}

// Delete removes the session from memory
func (s *SessionMemoryStore) Delete(id string) error {
	if s.store == nil {
		return nil
	}

	s.mu.Lock()
	delete(s.store, id)
	s.mu.Unlock()
	return nil
}

// Clear removes all session data
func (s *SessionMemoryStore) Clear() error {
	s.mu.Lock()
	s.store = make(map[string]string)
	s.mu.Unlock()
	return nil
}

//DeleteFromTicket ...
func (s *SessionMemoryStore) DeleteFromTicket(ticket string) error {

	var id string
	for s, t := range s.store {
		if t == ticket {
			id = s
			break
		}
	}

	if id == "" {
		return nil
	}

	return s.Delete(id)
}
