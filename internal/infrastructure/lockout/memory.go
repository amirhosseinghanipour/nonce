package lockout

import (
	"context"
	"sync"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
)

type entry struct {
	failures   int
	lockedUntil time.Time
}

// MemoryStore is an in-memory LoginLockoutStore (single instance; use Redis for multi-instance).
type MemoryStore struct {
	mu     sync.RWMutex
	data   map[string]*entry
	max    int
	cooldown time.Duration
}

// NewMemoryStore returns a lockout store with given max attempts and cooldown. maxAttempts 0 = disabled.
func NewMemoryStore(maxAttempts, cooldownSeconds int) *MemoryStore {
	cd := time.Duration(cooldownSeconds) * time.Second
	if cd <= 0 {
		cd = 15 * time.Minute
	}
	return &MemoryStore{
		data:   make(map[string]*entry),
		max:    maxAttempts,
		cooldown: cd,
	}
}

func (s *MemoryStore) key(projectID, email string) string {
	return projectID + ":" + email
}

func (s *MemoryStore) IsLocked(ctx context.Context, projectID, email string) (locked bool, retryAfterSeconds int) {
	if s.max <= 0 {
		return false, 0
	}
	s.mu.RLock()
	e, ok := s.data[s.key(projectID, email)]
	s.mu.RUnlock()
	if !ok || e == nil {
		return false, 0
	}
	now := time.Now()
	if now.Before(e.lockedUntil) {
		secs := int(time.Until(e.lockedUntil).Seconds())
		if secs < 1 {
			secs = 1
		}
		return true, secs
	}
	// cooldown expired; clear so next attempt can count again (optional: keep failures and only clear on success)
	return false, 0
}

func (s *MemoryStore) RecordFailure(ctx context.Context, projectID, email string) {
	if s.max <= 0 {
		return
	}
	k := s.key(projectID, email)
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.data[k]
	if e == nil {
		e = &entry{}
		s.data[k] = e
	}
	// if was locked and cooldown expired, reset failures
	now := time.Now()
	if now.After(e.lockedUntil) {
		e.failures = 0
		e.lockedUntil = time.Time{}
	}
	e.failures++
	if e.failures >= s.max {
		e.lockedUntil = now.Add(s.cooldown)
	}
}

func (s *MemoryStore) RecordSuccess(ctx context.Context, projectID, email string) {
	if s.max <= 0 {
		return
	}
	k := s.key(projectID, email)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, k)
}

var _ ports.LoginLockoutStore = (*MemoryStore)(nil)
