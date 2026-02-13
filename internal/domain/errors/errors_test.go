package errors

import "testing"

func TestSentinelErrors(t *testing.T) {
	if ErrUserExists == nil {
		t.Error("ErrUserExists should not be nil")
	}
	if ErrInvalidCredentials == nil {
		t.Error("ErrInvalidCredentials should not be nil")
	}
	if ErrTenantNotFound == nil {
		t.Error("ErrTenantNotFound should not be nil")
	}
}
