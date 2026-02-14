package handlers

import (
	"encoding/json"
	"net/http"
)

// writeErr sends JSON { "error": message, "code": errCode }. If errCode is empty, a default is used from code.
func writeErr(w http.ResponseWriter, code int, errCode string, message string) {
	if errCode == "" {
		errCode = defaultErrCode(code)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message, "code": errCode})
}

func defaultErrCode(httpCode int) string {
	switch httpCode {
	case http.StatusBadRequest:
		return ErrCodeInvalidRequest
	case http.StatusUnauthorized:
		return ErrCodeUnauthorized
	case http.StatusForbidden:
		return ErrCodeForbidden
	case http.StatusNotFound:
		return ErrCodeNotFound
	case http.StatusConflict:
		return ErrCodeConflict
	case http.StatusTooManyRequests:
		return ErrCodeAccountLocked
	case http.StatusInternalServerError:
		return ErrCodeInternal
	case http.StatusNotImplemented:
		return ErrCodeNotImplemented
	default:
		return ErrCodeInternal
	}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
