package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers       http.Header
		wantAPIKey    string
		wantErrResult error
	}{
		"no auth header": {
			headers:       http.Header{},
			wantAPIKey:    "",
			wantErrResult: ErrNoAuthHeaderIncluded,
		},
		"valid auth header": {
			headers: http.Header{
				"Authorization": []string{"ApiKey 12345xyz"},
			},
			wantAPIKey:    "12345xyz",
			wantErrResult: nil,
		},
		"malformed auth header - missing key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantAPIKey:    "",
			wantErrResult: errors.New("malformed authorization header"),
		},
		"malformed auth header - wrong prefix": {
			headers: http.Header{
				"Authorization": []string{"Bearer 12345xyz"},
			},
			wantAPIKey:    "",
			wantErrResult: errors.New("malformed authorization header"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotAPIKey, err := GetAPIKey(tc.headers)

			// Check for error expectations
			if tc.wantErrResult != nil {
				if err == nil {
					t.Fatalf("expected error: %v, got nil", tc.wantErrResult)
				}
				// if err. some error string check can be done since errors.New creates a unique reference
				if err.Error() != tc.wantErrResult.Error() {
					t.Fatalf("expected error message: %v, got: %v", tc.wantErrResult.Error(), err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			// Check for return value
			if gotAPIKey != tc.wantAPIKey {
				t.Errorf("expected API key: %s, got: %s", tc.wantAPIKey, gotAPIKey)
			}
		})
	}
}
