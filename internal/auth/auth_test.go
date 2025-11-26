package auth

import (
	"testing"
	"net/http"
	"strings"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
		errorContains string
	}{
		{
			name: "valid API key",
			headers: http. Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			expectedKey:   "my-secret-api-key",
			expectedError: nil,
		},
		{
			name: "valid API key with special characters",
			headers: http. Header{
				"Authorization": []string{"ApiKey abc123-xyz_789.token"},
			},
			expectedKey:   "abc123-xyz_789.token",
			expectedError: nil,
		},
		{
			name:          "no authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-token"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "only ApiKey without token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "wrong case for ApiKey",
			headers: http.Header{
				"Authorization": []string{"apikey my-secret-key"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "API key with extra spaces",
			headers: http. Header{
				"Authorization": []string{"ApiKey  my-key-with-spaces"},
			},
			expectedKey:   "",
			expectedError: nil,
		},
		{
			name: "API key with multiple parts",
			headers: http.Header{
				"Authorization": []string{"ApiKey part1 part2 part3"},
			},
			expectedKey:   "part1",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			// Check the returned API key
			if gotKey != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.expectedKey)
			}

			// Check the error
			if tt.expectedError != nil {
				if gotErr != tt.expectedError {
					t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tt.expectedError)
				}
			} else if tt.errorContains != "" {
				if gotErr == nil {
					t. Errorf("GetAPIKey() expected error containing %q, got nil", tt. errorContains)
				} else if ! strings.Contains(gotErr.Error(), tt.errorContains) {
					t.Errorf("GetAPIKey() error = %q, should contain %q", gotErr.Error(), tt.errorContains)
				}
			} else {
				if gotErr != nil {
					t.Errorf("GetAPIKey() unexpected error = %v", gotErr)
				}
			}
		})
	}
}

func TestGetAPIKey_CaseInsensitiveHeader(t *testing.T) {
	// HTTP headers are case-insensitive, test various capitalizations
	tests := []struct {
		name        string
		headerKey   string
		headerValue string
		expectedKey string
	}{
		{
			name:        "lowercase authorization",
			headerKey:   "authorization",
			headerValue: "ApiKey test-key-1",
			expectedKey: "test-key-1",
		},
		{
			name:        "uppercase AUTHORIZATION",
			headerKey:   "AUTHORIZATION",
			headerValue: "ApiKey test-key-2",
			expectedKey: "test-key-2",
		},
		{
			name:        "mixed case AuThOrIzAtIoN",
			headerKey:   "AuThOrIzAtIoN",
			headerValue: "ApiKey test-key-3",
			expectedKey: "test-key-3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set(tt.headerKey, tt.headerValue)

			gotKey, gotErr := GetAPIKey(headers)

			if gotErr != nil {
				t. Errorf("GetAPIKey() unexpected error = %v", gotErr)
			}

			if gotKey != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.expectedKey)
			}
		})
	}
}
