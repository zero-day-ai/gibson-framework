// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package utils

import (
	"testing"
)

func TestValidateGitURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		// Valid SSH URLs
		{
			name:    "valid SSH URL",
			url:     "git@github.com:user/repo.git",
			wantErr: false,
		},
		{
			name:    "valid SSH URL without .git",
			url:     "git@github.com:user/repo",
			wantErr: false,
		},
		{
			name:    "valid SSH URL with subdirectory",
			url:     "git@gitlab.com:group/subgroup/repo.git",
			wantErr: false,
		},
		{
			name:    "valid SSH scheme URL",
			url:     "ssh://git@github.com/user/repo.git",
			wantErr: false,
		},

		// Valid HTTPS URLs
		{
			name:    "valid HTTPS URL",
			url:     "https://github.com/user/repo.git",
			wantErr: false,
		},
		{
			name:    "valid HTTP URL",
			url:     "http://github.com/user/repo.git",
			wantErr: false,
		},

		// Invalid URLs
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
			errMsg:  "URL cannot be empty",
		},
		{
			name:    "SSH URL without colon",
			url:     "git@github.com",
			wantErr: true,
			errMsg:  "SSH URL must be in format git@hostname:path",
		},
		{
			name:    "SSH URL without hostname",
			url:     "git@:user/repo.git",
			wantErr: true,
			errMsg:  "SSH URL hostname cannot be empty",
		},
		{
			name:    "SSH URL without path",
			url:     "git@github.com:",
			wantErr: true,
			errMsg:  "SSH URL path cannot be empty",
		},
		{
			name:    "invalid scheme",
			url:     "ftp://github.com/user/repo.git",
			wantErr: true,
			errMsg:  "URL must start with http://, https://, git@, or ssh://",
		},
		{
			name:    "HTTPS URL without path",
			url:     "https://github.com",
			wantErr: true,
			errMsg:  "HTTP URL must have a repository path",
		},
		{
			name:    "HTTPS URL with only slash",
			url:     "https://github.com/",
			wantErr: true,
			errMsg:  "HTTP URL must have a repository path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGitURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGitURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("ValidateGitURL() error = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestIsSSHURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"SSH format", "git@github.com:user/repo.git", true},
		{"SSH scheme", "ssh://git@github.com/user/repo.git", true},
		{"HTTPS", "https://github.com/user/repo.git", false},
		{"HTTP", "http://github.com/user/repo.git", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSSHURL(tt.url); got != tt.want {
				t.Errorf("IsSSHURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsHTTPURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"HTTPS", "https://github.com/user/repo.git", true},
		{"HTTP", "http://github.com/user/repo.git", true},
		{"SSH format", "git@github.com:user/repo.git", false},
		{"SSH scheme", "ssh://git@github.com/user/repo.git", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHTTPURL(tt.url); got != tt.want {
				t.Errorf("IsHTTPURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeGitURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"remove .git", "https://github.com/user/repo.git", "https://github.com/user/repo"},
		{"remove trailing slash", "https://github.com/user/repo/", "https://github.com/user/repo"},
		{"SSH with .git", "git@github.com:user/repo.git", "git@github.com:user/repo"},
		{"already normalized", "https://github.com/user/repo", "https://github.com/user/repo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeGitURL(tt.url); got != tt.want {
				t.Errorf("NormalizeGitURL() = %v, want %v", got, tt.want)
			}
		})
	}
}