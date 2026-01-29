package auth

import (
	"testing"
)

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain text",
			input: "Hello World",
			want:  "Hello World",
		},
		{
			name:  "html escape",
			input: "<script>alert('xss')</script>",
			want:  "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
		},
		{
			name:  "special characters",
			input: "Test & Co.",
			want:  "Test &amp; Co.",
		},
		{
			name:  "quotes",
			input: `Hello "World"`,
			want:  "Hello &#34;World&#34;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeInput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeInput() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain name",
			input: "John Doe",
			want:  "John Doe",
		},
		{
			name:  "trim spaces",
			input: "  John Doe  ",
			want:  "John Doe",
		},
		{
			name:  "html escape",
			input: "John <script>",
			want:  "John &lt;script&gt;",
		},
		{
			name:  "unicode name",
			input: "José García",
			want:  "José García",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeName(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateStringLength(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		value   string
		min     int
		max     int
		wantErr bool
	}{
		{
			name:    "valid - within range",
			field:   "username",
			value:   "john",
			min:     3,
			max:     10,
			wantErr: false,
		},
		{
			name:    "too short",
			field:   "username",
			value:   "ab",
			min:     3,
			max:     10,
			wantErr: true,
		},
		{
			name:    "too long",
			field:   "username",
			value:   "verylongusername",
			min:     3,
			max:     10,
			wantErr: true,
		},
		{
			name:    "no min requirement",
			field:   "username",
			value:   "",
			min:     0,
			max:     10,
			wantErr: false,
		},
		{
			name:    "no max requirement",
			field:   "username",
			value:   "verylongusername",
			min:     3,
			max:     0,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStringLength(tt.field, tt.value, tt.min, tt.max)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateStringLength() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
