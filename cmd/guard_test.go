package cmd

import "testing"

func TestRunGuardInvalidDuration(t *testing.T) {
	old := guardDuration
	defer func() { guardDuration = old }()

	guardDuration = "abc"
	err := runGuard(nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid duration, got nil")
	}
}

func TestRunGuardInvalidWindow(t *testing.T) {
	old := guardWindow
	defer func() { guardWindow = old }()

	guardWindow = "xyz"
	err := runGuard(nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid window, got nil")
	}
}
