// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package teams_test

import (
	"os"
	"testing"

	"github.com/hanzoai/iam/internal/oidc"
)

// TestMain installs the issuer as a server's boot does (server.RequireIssuer):
// every bearer these tests sign says iss=https://hanzo.id, and a process with no
// issuer installed accepts none.
func TestMain(m *testing.M) {
	os.Setenv("IAM_ISSUER", "https://hanzo.id")
	os.Unsetenv("IAM_ISSUER_MAP")
	os.Unsetenv("IAM_DEV_HOST_RELATIVE")
	if err := oidc.InitIssuerResolver(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
