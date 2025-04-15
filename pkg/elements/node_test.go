// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package elements_test

import (
	"testing"

	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/require"

	"github.com/protobom/cel/pkg/runner"
)

func TestNodeGet(t *testing.T) {
	r, err := runner.NewRunner()
	require.NoError(t, err)
	vars, err := runner.BuildVariables(
		runner.WithPaths([]string{"testdata/github.spdx.json"}),
	)
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		code    string
		mustErr bool
		eval    func(*testing.T, ref.Val)
	}{
		{"name", "sboms[0].node_list.get_root_nodes()[0].name", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			require.Equal(t, "com.github.kubernetes-sigs/bom", v.Value())
		}},
		{"name", "sboms[0].node_list.get_root_nodes()[0].version", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			require.Equal(t, "2cc9dcc83b2867047edff143905829ff9e3b98ff", v.Value())
		}},
		{"name", "sboms[0].node_list.get_root_nodes()[0].url_download", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			require.Equal(t, "git+https://github.com/kubernetes-sigs/bom@2cc9dcc83b2867047edff143905829ff9e3b98ff", v.Value())
		}},
		{"name", "sboms[0].node_list.get_root_nodes()[0].licenses", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			require.Equal(t, []string{"Apache-2.0"}, v.Value())
		}},
		// TODO(puerco): More SBOMs, testa ll fiuelds
	} {
		t.Run(tc.name, func(t *testing.T) {
			ret, err := r.Evaluate(tc.code, vars)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			t.Log(ret)
			tc.eval(t, ret)
		})
	}
}
