// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package elements_test

import (
	"testing"
	"time"

	"github.com/google/cel-go/common/types/ref"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"github.com/protobom/cel/pkg/runner"
)

func TestMetadataGet(t *testing.T) {
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
		{"name", "sboms[0].metadata.id", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			require.Equal(t, "https://github.com/kubernetes-sigs/bom/dependency_graph/sbom-97744edb52ba65a1#DOCUMENT", v.Value())
		}},
		{"name", "sboms[0].metadata.version", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			require.Equal(t, "1", v.Value())
		}},
		{"name", "sboms[0].metadata.name", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			require.Equal(t, "com.github.kubernetes-sigs/bom", v.Value())
		}},
		{"name", "sboms[0].metadata.date", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			tm, err := time.Parse("2006-01-02 15:04:05 -0700", "2023-08-10 01:04:39 -0000")
			require.NoError(t, err)
			require.Equal(t, tm.UTC(), v.Value())
		}},
		// TODO(puerco): More SBOMs, test all fiuelds
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

func TestGetMetadataGet(t *testing.T) {
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
		{"name", "sboms[0].get_metadata().id", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			require.Equal(t, "https://github.com/kubernetes-sigs/bom/dependency_graph/sbom-97744edb52ba65a1#DOCUMENT", v.Value())
		}},
		{"name", "sboms[0].get_metadata().version", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			require.Equal(t, "1", v.Value())
		}},
		{"name", "sboms[0].get_metadata().name", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			require.Equal(t, "com.github.kubernetes-sigs/bom", v.Value())
		}},
		{"name", "sboms[0].get_metadata().date", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			tm, err := time.Parse("2006-01-02 15:04:05 -0700", "2023-08-10 01:04:39 -0000")
			require.NoError(t, err)
			require.Equal(t, tm.UTC(), v.Value())
		}},
		{"name", "sboms[0].get_metadata().get_authors()", false, func(t *testing.T, v ref.Val) {
			t.Helper()
			require.NoError(t, err)
			docdata, ok := v.Value().([]*sbom.Person)
			require.True(t, ok)
			expect := []*sbom.Person{{
				Name: "Dependabot (bot@dependa.net)",
			}}
			require.Equal(t, expect[0].Name, docdata[0].Name)
		}},
		// TODO(puerco): More SBOMs, test all fiuelds
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
