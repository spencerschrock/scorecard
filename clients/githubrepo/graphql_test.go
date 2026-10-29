// Copyright 2023 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package githubrepo

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/shurcooL/githubv4"

	"github.com/ossf/scorecard/v5/clients"
)

type badGatewayRoundTripper struct {
	requestCounter *int
}

func (b badGatewayRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	*b.requestCounter += 1
	return &http.Response{
		StatusCode: http.StatusBadGateway,
		Status:     "502 Bad Gateway",
	}, nil
}

func Test_getCommits_retry(t *testing.T) {
	t.Parallel()
	var nRequests int
	rt := badGatewayRoundTripper{requestCounter: &nRequests}
	handler := graphqlHandler{
		client: githubv4.NewClient(&http.Client{
			Transport: rt,
		}),
	}
	handler.init(t.Context(), &Repo{}, 1)
	_, err := handler.getCommits()
	if err == nil {
		t.Error("expected error")
	}
	want := retryLimit + 1 // 1 represents the initial request
	if *rt.requestCounter != want {
		t.Errorf("wanted %d retries, got %d", want, *rt.requestCounter)
	}
}

type seqJSONRoundTripper struct {
	bodies []string
	calls  int
}

func (s *seqJSONRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	if s.calls >= len(s.bodies) {
		return nil, errors.New("unexpected GraphQL query")
	}
	body := s.bodies[s.calls]
	s.calls++
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func Test_getCommits_closedPRs(t *testing.T) {
	t.Parallel()
	commitJSON := func(msg string) string {
		return `{
			"data": {"repository": {"object": {"history": {"nodes": [{
				"committedDate": "2026-10-27T12:00:00Z",
				"message": ` + msg + `,
				"oid": "sha1",
				"associatedPullRequests": {"nodes": []}
			}]}}}}
		}`
	}
	const closedPRsJSON = `{
		"data": {"repository": {"pullRequests": {"nodes": [
			{
				"number": 41,
				"timelineItems": {"nodes": [{"closer": null}]}
			},
			{
				"author": {"login": "alice", "resourcePath": "/alice"},
				"number": 42,
				"headRefOid": "head1",
				"closedAt": "2026-10-27T12:37:18Z",
				"reviews": {"nodes": [{"state": "APPROVED", "author": {"login": "bob"}}]},
				"timelineItems": {"nodes": [{"actor": {"login": "bob"}, "closer": {"oid": "sha1"}}]}
			}
		]}}}
	}`
	tests := []struct {
		name      string
		bodies    []string
		wantPR    clients.PullRequest
		wantCalls int
	}{
		{
			name:      "links PR closed by commit",
			bodies:    []string{commitJSON(`"change\n\nCloses #42"`), closedPRsJSON},
			wantCalls: 2,
			wantPR: clients.PullRequest{
				Number:   42,
				HeadSHA:  "head1",
				MergedAt: time.Date(2026, 10, 27, 12, 37, 18, 0, time.UTC),
				Author:   clients.User{Login: "alice"},
				MergedBy: clients.User{Login: "bob"},
				Reviews:  []clients.Review{{State: "APPROVED", Author: &clients.User{Login: "bob"}}},
			},
		},
		{
			name:      "skips closed PR query without closing ref",
			bodies:    []string{commitJSON(`"fix: bump version"`)},
			wantCalls: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rt := &seqJSONRoundTripper{bodies: tt.bodies}
			handler := graphqlHandler{client: githubv4.NewClient(&http.Client{Transport: rt})}
			handler.init(t.Context(), &Repo{owner: "foo", repo: "bar", commitSHA: "HEAD"}, 1)
			commits, err := handler.getCommits()
			if err != nil {
				t.Fatalf("getCommits() unexpected error: %v", err)
			}
			if rt.calls != tt.wantCalls {
				t.Errorf("queries = %d, want %d", rt.calls, tt.wantCalls)
			}
			if diff := cmp.Diff(tt.wantPR, commits[0].AssociatedMergeRequest); diff != "" {
				t.Errorf("AssociatedMergeRequest mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_hasClosingKeyword(t *testing.T) {
	t.Parallel()
	for msg, want := range map[string]bool{
		"Closes #42":             true,
		"closes: #42":            true,
		"Fixes GH-42":            true,
		"Resolves foo/bar.js#26": true,
		"Fixed https://github.com/foo/bar/pull/42": true,
		"fix: bump version to 1.2.3":               false,
		"Fixed the bug in #12":                     false,
		"prefixes #12":                             false,
	} {
		if got := hasClosingKeyword(msg); got != want {
			t.Errorf("hasClosingKeyword(%q) = %v, want %v", msg, got, want)
		}
	}
}
