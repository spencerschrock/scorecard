// Copyright 2023 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package githubrepo

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/shurcooL/githubv4"

	"github.com/ossf/scorecard/v5/clients"
	sce "github.com/ossf/scorecard/v5/errors"
)

func Test_init_clearsErr(t *testing.T) {
	t.Parallel()
	handler := &checkrunsHandler{errSetup: sce.ErrScorecardInternal}
	handler.init(t.Context(), nil, 0)
	if handler.errSetup != nil {
		t.Errorf("expected nil error, got %v", handler.errSetup)
	}
}

func Test_listCheckRunsForRef_closedPRCacheHit(t *testing.T) {
	t.Parallel()
	const setupJSON = `{
		"data": {"repository": {"object": {"history": {"nodes": [{
			"associatedPullRequests": {"nodes": [{"headRefOid": "associated-sha", "commits": {"nodes": []}}]}
		}]}}}}
	}`
	const closedPRsJSON = `{
		"data": {"repository": {"pullRequests": {"nodes": [{
			"headRefOid": "closed-sha",
			"commits": {"nodes": [{"commit": {"checkSuites": {"nodes": [
				{"app": {"slug": "github-actions"}, "conclusion": "SUCCESS", "status": "COMPLETED"}
			]}}}]}
		}]}}}
	}`
	rt := &seqJSONRoundTripper{bodies: []string{setupJSON, closedPRsJSON}}
	handler := &checkrunsHandler{graphClient: githubv4.NewClient(&http.Client{Transport: rt})}
	handler.init(t.Context(), &Repo{owner: "foo", repo: "bar", commitSHA: "HEAD"}, 1)

	if _, err := handler.listCheckRunsForRef("associated-sha"); err != nil || rt.calls != 1 {
		t.Fatalf("associated hit: err=%v, calls=%d (want 1)", err, rt.calls)
	}
	for range 2 {
		crs, err := handler.listCheckRunsForRef("closed-sha")
		if err != nil || rt.calls != 2 {
			t.Fatalf("closed hit: err=%v, calls=%d (want 2)", err, rt.calls)
		}
		want := []clients.CheckRun{{Status: "completed", Conclusion: "success", App: clients.CheckRunApp{Slug: "github-actions"}}}
		if diff := cmp.Diff(want, crs); diff != "" {
			t.Errorf("check runs mismatch (-want +got):\n%s", diff)
		}
	}
}
