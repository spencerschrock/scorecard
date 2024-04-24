// Copyright 2024 OpenSSF Scorecard Authors
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

package foo

import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/internal/probes"
	"github.com/ossf/scorecard/v5/probes/internal/utils/uerror"
)

func init() {
	probes.MustRegisterIndependent(Probe, Run)
}

//go:embed *.yml
var fs embed.FS

const Probe = "foo"

func Run(cr *checker.CheckRequest) ([]finding.Finding, string, error) {
	if cr == nil {
		return nil, "", fmt.Errorf("%w: check request", uerror.ErrNil)
	}

	name, err := cr.RepoClient.GetDefaultBranchName()
	if err != nil {
		return nil, Probe, fmt.Errorf("fetching default branch name: %w", err)
	}
	f, err := finding.New(fs, Probe)
	if err != nil {
		return nil, Probe, fmt.Errorf("create finding: %w", err)
	}
	if name == "foo" {
		f.WithMessage("foo!").WithOutcome(finding.OutcomeTrue)
	} else {
		f.WithMessage("not foo!!").WithOutcome(finding.OutcomeFalse)
	}
	return []finding.Finding{*f}, Probe, nil
}
