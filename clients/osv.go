// Copyright 2021 OpenSSF Scorecard Authors
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

package clients

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osvscanner"

	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/finding"
)

var _ VulnerabilitiesClient = osvClient{}

type osvClient struct{}

// ListUnfixedVulnerabilities implements VulnerabilityClient.ListUnfixedVulnerabilities.
func (v osvClient) ListUnfixedVulnerabilities(
	ctx context.Context,
	commit,
	localPath string,
) (_ VulnerabilitiesResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = sce.CreateInternal(sce.ErrScorecardInternal, fmt.Sprintf("osv-scanner panic: %v", r))
		}
	}()
	directoryPaths := []string{}
	if localPath != "" {
		directoryPaths = append(directoryPaths, localPath)
	}
	gitCommits := []string{}
	if commit != "" {
		gitCommits = append(gitCommits, commit)
	}
	res, err := osvscanner.DoScan(osvscanner.ScannerActions{
		DirectoryPaths: directoryPaths,
		SkipGit:        true,
		Recursive:      true,
		GitCommits:     gitCommits,
	}, nil) // TODO: Do logging?

	response := VulnerabilitiesResponse{}

	if err == nil { // No vulns found
		return response, nil
	}

	// If vulnerabilities are found, err will be set to osvscanner.VulnerabilitiesFoundErr
	if errors.Is(err, osvscanner.VulnerabilitiesFoundErr) {
		vulns := res.Flatten()
		for i := range vulns {
			response.Vulnerabilities = append(response.Vulnerabilities, Vulnerability{
				ID:       vulns[i].Vulnerability.ID,
				Aliases:  vulns[i].Vulnerability.Aliases,
				Location: location(&vulns[i]),
			})
		}

		return response, nil
	}

	return VulnerabilitiesResponse{}, fmt.Errorf("osvscanner.DoScan: %w", err)
}

func location(vuln *models.VulnerabilityFlattened) *finding.Location {
	if vuln == nil {
		return nil
	}
	return &finding.Location{
		Type:    finding.FileTypeSource,
		Snippet: &vuln.Package.Name,
		Path:    vuln.Source.Path,
	}
}
