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
	"strings"

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

	vulnLocations := map[string][]finding.Location{}
	// If vulnerabilities are found, err will be set to osvscanner.VulnerabilitiesFoundErr
	if errors.Is(err, osvscanner.VulnerabilitiesFoundErr) {
		vulns := res.Flatten()
		for _, vuln := range vulns {
			vuln := vuln
			loc := location(&vuln, localPath)
			if !update(vulnLocations, vuln.Vulnerability.ID, *loc) {
				var found bool
				for _, alias := range vuln.Vulnerability.Aliases {
					if update(vulnLocations, alias, *loc) {
						found = true
						break
					}
				}
				if !found {
					vulnLocations[vuln.Vulnerability.ID] = []finding.Location{*loc}
				}
			}
		}
		for vuln, locations := range vulnLocations {
			response.Vulnerabilities = append(response.Vulnerabilities, Vulnerability{
				ID: vuln,
				// Aliases:   vulns[i].Vulnerability.Aliases,
				Locations: locations,
			})
		}
		return response, nil
	}

	return VulnerabilitiesResponse{}, fmt.Errorf("osvscanner.DoScan: %w", err)
}

func update(m map[string][]finding.Location, key string, value finding.Location) bool {
	if slice, ok := m[key]; ok {
		m[key] = append(slice, value)
		return true
	}
	return false
}

func location(vuln *models.VulnerabilityFlattened, pathPrefix string) *finding.Location {
	if vuln == nil {
		return nil
	}
	return &finding.Location{
		Type:    finding.FileTypeSource,
		Snippet: &vuln.Package.Name,
		Path:    strings.TrimPrefix(vuln.Source.Path, pathPrefix),
	}
}
