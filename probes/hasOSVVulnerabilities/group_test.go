// Copyright 2025 OpenSSF Scorecard Authors
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

//nolint:stylecheck
package hasOSVVulnerabilities

import (
	"testing"

	"github.com/ossf/scorecard/v5/clients"
)

func TestGroup(t *testing.T) {
	vulns := []clients.Vulnerability{
		{
			ID: "foo",
		}, {
			ID: "bar", Aliases: []string{"foo"},
		},
	}
	grouped := group(vulns)
	if len(grouped) != 1 {
		t.Error(grouped)
	}
}
