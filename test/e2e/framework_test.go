// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2e

import (
	"gotest.tools/assert"
	"testing"
)

func TestReplaceFieldValue(t *testing.T) {
	content := `
#field0:
# field1: 123
`
	fields := []string{"field0", "field1"}
	values := []string{"456", "789"}
	expected := `
field0: 456
field1: 789
`
	content = replaceFieldValue(content, fields[0], values[0])
	content = replaceFieldValue(content, fields[1], values[1])
	assert.Equal(t, expected, content)
}
