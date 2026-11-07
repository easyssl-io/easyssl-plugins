package ops

import (
	"testing"

	"github.com/easyssl-io/easyssl-contract/contracttest"
)

// The describe answer is what every Target of this Plugin is stored against:
// a setting key renamed or removed here strands the values saved under it, so
// a change shows as a diff of testdata/describe.json.
func TestDescribeFile(t *testing.T) {
	contracttest.Golden(t, "testdata/describe.json", Describe())
}
