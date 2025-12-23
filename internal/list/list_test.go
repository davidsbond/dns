package list_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/davidsbond/tsdns/internal/list"
)

func TestBlock(t *testing.T) {
	t.Parallel()

	blockList, err := list.Block(t.Context())
	require.NoError(t, err)
	require.NotNil(t, blockList)
	require.True(t, blockList.Contains("0.club"))
}

func TestAllow(t *testing.T) {
	t.Parallel()

	allowList, err := list.Allow(t.Context())
	require.NoError(t, err)
	require.NotNil(t, allowList)
	require.True(t, allowList.Contains("tags.tiqcdn.com"))
}
