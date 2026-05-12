package collectors_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/secra/netbrain-beacon/internal/collectors"
	"github.com/secra/netbrain-beacon/internal/collectors/configs"
	"github.com/secra/netbrain-beacon/internal/collectors/netflow"
	"github.com/secra/netbrain-beacon/internal/collectors/snmp"
)

func TestRegistryAddGet(t *testing.T) {
	r := collectors.NewRegistry()
	r.Add("netflow", &netflow.Stub{})
	c, ok := r.Get("netflow")
	require.True(t, ok)
	require.NotNil(t, c)
	require.False(t, c.Running())
}

func TestRegistryEnableDisable(t *testing.T) {
	r := collectors.NewRegistry()
	r.Add("snmp", &snmp.Stub{})

	require.NoError(t, r.Enable(context.Background(), "snmp"))
	c, _ := r.Get("snmp")
	require.True(t, c.Running())

	// Idempotent Enable.
	require.NoError(t, r.Enable(context.Background(), "snmp"))

	require.NoError(t, r.Disable("snmp"))
	require.False(t, c.Running())

	// Idempotent Disable.
	require.NoError(t, r.Disable("snmp"))
}

func TestRegistryUnknownName(t *testing.T) {
	r := collectors.NewRegistry()
	err := r.Enable(context.Background(), "missing")
	require.True(t, errors.Is(err, collectors.ErrUnknownCollector))
	err = r.Disable("missing")
	require.True(t, errors.Is(err, collectors.ErrUnknownCollector))
}

func TestRegistryCloseAll(t *testing.T) {
	r := collectors.NewRegistry()
	r.Add("snmp", &snmp.Stub{})
	r.Add("netflow", &netflow.Stub{})
	r.Add("configs", &configs.Stub{})

	require.NoError(t, r.Enable(context.Background(), "snmp"))
	require.NoError(t, r.Enable(context.Background(), "netflow"))

	require.NoError(t, r.CloseAll())

	for _, s := range r.States() {
		require.False(t, s.Running, "all stubs must be stopped after CloseAll: %s", s.Name)
	}
}

func TestRegistryNames(t *testing.T) {
	r := collectors.NewRegistry()
	r.Add("snmp", &snmp.Stub{})
	r.Add("netflow", &netflow.Stub{})
	r.Add("configs", &configs.Stub{})
	names := r.Names()
	require.Len(t, names, 3)
}

// --- DEK holder ---

func TestDEKHolderCurrentInitially(t *testing.T) {
	h := collectors.NewDEKHolder(&collectors.DEK{Key: []byte("k"), Version: 7})
	cur := h.Current()
	require.Equal(t, byte(7), cur.Version)
}

func TestDEKHolderEmpty(t *testing.T) {
	h := collectors.NewDEKHolder(nil)
	require.Nil(t, h.Current())
}
