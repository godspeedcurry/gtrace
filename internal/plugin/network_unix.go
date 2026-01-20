//go:build !windows

package plugin

import (
	"context"

	"gtrace/pkg/model"
)

// CollectNetwork is a stub for non-Windows systems.
func CollectNetwork(ctx context.Context, callback func(model.TimelineEvent)) error {
	return nil
}
