//go:build !windows

package plugin

import (
	"context"

	"gtrace/pkg/model"
)

func CollectWMIPersistence(ctx context.Context, callback func(model.TimelineEvent)) error {
	return nil
}
