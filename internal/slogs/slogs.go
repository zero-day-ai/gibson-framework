// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package slogs

// Structured logging keys following k9s patterns
const (
	// Core entity keys
	Key         = "key"
	ID          = "id"
	Name        = "name"
	Namespace   = "namespace"
	Path        = "path"

	// Resource keys
	ResKind        = "resource_kind"
	ResGrpVersion  = "resource_group_version"
	GVR            = "gvr"

	// Scanner-specific keys
	ScanID      = "scan_id"
	TargetID    = "target_id"
	FindingID   = "finding_id"
	PluginID    = "plugin_id"

	// Status and operation keys
	Status      = "status"
	Error       = "error"
	Count       = "count"
	Progress    = "progress"
	Duration    = "duration"

	// Plugin system keys
	PluginName  = "plugin_name"
	PluginType  = "plugin_type"

	// Factory and lifecycle keys
	Factory     = "factory"
	Component   = "component"
	Lifecycle   = "lifecycle"
)