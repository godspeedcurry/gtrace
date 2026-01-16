package rules

import (
	"embed"
)

//go:embed all:sigma_rules_repo/rules/windows/*
var WindowsRules embed.FS
