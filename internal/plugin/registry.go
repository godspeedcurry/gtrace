package plugin

import (
	"gtrace/pkg/analyzers"
	"gtrace/pkg/parsers"
	"gtrace/pkg/pluginsdk"
)

// Registry keeps track of available parsers and analyzers (built-in + external in future).
type Registry struct {
	parsers   []pluginsdk.ParserPlugin
	analyzers []pluginsdk.AnalyzerPlugin
}

// NewDefaultRegistry returns built-in stub parsers/analyzers.
func NewDefaultRegistry() *Registry {
	return &Registry{
		parsers: []pluginsdk.ParserPlugin{
			&parsers.LNKStubParser{},
			&WintriProcessParser{},
			&PrefetchParser{},
			&ShimCacheParser{},
			&AmcacheParser{},
			&UserAssistParser{},
			&JumplistParser{},
			&TaskXMLParser{},
			&TaskXMLParser{},
			&EvtxParser{},
			&SAMParser{},
		},
		analyzers: []pluginsdk.AnalyzerPlugin{
			&analyzers.TempExecutionAnalyzer{},
			&analyzers.ExecutionAnomalyAnalyzer{},
		},
	}
}

func (r *Registry) Parsers() []pluginsdk.ParserPlugin     { return r.parsers }
func (r *Registry) Analyzers() []pluginsdk.AnalyzerPlugin { return r.analyzers }
