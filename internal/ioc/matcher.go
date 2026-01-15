package ioc

import (
	"strings"

	"gtrace/pkg/model"
)

// MatchTimeline tags events with IOC hits (path/domain/hash simple matching).
func MatchTimeline(events []model.TimelineEvent, iocs []model.IOCMaterial) []model.TimelineEvent {
	for i := range events {
		for _, ioc := range iocs {
			switch strings.ToLower(ioc.Type) {
			case "path":
				if strings.Contains(strings.ToLower(events[i].Details["path"]), strings.ToLower(ioc.Value)) {
					events[i].IOCHits = append(events[i].IOCHits, ioc.Value)
				}
			case "hash", "sha256", "md5", "sha1":
				if events[i].Details["hash"] == ioc.Value {
					events[i].IOCHits = append(events[i].IOCHits, ioc.Value)
				}
			case "domain":
				if strings.Contains(strings.ToLower(events[i].Details["domain"]), strings.ToLower(ioc.Value)) {
					events[i].IOCHits = append(events[i].IOCHits, ioc.Value)
				}
			case "ip":
				if strings.Contains(events[i].Details["ip"], ioc.Value) {
					events[i].IOCHits = append(events[i].IOCHits, ioc.Value)
				}
			}
		}
	}
	return events
}
