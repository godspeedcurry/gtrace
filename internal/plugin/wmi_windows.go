//go:build windows

package plugin

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"gtrace/pkg/model"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// CollectWMIPersistence gathers WMI EventFilters, EventConsumers, and FilterToConsumerBindings
// to detect potential persistence mechanisms (e.g., fileless malware).
// This version uses native COM (go-ole) to avoid spawning powershell.exe processes.
func CollectWMIPersistence(ctx context.Context, callback func(model.TimelineEvent)) error {
	// WMI COM operations must be bound to a single OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Initialize COM
	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return fmt.Errorf("failed to create WbemScripting.SWbemLocator: %w", err)
	}
	defer unknown.Release()

	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("failed to get IDispatch: %w", err)
	}
	defer wmi.Release()

	// Connect to root\subscription
	serviceRaw, err := oleutil.CallMethod(wmi, "ConnectServer", nil, "root\\subscription")
	if err != nil {
		return fmt.Errorf("failed to connect to root\\subscription: %w", err)
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	// 1. Event Filters
	queryWMI(service, "SELECT * FROM __EventFilter", "WMI EventFilter", callback)

	// 2. Consumers
	queryWMI(service, "SELECT * FROM CommandLineEventConsumer", "WMI Consumer (CMD)", callback)
	queryWMI(service, "SELECT * FROM ActiveScriptEventConsumer", "WMI Consumer (Script)", callback)

	// 3. Bindings
	queryWMI(service, "SELECT * FROM __FilterToConsumerBinding", "WMI Binding", callback)

	return nil
}

func queryWMI(service *ole.IDispatch, query, artifactName string, callback func(model.TimelineEvent)) {
	resultRaw, err := oleutil.CallMethod(service, "ExecQuery", query)
	if err != nil {
		return
	}
	result := resultRaw.ToIDispatch()
	defer result.Release()

	countVar, err := oleutil.GetProperty(result, "Count")
	if err != nil {
		return
	}
	if countVar.Val == 0 {
		return
	}

	enumRaw, err := oleutil.GetProperty(result, "_NewEnum")
	if err != nil {
		return
	}
	defer enumRaw.Clear()

	enum, err := enumRaw.ToIUnknown().QueryInterface(ole.IID_IEnumVariant)
	if err != nil {
		return
	}
	qenum := (*ole.IEnumVARIANT)(enum)
	defer qenum.Release()

	now := time.Now()

	for {
		variant, fetched, err := qenum.Next(1)
		if err != nil || fetched == 0 {
			break
		}
		item := variant.ToIDispatch()

		processItem(item, artifactName, callback, now)

		item.Release()
	}
}

func processItem(item *ole.IDispatch, artifactName string, callback func(model.TimelineEvent), now time.Time) {
	// Helper to get string property
	getStr := func(name string) string {
		v, err := oleutil.GetProperty(item, name)
		if err == nil && v.VT != ole.VT_NULL && v.VT != ole.VT_EMPTY {
			return fmt.Sprintf("%v", v.Value())
		}
		return ""
	}

	details := make(map[string]string)

	if artifactName == "WMI EventFilter" {
		details["Name"] = getStr("Name")
		details["Query"] = getStr("Query")
	} else if artifactName == "WMI Consumer (CMD)" {
		details["Name"] = getStr("Name")
		details["CommandLine"] = getStr("CommandLineTemplate")
		details["Executable"] = getStr("ExecutablePath")
	} else if artifactName == "WMI Consumer (Script)" {
		details["Name"] = getStr("Name")
		details["ScriptText"] = getStr("ScriptText")
	} else if artifactName == "WMI Binding" {
		details["Filter"] = getStr("Filter")
		details["Consumer"] = getStr("Consumer")
	} else {
		details["Info"] = "Unknown WMI Artifact"
	}
	details["EventID"] = "WMI"

	// Determine Subject
	subject := details["Name"]
	if artifactName == "WMI Binding" {
		subject = details["Filter"]
	}

	callback(model.TimelineEvent{
		EventTime: now,
		Source:    "WMI",
		Artifact:  artifactName,
		Action:    "Persistence",
		Subject:   subject,
		Details:   details,
		EvidenceRef: model.EvidenceRef{
			SourcePath: "WMI Namespace: root\\subscription",
		},
	})
}
