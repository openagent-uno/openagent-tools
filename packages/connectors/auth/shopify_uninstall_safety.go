package auth

// These reasons describe uncertainty, never a provider installation generation.
// They are durable internal metadata and are not added to the public receipt.
const (
	uninstallHistoryUnknown     = "uninstall_authorization_history_unknown"
	uninstallAcquisitionPending = "uninstall_authorization_acquisition_uncertain"
	uninstallAfterAcquisition   = "uninstall_precedes_authorization_acquisition"
	uninstallPairPending        = "uninstall_counterpart_unverified"
)

func assessUninstallAtReceipt(group *Group, event *Event) {
	if event.Topic != "app/uninstalled" {
		return
	}
	event.UninstallSafetyChecked = true
	switch {
	case group == nil:
		event.PendingReason = uninstallHistoryUnknown
	case group.AuthorizationAcquisitionUncertain:
		event.PendingReason = uninstallAcquisitionPending
	case group.LastAuthorizationAcquiredAt.IsZero():
		event.PendingReason = uninstallHistoryUnknown
	case event.OccurredAt.Before(group.LastAuthorizationAcquiredAt):
		event.PendingReason = uninstallAfterAcquisition
	}
}

func quarantineHistoricalUninstalls(state *State) {
	for _, event := range state.Events {
		if event.Topic == "app/uninstalled" && !event.UninstallSafetyChecked {
			// Current group metadata cannot prove what was known at old intake.
			// Never backfill a safe decision, even after a later authorization.
			event.UninstallSafetyChecked = true
			event.PendingReason = uninstallHistoryUnknown
		}
	}
}

func cutoffDeliveryReady(state *State, event *Event) bool {
	if event == nil || event.PendingReason != "" {
		return false
	}
	switch event.Topic {
	case "app/uninstalled":
		return event.UninstallSafetyChecked && eligibleUninstall(event)
	case "shop/redact":
		return validNativeReceipt(state, event)
	default:
		return true
	}
}
