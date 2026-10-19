package auth

import (
	"encoding/hex"
	"sort"
	"time"
)

// Shopify emits shop/redact 48 hours after uninstall. A small provider-clock
// tolerance does not change the notification's original OccurredAt.
const shopRedactMinimumDelay = 48*time.Hour - 5*time.Minute

func sortedEventIDs(state *State) []string {
	ids := make([]string, 0, len(state.Events))
	for id := range state.Events {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := state.Events[ids[i]], state.Events[ids[j]]
		if !a.OccurredAt.Equal(b.OccurredAt) {
			return a.OccurredAt.Before(b.OccurredAt)
		}
		return ids[i] < ids[j]
	})
	return ids
}

func nativeEventID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && len(value) == 64
}

func eligibleUninstall(event *Event) bool {
	// Historical v1 metadata cannot establish a new authenticated pairing. In
	// particular, old ACKed synthetic receipts are never silently upgraded.
	return event != nil && event.ReceiptVersion == 2 && event.Topic == "app/uninstalled" &&
		event.AuthorizationCutoffAt != nil && event.AuthorizationCutoffAt.Equal(event.OccurredAt) &&
		event.OccurredAt.Unix() > 0 && event.ShopID > 0 && event.UninstallEventID == "" && nativeEventID(event.ID)
}

func validNativeReceipt(state *State, event *Event) bool {
	if event == nil || event.ShopID == 0 || event.ReceiptVersion != 2 || !nativeEventID(event.ID) || !nativeEventID(event.Group) || event.OccurredAt.Unix() <= 0 || event.CreatedAt.Unix() <= 0 || event.AuthorizationCutoffAt == nil || event.AuthorizationCutoffAt.Unix() <= 0 {
		return false
	}
	if group := state.Groups[event.Group]; group != nil && group.ShopID != event.ShopID {
		return false
	}
	if event.Topic != "shop/redact" {
		return (event.Topic == "app/uninstalled" || event.Topic == "customers/data_request" || event.Topic == "customers/redact") && event.UninstallEventID == "" && event.AuthorizationCutoffAt.Equal(event.OccurredAt)
	}
	uninstall := state.Events[event.UninstallEventID]
	return eligibleUninstall(uninstall) && uninstall.Group == event.Group && uninstall.ShopID == event.ShopID &&
		event.AuthorizationCutoffAt.Equal(uninstall.OccurredAt) &&
		!uninstall.OccurredAt.After(event.OccurredAt.Add(-shopRedactMinimumDelay))
}

// Unemitted notifications may be reconciled when an out-of-order uninstall
// arrives. Once first emitted, the pair is immutable across retries/restarts.
// Missing or ambiguous counterparts remain durable and unacknowledgeable.
// Shopify supplies no uninstall correlation ID, so event ordering is not proof.
func reconcileShopRedacts(state *State) {
	ids := sortedEventIDs(state)
	used := map[string]bool{}
	for _, id := range ids {
		event := state.Events[id]
		if event.Topic == "shop/redact" && event.NativeEmitted && event.UninstallEventID != "" {
			used[event.UninstallEventID] = true
		}
	}
	for _, id := range ids {
		event := state.Events[id]
		if event.Topic != "shop/redact" || event.ReceiptVersion != 2 || event.NativeEmitted {
			continue
		}
		event.UninstallEventID = ""
		event.AuthorizationCutoffAt = nil
		candidate := ""
		ambiguous := false
		for _, candidateID := range ids {
			uninstall := state.Events[candidateID]
			if used[candidateID] || !eligibleUninstall(uninstall) || uninstall.Group != event.Group || uninstall.ShopID != event.ShopID || uninstall.OccurredAt.After(event.OccurredAt.Add(-shopRedactMinimumDelay)) {
				continue
			}
			if candidate != "" {
				ambiguous = true
				break
			}
			candidate = candidateID
		}
		if candidate != "" && !ambiguous {
			cutoff := state.Events[candidate].OccurredAt
			event.UninstallEventID = candidate
			event.AuthorizationCutoffAt = &cutoff
			used[candidate] = true
		}
	}
}
