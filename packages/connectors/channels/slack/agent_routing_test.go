//go:build darwin || linux

package slackchannel

import (
	"context"
	"testing"
)

func TestChannelSharedBotRoutesToExactlyOneExplicitAgent(t *testing.T) {
	f := newChannelFixture(t)
	first, firstSession := f.active()
	client := f.publicClient(f.owner)
	secondRequest := StartRequest{
		Recipient:  Recipient{WorkspaceID: "workspace", SubjectID: "subject", AgentID: "second-agent"},
		AgentLabel: "Second agent", TeamID: "TONE", ChannelID: "CTWO",
	}
	second, err := client.Start(context.Background(), secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Session(context.Background(), second.ID); err == nil {
		t.Fatal("shared bot grant automatically enabled another agent")
	}
	if f.callback(f.consent(second)) != 200 {
		t.Fatal("second agent consent failed")
	}
	second, err = client.Activate(context.Background(), second.ID)
	if err != nil {
		t.Fatal(err)
	}
	secondSession, err := client.Session(context.Background(), second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second.Recipient != secondRequest.Recipient || first.Recipient.AgentID == second.Recipient.AgentID {
		t.Fatal("explicit agent recipient was lost")
	}
	duplicate := secondRequest
	duplicate.ChannelID = first.ChannelID
	if _, err := client.Start(context.Background(), duplicate); err == nil {
		t.Fatal("one conversation was assigned to two agents")
	}
	event := f.event("EVENTONE", map[string]any{
		"type": "app_mention", "user": "UACTOR", "channel": first.ChannelID,
		"ts": "100.000002", "text": "<@UBOT> synthetic agent routing",
	})
	for range 2 {
		if status := f.postEvent(event, f.clock, true); status != 200 {
			t.Fatal("signed event or retry rejected")
		}
	}
	if status, deliveries := f.inbox(first, firstSession); status != 200 || len(deliveries) != 1 || deliveries[0].BindingID != first.ID {
		t.Fatal("event did not reach exactly its bound agent once")
	}
	if status, deliveries := f.inbox(second, secondSession); status != 200 || len(deliveries) != 0 {
		t.Fatal("shared bot broadcast an event to another agent")
	}
	event = f.event("EVENTUNBOUND", map[string]any{
		"type": "app_mention", "user": "UACTOR", "channel": "CUNBOUND",
		"ts": "100.000003", "text": "<@UBOT> no recipient",
	})
	if status := f.postEvent(event, f.clock, true); status != 200 {
		t.Fatal("unbound event was not acknowledged safely")
	}
	view, err := f.store.View()
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Deliveries) != 1 {
		t.Fatal("unbound conversation fell back to a global recipient")
	}
}

func TestChannelRecipientRequiresExplicitAgent(t *testing.T) {
	f := newChannelFixture(t)
	input := StartRequest{
		Recipient:  Recipient{WorkspaceID: "workspace", SubjectID: "subject"},
		AgentLabel: "No agent", TeamID: "TONE", ChannelID: "CONE",
	}
	status, _, _ := f.request("POST", Prefix+"/bindings", jsonBody(input), &f.owner, "", nil)
	view, err := f.store.View()
	if err != nil {
		t.Fatal(err)
	}
	if status != 400 || len(view.Bindings) != 0 {
		t.Fatal("missing agent was accepted or assigned an owner fallback")
	}
}
