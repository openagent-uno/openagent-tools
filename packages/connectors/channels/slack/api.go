package slackchannel

import (
	"encoding/json"
	"net/http"
	"strings"
)

type apiRequest struct {
	DeliveryID  string         `json:"delivery_id"`
	Method      string         `json:"method"`
	Arguments   map[string]any `json:"arguments"`
	OperationID string         `json:"operation_id,omitempty"`
}

func (s *Server) api(w http.ResponseWriter, r *http.Request, record bindingRecord, b []byte) {
	var input apiRequest
	if strict(b, &input) != nil || !id(input.DeliveryID) || input.Arguments == nil {
		failure(w, 400, "invalid_api_request")
		return
	}
	st, e := s.store.View()
	delivery, ok := st.Deliveries[input.DeliveryID]
	if e != nil || !ok || !s.current(&st, record) || delivery.BindingID != record.Public.ID || delivery.BindingVersion != record.Public.Version || (delivery.Status != "pending" && delivery.Status != "acknowledged") {
		failure(w, 403, "denied")
		return
	}
	args, write, e := boundArguments(input, record.Public, delivery)
	if e != nil {
		failure(w, 400, "invalid_api_request")
		return
	}
	operationKey := ""
	hash := digest(b)
	if write {
		if !id(input.OperationID) {
			failure(w, 400, "operation_id_required")
			return
		}
		operationKey = digest([]byte(record.Public.ID + "/" + input.OperationID))
		if previous, exists := st.Operations[operationKey]; exists {
			if previous.BindingID != record.Public.ID || previous.DeliveryID != delivery.ID || previous.BodySHA256 != hash {
				failure(w, 409, "operation_conflict")
				return
			}
			if previous.Status != "completed" {
				failure(w, 409, "operation_outcome_unknown")
				return
			}
			_, e = s.withGrant(r.Context(), record.Public.TeamID, func() error { return s.admit(record, "active", delivery.ID) }, func(g BotGrant) (json.RawMessage, error) {
				return nil, s.membership(r.Context(), record, g, "active", delivery.ID)
			})
			if e != nil {
				failure(w, 403, "denied")
				return
			}
			e = s.fence(record.Host, func() error {
				fresh, e := s.store.View()
				if e != nil || !s.current(&fresh, record) {
					return errDenied
				}
				op := fresh.Operations[operationKey]
				event := fresh.Deliveries[delivery.ID]
				if op.Status != "completed" || op.BodySHA256 != hash || event.Status == "denied" {
					return errDenied
				}
				output(w, 200, op.Result)
				return nil
			})
			if e != nil {
				failure(w, 403, "denied")
			}
			return
		}
		e = s.fence(record.Host, func() error {
			return s.store.Update(func(st *state) error {
				if !s.current(st, record) || len(st.Operations) >= 20000 {
					return errDenied
				}
				if _, exists := st.Operations[operationKey]; exists {
					return errDenied
				}
				st.Operations[operationKey] = operation{BindingID: record.Public.ID, DeliveryID: delivery.ID, BodySHA256: hash, Status: "running", CreatedAt: s.now()}
				return nil
			})
		})
		if e != nil {
			failure(w, 409, "operation_unavailable")
			return
		}
	}
	result, callErr := s.withGrant(r.Context(), record.Public.TeamID, func() error { return s.admit(record, "active", delivery.ID) }, func(g BotGrant) (json.RawMessage, error) {
		if e := s.membership(r.Context(), record, g, "active", delivery.ID); e != nil {
			return nil, e
		}
		if s.admit(record, "active", delivery.ID) != nil {
			return nil, errDenied
		}
		return s.provider.Call(r.Context(), g, input.Method, args)
	})
	if callErr != nil {
		if write {
			_ = s.store.Update(func(st *state) error {
				op := st.Operations[operationKey]
				if op.Status == "running" {
					op.Status = "outcome_unknown"
					op.Result = nil
					st.Operations[operationKey] = op
				}
				return nil
			})
			failure(w, 503, "operation_outcome_unknown")
		} else {
			failure(w, 503, "provider_read_failed")
		}
		return
	}
	e = s.fence(record.Host, func() error {
		err := s.store.Update(func(st *state) error {
			if !s.current(st, record) {
				return errDenied
			}
			current := st.Deliveries[delivery.ID]
			if current.Status != "pending" && current.Status != "acknowledged" {
				return errDenied
			}
			if write {
				op := st.Operations[operationKey]
				if op.Status != "running" || op.BodySHA256 != hash {
					return errDenied
				}
				op.Status = "completed"
				op.Result = result
				st.Operations[operationKey] = op
			}
			return nil
		})
		if err != nil {
			return err
		}
		output(w, 200, result)
		return nil
	})
	if e != nil {
		failure(w, 403, "destination_revoked")
		return
	}
}

func boundArguments(input apiRequest, binding Binding, delivery Delivery) (map[string]any, bool, error) {
	var envelope struct {
		Event struct {
			TS       string `json:"ts"`
			ThreadTS string `json:"thread_ts"`
		} `json:"event"`
	}
	if json.Unmarshal(delivery.Payload, &envelope) != nil || !text(envelope.Event.TS, 64) {
		return nil, false, errDenied
	}
	args := make(map[string]any, len(input.Arguments)+2)
	for k, v := range input.Arguments {
		args[k] = v
	}
	allowed := map[string]bool{}
	write := false
	switch input.Method {
	case "auth.test":
	case "conversations.info":
		allowed["channel"] = true
	case "conversations.members":
		allowed["channel"] = true
		allowed["limit"] = true
		allowed["cursor"] = true
	case "conversations.history":
		for _, k := range []string{"channel", "limit", "cursor", "latest", "inclusive"} {
			allowed[k] = true
		}
		if args["latest"] != envelope.Event.TS || args["inclusive"] != false {
			return nil, false, errDenied
		}
	case "conversations.replies":
		for _, k := range []string{"channel", "limit", "cursor", "latest", "inclusive", "ts"} {
			allowed[k] = true
		}
		if envelope.Event.ThreadTS == "" || args["ts"] != envelope.Event.ThreadTS || args["latest"] != envelope.Event.TS || args["inclusive"] != false {
			return nil, false, errDenied
		}
	case "chat.postMessage":
		write = true
		for _, k := range []string{"channel", "text", "thread_ts", "mrkdwn", "unfurl_links", "unfurl_media"} {
			allowed[k] = true
		}
		value, ok := args["text"].(string)
		if !ok || value == "" || len(value) > 40000 {
			return nil, false, errDenied
		}
		thread := envelope.Event.ThreadTS
		if thread == "" {
			thread = envelope.Event.TS
		}
		if requested, exists := args["thread_ts"]; exists && requested != thread {
			return nil, false, errDenied
		}
		args["thread_ts"] = thread
		args["unfurl_links"] = false
		args["unfurl_media"] = false
	default:
		return nil, false, errDenied
	}
	for k, v := range args {
		if !allowed[k] {
			return nil, false, errDenied
		}
		switch k {
		case "channel":
			if v != binding.ChannelID {
				return nil, false, errDenied
			}
		case "limit":
			number, ok := v.(float64)
			if !ok || number < 1 || number > 100 || number != float64(int(number)) {
				return nil, false, errDenied
			}
		case "cursor":
			value, ok := v.(string)
			if !ok || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
				return nil, false, errDenied
			}
		case "mrkdwn", "unfurl_links", "unfurl_media", "inclusive":
			if _, ok := v.(bool); !ok {
				return nil, false, errDenied
			}
		}
	}
	if input.Method != "auth.test" && args["channel"] != binding.ChannelID {
		return nil, false, errDenied
	}
	if !write && input.OperationID != "" {
		return nil, false, errDenied
	}
	return args, write, nil
}
