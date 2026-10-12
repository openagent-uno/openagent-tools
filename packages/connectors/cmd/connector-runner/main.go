// connector-runner is a local trusted-host protocol. It is never an unauthenticated network server.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	connectors "github.com/openagent-uno/openagent-tools/packages/connectors"
	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

type request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}
type response struct {
	ID     string `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

func main() {
	identityPath := flag.String("identity-file", "", "Host-owned installation identity file")
	broker := flag.String("broker", "https://auth.openagent.uno", "Official authentication service")
	product := flag.String("product", "openagent", "Product name")
	name := flag.String("name", "OpenAgent server", "Installation display name")
	ownPath := flag.String("oauth-providers", "", "Optional host-owned app configuration with loopback callbacks")
	flag.Parse()
	local, localErr := auth.NewLocalOAuth(*ownPath)
	if localErr != nil {
		fmt.Fprintln(os.Stderr, "own-app configuration unavailable")
		os.Exit(1)
	}
	defer local.Close()
	runtime, err := connectors.NewRuntime(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connector runtime unavailable")
		os.Exit(1)
	}
	var client *auth.Client
	if *identityPath != "" {
		identity, err := auth.LoadIdentity(*identityPath, *product, *name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "connector installation identity unavailable")
			os.Exit(1)
		}
		client = &auth.Client{Origin: *broker, Identity: identity}
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 65536), 32<<20)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var req request
		reply := response{}
		if json.Unmarshal(scanner.Bytes(), &req) != nil {
			reply.Error = "invalid_request"
			_ = encoder.Encode(reply)
			continue
		}
		reply.ID = req.ID
		ctx := context.Background()
		switch req.Method {
		case "catalog":
			reply.Result = connectors.Catalog()
		case "tools":
			var binding connectors.Binding
			if json.Unmarshal(req.Params, &binding) != nil {
				err = auth.ErrDenied
			} else {
				reply.Result, err = runtime.Tools(binding)
			}
		case "invoke":
			var call connectors.Call
			if json.Unmarshal(req.Params, &call) != nil {
				err = auth.ErrDenied
			} else {
				reply.Result, err = runtime.Invoke(ctx, call)
			}
		default:
			if client == nil {
				err = auth.ErrDenied
				break
			}
			switch req.Method {
			case "auth.register":
				if local == nil {
					err = client.Register(ctx)
				}
				reply.Result = map[string]string{"installation": client.Identity.ID()}
			case "auth.start":
				var start auth.Start
				err = json.Unmarshal(req.Params, &start)
				if err == nil {
					if local.HasProvider(start.Provider) {
						reply.Result, err = local.Start(start)
					} else {
						err = client.Register(ctx)
						if err == nil {
							reply.Result, err = client.Start(ctx, start)
						}
					}
				}
			case "auth.poll", "auth.redeem":
				var p struct {
					ID string `json:"id"`
				}
				err = json.Unmarshal(req.Params, &p)
				if err == nil {
					if req.Method == "auth.poll" {
						if local.Owns(p.ID) {
							reply.Result, err = local.Transaction(p.ID)
						} else {
							reply.Result, err = client.Transaction(ctx, p.ID)
						}
					} else {
						if local.Owns(p.ID) {
							reply.Result, err = local.Redeem(ctx, p.ID)
						} else {
							reply.Result, err = client.Redeem(ctx, p.ID)
						}
					}
				}
			case "auth.refresh":
				var p struct {
					Provider string      `json:"provider"`
					Token    oauth.Token `json:"token"`
				}
				err = json.Unmarshal(req.Params, &p)
				if err == nil {
					if local.Issued(p.Provider, p.Token.AppID) {
						reply.Result, err = local.Refresh(ctx, p.Provider, p.Token)
					} else {
						reply.Result, err = client.Refresh(ctx, p.Provider, p.Token)
					}
				}
			case "auth.publish":
				var rotation auth.Rotation
				err = json.Unmarshal(req.Params, &rotation)
				if err == nil {
					err = client.Publish(ctx, rotation)
				}
			case "sync.mail":
				reply.Result, err = client.Mail(ctx)
			case "sync.open":
				var p struct {
					Envelope auth.Envelope     `json:"envelope"`
					Sender   auth.Installation `json:"sender"`
					Group    auth.GroupInfo    `json:"group"`
				}
				err = json.Unmarshal(req.Params, &p)
				if err == nil {
					var plaintext []byte
					plaintext, err = auth.Open(client.Identity, p.Sender, p.Envelope, timeNow())
					if err == nil {
						var token oauth.Token
						err = json.Unmarshal(plaintext, &token)
						if err == nil && (p.Group.ID != p.Envelope.Group || !p.Group.Validates(token)) {
							err = auth.ErrDenied
						}
						reply.Result = token
					}
				}
			case "sync.send":
				var p struct {
					Recipient auth.Installation `json:"recipient"`
					Group     string            `json:"group"`
					Token     oauth.Token       `json:"token"`
				}
				err = json.Unmarshal(req.Params, &p)
				if err == nil {
					var data []byte
					data, err = json.Marshal(p.Token)
					if err == nil {
						var envelope auth.Envelope
						envelope, err = auth.Seal(client.Identity, p.Recipient, p.Group, p.Token.Version, data, timeNow())
						if err == nil {
							err = client.Send(ctx, envelope)
						}
					}
				}
			case "sync.commit", "sync.recover", "sync.disconnect":
				var p struct {
					Group   string `json:"group"`
					Version uint64 `json:"version"`
				}
				err = json.Unmarshal(req.Params, &p)
				if err == nil {
					switch req.Method {
					case "sync.commit":
						err = client.Commit(ctx, p.Group, p.Version)
					case "sync.recover":
						reply.Result, err = client.Recover(ctx, p.Group)
					case "sync.disconnect":
						err = client.Disconnect(ctx, p.Group)
					}
				}
			case "events":
				reply.Result, err = client.Events(ctx)
			case "events.ack":
				var p struct {
					ID string `json:"id"`
				}
				err = json.Unmarshal(req.Params, &p)
				if err == nil {
					err = client.Acknowledge(ctx, p.ID)
				}
			default:
				err = auth.ErrDenied
			}
		}
		if err != nil {
			reply.Result = nil
			reply.Error = "connector_request_failed"
			if remote, ok := err.(*auth.RemoteError); ok {
				reply.Error = remote.Code
			}
		} else if reply.Result == nil {
			reply.Result = map[string]bool{"ok": true}
		}
		_ = encoder.Encode(reply)
		err = nil
	}
	if scanner.Err() != nil {
		fmt.Fprintln(os.Stderr, "connector input unavailable")
		os.Exit(1)
	}
}

func timeNow() time.Time { return time.Now().UTC() }
