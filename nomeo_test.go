package nomeo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func testProvider(server *httptest.Server) *Provider {
	return &Provider{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		HTTPClient:   server.Client(),
		baseURL:      server.URL,
	}
}

func TestGetRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			writeJSON(t, w, map[string]string{"access_token": "test-token"})
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/domains/example.com/records" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}
		writeJSON(t, w, map[string]any{
			"Success": true,
			"Result": map[string]any{
				"Records": map[string]any{
					"A": []any{map[string]any{
						"Id": 10, "RecordName": "www.example.com", "RecordTypeName": "A",
						"RecordData": "192.0.2.1", "TTL": 300,
					}},
					"MX": []any{map[string]any{
						"Id": 11, "RecordName": "example.com", "RecordTypeName": "MX",
						"RecordData": "mail.example.net", "Priority": 10, "TTL": 600,
					}},
					"TXT": []any{map[string]any{
						"Id": 12, "RecordName": "example.com", "RecordTypeName": "TXT",
						"RecordData": "v=spf1 -all", "TTL": 120,
					}},
				},
			},
		})
	}))
	defer server.Close()

	records, err := testProvider(server).GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}
	found := make(map[string]bool)
	for _, record := range records {
		switch value := record.(type) {
		case libdns.Address:
			if value.Name != "www" || value.IP != netip.MustParseAddr("192.0.2.1") || value.TTL != 300*time.Second {
				t.Fatalf("unexpected address record: %#v", value)
			}
			found["A"] = true
		case libdns.MX:
			if value.Name != "@" || value.Preference != 10 || value.Target != "mail.example.net" {
				t.Fatalf("unexpected MX record: %#v", value)
			}
			found["MX"] = true
		case libdns.TXT:
			if value.Name != "@" || value.Text != "v=spf1 -all" {
				t.Fatalf("unexpected TXT record: %#v", value)
			}
			found["TXT"] = true
		default:
			t.Fatalf("unexpected record type: %#v", record)
		}
	}
	for _, recordType := range []string{"A", "MX", "TXT"} {
		if !found[recordType] {
			t.Errorf("missing %s record", recordType)
		}
	}
}

func TestAppendRecordsEncodesMX(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			writeJSON(t, w, map[string]string{"access_token": "test-token"})
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/domains/example.com/record" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}
		var payload apiRecordPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		want := apiRecordPayload{
			RecordTypeName: "MX",
			RecordName:     "example.com",
			RecordData:     "mail.example.net",
			Priority:       10,
		}
		if payload != want {
			t.Fatalf("payload = %#v, want %#v", payload, want)
		}
		writeJSON(t, w, map[string]any{"success": true, "message": "created"})
	}))
	defer server.Close()

	input := libdns.MX{Name: "@", Preference: 10, Target: "mail.example.net"}
	created, err := testProvider(server).AppendRecords(context.Background(), "example.com", []libdns.Record{input})
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 {
		t.Fatalf("got %d created records, want 1", len(created))
	}
}

func TestAppendSRVRecordUsesRelativeDottedName(t *testing.T) {
	payload, err := toNomeoRecord(libdns.SRV{
		Service:   "sip",
		Transport: "tcp",
		Name:      "sub",
		Priority:  20,
		Weight:    5,
		Port:      5060,
		Target:    "sip.example.net",
	}, "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	want := apiRecordPayload{
		RecordTypeName: "SRV",
		RecordName:     "_sip._tcp.sub.example.com",
		RecordData:     "5 5060 sip.example.net",
		Priority:       20,
	}
	if payload != want {
		t.Fatalf("payload = %#v, want %#v", payload, want)
	}
}

func TestDeleteRecordsLooksUpRecordID(t *testing.T) {
	var tokenCalls, deleteCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/token":
			tokenCalls++
			writeJSON(t, w, map[string]string{"access_token": "test-token"})
		case "/domains/example.com/records":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected method for records: %s", r.Method)
			}
			writeJSON(t, w, map[string]any{
				"Success": true,
				"Result": map[string]any{
					"Records": map[string]any{
						"A": []any{map[string]any{
							"Id": 42, "RecordName": "example.com", "RecordTypeName": "A",
							"RecordData": "192.0.2.2", "TTL": 300,
						}},
					},
				},
			})
		case "/domains/example.com/record/42":
			if r.Method != http.MethodDelete {
				t.Fatalf("unexpected method for delete: %s", r.Method)
			}
			deleteCalls++
			writeJSON(t, w, map[string]any{"success": true})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	provider := testProvider(server)
	deleted, err := provider.DeleteRecords(context.Background(), "example.com", []libdns.Record{
		libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.2")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleteCalls != 1 || tokenCalls != 1 {
		t.Fatalf("deleted=%d, delete calls=%d, token calls=%d", len(deleted), deleteCalls, tokenCalls)
	}
}

func TestAPIErrorIsReturned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			writeJSON(t, w, map[string]string{"access_token": "test-token"})
			return
		}
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := testProvider(server).GetRecords(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected API error")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}
