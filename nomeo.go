package nomeo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

const defaultBaseURL = "https://api.nomeo.com"

// Provider implements libdns record management for Nomeo.
type Provider struct {
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client

	baseURL string

	mu    sync.Mutex
	token string
}

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)

// GetRecords returns all records in zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	apiRecords, err := p.getAPIRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	records := make([]libdns.Record, 0, len(apiRecords))
	for _, apiRecord := range apiRecords {
		record, err := p.toLibdnsRecord(zone, apiRecord)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

// AppendRecords creates records in zone. Nomeo assigns the TTL, so input TTLs
// cannot be applied through this API.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	created := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		apiRecord, err := toNomeoRecord(record, zone)
		if err != nil {
			return created, err
		}

		var response apiEnvelope
		if err := p.apiRequest(ctx, http.MethodPost, p.domainPath(zone, "/record"), apiRecord, &response); err != nil {
			return created, err
		}
		if err := response.checkSuccess(); err != nil {
			return created, err
		}
		created = append(created, record)
	}
	return created, nil
}

// DeleteRecords deletes matching records from zone.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	apiRecords, err := p.getAPIRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	deleted := make([]libdns.Record, 0, len(records))
	deletedIDs := make(map[int]struct{}, len(records))
	for _, record := range records {
		target, err := recordKey(record, zone)
		if err != nil {
			return deleted, err
		}

		match := -1
		for i, apiRecord := range apiRecords {
			if _, alreadyDeleted := deletedIDs[apiRecord.ID]; alreadyDeleted {
				continue
			}
			current, err := p.toLibdnsRecord(zone, apiRecord)
			if err != nil {
				return deleted, err
			}
			key, err := recordKey(current, zone)
			if err != nil {
				return deleted, err
			}
			if target == key {
				match = i
				break
			}
		}
		if match < 0 {
			return deleted, fmt.Errorf("Nomeo: record %q %s %q not found in zone %q", target.name, target.typ, target.data, zone)
		}

		apiRecord := apiRecords[match]
		if apiRecord.ID <= 0 {
			return deleted, fmt.Errorf("Nomeo: record %q %s has invalid ID %d", apiRecord.RecordName, apiRecord.RecordTypeName, apiRecord.ID)
		}
		path := p.domainPath(zone, "/record/"+strconv.Itoa(apiRecord.ID))
		var response apiEnvelope
		if err := p.apiRequest(ctx, http.MethodDelete, path, nil, &response); err != nil {
			return deleted, err
		}
		if err := response.checkSuccess(); err != nil {
			return deleted, err
		}
		deletedIDs[apiRecord.ID] = struct{}{}
		deleted = append(deleted, record)
	}
	return deleted, nil
}

func (p *Provider) getAPIRecords(ctx context.Context, zone string) ([]apiRecord, error) {
	zone, err := normalizeZone(zone)
	if err != nil {
		return nil, fmt.Errorf("Nomeo: invalid zone: %w", err)
	}
	var response struct {
		apiEnvelope
		Result struct {
			Records map[string][]apiRecord `json:"Records"`
		} `json:"Result"`
	}
	if err := p.apiRequest(ctx, http.MethodGet, p.domainPath(zone, "/records"), nil, &response); err != nil {
		return nil, err
	}
	if err := response.apiEnvelope.checkSuccess(); err != nil {
		return nil, err
	}

	var records []apiRecord
	for recordType, group := range response.Result.Records {
		for _, record := range group {
			if record.RecordTypeName == "" {
				record.RecordTypeName = recordType
			}
			records = append(records, record)
		}
	}
	if response.Result.Records == nil {
		return nil, errors.New("Nomeo: records response did not contain a records object")
	}
	return records, nil
}

func (p *Provider) toLibdnsRecord(zone string, record apiRecord) (libdns.Record, error) {
	name, err := relativeName(record.RecordName, zone)
	if err != nil {
		return nil, fmt.Errorf("Nomeo: invalid record name %q: %w", record.RecordName, err)
	}

	recordType := strings.ToUpper(record.RecordTypeName)
	if recordType == "" {
		return nil, fmt.Errorf("Nomeo: record %d has no record type", record.ID)
	}
	data := record.RecordData
	switch recordType {
	case "MX", "SRV":
		data = fmt.Sprintf("%d %s", record.Priority, data)
	}

	rr := libdns.RR{
		Name: name,
		Type: recordType,
		Data: data,
		TTL:  time.Duration(record.TTL) * time.Second,
	}
	parsed, err := rr.Parse()
	if err != nil {
		return nil, fmt.Errorf("Nomeo: parse %s record %q: %w", recordType, record.RecordName, err)
	}
	return parsed, nil
}

func toNomeoRecord(record libdns.Record, zone string) (apiRecordPayload, error) {
	if record == nil {
		return apiRecordPayload{}, errors.New("Nomeo: cannot create a nil record")
	}
	rr := record.RR()
	name, err := absoluteName(rr.Name, zone)
	if err != nil {
		return apiRecordPayload{}, fmt.Errorf("Nomeo: invalid record name %q: %w", rr.Name, err)
	}

	recordType := strings.ToUpper(rr.Type)
	switch recordType {
	case "A", "AAAA", "CNAME", "ANAME", "MX", "TXT", "SRV", "CAA", "NS", "DS", "LUA", "ALIAS":
	default:
		return apiRecordPayload{}, fmt.Errorf("Nomeo: record type %q is not supported by the API", recordType)
	}

	payload := apiRecordPayload{
		RecordTypeName: recordType,
		RecordName:     name,
		RecordData:     rr.Data,
		Priority:       1,
	}

	parsed, err := rr.Parse()
	if err != nil {
		return apiRecordPayload{}, fmt.Errorf("Nomeo: parse %s record %q: %w", recordType, rr.Name, err)
	}
	switch record := parsed.(type) {
	case libdns.MX:
		payload.Priority = int(record.Preference)
		payload.RecordData = record.Target
	case libdns.SRV:
		payload.Priority = int(record.Priority)
		payload.RecordData = fmt.Sprintf("%d %d %s", record.Weight, record.Port, record.Target)
	}
	if payload.Priority < 1 || payload.Priority > 1000 {
		return apiRecordPayload{}, fmt.Errorf("Nomeo: priority %d for %s record must be between 1 and 1000", payload.Priority, recordType)
	}
	return payload, nil
}

type recordIdentity struct {
	name string
	typ  string
	data string
}

func recordKey(record libdns.Record, zone string) (recordIdentity, error) {
	if record == nil {
		return recordIdentity{}, errors.New("Nomeo: cannot match a nil record")
	}
	rr := record.RR()
	name, err := absoluteName(rr.Name, zone)
	if err != nil {
		return recordIdentity{}, err
	}
	return recordIdentity{
		name: strings.ToLower(name),
		typ:  strings.ToUpper(rr.Type),
		data: rr.Data,
	}, nil
}

func absoluteName(name, zone string) (string, error) {
	zone, err := normalizeZone(zone)
	if err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("record name must not be empty")
	}
	if name == "@" || name == "." {
		return zone, nil
	}

	isAbsolute := strings.HasSuffix(name, ".")
	name = strings.TrimSuffix(name, ".")
	if strings.EqualFold(name, zone) || strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone)) {
		return name, nil
	}
	if isAbsolute {
		return "", fmt.Errorf("name %q is outside zone %q", name, zone)
	}
	return name + "." + zone, nil
}

func relativeName(name, zone string) (string, error) {
	zone, err := normalizeZone(zone)
	if err != nil {
		return "", err
	}
	isAbsolute := strings.HasSuffix(strings.TrimSpace(name), ".")
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return "", errors.New("record name must not be empty")
	}
	if name == "@" || strings.EqualFold(name, zone) {
		return "@", nil
	}
	suffix := "." + zone
	if len(name) > len(suffix) && strings.EqualFold(name[len(name)-len(suffix):], suffix) {
		return name[:len(name)-len(suffix)], nil
	}
	if isAbsolute {
		return "", fmt.Errorf("name %q is outside zone %q", name, zone)
	}
	return name, nil
}

func normalizeZone(zone string) (string, error) {
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if zone == "" {
		return "", errors.New("zone must not be empty")
	}
	return zone, nil
}

func (p *Provider) domainPath(zone, suffix string) string {
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	return "/domains/" + url.PathEscape(zone) + suffix
}

func (p *Provider) apiRequest(ctx context.Context, method, path string, body any, result any) error {
	var encodedBody []byte
	var err error
	if body != nil {
		encodedBody, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("Nomeo: encode request: %w", err)
		}
	}

	for attempt := 0; attempt < 2; attempt++ {
		token, err := p.accessToken(ctx)
		if err != nil {
			return err
		}

		requestURL := p.baseURL
		if requestURL == "" {
			requestURL = defaultBaseURL
		}
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(requestURL, "/")+path, bytes.NewReader(encodedBody))
		if err != nil {
			return fmt.Errorf("Nomeo: create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := p.httpClient().Do(req)
		if err != nil {
			return fmt.Errorf("Nomeo: %s %s: %w", method, path, err)
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		closeErr := resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("Nomeo: read %s response: %w", method, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("Nomeo: close %s response: %w", method, closeErr)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			p.invalidateToken(token)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("Nomeo: %s %s returned HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(responseBody)))
		}
		if result != nil {
			if err := json.Unmarshal(responseBody, result); err != nil {
				return fmt.Errorf("Nomeo: decode %s response: %w", method, err)
			}
		}
		return nil
	}
	return errors.New("Nomeo: authentication failed after refreshing the access token")
}

func (p *Provider) accessToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token != "" {
		return p.token, nil
	}
	if strings.TrimSpace(p.ClientID) == "" || strings.TrimSpace(p.ClientSecret) == "" {
		return "", errors.New("Nomeo: ClientID and ClientSecret are required")
	}

	body, err := json.Marshal(map[string]string{
		"client_id":     p.ClientID,
		"client_secret": p.ClientSecret,
	})
	if err != nil {
		return "", fmt.Errorf("Nomeo: encode authentication request: %w", err)
	}
	requestURL := p.baseURL
	if requestURL == "" {
		requestURL = defaultBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(requestURL, "/")+"/auth/token", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("Nomeo: create authentication request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("Nomeo: request access token: %w", err)
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return "", fmt.Errorf("Nomeo: read authentication response: %w", readErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("Nomeo: close authentication response: %w", closeErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("Nomeo: token endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(responseBody, &tokenResponse); err != nil {
		return "", fmt.Errorf("Nomeo: decode authentication response: %w", err)
	}
	if tokenResponse.AccessToken == "" {
		return "", errors.New("Nomeo: token endpoint returned an empty access token")
	}
	p.token = tokenResponse.AccessToken
	return p.token, nil
}

func (p *Provider) invalidateToken(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token == token {
		p.token = ""
	}
}

func (p *Provider) httpClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

type apiEnvelope struct {
	Success       *bool  `json:"success"`
	ResultMessage string `json:"ResultMessage"`
	Message       string `json:"message"`
}

func (r apiEnvelope) checkSuccess() error {
	if r.Success == nil {
		return errors.New("Nomeo: API response did not include a success status")
	}
	if *r.Success {
		return nil
	}
	message := r.Message
	if message == "" {
		message = r.ResultMessage
	}
	if message == "" {
		message = "API reported an unsuccessful operation"
	}
	return errors.New("Nomeo: " + message)
}

type apiRecord struct {
	ID             int    `json:"Id"`
	Priority       int    `json:"Priority"`
	RecordData     string `json:"RecordData"`
	RecordName     string `json:"RecordName"`
	RecordTypeName string `json:"RecordTypeName"`
	TTL            int    `json:"TTL"`
}

type apiRecordPayload struct {
	RecordTypeName string `json:"record_type_name"`
	RecordName     string `json:"record_name"`
	RecordData     string `json:"record_data"`
	Priority       int    `json:"priority"`
}
