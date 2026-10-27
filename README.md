# libdns-nomeo

Nomeo DNS provider for [libdns](https://github.com/libdns/libdns).

The provider supports fetching, appending, and deleting DNS records using
Nomeo's API. Configure a Nomeo API client ID and client secret on `Provider`.

```go
provider := &nomeo.Provider{
    ClientID:     os.Getenv("NOMEO_CLIENT_ID"),
    ClientSecret: os.Getenv("NOMEO_CLIENT_SECRET"),
}
```

Nomeo assigns record TTLs through the API, so TTL values supplied when
appending records cannot be applied. Deleting a record looks up the current
record list to resolve Nomeo's record ID.
