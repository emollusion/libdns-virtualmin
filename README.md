# virtualmin

[![Go Reference](https://pkg.go.dev/badge/github.com/libdns/virtualmin.svg)](https://pkg.go.dev/github.com/libdns/virtualmin)

This package implements the [libdns](https://github.com/libdns/libdns) interfaces for [Virtualmin](https://www.virtualmin.com/), allowing you to manage DNS records in BIND zones managed by Virtualmin/Webmin.

## Requirements

- **Virtualmin ≥ 7.50.0** — earlier versions have a bug ([#1104](https://github.com/virtualmin/virtualmin-gpl/issues/1104)) that strips spaces from TXT record values written via the API.
- The authenticating Webmin user must be the **master administrator** (`root` or `admin`). The Remote API is not accessible to virtual-server owners.
- The Webmin user must have the *Virtualmin Remote CLI* ACL bit enabled.

## Credentials

You may authenticate with either a **Webmin API key** (preferred) or a **username and password**.

### Webmin API key

Generate a key in Webmin → Webmin Users → your user → API Tokens, then supply it as `APIKey`.

### Username + password

Use the Webmin master administrator credentials.  Be aware that this grants full control of the Webmin server.  Mitigate the risk by:

- Running Caddy on the same host as Virtualmin and pointing `ServerURL` at `https://127.0.0.1:10000`.
- Creating a dedicated Webmin admin user with a separate password.

## Usage

```go
import (
    "context"
    "github.com/libdns/virtualmin"
    "github.com/libdns/libdns"
    "time"
)

provider := &virtualmin.Provider{
    ServerURL: "https://vps.example.com:10000",
    APIKey:    "my-webmin-api-key",
    // Or: Username: "root", Password: "secret",
}

zone := "example.com."
ctx := context.Background()

// List all records.
records, err := provider.GetRecords(ctx, zone)

// Append a TXT record (e.g. for ACME DNS-01 challenge).
_, err = provider.AppendRecords(ctx, zone, []libdns.Record{
    libdns.TXT{
        Name: "_acme-challenge",
        TTL:  60 * time.Second,
        Text: "challenge-token-value",
    },
})

// Delete it afterwards.
_, err = provider.DeleteRecords(ctx, zone, []libdns.Record{
    libdns.TXT{
        Name: "_acme-challenge",
        Text: "challenge-token-value",
    },
})
```

## Caddyfile (with [caddy-dns/virtualmin](https://github.com/caddy-dns/virtualmin))

```caddy
tls {
    dns virtualmin {
        server_url {env.VIRTUALMIN_URL}
        api_key    {env.VIRTUALMIN_API_KEY}
        # or:
        # username {env.VIRTUALMIN_USER}
        # password {env.VIRTUALMIN_PASS}
    }
    propagation_timeout 2m
    propagation_delay   30s
}
```

## Self-signed Webmin certificate

If your Webmin instance uses a self-signed TLS certificate, set `Insecure: true`.
This disables certificate verification and should **not** be used in production
without understanding the security implications.  The recommended approach is to
configure a proper certificate for Webmin (Virtualmin can manage Let's Encrypt
certificates for Webmin itself).

## How it works

Records are managed via the [Virtualmin Remote API](https://www.virtualmin.com/docs/development/remote-api/):

| libdns method    | Virtualmin program | API call |
|---|---|---|
| `GetRecords`     | `get-dns`    | `?program=get-dns&multiline=1&json=1` |
| `AppendRecords`  | `modify-dns` | `add-record-with-ttl=<name TYPE ttl value>` |
| `SetRecords`     | `modify-dns` | delete matching RRset, then append new records |
| `DeleteRecords`  | `modify-dns` | `remove-record=<name TYPE value>` |

`modify-dns` automatically increments the SOA serial and reloads BIND via `rndc reload <zone>`.  For secondary nameservers that receive NOTIFY from the primary, this is sufficient.  For slaves not in Virtualmin's cluster, you may need to increase `propagation_delay` in Caddy to cover the slave's SOA refresh interval.

## Running the integration tests

```shell
export TEST_VIRTUALMIN_URL=https://vps.example.com:10000
export TEST_VIRTUALMIN_API_KEY=my-api-key  # or USER + PASS
export TEST_ZONE=example.com.
# export TEST_VIRTUALMIN_INSECURE=1        # if self-signed cert

go test -v ./...
```

The tests create and delete records in the named zone.  Use a dedicated test zone or at minimum a sub-domain you control.

## Supported record types

| Type | Get | Append / Set / Delete |
|---|---|---|
| A / AAAA | ✅ | ✅ |
| CNAME    | ✅ | ✅ |
| MX       | ✅ | ✅ |
| NS       | ✅ | ✅ |
| TXT      | ✅ | ✅ |
| SRV      | ✅ | ✅ |
| CAA      | ✅ | ✅ |
| Other    | ✅ (as `libdns.RR`) | ✅ (raw RDATA passthrough) |

## License

MIT — see [LICENSE](LICENSE).
