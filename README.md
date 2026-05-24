# virtualmin

[![Go Reference](https://pkg.go.dev/badge/github.com/libdns/virtualmin.svg)](https://pkg.go.dev/github.com/libdns/virtualmin)

This package implements the [libdns](https://github.com/libdns/libdns) interfaces for [Virtualmin](https://www.virtualmin.com/), allowing you to manage DNS records in BIND zones managed by Virtualmin/Webmin.

## Requirements

- **Virtualmin ≥ 7.50.0** — earlier versions have a bug ([#1104](https://github.com/virtualmin/virtualmin-gpl/issues/1104)) that strips spaces from TXT record values written via the API.
- The target DNS zone must be configured as a **Virtualmin virtual server with DNS enabled**. Raw BIND zones managed directly by Webmin's BIND module without an associated virtual server are not accessible via the Virtualmin Remote API.
- A Webmin user configured with the access rights described below.

## Webmin user setup

The provider authenticates as a Webmin user. That user requires specific access rights at both the Webmin level and the Virtualmin module level. A dedicated user scoped to only the required domain and feature is strongly recommended over using `root`.

### Step 1 — Create the Webmin user

In Webmin → Webmin Users → Create a new Webmin user.

Set a strong password (or leave the password field and use an API key instead — see [Authentication](#authentication)).

### Step 2 — Webmin-level access rights

Still on the user's edit page, configure:

| Setting | Value | Notes |
|---|---|---|
| **Available Webmin modules** | tick **Virtualmin Virtual Servers** | Required — without this the user cannot reach the Virtualmin module at all |
| **Can use Webmin RPC?** | **Yes** | Required — the Remote API goes through the Webmin RPC layer |
| **IP access control** | restrict to your Caddy server IP (optional) | Recommended for production |

### Step 3 — Virtualmin module access rights

After saving the Webmin user, go to Webmin → Webmin Users → your user → **Virtualmin Virtual Servers** (the module ACL).

| Setting | Value | Notes |
|---|---|---|
| **Can edit module configuration?** | **Yes** | **Critical** — despite the name, this is what gates Remote API access. Internally this sets `noconfig=0` in the ACL file, which is what `master_admin()` checks before allowing any remote API call. Without this, every API call returns "You are not allowed to run remote commands" regardless of any other setting. |
| **Domains this user can manage** | select specific domain(s) | Scope the user to only the domains Caddy needs to manage |
| **Features this user can manage** | tick **DNS** only | Limits the user to DNS operations only — untick web, mail, FTP, etc. |
| **Can create virtual servers?** | No | Not needed |
| **Can stop/start servers?** | No | Not needed (optional) |

### Resulting ACL files (for reference)

The above configuration produces these entries in the Webmin ACL files on the Virtualmin host:

`/etc/webmin/acl/<username>.acl`:
```
rpc=1
```

`/etc/webmin/virtual-server/<username>.acl`:
```
noconfig=0
feature_dns=1
domains=<domain-id>
create=0
import=0
```

### Why "Can edit module configuration?" is required

Virtualmin's Remote API (`remote.cgi`) checks whether the authenticated user is a "master admin" before allowing any program call. Internally this is:

```perl
sub master_admin { return !$access{'noconfig'}; }
```

So `noconfig=0` (i.e. "Can edit module configuration = Yes") is required for the Remote API to work, even though editing global Virtualmin configuration is not actually needed for DNS management. This is a Virtualmin implementation detail, not a security requirement — you can safely enable this on a user that is otherwise scoped to a single domain with DNS-only access.

## Known limitations

### TXT value truncation in GetRecords

Virtualmin's `get-dns` API returns records in a fixed-width plaintext table where the value column is approximately **40 characters wide**. Long TXT values are silently truncated:

- ACME DNS-01 challenge tokens are 43 characters — truncated
- DKIM public keys are typically 200+ characters — severely truncated
- SPF records with many includes may also be truncated

`GetRecords` therefore cannot return reliable full TXT values for long records. This does **not** affect ACME DNS-01 correctness:

- `AppendRecords` writes the full value correctly via `modify-dns`
- `DeleteRecords` targets records by **name and type only** (not value), so truncation does not affect deletion
- Caddy's ACME solver never reads back the challenge token after writing it

If you need to read full TXT values, query DNS directly (e.g. `dig TXT _acme-challenge.example.com`).

## Authentication

You may authenticate with either a **Webmin API key** (preferred) or a **username and password**.

### Webmin API key

Generate a key in Webmin → Webmin Users → your user → API Tokens. This is preferred as it avoids exposing a password and can be rotated independently.

### Username + password

Use the credentials of the Webmin user configured above.

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
    // Or: Username: "caddy", Password: "secret",
}

zone := "example.com."
ctx := context.Background()

// List all records (note: TXT values > ~40 chars are truncated).
records, err := provider.GetRecords(ctx, zone)

// Append a TXT record (e.g. for ACME DNS-01 challenge).
// Full value is always written correctly regardless of length.
_, err = provider.AppendRecords(ctx, zone, []libdns.Record{
    libdns.TXT{
        Name: "_acme-challenge",
        TTL:  60 * time.Second,
        Text: "challenge-token-value",
    },
})

// Delete by name+type. Value is not used for matching.
_, err = provider.DeleteRecords(ctx, zone, []libdns.Record{
    libdns.TXT{
        Name: "_acme-challenge",
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

If your Webmin instance uses a self-signed TLS certificate, set `Insecure: true`. This disables certificate verification and should **not** be used in production. The recommended approach is to configure a proper certificate for Webmin (Virtualmin can manage Let's Encrypt certificates for Webmin itself).

## How it works

Records are managed via the [Virtualmin Remote API](https://www.virtualmin.com/docs/development/remote-api/) at `/virtual-server/remote.cgi`:

| libdns method   | Virtualmin program | Notes |
|---|---|---|
| `GetRecords`    | `get-dns` | Parses a fixed-width 77-char plaintext table from the JSON response. Column layout: name [0:30], type [30:36], value [36:77]. TXT values truncated at ~40 chars. |
| `AppendRecords` | `modify-dns` | `add-record-with-ttl=<name TYPE ttl value>`. Full value written correctly. Virtualmin adds quotes around TXT values itself — do not pre-quote. |
| `SetRecords`    | `modify-dns` | Fetches existing records, deletes matching (name, type) pairs, appends new records. Not atomic. |
| `DeleteRecords` | `modify-dns` | `remove-record=<name TYPE>`. Value intentionally omitted — see truncation caveat above. |

`modify-dns` automatically increments the SOA serial and reloads BIND via `rndc reload`. For secondary nameservers outside Virtualmin's cluster, increase `propagation_delay` in Caddy to cover the slave's SOA refresh interval.

## Running the integration tests

```shell
export TEST_VIRTUALMIN_URL=https://vps.example.com:10000
export TEST_VIRTUALMIN_USER=my-webmin-user
export TEST_VIRTUALMIN_API_KEY=my-api-key  # or TEST_VIRTUALMIN_PASS
export TEST_ZONE=example.com.              # trailing dot required
# export TEST_VIRTUALMIN_INSECURE=1        # if self-signed cert

go test -v ./...
```

The tests create and delete records in the named zone. Use a test zone or subdomain you control.

## Supported record types

| Type | Get | Append / Set / Delete |
|---|---|---|
| A / AAAA | ✅ | ✅ |
| CNAME    | ✅ | ✅ |
| MX       | ✅ | ✅ |
| NS       | ✅ | ✅ |
| TXT      | ✅ (truncated > ~40 chars) | ✅ (full value) |
| SRV      | ✅ | ✅ |
| CAA      | ✅ | ✅ |
| Other    | ✅ (as `libdns.RR`) | ✅ (raw RDATA passthrough) |

## License

MIT — see [LICENSE](LICENSE).
