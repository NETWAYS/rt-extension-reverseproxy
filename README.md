# RT::Extension::ReverseProxy

Make [Request Tracker 6](https://bestpractical.com/rt) trust `X-Forwarded-*`
headers when it runs behind a reverse proxy (nginx, haproxy, ...).

When a proxy terminates TLS and forwards to `rt-server`/Starlet over plain
HTTP, RT must read the `X-Forwarded-*` headers to learn the real scheme, host,
port and client IP. Without that, RT sees every request as `http://host:9000`
instead of `https://rt.example.com:443` — which breaks absolute URLs,
`$RestrictReferrer`, inline edit, and secure cookies.

This extension wraps RT's PSGI app with
[`Plack::Middleware::ReverseProxy`](https://metacpan.org/pod/Plack::Middleware::ReverseProxy)
through RT's supported `PSGIWrap` plugin hook, and adds a **trusted-proxy**
option so forwarded headers are only believed when the request really comes
from your proxy.

## Why `rt-server -e 'enable "ReverseProxy"'` does *not* work

That looks right but is **silently ignored**. `rt-server` (via
`RT::PlackRunner`) pre-builds the PSGI app and assigns it to `$self->{app}`.
Because `Plack::Runner` already has an app, it skips its own `build_app` step —
the very step that would have applied the `-e` middleware. So the middleware
never runs and RT keeps computing `http://host:9000`.

The supported hook is the per-plugin `PSGIWrap` method, which
`RT::Interface::Web::Handler::PSGIApp` applies for every active plugin:

```perl
for my $plugin (RT->Config->Get("Plugins")) {
    my $wrap = $plugin->can("PSGIWrap") or next;
    $app = $wrap->($plugin, $app);
}
```

This extension implements `PSGIWrap`, so **activating the plugin is enough** —
and you should **remove** any dead `-e 'enable "ReverseProxy"'` from your
`rt-server` invocation / service unit.

## Installation

```bash
perl -I. Makefile.PL    # -I. is required: modern Perl drops "." from @INC
make
make install            # may need root
```

Then add to `/opt/rt/etc/RT_SiteConfig.pm`:

```perl
Plugin('RT::Extension::ReverseProxy');
```

Clear the Mason cache (`rm -rf /opt/rt/var/mason_data/obj`) and restart the
webserver. If your server invocation still passes `-e 'enable "ReverseProxy"'`,
remove it.

## Configuration

### `$ReverseProxy_TrustedProxies` (recommended)

A list of IP addresses and/or CIDR ranges (IPv4 or IPv6) allowed to set
`X-Forwarded-*`. This is matched against `REMOTE_ADDR` — the address of the
host that connects to `rt-server`, i.e. your proxy (usually loopback).

```perl
Set( $ReverseProxy_TrustedProxies, [ '127.0.0.1', '::1', '10.0.0.0/24' ] );
```

| `REMOTE_ADDR` | Behaviour                                  |
|---------------|--------------------------------------------|
| trusted       | `X-Forwarded-*` applied                     |
| anything else | `X-Forwarded-*` ignored; real conn details |

**Default (unset): trust all clients.** If `$ReverseProxy_TrustedProxies` is
not set, `X-Forwarded-*` from *any* client is honoured — matching plain
`Plack::Middleware::ReverseProxy`. That is only safe when the PSGI port is not
reachable by untrusted clients (binds to `127.0.0.1`, only the proxy connects).
If the PSGI port is exposed, a client can spoof
`X-Forwarded-For`/`-Proto`/`-Host`; set `$ReverseProxy_TrustedProxies` to
prevent it.

Changes take effect at server start — restart `rt-server` after editing.

## Verifying it works

With the plugin active and a request carrying `X-Forwarded-Proto: https` and
`X-Forwarded-Host: rt.example.com`, RT's `GetWebURLFromRequest()` resolves to
`https://rt.example.com` instead of `http://host:9000`, the `$RestrictReferrer`
domain warning disappears, and inline edit works.

> When both `X-Forwarded-Host` and `X-Forwarded-Port` are sent, the middleware
> sets `HTTP_HOST` to `host:443`. This is harmless — RT normalises host and port.

## Requirements

- RT 6.0.0 or later
- [`Plack::Middleware::ReverseProxy`](https://metacpan.org/pod/Plack::Middleware::ReverseProxy)
  (ships as an RT dependency)
- [`Net::CIDR`](https://metacpan.org/pod/Net::CIDR) (only used when
  `$ReverseProxy_TrustedProxies` is set)

## License

GPL v2. Copyright (c) 2026 NETWAYS GmbH.
