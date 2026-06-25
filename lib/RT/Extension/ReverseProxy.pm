package RT::Extension::ReverseProxy;

use 5.10.1;
use strict;
use warnings;

our $VERSION = '0.9.0';

sub PSGIWrap {
    my ( $class, $app ) = @_;

    require Plack::Middleware::ReverseProxy;
    my $proxied = Plack::Middleware::ReverseProxy->wrap($app);

    my @trusted = $class->_TrustedCIDRs;

    # No trusted proxies configured: honour X-Forwarded-* from any client
    # (back-compat default). This is only safe when the PSGI port is not
    # reachable by untrusted clients. See the SECURITY section in the docs.
    return $proxied unless @trusted;

    require Net::CIDR;
    return sub {
        my $env    = shift;
        my $remote = $env->{REMOTE_ADDR};

        # Trusted hop: honour X-Forwarded-* for this request.
        return $proxied->($env)
            if defined $remote
            && length $remote
            && eval { Net::CIDR::cidrlookup( $remote, @trusted ) };

        # Untrusted (or undeterminable) client: ignore X-Forwarded-* entirely.
        return $app->($env);
    };
}

# Read $ReverseProxy_TrustedProxies and return a list of validated CIDR
# strings. Accepts an arrayref, a single string, or a list config; bare
# addresses are promoted to host CIDRs. Invalid entries are logged and
# skipped rather than silently trusting/ignoring everything.
sub _TrustedCIDRs {
    my $class = shift;

    my @raw;
    for my $v ( RT->Config->Get('ReverseProxy_TrustedProxies') ) {
        next unless defined $v;
        push @raw, ref $v eq 'ARRAY' ? @$v : $v;
    }

    require Net::CIDR;
    my @cidrs;
    for my $entry (@raw) {
        next unless defined $entry;
        $entry =~ s/^\s+//;
        $entry =~ s/\s+$//;
        next unless length $entry;

        my $cidr =
              $entry =~ m{/} ? $entry
            : $entry =~ /:/  ? "$entry/128"
            :                  "$entry/32";

        if ( eval { Net::CIDR::cidrvalidate($cidr) } ) {
            push @cidrs, $cidr;
        }
        else {
            RT->Logger->error(
                "ReverseProxy: ignoring invalid \$ReverseProxy_TrustedProxies entry '$entry'"
            );
        }
    }

    return @cidrs;
}

1;

__END__

=pod

=head1 NAME

RT::Extension::ReverseProxy - Make RT trust X-Forwarded-* headers behind a reverse proxy

=head1 DESCRIPTION

When RT runs behind a reverse proxy (nginx, haproxy, ...) that terminates TLS
and forwards to C<rt-server>/Starlet over plain HTTP, RT must look at the
C<X-Forwarded-*> request headers to learn the real scheme, host, port and
client IP. Otherwise it sees every request as e.g. C<http://host:9000> instead
of C<https://rt.example.com:443>, which breaks absolute-URL generation,
C<$RestrictReferrer>, inline edit, and secure cookies.

This extension wraps the RT PSGI application with
L<Plack::Middleware::ReverseProxy> so the forwarded headers are honoured. It
adds a B<trusted-proxy> option so the forwarded headers are only believed when
the request actually comes from your proxy.

=head1 RT VERSION

Works with RT 6.0.0 and later.

=head1 WHY THE OBVIOUS APPROACH DOES NOT WORK

The intuitive way to enable this middleware is to pass it to the server:

    rt-server ... -e 'enable "ReverseProxy"'

B<This is silently ignored.> C</opt/rt/sbin/rt-server> (via
C<RT::PlackRunner>) pre-builds the PSGI app and assigns it to
C<< $self->{app} >>. Because L<Plack::Runner> already has an app, it skips its
own C<build_app> step -- which is what would have applied the C<-e> middleware.
The result: the middleware never runs and RT keeps seeing C<http://host:9000>.

The supported, version-stable hook is instead the per-plugin C<PSGIWrap>
method. C<RT::Interface::Web::Handler::PSGIApp> wraps the app with every active
plugin that provides one:

    for my $plugin (RT->Config->Get("Plugins")) {
        my $wrap = $plugin->can("PSGIWrap") or next;
        $app = $wrap->($plugin, $app);
    }

This extension implements C<PSGIWrap>, so simply activating the plugin is
enough -- and you should B<remove> any dead C<-e 'enable "ReverseProxy"'> from
your C<rt-server> invocation.

=head1 INSTALLATION

=over

=item C<perl -I. Makefile.PL>

The C<-I.> is required: modern Perl does not keep C<.> in C<@INC>, and
C<use inc::Module::Install> must find the bundled F<inc/> directory.

=item C<make>

=item C<make install>

May need root permissions.

=item Edit your F</opt/rt/etc/RT_SiteConfig.pm>

    Plugin('RT::Extension::ReverseProxy');

=item Remove the dead middleware from your server invocation

If your C<rt-server> / service unit still passes
C<-e 'enable "ReverseProxy"'>, remove it -- it never worked (see above) and is
now superseded by this plugin.

=item Clear your Mason cache and restart the webserver

    rm -rf /opt/rt/var/mason_data/obj

=back

=head1 CONFIGURATION

=head2 C<$ReverseProxy_TrustedProxies>

A list of IP addresses and/or CIDR ranges (IPv4 or IPv6) that are allowed to
set C<X-Forwarded-*>. The value is the address of the host that connects to
C<rt-server> (i.e. C<REMOTE_ADDR>), which for a local nginx/haproxy is usually
the loopback address.

    Set( $ReverseProxy_TrustedProxies, [ '127.0.0.1', '::1', '10.0.0.0/24' ] );

When a request arrives from a trusted address, its C<X-Forwarded-*> headers are
applied. When it arrives from any other address, the headers are B<ignored> and
RT uses the real connection details.

B<Default (unset): trust all clients.> If C<$ReverseProxy_TrustedProxies> is
not set, C<X-Forwarded-*> from B<any> client is honoured -- matching the plain
L<Plack::Middleware::ReverseProxy> behaviour. This is only safe when the PSGI
port is not reachable by untrusted clients (e.g. it binds to C<127.0.0.1> and
only the proxy connects to it). If the PSGI port is exposed, a client can spoof
C<X-Forwarded-For>/C<-Proto>/C<-Host>; set C<$ReverseProxy_TrustedProxies> to
prevent that.

Changes take effect at server start, so restart C<rt-server> after editing.

=head1 HOW IT WORKS

At application build time RT calls C<< RT::Extension::ReverseProxy->PSGIWrap($app) >>.
We wrap C<$app> with L<Plack::Middleware::ReverseProxy>. If
C<$ReverseProxy_TrustedProxies> is set, the wrap is gated: for each request we
test C<REMOTE_ADDR> against the configured ranges with L<Net::CIDR> and only
run the middleware for trusted peers; untrusted peers bypass it untouched.

Note: when both C<X-Forwarded-Host> and C<X-Forwarded-Port> are present,
L<Plack::Middleware::ReverseProxy> sets C<HTTP_HOST> to C<host:port> (e.g.
C<rt.example.com:443>). This is harmless; RT normalises the host and port.

=head1 VERIFICATION

Without this plugin, RT computes request URLs from the raw connection. With it
active and a request carrying C<X-Forwarded-Proto: https> and
C<X-Forwarded-Host: rt.example.com>, RT's C<GetWebURLFromRequest()> resolves to
C<https://rt.example.com> instead of C<http://host:9000>, the
C<$RestrictReferrer> domain warning disappears, and inline edit works.

=head1 DEPENDENCIES

=over

=item L<Plack::Middleware::ReverseProxy> (ships as an RT dependency)

=item L<Net::CIDR> (only used when C<$ReverseProxy_TrustedProxies> is set)

=back

=head1 AUTHOR

NETWAYS GmbH E<lt>support@netways.deE<gt>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by NETWAYS GmbH

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991

=cut
