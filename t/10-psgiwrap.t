use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib";
use TestHelper;

# These tests exercise the real Plack::Middleware::ReverseProxy through our
# PSGIWrap, so the mechanism under test is the actual middleware chain RT uses.
plan skip_all => 'Plack::Middleware::ReverseProxy not installed'
    unless eval { require Plack::Middleware::ReverseProxy; 1 };

# Build a minimal-but-complete PSGI env. Plack::Middleware::ReverseProxy only
# rewrites psgi.url_scheme / HTTP_HOST / SERVER_PORT / REMOTE_ADDR.
sub env {
    my %override = @_;
    return {
        REQUEST_METHOD    => 'GET',
        SCRIPT_NAME       => '',
        PATH_INFO         => '/',
        REQUEST_URI       => '/',
        SERVER_NAME       => 'localhost',
        SERVER_PORT       => 9000,
        SERVER_PROTOCOL   => 'HTTP/1.1',
        HTTP_HOST         => 'localhost:9000',
        REMOTE_ADDR       => '127.0.0.1',
        'psgi.version'    => [ 1, 1 ],
        'psgi.url_scheme' => 'http',
        'psgi.input'      => undef,
        'psgi.errors'     => \*STDERR,
        %override,
    };
}

# Headers a TLS-terminating proxy would add.
my %FWD = (
    HTTP_X_FORWARDED_PROTO => 'https',
    HTTP_X_FORWARDED_HOST  => 'rt.example.com',
    HTTP_X_FORWARDED_PORT  => '443',
);

# Wrap a capturing inner app, run one request, return the env the inner app saw.
sub seen_by_inner {
    my %override = @_;
    my $captured;
    my $inner = sub {
        $captured = shift;
        return [ 200, [ 'Content-Type' => 'text/plain' ], ['ok'] ];
    };
    my $wrapped = RT::Extension::ReverseProxy->PSGIWrap($inner);
    $wrapped->( env(%override) );
    return $captured;
}

subtest 'default (no trusted proxies): forwarded headers are honoured' => sub {
    TestHelper::config_unset('ReverseProxy_TrustedProxies');
    my $e = seen_by_inner(%FWD);
    is( $e->{'psgi.url_scheme'}, 'https', 'scheme rewritten to https' );
    is( $e->{SERVER_PORT}, 443, 'port rewritten to 443' );
    like( $e->{HTTP_HOST}, qr/^rt\.example\.com\b/, 'host rewritten to forwarded host' );
};

subtest 'trusted peer: forwarded headers are honoured' => sub {
    TestHelper::config_set( ReverseProxy_TrustedProxies => ['127.0.0.1'] );
    my $e = seen_by_inner( %FWD, REMOTE_ADDR => '127.0.0.1' );
    is( $e->{'psgi.url_scheme'}, 'https', 'trusted REMOTE_ADDR → rewrite applied' );
};

subtest 'untrusted peer: forwarded headers are ignored' => sub {
    TestHelper::config_set( ReverseProxy_TrustedProxies => ['10.0.0.0/24'] );
    my $e = seen_by_inner( %FWD, REMOTE_ADDR => '127.0.0.1' );
    is( $e->{'psgi.url_scheme'}, 'http', 'untrusted REMOTE_ADDR → no rewrite' );
    is( $e->{SERVER_PORT}, 9000, 'port left untouched' );
    is( $e->{HTTP_HOST}, 'localhost:9000', 'host left untouched' );
};

subtest 'CIDR range matches' => sub {
    TestHelper::config_set( ReverseProxy_TrustedProxies => ['10.0.0.0/24'] );
    my $e = seen_by_inner( %FWD, REMOTE_ADDR => '10.0.0.5' );
    is( $e->{'psgi.url_scheme'}, 'https', 'REMOTE_ADDR inside CIDR → rewrite applied' );
};

subtest 'invalid trusted entries are skipped, valid ones still work' => sub {
    TestHelper::config_set(
        ReverseProxy_TrustedProxies => [ 'not-an-ip', '127.0.0.1' ] );
    my $e = seen_by_inner( %FWD, REMOTE_ADDR => '127.0.0.1' );
    is( $e->{'psgi.url_scheme'}, 'https', 'valid entry still trusted despite a bad neighbour' );
};

done_testing;
