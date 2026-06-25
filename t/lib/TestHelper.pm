package TestHelper;

use strict;
use warnings;

use lib '/opt/rt/lib', '/opt/rt/local/lib';

# Bootstrap RT just far enough that RT->Config->Get/Set and RT->Logger work
# without touching the database. RT::Init would open a DB connection — we
# explicitly avoid it so unit tests stay hermetic.
require RT;
RT::LoadConfig();
RT::InitLogging();

require RT::Extension::ReverseProxy;

sub config_set {
    my %kv = @_;
    RT->Config->Set( $_ => $kv{$_} ) for keys %kv;
}

sub config_unset {
    RT->Config->Set( $_ => undef ) for @_;
}

1;
