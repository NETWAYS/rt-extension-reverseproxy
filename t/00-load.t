use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib";
use TestHelper;

ok( $RT::Extension::ReverseProxy::VERSION, 'module loaded with VERSION set' );
can_ok( 'RT::Extension::ReverseProxy', 'PSGIWrap' );

done_testing;
