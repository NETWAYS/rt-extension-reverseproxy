use inc::Module::Install;

RTx     'RT-Extension-ReverseProxy';
license 'gpl_2';
repository 'https://github.com/NETWAYS/rt-extension-reverseproxy';
readme_from 'lib/RT/Extension/ReverseProxy.pm';

requires_rt '6.0.0';

requires 'Plack::Middleware::ReverseProxy';
requires 'Net::CIDR';

WriteAll;
