#!/usr/bin/perl -w

use strict;
use Net::RawIP;

my $a = new Net::RawIP({ip => { ttl => 0},
                        udp => { source => 22, dest => 23}});
$a->ethnew("eth0");
$a->ethset(source => 'de:ad:de:ad:de:ad',
           dest => 'de:ad:de:ad:de:ad');
$a->ethsend;
