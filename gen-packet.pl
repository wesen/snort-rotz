#!/usr/bin/perl -w
#
# Generates and sends packets matching snort rules
# $Id: gen-packet.pl,v 1.5 2002-01-22 01:47:07 manuel Exp $

use strict;
use Net::RawIP;

my @srcips = qw(192.168.23.2 192.168.23.3);
my @destips = qw(192.168.23.135);
my $ethint = "eth0";

while (<>) {
   if (/^(alert|log) (.*?) (.*?) (.*?) .*? (.*?) (.*?) \((.*)\)/) {
      my ($proto, $srcip, $srcport, $dstip, $dstport, $params) = 
         ($2,     $3,     $4,       $5,     $6,       $7);
      my (%params, %pktparams, %ipparams);
      my ($payload);

      print "proto $proto, srcip $srcip, srcport $srcport\n";
      print "dstip $dstip, dstport $dstport\n";
      print "params: $params\n";

      while ($params =~ /\s?(.*?);/g) {
         my $opt = $1;
         if ($opt =~ /(.*?):(.*)/) {
            $params{$1} = $2;
            print "$1: $2\n";
         } else {
            $params{$opt} = 1;
         }
      }

      # we don't like fragbits
      next if (defined($params{fragbits}) or
               defined($params{ipoption}));

      # ttl, ip, tos
      $ipparams{daddr} = tbl_rand(@destips);
      if (defined($params{sameip})) {
         $ipparams{saddr} = $ipparams{daddr};
      } else {
         $ipparams{saddr} = tbl_rand(@srcips);
      }
      $ipparams{tos} = $params{tos} if (defined($params{tos}));
      if (defined($params{ttl})) {
         $ipparams{ttl} = $params{ttl};
      } else {
         $ipparams{ttl} = rand 63;
      }
      $ipparams{id} = $params{id} if (defined($params{id}));
      $pktparams{ip} = \%ipparams;

      if (($proto eq "tcp") or ($proto eq "ip")) {
         my %tcpparams;

         if ($srcport eq "any") {
            $tcpparams{source} = rand(65535) + 1;
         } else {
            $tcpparams{source} = $srcport;
         }
         if ($dstport eq "any") {
            $tcpparams{dest} = rand(65535) + 1;
         } else {
            $tcpparams{dest} = $dstport;
         }

         # seq, ack
         $tcpparams{seq} = $params{seq} if (defined($params{seq}));
         $tcpparams{ack} = $params{ack} if (defined($params{ack}));

         $tcpparams{data} = gen_content($params{content},
                                        $params{offset},
                                        $params{dsize});

         # flags: (F, S, R, P, A, U, 2, 1, 0)
         # We don't catch "!+*"
         if (defined($params{flags})) {
            my %bla = (F => "fin",
                       S => "syn",
                       R => "rst",
                       P => "psh",
                       A => "ack",
                       U => "urg",
                       2 => "res2",
                       1 => "res1");

            foreach my $key (keys %bla) {
               $tcpparams{$bla{$key}} = 1 if ($params{flags} =~ /$key/);
            }
         }

         $pktparams{tcp} = \%tcpparams;
      } elsif ($proto eq "udp") {
         my %udpparams;

         if ($srcport eq "any") {
            $udpparams{source} = rand(65535) + 1;
         } else {
            $udpparams{source} = $srcport;
         }
         if ($dstport eq "any") {
            $udpparams{dest} = rand(65535) + 1;
         } else {
            $udpparams{dest} = $dstport;
         }

         $udpparams{data} = gen_content($params{content},
                                        $params{offset},
                                        $params{dsize});

         $pktparams{udp} = \%udpparams;
      } elsif($proto eq "icmp") {
         my %icmpparams;

         # itype, icode, icmp_id, icmp_seq
         $icmpparams{sequence} = $params{icmp_seq} 
             if (defined($params{icmp_seq}));
         $icmpparams{type} = $params{itype} 
             if (defined($params{itype}));
         $icmpparams{code} = $params{icode} 
             if (defined($params{icode}));
         $icmpparams{id} = $params{icmp_id} 
             if (defined($params{icmp_id}));

         $icmpparams{data} = gen_content($params{content},
                                        $params{offset},
                                        $params{dsize});
         $pktparams{icmp} = \%icmpparams;
      }

      my $pkt = new Net::RawIP(\%pktparams);
      $pkt->ethnew($ethint);
      $pkt->ethset(source => 'de:ad:de:ad:be:ef',
                   dest => 'de:ad:be:ef:08:15');
      $pkt->ethsend;

      print "*************************\n";
   }
}

sub tbl_rand {
   return $_[rand($#_ + 1)];
}

sub gen_content {
   my ($content, $offset, $size) = @_;
   my $data = "";

   if (defined($content)) {
      $content =~ s/^"//;
      $content =~ s/"$//;
      $content =~ s/\\"/"/g;
      $content =~ s/\\:/:/g;

      while (length($content) > 0) {
         if ($content =~ s/^([^\|]*)//) {
            # handle escape characters
            $data .= $1;
         }
         if ($content =~ s/^\|(.*)\|//) {
            my $str = $1;
            $str =~ s/\s+//g;
            $str =~ s/(..)/$1 /g;
            print "content: $str\n";
            my @values = split(/\s/, $str);
            $data .= pack("C*", map(hex, @values));
         }
      }
   }

   $data = ((' ' x $offset) . $data) if (defined($offset));
   if (defined($size)) {
      if ($size =~ />([0-9]*)/) {
         $size = $1 + 1;
      } elsif ($size =~ /<([0-9]*)/) {
         $size = $1 - 1;
      }
      print "length ".length($data)." size $size\n";
      $data .= (' ' x ($size - length($data)));
   }

   return $data;
}
