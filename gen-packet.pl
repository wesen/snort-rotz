#!/usr/bin/perl -w
#
# Generates and sends packets matching snort rules
# $Id: gen-packet.pl,v 1.8 2002-01-22 04:24:55 dividuum Exp $

use strict;
use Net::IPv4Addr qw( ipv4_parse );
use Net::RawIP;

my @srcips = qw(192.168.23.2 192.168.23.3);
my @destips = qw(192.168.23.135);
my $ethint = "eth0";

while (<>) {
   my $rule = $_;


   if (/^(alert|log) (.*?) (.*?) (.*?) .*? (.*?) (.*?) \((.*)\)/) {
      my ($proto, $srcip, $srcport, $dstip, $dstport, $params) = 
         ($2,     $3,     $4,       $5,     $6,       $7);
      my (%params, %pktparams, %ipparams);
      my ($payload);


      $dstport =~ s/:.*$//;
      $srcport =~ s/:.*$//;
#print "rule: $rule";

#print "proto $proto, srcip $srcip, srcport $srcport\n";
#print "dstip $dstip, dstport $dstport\n";
#print "params: $params\n";

      while ($params =~ /\s?(.*?);/g) {
         my $opt = $1;
         if ($opt =~ /(.*?):(.*)/) {
            if (defined($params{$1})) {
               $params{$1} .= $2;
            } else {
               $params{$1} = $2;
            }
         } else {
            $params{$opt} = 1;
         }
      }

#print "params: @{[ %params ]}\n";

      # we don't like fragbits
      next if (defined($params{fragbits}) or
               defined($params{ipoption}));

      # ttl, ip, tos
      if ($dstip =~ /EXTERNAL_NET/) {
         $ipparams{daddr} = tbl_rand(@srcips);
      } else {
         $ipparams{daddr} = tbl_rand(@destips);
      }

      if (defined($params{sameip})) {
         $ipparams{saddr} = $ipparams{daddr};
      } elsif ($srcip =~ /(HOME_NET|SMTP|HTTP_SERVER|SQL_SERVER)/) {
         $ipparams{saddr} = tbl_rand(@destips);
      } else {
         if ($srcip =~ /\[(.*?),.*\]/) {
            $srcip = $1;
         }
         if ($srcip =~ /[0-9]\./) {
            my ($ip, $cidr) = ipv4_parse($srcip);
            my $nip = ip_to_int($ip);
            $nip = $nip + ((rand (2 ** 32 + 1)) % (2 ** (32 - $cidr)));
            $ipparams{saddr} = int_to_ip($nip);
         } else {
            $ipparams{saddr} = tbl_rand(@srcips);
         }
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
         $tcpparams{ack_seq} = $params{ack} if (defined($params{ack}));

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

      print $params{msg}."\n";
   }
}

sub tbl_rand {
   return $_[rand($#_ + 1)];
}

sub gen_content {
   my ($content, $offset, $size) = @_;
   my $data = "";

   if (defined($content)) {
      $content =~ s/^\s*"//;
      $content =~ s/"$//;
      $content =~ s/\\"/"/g;
      $content =~ s/\\:/:/g;

      while (length($content) > 0) {
         if ($content =~ s/^([^\|]+)//) {
            # handle escape characters
            $data .= $1;
            if ((substr($1, -1, 1)) eq "\\") {
               $data .= substr($content, 0, 1);
               $content = substr($content, 1);
            }
         }
         if ($content =~ s/^\|(.+?)\|//) {
            my $str = $1;
            $str =~ s/\s+//g;
            $str =~ s/(..)/$1 /g;
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
      return $data if ($size > 4000);
      $data .= (' ' x ($size - length($data)));
   }

   return $data;
}

sub ip_to_int {
   my $ip = shift;

   if ($ip =~ /([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/) {
      return (($1 << 24) + ($2 << 16) + ($3 << 8) + ($4));
   } else {
      return undef;
   }
}

sub int_to_ip {
   my $ip = shift;
   return join(".", map { $_ = ($ip >> $_) & 0xff } my @blah=(24,16,8,0));
}
