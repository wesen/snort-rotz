#!/usr/bin/perl -w
#
# Generates and sends packets matching snort rules
# $Id: gen-packet.pl,v 1.10 2002-01-28 01:54:17 manuel Exp $
#
# TODO: uricontent, regex, rpc

use strict;
use Net::IPv4Addr qw( ipv4_parse );
use Net::RawIP;

################# 
# Configuration #
#################

# Our source IPs (match EXTERNAL_NET in snort config)
my @srcips = qw(192.168.23.2 192.168.23.3);

# Our destination IPs (match HOME_NET in snort config)
my @destips = qw(192.168.10.3);

# Interface we want to send our packets from
my $ethint = "eth0";

# Are we on the same network, so we can spoof destination addresses too?
my $localnet = 1;

# Do we want debug?
#my $debug = "rule,payload,params";
my $debug = "rule,params";

####################
# Helper functions #
####################

sub tbl_rand {
   return $_[int(rand($#_ + 1))];
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

################################
# Content generation functions #
################################

# Generate a matching port number
sub gen_port {
   my $port = shift;

   if ($port =~ /^:(.*)$/) {
      $port = $1
   } else {
      $port =~ s/:.*$//;
   }
   
   if ($port =~ /!([0-9]*)$/) {
      $port = $1 + 1;
   }

   if ($port eq "any") {
      return int(rand(65535) + 1);
   } else {
      return $port;
   }
}

# Generate a matching IP
sub gen_ip {
   my $ipstr = shift;

   if ($ipstr =~ /(HOME_NET|SMTP|HTTP_SERVER|SQL_SERVER)/) {
      return tbl_rand(@destips);
   } elsif ($ipstr =~ /EXTERNAL_NET/) {
      return tbl_rand(@srcips);
   } else {
      # Multiple IPs
      if ($ipstr =~ /\[(.*?),.*\]/) {
         $ipstr = $1;
      }
   
      # Explicit IP or netmask
      if ($ipstr =~ /[0-9]\./) {
         my ($ip, $cidr) = ipv4_parse($ipstr);

         # Netmask
         if (defined($cidr) and defined($ip)) {
            my $nip = ip_to_int($ip);
            $nip = $nip + (int(rand (2 ** 32 + 1)) % (2 ** (32 - $cidr)));
            return int_to_ip($nip);
         } elsif (defined($ip)) {
            return $ip;
         } else {
            return undef;
         }
      } else {
         return undef;
      }
   }
}

# Generate random padding data
sub gen_rand_tbl {
   my ($len) = @_;
   my @pad;

   push @pad, int(rand(256)) for (1 .. $len);
   return @pad;
}

sub gen_num {
   my $str = shift;

   if ($str =~ /^>([0-9]*)/) {
      return ($1 + 1);
   } elsif ($str =~ /^<([0-9]*)/) {
      return ($1 - 1);
   } elsif ($str =~ /^!([0-9]*)/) {
      return $str + 1;
   } else {
      return $str;
   }
}

# Generate a matching packet content
sub gen_content {
   my ($content) = @_;
   my @data;

   if (defined($content)) {
      $content =~ s/\\"/"/g;
      $content =~ s/\\:/:/g;

      while (defined($content) and (length($content) > 0)) {
         if ($content =~ s/^([^\|]+)//) {
            my $str = $1;

            $str =~ s/[^\\]\\$/|/;
            $str =~ s/\\(.)/$1/g;

            # handle escape characters
            push(@data, map(ord, split(//, $str)));
         }
         if ($content =~ s/^\|(.+?)\|//) {
            my $str = $1;
            $str =~ s/\s+//g;
            $str =~ s/(..)/$1 /g;
            my @values = split(/\s/, $str);
            push(@data, map(hex, @values));
         } elsif ($content =~ /^\|$/) {
            # Handle special case (\|)
            return @data;
         } 
      }
   }

   return @data;
}

#########################################
# Layer parameters generation functions #
#########################################

# Generate the IP parameters
sub gen_ipparams {
   my ($srcip, $dstip, $params) = @_;
   my (%ipparams, $ip);

   # Destination IP
   if (($localnet == 1) && defined($ip = gen_ip($dstip))) {
      $ipparams{daddr} = $ip;
   } else {
      $ipparams{daddr} = tbl_rand(@destips);
   }

   if (defined($ip = gen_ip($srcip))) {
      $ipparams{saddr} = $ip;
   } else {
      $ipparams{saddr} = tbl_rand(@srcips);
   }

   if (defined($params->{sameip})) {
      $ipparams{saddr} = $ipparams{daddr};
   }

   $ipparams{tos} = $params->{tos} if (defined($params->{tos}));
   if (defined($params->{ttl})) {
      $ipparams{ttl} = gen_num($params->{ttl});
   } else {
      $ipparams{ttl} = int(rand(63));
   }
   $ipparams{id} = $params->{id} if (defined($params->{id}));

   return \%ipparams;
}

# Generate the TCP parameters
sub gen_tcpparams {
   my ($srcport, $dstport, $params, $payload) = @_;
   my %tcpparams;

   $tcpparams{source} = gen_port($srcport);
   $tcpparams{dest} = gen_port($dstport);
   
   # seq, ack
   $tcpparams{seq} = gen_num($params->{seq}) if (defined($params->{seq}));
   $tcpparams{ack_seq} = gen_num($params->{ack}) if (defined($params->{ack}));
   
   $tcpparams{data} = $payload;
   
   # flags: (F, S, R, P, A, U, 2, 1, 0)
   if (defined($params->{flags})) {
      my %bla = (F => "fin",
                 S => "syn",
                 R => "rst",
                 P => "psh",
                 A => "ack",
                 U => "urg",
                 2 => "res2",
                 1 => "res1");
      
      foreach my $key (keys %bla) {
         $tcpparams{$bla{$key}} = 1 if ($params->{flags} =~ /$key/);
      }
   }

   return \%tcpparams;
}

# Generate the UDP parameters
sub gen_udpparams {
   my ($srcport, $dstport, $params, $payload) = @_;
   my %udpparams;

   $udpparams{source} = gen_port($srcport);
   $udpparams{dest} = gen_port($dstport);
   
   $udpparams{data} = $payload;
   
   return \%udpparams;
}

# Generate the ICMP headers
sub gen_icmpparams {
   my ($params, $payload) = @_;
   my %icmpparams;
   
   # itype, icode, icmp_id, icmp_seq
   $icmpparams{sequence} = gen_num($params->{icmp_seq}) 
      if (defined($params->{icmp_seq}));
   $icmpparams{type} = gen_num($params->{itype}) 
      if (defined($params->{itype}));
   $icmpparams{code} = gen_num($params->{icode}) 
      if (defined($params->{icode}));
   $icmpparams{id} = gen_num($params->{icmp_id}) 
      if (defined($params->{icmp_id}));
   
   $icmpparams{data} = $payload;

   return \%icmpparams;
}

###################
# Debug functions #
###################

# Debug payload
sub debug_payload {
   my ($payload) = @_;

   print "payload real ".join(" ", (map { sprintf "%02x", $_ }
            unpack("C*", $payload)))."\n";
   print "payload real ".join(" ", (map { sprintf "%c", $_ }
            unpack("C*", $payload)))."\n";
}

# Debug parameter list
sub debug_params {
   my ($params) = @_;

   foreach my $key (keys %{$params}) {
      print "$key\: ".$params->{$key}."\n" if (!($key eq "data"));
   }
}

#############
# Main loop #
#############

while (<>) {
   my $rule = $_;

   if (/^(alert|log) (.*?) (.*?) (.*?) .*? (.*?) (.*?) \((.*)\)/) {
      my ($proto, $srcip, $srcport, $dstip, $dstport, $params) = 
         ($2,     $3,     $4,       $5,     $6,       $7);
      my (%pktparams, %params);
      my (@payload, $payload);

      print "rule: $rule" if ($debug =~ /rule/);

      while ($params =~ /\s?(.*?)\"?\s*\;/g) {
         my $opt = $1;
         if ($opt =~ /(.*?)\:\s*\"?(.*)/) {
            if ($1 eq "content") {
               my @tmpdata = gen_content($2);
               if (defined($params{depth}) and 
                     ($params{depth} > $#payload)) {
                  for (my $i = $#payload + 1; $i < $params{depth}; $i++) {
                     push (@payload, int(rand(256)));
                  }
               }
               push(@payload, @tmpdata);
            } else {
               $params{$1} = $2;
            }
         } else {
            $params{$opt} = 1;
         }
      }
      if (defined($params{dsize}) && ($params{dsize} =~ />([0-9]*)/)) {
         my $size = $1 + 1;
         push(@payload, gen_rand_tbl($size - $#payload));
      }

      $payload = pack("C*", @payload);
      
      # we don't like fragbits
      next if (defined($params{fragbits}) or
               defined($params{ipoption}));

      # we don't like packets that are too big (in fact, Net::RawIP
      # doesn't)
      next if ($#payload >= 4000);

      $pktparams{ip} = gen_ipparams($srcip, $dstip, \%params);

      if ($proto eq "tcp") {
         $pktparams{tcp} = gen_tcpparams($srcport, $dstport, \%params, $payload);
         debug_params($pktparams{tcp}) if ($debug =~ /params/);
      } elsif ($proto eq "udp") {
         $pktparams{udp} = gen_udpparams($srcport, $dstport, \%params, $payload);
         debug_params($pktparams{udp}) if ($debug =~ /params/);
      } elsif($proto eq "icmp") {
         $pktparams{icmp} = gen_icmpparams(\%params, $payload);
         debug_params($pktparams{icmp}) if ($debug =~ /params/);
      }

      debug_payload($payload) if ($debug =~ /payload/);
      my $pkt = new Net::RawIP(\%pktparams);
      $pkt->ethnew($ethint);
      $pkt->ethset(source => 'de:ad:de:ad:be:ef',
                   dest => 'de:ad:be:ef:08:15');
      $pkt->ethsend;

      print $params{msg}."\n";
      #<STDIN>;
   }
}
