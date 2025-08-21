#!/usr/bin/env perl

use strict;
use warnings;

my ($out, $fdout) = ("nist_ecdsa.json");
my ($state, $i, $first) = (0, 0, 1);
my ($bufpre, $buf, $bufpost) = ("", "", "");
my ($in, $fdin, $line);

my ($curve, $curvere) = ("", '^\[([A-Z]-[0-9][0-9][0-9]*)');
my ($msg, $msgre) = ("", '^Msg = ([0-9a-f]*)');
my ($priv_d, $priv_dre) = ("", '^d = ([0-9a-f]*)');
my ($pub_x, $pub_xre) = ("", '^Qx = ([0-9a-f]*)');
my ($pub_y, $pub_yre) = ("", '^Qy = ([0-9a-f]*)');
my ($rand_k, $rand_kre) = ("", '^k = ([0-9a-f]*)');
my ($sig_r, $sig_rre) = ("", '^R = ([0-9a-f]*)');
my ($sig_s, $sig_sre) = ("", '^S = ([0-9a-f]*)');

sub print_begin_tests {
    $buf .= ",\n" if ($first != 1);
    $buf .= <<__;
    {
      "tests" : [
__
    $first = 0;
}

sub print_test {
    $buf .= <<__;
        {
          "tcId" : $i,
          "curve" : "$curve",
          "msg" : "$msg",
          "d"   : "$priv_d",
          "x"   : "$pub_x",
          "y"   : "$pub_y",
          "sig_r" : "$sig_r",
          "sig_s" : "$sig_s"
__
    $buf .= "        },";

    $i = $i + 1;
    $msg = "";
    $priv_d = "";
    $pub_x = "";
    $pub_y = "";
    $sig_r = "";
    $sig_s = "";
}

sub print_end_tests {
    $buf .= "\n      ]\n";
    $buf .= "    }";
}

printf("Parsing NIST ECDSA test vectors ...\n");

for (@ARGV) {
    $in=$_;
    open($fdin, '<', $in) || die("ERROR: couldn't open $in ($!).");

    print_begin_tests();

    $state = 0;

    while ($line = <$fdin>) {
        chomp($line);

        $curve = $1 if ($line =~ /$curvere/);
        $msg = $1 if ($line =~ /$msgre/);
        $priv_d = $1 if ($line =~ /$priv_dre/);
        $pub_x = $1 if ($line =~ /$pub_xre/);
        $pub_y = $1 if ($line =~ /$pub_yre/);
        $rand_k = $1 if ($line =~ /$rand_kre/);
        $sig_r = $1 if ($line =~ /$sig_rre/);
        $sig_s = $1 if ($line =~ /$sig_sre/);

        if ($state == 0 && $line =~ /$msgre/) {
            $state = 1;
            next;
        }
        if ($state == 1 && $line =~ /$sig_sre/) {
            print_test() if ($curve eq "P-256" || $curve eq "P-384" || $curve eq "P-521");
            $state = 0;
            next;
        }
    }

    print_end_tests();
    close($fdin);
}

$bufpre = <<__;
{
  "algorithm" : "ECDSA",
  "numberOfTests" : $i,
  "testGroups" : [
__
$bufpost = "\n  ]\n}";

$buf = $bufpre . $buf . $bufpost;

# Expect 150
printf("$i test vectors found.\n");

open($fdout, '>', $out) || die("ERROR: couldn't open $out ($!).");
print({$fdout}$buf);
close($fdout);
