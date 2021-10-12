#!/usr/bin/env perl

use strict;
use warnings;

my ($out, $fdout) = ("nist_aes_gcm.json");
my ($state, $i, $j) = (0, 0, 0);
my ($bufpre, $buf, $bufpost, $deconly) = ("", "", "", "");
my ($in, $fdin, $line);

my ($keylen, $keylenre) = (undef, '^\[Keylen = (128|192|256)\]');
my ($ivlen, $ivlenre) = (undef, '^\[IVlen = (\d+)\]');
my ($ptlen, $ptlenre) = (undef, '^\[PTlen = (\d+)\]');
my ($aadlen, $aadlenre) = (undef, '^\[AADlen = (\d+)\]');
my ($taglen, $taglenre) = (undef, '^\[Taglen = (\d+)\]');
my ($count, $countre) = ("", '^Count = (\d+)');
my ($key, $keyre) = ("", '^Key = ([0-9a-f]*)');
my ($iv, $ivre) = ("", '^IV = ([0-9a-f]*)');
my ($ct, $ctre) = ("", '^CT = ([0-9a-f]*)');
my ($aad, $aadre) = ("", '^AAD = ([0-9a-f]*)');
my ($tag, $tagre) = ("", '^Tag = ([0-9a-f]*)');
my ($pt, $ptre) = ("", '^PT = ([0-9a-f]*)');
my ($result, $resultre) = ("valid", '^FAIL');

sub print_begin_tests {
    $buf .= ",\n" if ($state != 0);
    $buf .= <<__;
    {
      "ivSize" : $ivlen,
      "keySize" : $keylen,
      "tagSize" : $taglen,
      "tests" : [
__
    $keylen = undef;
    $ivlen = undef;
    $taglen = undef;
    $ptlen = undef;
    $aadlen = undef;
}

sub print_test {
    $buf .= ",\n" if ($state != 1);
    $buf .= <<__;
        {
          "tcId" : $i,
          "comment" : "$count",
          "key" : "$key",
          "iv" : "$iv",
          "aad" : "$aad",
          "msg" : "$pt",
          "ct" : "$ct",
          "tag" : "$tag",
          "result" : "$result",
          "flags" : [$deconly]
__
    $buf .= "        }";

    $i = $i + 1;
    $key = "";
    $iv = "";
    $ct = "";
    $aad = "";
    $tag = "";
    $pt = "";
    $result = "valid";
}

sub print_end_tests {
    $buf .= "\n      ]\n";
    $buf .= "    }";
}

printf("Parsing NIST AES-GCM test vectors ...\n");

for (@ARGV) {
    $in=$_;
    open($fdin, '<', $in) || die("ERROR: couldn't open $in ($!).");

    if ($in =~ /Decrypt/) {
        $deconly = "\"DecryptOnly\"";
    } else {
        $deconly = "";
    }

    while ($line = <$fdin>) {
        chomp($line);

        $keylen = $1 if ($line =~ /$keylenre/);
        $ivlen = $1 if ($line =~ /$ivlenre/);
        $taglen = $1 if ($line =~ /$taglenre/);
        $ptlen = $1 if ($line =~ /$ptlenre/);
        $aadlen = $1 if ($line =~ /$aadlenre/);

        $key = $1 if ($line =~ /$keyre/);
        $iv = $1 if ($line =~ /$ivre/);
        $ct = $1 if ($line =~ /$ctre/);
        $aad = $1 if ($line =~ /$aadre/);
        $tag = $1 if ($line =~ /$tagre/);
        $pt = $1 if ($line =~ /$ptre/);
        $result ="invalid" if ($line =~ /$resultre/);

	if ($state == 0 && $line =~ /$countre/) {
            print_begin_tests();
            $state = 1;
            $j = $j + 1;
            next;
        }
	if ($state == 1 && $line =~ /$countre/) {
            print_test();
            $state = 2;
            $j = $j + 1;
            next;
        }
	if ($state == 2 && $line =~ /$countre/) {
            print_test();
            $j = $j + 1;
            next;
        }
	if ($state == 2 && $line =~ /$keylenre/) {
            print_test();
            $state = 3;
            next;
        }
	if ($state == 3 && $line =~ /$countre/) {
            print_end_tests();
            print_begin_tests();
            $state = 1;
            $j = $j + 1;
            next;
        }
    }
    close($fdin);
}

print_test();
print_end_tests();

$bufpre = <<__;
{
  "algorithm" : "AES-GCM",
  "numberOfTests" : $i,
  "testGroups" : [
__
$bufpost = "\n  ]\n}";

$buf = $bufpre . $buf . $bufpost;

# Expect 47250
printf("$i test vectors found.\n");
if ($i != $j) {
    die ("ERROR: expected $j test vectors");
}

open($fdout, '>', $out) || die("ERROR: couldn't open $out ($!).");
print({$fdout}$buf);
close($fdout);
