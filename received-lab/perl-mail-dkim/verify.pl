#!/usr/bin/perl
# K-series: verify a DKIM-signed message from stdin using Mail::DKIM::Verifier.
# Prints "result: <pass|fail|none|invalid>; <detail>".
use strict;
use warnings;
use Mail::DKIM::Verifier;

my $dkim = Mail::DKIM::Verifier->new();
while (my $line = <STDIN>) {
    chomp $line;
    $line =~ s/\r$//;
    $dkim->PRINT("$line\r\n");
}
$dkim->finish_body;

my @sigs = $dkim->signatures;
if (@sigs) {
    my $r = $sigs[0]->result // 'none';
    my $d = $sigs[0]->result_detail // '';
    print "result: $r; $d\n";
} else {
    print "result: none; no signature found\n";
}
