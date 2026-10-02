#!/usr/bin/perl
# Feed Mail::DKIM the same way the historical verifier did (readline, strip
# one trailing CR/LF, PRINT CRLF), but report both hashes. The newline rewrite
# is a separate step from the verdict.
use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use Mail::DKIM::Verifier;

my $raw = do { local $/; <STDIN> };
$raw = "" unless defined $raw;
print "input_sha256: ", sha256_hex($raw), "\n";
print "input_len: ", length($raw), "\n";

my $dkim = Mail::DKIM::Verifier->new();
my $fed = "";
open my $fh, "<", \$raw or die "open raw: $!";
binmode $fh;
while (my $line = <$fh>) {
    $line =~ s/\r?\n\z//;
    my $out = $line . "\r\n";
    $fed .= $out;
    $dkim->PRINT($out);
}
close $fh;
$dkim->finish_body();

print "fed_sha256: ", sha256_hex($fed), "\n";
print "fed_len: ", length($fed), "\n";
print "normalization: ", ($fed eq $raw ? "identity" : "newline-rewritten"), "\n";

my @sigs = $dkim->signatures;
print "signature_count: ", scalar(@sigs), "\n";
if (!@sigs) {
    print "result: none\n";
    print "detail: no signature found\n";
    exit 0;
}
my $sig = $sigs[0];
my $result = $sig->result;
$result = "none" unless defined $result;
my $detail = $sig->result_detail;
$detail = "" unless defined $detail;
$detail =~ s/[\r\n]+/ /g;
print "result: $result\n";
print "detail: $detail\n";
