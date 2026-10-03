use strict; use warnings;
use Mail::DKIM::Verifier;
my $raw = do { local $/; <STDIN> };
$raw = "" unless defined $raw;
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
my @sigs = $dkim->signatures;
print "signature_count: ", scalar(@sigs), "\n";
my $i = 0;
for my $sig (@sigs) {
  printf "sig[%d] result=%s detail=%s\n", $i++, $sig->result // 'none', ($sig->result_detail // '');
}
