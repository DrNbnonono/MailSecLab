use Mail::DKIM::Verifier;
my $path = $ARGV[0];
open my $fh, '<', $path or die $!;
binmode $fh; local $/; my $raw = <$fh>; close $fh;
my $dkim = Mail::DKIM::Verifier->new();
$dkim->PRINT($raw); $dkim->finish_body;
my $i = 0;
for my $sig ($dkim->signatures) {
  printf "sig[%d] result=%s detail=%s\n", $i++, $sig->result // 'none', ($sig->result_detail // '');
}
