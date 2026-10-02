use strict;
use warnings;
use Mail::DKIM::Verifier;
use Digest::SHA qw(sha256_hex);
use JSON::PP;
binmode STDIN;
local $/;
my $raw = <STDIN> // '';
my $out = { status => 'none', input_sha256 => sha256_hex($raw), signatures => [] };
eval {
    my $dkim = Mail::DKIM::Verifier->new();
    $dkim->PRINT($raw); # Preserve bytes; do not chomp or reconstruct lines.
    $dkim->finish_body;
    for my $sig ($dkim->signatures) {
        my $r = $sig->result // 'none';
        my %states = (pass=>'pass', fail=>'fail', invalid=>'parse-error', temperror=>'temp-error', none=>'none', neutral=>'policy-reject');
        push @{$out->{signatures}}, { status => $states{$r} // 'tool-error', native_result=>$r, detail=>($sig->result_detail // '') };
    }
    $out->{status} = $out->{signatures}[0]{status} if @{$out->{signatures}};
};
if ($@) { $out->{status} = 'tool-error'; $out->{error} = "$@"; }
print encode_json($out), "\n";
