#! /usr/bin/env perl
# usage: pair-union.pl pairfile1 pairfile2...
# prints pairs that exist in every file

use strict;

if (scalar @ARGV < 2) {
    print STDERR "usage: pair-union.pl pairfile1 pairfile2...\n";
    print STDERR "prints pairs that exist in any file\n";
    exit 1;
}

print "# command line: $0 ", join(' ', @ARGV), "\n";

my %pairs;

for my $file (@ARGV) {
    open IN, "<", $file or die "$file: $!\n";
    while (<IN>) {
	chomp;
	next if (/^#|^$/);
	my @pair = split;
	if ($pair[0] gt $pair[1]) {
	    @pair = reverse @pair;
	}
	$pairs{$pair[0]}{$pair[1]}++;
    }
}

while (my ($addr1, $ref) = each %pairs) {
    while (my ($addr2, $n) = each %$ref) {
	print "$addr1 $addr2\n";
    }
}
