#! /usr/bin/env perl
# usage: pair-diff.pl pairfile1 pairfile2
# prints pairs that exist in pairfile1 but not pairfile2

use strict;

if (scalar @ARGV != 2) {
    print STDERR "usage: pair-diff.pl pairfile1 pairfile2\n";
    print STDERR "prints pairs that exist in pairfile1 but not pairfile2\n";
    exit 1;
}

print "# command line: $0 ", join(' ', @ARGV), "\n";

my %pairs;
my $nfiles = 0;

for my $file (@ARGV) {
    open IN, "<", $file or die "$file: $!\n";
    while (<IN>) {
	chomp;
	next if (/^#|^$/);
	my @pair = split;
	if ($pair[0] gt $pair[1]) {
	    @pair = reverse @pair;
	}
	if ($nfiles == 0) {
	    # first file: count the pair
	    $pairs{$pair[0]}{$pair[1]}++;
	} elsif (defined $pairs{$pair[0]}{$pair[1]}) {
	    # second file: remove the pair
	    $pairs{$pair[0]}{$pair[1]} = 0;
	}
    }
    $nfiles++;
}

while (my ($addr1, $ref) = each %pairs) {
    while (my ($addr2, $n) = each %$ref) {
	print "$addr1 $addr2\n" if ($n);
    }
}
