#! /usr/bin/env perl
# usage: pair-intersect.pl pairfile1 pairfile2...
# prints pairs that exist in every file

use strict;

if (scalar @ARGV < 2) {
    print "usage: pair-intersect.pl pairfile1 pairfile2...\n";
    print "prints pairs that exist in every file\n";
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
	if ($nfiles == 0 || defined $pairs{$pair[0]}{$pair[1]}) {
	    $pairs{$pair[0]}{$pair[1]}++;
	}
    }
    $nfiles++;
}

while (my ($addr1, $ref) = each %pairs) {
    while (my ($addr2, $n) = each %$ref) {
	print "$addr1 $addr2\n" if ($n == $nfiles);
    }
}
