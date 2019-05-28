#!/usr/bin/env perl
#
# $Id: plot-link-period-percentiles.pl,v 1.1 2008/07/07 17:35:37 kkeys Exp $
#

use strict;

sub usage {
    print "usage: $0 tabfile\n";
    return;
}

sub xlabel($) {
    my $label = shift;
    $label =~ s/^(....)(....)$/\1\\n\2/;
    return $label;
}

if ($#ARGV+1 != 1) {
    usage;
    exit -1;
}

my $min_appearances = 3;
my @period;
my @stddev;
my %pv;
my $file = $ARGV[0];
open(DATA, $file) or die "could not open $file: $!";
while (<DATA>) {
    chomp;
    next if (/^#/ or /^\s*$/);
    my ($n, $mean, $sd, $min, $p25, $p50, $p75, $max, $mic) = split /\s/;
    next if ($n < $min_appearances);
    push @{$pv{"minimum"}}, $min;
    push @{$pv{"25th percentile"}}, $p25;
    push @{$pv{"50th percentile"}}, $p50;
    push @{$pv{"75th percentile"}}, $p75;
    push @{$pv{"maximum"}}, $max;
    push @{$pv{"maximum intra-cluster"}}, $mic;
}
close DATA;

plot("link-period-percentiles-${min_appearances}.png",
    "minimum",
    "25th percentile",
    "50th percentile",
    "75th percentile",
    "maximum",
    "maximum intra-cluster");

sub plot($@) {
    my ($out, @p) = @_;

    open(GP, "|gnuplot >$out") or die "could not gnuplot: $!\n";
    #open(GP, ">/dev/tty") or die "could not gnuplot: $!\n";
    print GP "set title \"cumulative distribution of period of intermediate links\\nthat appear at least $min_appearances times\"\n";
    print GP "set terminal png size 800,600\n";
    print GP "set key right bottom\n";
    print GP "set xlabel \"period\"\n";
    print GP "set ylabel \"number of links with periods <= x\"\n";
    print GP "set mxtics 10\n";
    print GP "set mytics 2\n";
    print GP "set data style linespoints\n";

    # print GP "plot [0:] [0:] ", $#{$pv{$p[0]}} + 1, " w l t \"total links\"";
    print GP "plot [0:] [0:] ";
    for my $p (@p) {
	print GP "'-' using 1:2 w l " . ($p =~ /cluster/ ? " lw 4" : "") .
	    "t \"${p}\", ";
    }
    print GP " 0 t \"\"\n";

    for my $p (@p) {
	my $i;
	my @sorted = sort {$a <=> $b} @{$pv{$p}};
	for ($i = 1; $i <= $#sorted; $i++) {
	    if ($sorted[$i] != $sorted[$i-1]) {
		print GP $sorted[$i-1], "\t", $i, "\n";
	    }
	}
	print GP $sorted[$i-1], "\t", $i, "\n";
	print GP "e\n";
    }
}

exit 0;
