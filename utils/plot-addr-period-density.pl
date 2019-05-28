#!/usr/bin/env perl
#
# $Id: plot-addr-period-density.pl,v 1.1 2008/07/07 17:35:37 kkeys Exp $
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

my $cycles = 108.0;
my @data;
my $file = $ARGV[0];
open(DATA, $file) or die "could not open $file: $!";
while (<DATA>) {
    chomp;
    next if (/^#/ or /^\s*$/);
    my ($n, $mean, $sd) = split /\s/;
    $data[int($mean)][int($cycles/$n)]++;
}
close DATA;

plot("addr-period-density.png");

sub plot($) {
    my ($out) = @_;
    open(GP, "|gnuplot >$out") or die "could not gnuplot: $!\n";
    #open(GP, ">/dev/tty") or die "could not gnuplot: $!\n";
    print GP "set terminal png size 960,720\n";
    print GP "set title \"actual vs. expected mean period\"\n";
    print GP "set xlabel \"actual mean period\"\n";
    print GP "set ylabel \"expected mean period\"\n";
    print GP "set view map\n";

    #print GP "set palette gray negative\n";
    print GP "set palette color negative\n";

    #print GP "set log cb\n";
    # print GP "set cbrange [0:]\n";

    print GP "splot [0:$cycles] [0:", $cycles/2 + 1, "] ",
	"'-' w l t \"\", ",
	"'-' using 1:2:3 w p ps 0.8 pt 5 palette t \"density\"\n";

    print GP "0 0 0\n";
    print GP "$cycles $cycles 0\n";
    print GP "e\n";

    for (my $x = 1; $x <= $cycles; $x++) {
	for (my $y = 1; $y <= $cycles; $y++) {
	    if ($data[$x][$y]) {
		print GP "$x $y ", $data[$x][$y], "\n";
	    }
	}
    }
}

exit 0;
