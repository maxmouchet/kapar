#!/usr/bin/env perl
#
# $Id: plot-addr-period-distribution.pl,v 1.1 2008/07/07 17:35:37 kkeys Exp $
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

my @num;
my @period;
my @stddev;
my $file = $ARGV[0];
open(DATA, $file) or die "could not open $file: $!";
while (<DATA>) {
    chomp;
    next if (/^#/ or /^\s*$/);
    my ($n, $p, $sd) = split /\s/;
    push @num, $n;
    push @period, $p;
    push @stddev, $sd;
}
close DATA;

plot_mean("addr-period-distribution.png");
plot_stddev("addr-period-stddev.png");
plot_num("addr-period-num.png");

sub plot_mean($) {
    my ($out) = @_;

    my @sorted = sort {$a <=> $b} @period;
    open(GP, "|gnuplot >$out") or die "could not gnuplot: $!\n";
    #open(GP, ">/dev/tty") or die "could not gnuplot: $!\n";
    print GP "set title \"distribution of mean period of intermediate addresses\"\n";
    print GP "set terminal png\n";
    print GP "set key right bottom\n";
    print GP "set xlabel \"mean period\"\n";
    print GP "set ylabel \"number of addresses with mean period <= x\"\n";
    print GP "set data style linespoints\n";

    print GP "plot [0:] [0:] '-' using 1:2 w lp t \"cdf\"\n";

    my $i;
    for ($i = 1; $i <= $#sorted; $i++) {
	if ($sorted[$i] != $sorted[$i-1]) {
	    print GP $sorted[$i-1], "\t", $i, "\n";
	}
    }
    print GP $sorted[$i-1], "\t", $i, "\n";
}

sub plot_stddev($) {
    my ($out) = @_;

    my @sorted = sort {$a <=> $b} @stddev;
    open(GP, "|gnuplot >$out") or die "could not gnuplot: $!\n";
    #open(GP, ">/dev/tty") or die "could not gnuplot: $!\n";
    print GP "set title \"distribution of std.dev. of period of intermediate addresses\"\n";
    print GP "set terminal png\n";
    print GP "set key right bottom\n";
    print GP "set xlabel \"standard deviation of period\"\n";
    print GP "set ylabel \"number of addresses with std.dev. <= x\"\n";
    print GP "set data style linespoints\n";

    print GP "plot [0:] [0:] '-' using 1:2 w lp t \"cdf\"\n";

    my $i;
    for ($i = 1; $i <= $#sorted; $i++) {
	if ($sorted[$i] != $sorted[$i-1]) {
	    print GP $sorted[$i-1], "\t", $i, "\n";
	}
    }
    print GP $sorted[$i-1], "\t", $i, "\n";
}

sub plot_num($) {
    my ($out) = @_;

    my @sorted = sort {$a <=> $b} @num;
    open(GP, "|gnuplot >$out") or die "could not gnuplot: $!\n";
    #open(GP, ">/dev/tty") or die "could not gnuplot: $!\n";
    print GP "set title \"distribution of ??? of period of intermediate addresses\"\n";
    print GP "set terminal png\n";
    print GP "set key right bottom\n";
    print GP "set xlabel \"??? of period\"\n";
    print GP "set ylabel \"number of addresses with ??? <= x\"\n";
    print GP "set data style linespoints\n";

    print GP "plot [0:] [0:] '-' using 1:2 w lp t \"cdf\"\n";

    my $i;
    for ($i = 1; $i <= $#sorted; $i++) {
	if ($sorted[$i] != $sorted[$i-1]) {
	    print GP $sorted[$i-1], "\t", $i, "\n";
	}
    }
    print GP $sorted[$i-1], "\t", $i, "\n";
}


exit 0;
