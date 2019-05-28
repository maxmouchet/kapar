#!/usr/bin/env perl
#
# $Id: plot-addr-appearances.pl,v 1.1 2008/07/07 17:35:37 kkeys Exp $
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

my @hist;
my $file = $ARGV[0];
open(DATA, $file) or die "could not open $file: $!";
while (<DATA>) {
    chomp;
    if (/# total addresses:\s*(\d+)/) {
	$hist[1] = $1;
    }
    next if (/^#/ or /^\s*$/);
    my ($n, $mean, $sd) = split /\s/;
    $hist[$n]++;
    $hist[1]--;
}
close DATA;

plot("addr-appearances.png");

sub plot($) {
    my ($out) = @_;
    open(GP, "|gnuplot >$out") or die "could not gnuplot: $!\n";
    #open(GP, ">/dev/tty") or die "could not gnuplot: $!\n";
    print GP "set title \"intermediate address appearances\"\n";
    print GP "set terminal png\n";
    print GP "set xlabel \"number of cycles\"\n";
    print GP "set ylabel \"number of addresses\"\n";
    print GP "set logscale y\n";
    print GP "set data style linespoints\n";

    #my $step = int(($#data + 10) / 10);
    ## print "n=$#data\n";
    ## print "step=$step\n";
    #print GP "set xtics (\"", xlabel($data[0][0]), "\" 0";
    #for (my $i = 1; $i <= $#data; $i++) {
    #    if (($i % $step) == 0) {
    #        print GP ", \"", xlabel($data[$i][0]), "\" $i";
    #    } else {
    #        # print GP ", \"\" $i 1"; # unlabelled minor tick
    #    }
    #}
    #print GP ")\n";

    print GP "plot '-' using (\$0 + 1):(\$1) w lp ",
	"t \"number of addrs appearing in exactly x cycles\"\n";

    for (my $i = 1; $i <= $#hist; $i++) {
	print GP $hist[$i] || 0, "\n";
	if ($i < 5) { print $hist[$i] || 0, "\n"; }
    }
}

exit 0;
