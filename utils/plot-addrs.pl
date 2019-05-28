#!/usr/bin/env perl
#
# $Id: plot-addrs.pl,v 1.2 2011/09/21 19:34:22 kkeys Exp $
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

my @data;
my $file = $ARGV[0];
open(DATA, $file) or die "could not open $file: $!";
while (<DATA>) {
    chomp;
    next if (/^#/ or /^\s*$/);
    push @data, [ split /\s/ ];
}
close DATA;
plot("addrs.png", "");
plot("addrs-zoom.png", "100000");

sub plot($$) {
    my ($out, $ymax) = @_;
    open(GP, "|gnuplot >$out") or die "could not gnuplot: $!\n";
#open(GP, ">/dev/tty") or die "could not gnuplot: $!\n";
    print GP "set title \"intermediate addresses\"\n";
    print GP "set terminal png\n";
    print GP "set xlabel \"cycle\"\n";
    print GP "set ylabel \"number of addresses\"\n";
    print GP "set data style linespoints\n";

    my $step = int(($#data + 10) / 10);
    print "n=$#data\n";
    print "step=$step\n";
    print GP "set xtics (\"", xlabel($data[0][0]), "\" 0";
    for (my $i = 1; $i <= $#data; $i++) {
	if (($i % $step) == 0) {
	    print GP ", \"", xlabel($data[$i][0]), "\" $i";
	} else {
	    # print GP ", \"\" $i 1"; # unlabelled minor tick
	}
    }
    print GP ")\n";

    print GP
	"plot [] [0:$ymax] ",
	"\"$file\" using 0:4 w lp t \"never seen again\", ",
	"\"$file\" using 0:3 w lp t \"never seen before\", ",
	"\"$file\" using 0:7 w lp t \"reverse total\", ",
	"\"$file\" using 0:6 w lp t \"forward total\", ",
#	"\"$file\" using 0:2 w lp t \"total in cycle\", ",
	"\"$file\" using 0:5 w lp t \"unique to this cycle\"\n";
}

exit 0;
