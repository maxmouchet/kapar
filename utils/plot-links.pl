#!/usr/bin/env perl
#
# $Id: plot-links.pl,v 1.1 2008/07/07 17:35:37 kkeys Exp $
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
plot("links.png", "");
plot("links-zoom.png", "150000");

sub plot($$) {
    my ($out, $ymax) = @_;
    open(GP, "|gnuplot >$out") or die "could not gnuplot: $!\n";
#open(GP, ">/dev/tty") or die "could not gnuplot: $!\n";
    print GP "set title \"intermediate links\"\n";
    print GP "set terminal png\n";
    print GP "set xlabel \"cycle\"\n";
    print GP "set ylabel \"number of links\"\n";
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
	"plot [] [0:$ymax] \"$file\" using 0:4 w lp t \"never seen again\", ",
	"\"$file\" using 0:3 w lp t \"never seen before\", ",
	"\"$file\" using 0:2 w lp t \"total in cycle\", ",
	"\"$file\" using 0:5 w lp t \"unique to this cycle\"\n";
}

exit 0;
