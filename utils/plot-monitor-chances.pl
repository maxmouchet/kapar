#!/usr/bin/env perl
#
# $Id: plot-monitor-chances.pl,v 1.1 2008/07/07 17:35:38 kkeys Exp $
#

use strict;
use Getopt::Long;

my @fon;
my $n = 12;
my $maxc = 24;

GetOptions(
    "monitors|n=i" => \$n,
    "cycles|c=i"   => \$maxc)
    or die;

$fon[1][1] = 1;

for (my $c = 2; $c <= $maxc; $c++) {
    for (my $m = 1; $m <= $c && $m <= $n; $m++) {
	$fon[$m][$c] = $fon[$m][$c-1] * $m + $fon[$m-1][$c-1] * ($n-$m+1);
    }
}

print "#  ";
for (my $c = 1; $c <= $maxc; $c++) {
    printf "%10d c", $c;
}
print "\n";
for (my $m = 1; $m <= $n; $m++) {
    printf "%2d:", $m;
    for (my $c = 1; $c <= $maxc; $c++) {
	printf "%12.8f", $fon[$m][$c] / ($n ** ($c-1));
    }
    print "\n";
}

for (my $c = 1; $c <= $maxc; $c++) {
    my $sum = 0;
    for (my $m = $n; $m >= 1; $m--) {
	$fon[$m][$c] += $fon[$m+1][$c];
    }
}

print "#  ";
for (my $c = 1; $c <= $maxc; $c++) {
    printf "%10d c", $c;
}
print "\n";
for (my $m = 1; $m <= $n; $m++) {
    printf "%2d:", $m;
    for (my $c = 1; $c <= $maxc; $c++) {
	printf "%12.8f", $fon[$m][$c] / ($n ** ($c-1));
    }
    print "\n";
}

sub xticincr($) {
    my ($maxc) = @_;
    my $incr = $maxc/10.0;
    my $mult = 1;
    for (my $i = 1; $incr > 10; $i++) {
	$mult *= 10;
	$incr /= 10;
    }
    return $mult * ($incr <= 2 ? 1 : $incr <= 3 ? 2 : $incr <= 6 ? 5 : 10);
}

{
    my $out = "monitor-prob-$n-in-$maxc.png";
    open(GP, "|gnuplot >$out") or die "could not gnuplot: $!\n";
    #open(GP, ">/dev/tty") or die "could not gnuplot: $!\n";
    print GP "set title \"probability of a destination being probed\\nby at least m of $n monitors in c cycles\"\n";
    print GP "set terminal png\n";
    print GP "set key bottom right\n";
    print GP "set xlabel \"number of cycles (c)\"\n";
    print GP "set ylabel \"probability\"\n";
    print GP "set ytics 0.1\n";
    print GP "set xtics ", xticincr($maxc), "\n";
    print GP "set grid xtics ytics\n";
    print GP "set data style linespoints\n";

    print GP "plot [0:$maxc] [0:1] ";
    for (my $m = 2; $m <= $n; $m++) {
	print GP "'-' using 1:2 w lp t \"m = $m\", ";
    }
    print GP "2 t \"\"\n";

    for (my $m = 2; $m <= $n; $m++) {
	for (my $c = 1; $c <= $maxc; $c++) {
	    printf GP "%d\t%12.8f\n", $c, $fon[$m][$c] / ($n ** ($c-1));
	}
	print GP "e\n";
    }
}
