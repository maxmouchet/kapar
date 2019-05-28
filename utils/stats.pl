#! /usr/bin/env perl
# Generate some basic stats for a kapar graph.

use strict;
use List::Util qw(first);

if (@ARGV < 2) {
    print STDERR "Usage: $0 {linkfiles} {nodefiles}\n";
    exit 1;
}

my $n_nodes = 0;
my $n_node_members = 0;
my $n_links = 0;
my $n_link_members = 0;
my $n_links_wo_named = 0;
my $n_links_wo_explicit = 0;
my $n_hyperlinks = 0;
my $n_hyperlinks_wo_named = 0;

while (<>) {
    if (/^node N\d+:\s+/) {
	my @members = split(/\s+/, $');
	$n_nodes++;
	$n_node_members += scalar @members;

    } elsif (/^link L\d+:\s+/) {
	my @members = split(/\s+/, $');
	$n_links++;
	$n_link_members += scalar @members;
	if (scalar @members > 2) {
	    $n_hyperlinks++;
	    if (!first { $_ =~ /:[1-9]/ } @members) {
		$n_hyperlinks_wo_named++
	    }
	}
	if (!first { $_ =~ /:[1-9]/ } @members) {
	    $n_links_wo_named++
	}
	if (!first { $_ =~ /:[0-9]/ } @members) {
	    $n_links_wo_explicit++
	}
    }
}

printf "nodes:                       %9d\n", $n_nodes;
printf "links:                       %9d\n", $n_links;
printf "average node degree:         %9.6f\n", $n_node_members / $n_nodes;
printf "average link degree:         %9.6f\n", $n_link_members / $n_links;
printf "links w/o named iface:       %9d\n", $n_links_wo_named;
printf "links w/o explicit iface:    %9d\n", $n_links_wo_explicit;
printf "hyperlinks:                  %9d\n", $n_hyperlinks;
printf "hyperlinks w/o named iface:  %9d\n", $n_hyperlinks_wo_named;
