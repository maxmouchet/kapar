#! /usr/local/bin/perl -w

# Reads Internet 2 interface addresses from a copy of
# http://vn.grnoc.iu.edu/Internet2/interfaces/interfaces-addresses.html
# and writes alias sets.

use strict;

my $prevname = "";
my $name;
my $addr;
my $ifname;
my @addrs = ();

sub dumpset($) {
    return if (!scalar @addrs);
    print "# name: ", $_[0], "\n";
    print join("\t", @addrs), "\n";
    @addrs = ();
}

while (<>) {
    next if (!/^<tr/);
    ($name, $ifname, $addr) = /<tr[^>]*><th[^>]*>([^<]*)<\/th><td[^>]*>([^<]*)<\/td><td[^>]*>[^<]*<\/td><td[^>]*>([^<]*)<\/td>(?:<td[^>]*>[^<]*<\/td>){2}<\/tr>/;
    if ($ifname !~ /^\w{2,}-\d\/\d\/\d$/) {
	print STDERR "ignoring interface $ifname\n";
	next;
    }
    next if ($addr eq "N/A");
    if ($name ne $prevname) {
	dumpset($prevname);
	$prevname = $name;
    }
    push @addrs, $addr;
}
dumpset($prevname);

print "# DONE\n";
