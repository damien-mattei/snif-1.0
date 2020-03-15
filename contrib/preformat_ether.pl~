#!/usr/bin/perl -w
# this files belongs from nntp://comp.lang.perl.misc (Brian Harnish)
# run like that:
# cd var
# ../contrib/preformat_ether.pl  < oui.txt > ieee_ethercodes.dat

use strict;

my $n_skip_lines = 6; # adjust this to the downloaded file

$_ = <> for(1..$n_skip_lines); #skip first 6 lines;

while(defined($_ = <>)) {
        chomp;

        # Seperate fields by whitespace (except the name)
        my @fields = split /\s+/, $_, 3;
        my @hex = split /-/, $fields[0];
        print join('',@hex), "\t", $fields[2], $/;

        # Skip until next blank line
        $_ = <> until(!defined($_) || /^$/);
}
