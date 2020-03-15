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
	# 2013 : (hex) as been added before name and after hex codes
	#my @fields = split /\s+/, $_, 3; 
        my @fields = split /\s+/, $_, 4; # last arg is the max number of times string can be split
	
	# for debug
	#print STDERR $fields[1];
	#print STDERR "\t";
	#print STDERR $fields[2];
	#print STDERR "\n";

        #my @hex = split /-/, $fields[0];
	my @hex = split /-/, $fields[1];
	#print join('',@hex), "\t", $fields[2], $/;
        print join('',@hex), "\t", $fields[3], $/;

        # Skip until next blank line
        $_ = <> until(!defined($_) || /^$/);
}
