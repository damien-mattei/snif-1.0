#!/usr/bin/perl -w
# file: preformat_ports.pl
# parse standart port file

# author: Damien Mattei
# email: damien_mattei@users.sf.net

# date: dim nov  2 21:53:52 CET 2003
# Location:  Nice - France

# last modified ven mai  4 10:18:54 CEST 2007

# run like that:
# ../contrib/preformat_ports.pl < port-numbers.txt > portnumbers.dat

use strict;

# skipping the beginning of the file
# number of lines to skip in the file
my $n_skip_lines = 1; # adjust this to the downloaded file 

my $previousport = -1; # 

$_ = <> for(1..$n_skip_lines); #skip first lines;

my $i = 0;

while(defined($_ = <>)) {
    chomp;

    # for debugging
    if ($i < 3) {
	print STDERR $_;
	print STDERR '\n';
    }  

    # deal only with number/tcp as udp is same number
    next if ($_ !~ /\d\/tcp/);

    # Seperate fields by whitespace (except the name)
    my @fields = split /\s+/, $_, 3;

    next if not defined $fields[2]; # skip port if no info available
    next if ($fields[2] =~ /^$/); # skip port if no info available

    # split port and protocol
    my @betwslash = split /\//, $fields[1];

    next if ((!($betwslash[0] =~ /-/)) && ($betwslash[0] == $previousport)); # skip if already in hash table (ex:80) but continue if it's a range

    if ($betwslash[0] =~ /-/) { # range case ex: 6000-6063: X Window System
	my @betwminus = split /-/, $betwslash[0];
	for(my $portnumber = $betwminus[0];
	    ($portnumber <= $betwminus[1]);
	    $portnumber++) { # print one line for each port number used

	    print $portnumber, "\t", $fields[2], $/;

	}
	$previousport = $betwminus[1];
    }

    else { # single case
	print $betwslash[0], "\t", $fields[2], $/ if ($fields[2] !~ /^$/);
	$previousport = $betwslash[0];
    }
    
     $i++; # for debug

}
