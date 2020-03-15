#!/usr/bin/perl -w

# read the of ethernet vendor codes on STDIN
# and convert it in a 2 columns file
# with Ethernet code and constructor
# separator of output file is tab


use strict; # it's always better to be strict when coding ;-)


# split1line (read split first line)
# read this: 00-00-00   (hex)		XEROX CORPORATION
# return that: 000000	XEROX CORPORATION

sub split1line() {

    
    my @betwtab = split /\t/ , <STDIN>;

    my @betwspc = split / / , $betwtab[0];

    my @hexaddr = split /-/ , $betwspc[0];

    my $vendor = $betwtab[2];

    my $ethercode = $hexaddr[0] . $hexaddr[1] . $hexaddr[2] ;

    return $ethercode . "\t" . $vendor ;

}





# skip the 6 first lines that do not contain any ethernet code

<STDIN>;
<STDIN>;
<STDIN>;
<STDIN>;
<STDIN>;
<STDIN>;

while (1) { 

    my $pair = split1line();

    print $pair;

   
    my $oneline;	

    # stop after the next empty line
    while (defined($oneline = <STDIN>) && ($oneline !~ /^\n$/)) { 
	
    }

    exit(0) if not defined $oneline;

   
    
}



