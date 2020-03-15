#! /usr/local/bin/perl
# this files belongs from nntp://comp.lang.perl.misc (Greg Bacon) 
    use strict;
    use warnings;

    # split1line (read split first line)
    # read this: 00-00-00   (hex)           CORPORATION NAME
    # return that: 000000   CORPORATION NAME

    sub next_pair {
        local $/ = "";

        my $h = qr/[A-Fa-f0-9][A-Fa-f0-9]/;

        RECORD: {
            local $_ = <>;
            return unless defined $_;

            redo if /^\s*OUI\b/;

            unless (/^($h)-($h)-($h)\s+\(hex\)\s+(.+?)\n/s) {
                warn "$0: record $.: no match";
                return;
            }

            return "$1$2$3", $4;
        }
    }

    while (my($ethercode, $vendor) = next_pair) {
         print $ethercode, "\t", $vendor, "\n";
    }

