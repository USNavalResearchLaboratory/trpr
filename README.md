         TRace Plot Realtime (trpr) Distribution (2.1b2)
     
OVERVIEW:

This directory contains the source code and documentation
for the "trpr" program which analyzes trace files, provides
statistics and histograms and allows for graphical display of 
analytical results.  Trpr supports trace (log) files produced 
by the following programs:

tcpdump (using tcpdump's hexadecimal (-x) output)

mgen  (NRL's "Multi-generator" message generation program)

ns-2 (The Berkeley/ISI network simulation tool.

"Trpr" has filter options and can display plots for different 
"flows" of data (defined by protocol type, source, and 
destination).  "Trpr" provides built-in support for display
of graphical data using the "gnuplot" plotting program, but 
its output may also be plotted using other graphing tools.


FILES:

README.TXT  - this file.

trpr.cpp    - C++ source code for the "trpr" program

trpr.html   - "Trpr" User's Guide.

hcat.cpp    - C++ source code for "hcat", the histogram
              concatenation program.

TO BUILD:

g++ -o trpr trpr.cpp -lm

g++ -o hcat hcat.cpp -lm

OR: "make -f Makefile.linux"

HCAT Usage:

The Histogram Concatenator ("hcat") is useful for post-processing
the histogram output produced by "trpr".  "hcat" can be used to 
combine multiple histograms and to retrieve some summary statistics
from the histogram data.  

Usage: 

hcat [normalize] [percent [<rangeMin>:]<rangeMax>] file1 [file2 file3 ...]

Options:

normalize  - The minimum bin is adjusted to correspond to zero.  Other
             bins are correspondingly linearly adjusted.
             
percent [<rangeMin>:]<rangeMax> - Calculates the percentage of data
                                  points lying in the specified range.
                                  
The <files> are expected to contain histogram data in pairs of data in  the
order of minimum bin to maximum bin, with the first value of the pair
specifying the bin and the second value specifying the number of data
points for that histogram bin.  Lines beginning with '#' are ignored as
comments.


IPv6 NOTES:

TRPR IPv6 support is still a bit "kludgy".  I plan to re-write TRPR to use my 
"Protolib" stuff to leverage those address-independent classes and to better
support TRPR cross-platform portability.  Meanwhile, some notes:

1) For MGEN IPv6 flows, you can (and may have) to use abbreviated IPv6 addresses
   in your flow descriptions provided on the command-line.
   
2) For tcpdump file analysis, note that full (non-abbreviated) IPv6 address
   syntax MUST be used.
