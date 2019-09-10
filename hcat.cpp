// hcat: Histogram concatenation program

/* allow files >2GB */
#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>  // for "isprint()"

const unsigned int MAX_LINE = 1024;

#ifndef MIN
#define MIN(X,Y) (X<Y?X:Y)
#define MAX(X,Y) (X>Y?X:Y)
#endif // MIN/MAX



#ifndef WIN32
#include <unistd.h>
#include <errno.h>       
#include <sys/time.h>  // for gettimeofday()
#include <sys/types.h>
#endif  // !WIN32

void usage()
{
    fprintf(stderr, "Usage: hcat [normalize][prange [<rangeMin>:]<rangeMax>][pc <percentile>]\n"
                    "            [percent][count][range [<rangeMin>:]<rangeMax>]\n"
                    "            <file1> [<file2> <file3> ...]\n");
}

class FastReader
{
    public:
        enum Result {OK, ERROR_, DONE, TIMEOUT};
        FastReader();
        FastReader::Result Read(FILE* filePtr, char* buffer, unsigned int* len, 
                                double timeout = -1.0);
        FastReader::Result Readline(FILE* filePtr, char* buffer, unsigned int* len,
                                    double timeout = -1.0);

    private:
        enum {BUFSIZE = 2048};
        char         savebuf[BUFSIZE];
        char*        saveptr;
        unsigned int savecount;
};  // end class FastReader


// Simple self-scaling linear/non-linear histogram (one-sided)
class Histogram
{
    public:
        Histogram();
        bool IsEmpty() {return (NULL == bin);}
        void Init(unsigned long numBins, double linearity)
        {
            num_bins = numBins;
            q = linearity;
            if (bin) delete[] bin;
            bin = NULL;
        }
        bool InitBins(double rangeMin, double rangeMax);
        bool Tally(double value, unsigned long count = 1);
        void Print(FILE* file, bool showAll = false);
        unsigned long Count();
        double PercentageInRange(double rangeMin, double rangeMax);
        unsigned long CountInRange(double rangeMin, double rangeMax);
        double Min() {return min_val;}
        double Max() {return ((max_val < 0.0) ? 2.0*max_val : 0.5*max_val);}
        double Percentile(double p);
               
    private:   
            
        double GetBinValue(unsigned int i)
        {
            if (bin && bin[i].count)
            {
                return (bin[i].total / ((double)bin[i].count));
            }
            else
            {
                double x = pow(((double)i) / ((double)num_bins-1), 1.0/q);
                x *= (max_val - min_val);
                x += min_val;
                return x;  
            }
        }
              
        typedef struct
        {
            double          total;
            unsigned long   count;
        } Bin;
        
        double          q;
        unsigned long   num_bins;
        double          min_val;
        double          max_val;  
        Bin*            bin;           
}; // end class Histogram

Histogram::Histogram()
 : q(1.0), num_bins(1000), min_val(0.0), max_val(0.0), bin(NULL)
{
}

/**  This method creates an empty histogram with a preset
  *  value range.  This is useful for outputting 
  *  equivalent histgrams for multiplots
  */
bool Histogram::InitBins(double rangeMin, double rangeMax)
{
    if (bin) delete[] bin;
    if (!(bin = new Bin[num_bins]))
    {
        perror("hcat: Histogram::InitBins() Error allocating bins");
        return false;   
    } 
    memset(bin, 0, num_bins*sizeof(Bin));
    min_val = rangeMin;
    max_val = rangeMax;
    return true;
}  // end Histogram::InitBins()

bool Histogram::Tally(double value, unsigned long count)
{
    if (!bin)
    {
        if (!(bin = new Bin[num_bins]))
        {
            perror("trpr: Histogram::Tally() Error allocating histogram");
            return false;   
        }
        memset(bin, 0, num_bins*sizeof(Bin));
        min_val = max_val = value;
        bin[0].count = count;
        bin[0].total = (value * (double)count);
    }
    else if ((value > max_val) || (value < min_val))
    {
        Bin* newBin = new Bin[num_bins];
        if (!newBin)
        {
            perror("trpr: Histogram::Tally() Error reallocating histogram");
            return false; 
        }
        memset(newBin, 0, num_bins*sizeof(Bin));

        double newScale, minVal;
        if (value < min_val)
        {        
            newScale = ((double)(num_bins-1)) / pow(max_val - value, q);
            minVal = value;
        }
        else
        {
            double s = (value < 0.0) ? 0.5 : 2.0;   
            newScale = ((double)(num_bins-1)) / pow(s*value - min_val, q);
            minVal = min_val;
        }
        
        // Copy old histogram bins into new bins
        for (unsigned int i = 0; i < num_bins; i++)
        {
            if (bin[i].count)
            {
                double x = bin[i].total / ((double)bin[i].count);
                unsigned long index = (unsigned long)ceil(newScale * pow(x - minVal, q));
                if (index > (num_bins-1)) index = num_bins - 1;
                newBin[index].count += bin[i].count;
                newBin[index].total += bin[i].total;
            }   
        }
        
        
        if (value < min_val)
        {
            newBin[0].count += count;
            newBin[0].total += (value * (double)count);
            min_val = value;
        }
        else
        {
            double s = (value < 0.0) ? 0.5 : 2.0;   
            max_val = s*value;
            unsigned long index = 
                (unsigned long)ceil(((double)(num_bins-1)) * pow((value-min_val)/(max_val-min_val), q));        
            if (index > (num_bins-1)) index = num_bins - 1;
            newBin[index].count += count;
            newBin[index].total += (value * (double)count);
        }
        delete[] bin;
        bin = newBin;
    }
    else
    {
        unsigned long index = 
            (unsigned long)ceil(((double)(num_bins-1)) * pow((value-min_val)/(max_val-min_val), q));        
        if (index > (num_bins-1)) index = num_bins - 1;
        bin[index].count += count;
        bin[index].total += (value * (double)count);
    }
    return true;
}  // end Histogram::Tally()

void Histogram::Print(FILE* file, bool showAll)
{
    if (bin)
    {
        for (unsigned int i = 0; i < num_bins; i++)
        {
            if ((0 != bin[i].count) || showAll)
            {
                fprintf(file, "%f, %lu\n", GetBinValue(i), bin[i].count);    
            }
        }
    }
}  // end Histogram::Print()


unsigned long Histogram::Count()
{
    if (bin)
    {
        unsigned long total = 0 ;
        for (unsigned int i = 0; i < num_bins; i++)
        {
            total += bin[i].count;
        }
        return total;
    }
    else
    {
         return 0;
    }   
}  // end Histogram::Count()

double Histogram::PercentageInRange(double rangeMin, double rangeMax)
{
    if (bin)
    {
        unsigned long countTotal = 0;
        unsigned long rangeTotal = 0;
        for (unsigned long i = 0; i < num_bins; i++)
        {
            if (bin[i].count)
            {
                double value = bin[i].total / ((double)bin[i].count);
                countTotal += bin[i].count;
                if (value < rangeMin)
                    continue;
                else if (value > rangeMax)
                    continue;
                else
                    rangeTotal += bin[i].count;
            }
        }
        return (100.0 * ((double)rangeTotal) / ((double)countTotal));
    }
    else
    {
        return 0.0;
    }         
}  // end Histogram::PercentageInRange()

unsigned long Histogram::CountInRange(double rangeMin, double rangeMax)
{
    if (bin)
    {
        unsigned long rangeTotal = 0;
        for (unsigned long i = 0; i < num_bins; i++)
        {
            if (bin[i].count)
            {
                double value = bin[i].total / ((double)bin[i].count);
                if (value < rangeMin)
                    continue;
                else if (value > rangeMax)
                    break;
                else
                    rangeTotal += bin[i].count;
            }
        }
        return rangeTotal;
    }
    else
    {
        return 0;
    }         
}  // end Histogram::CountInRange()


double Histogram::Percentile(double p)
{
    unsigned long goal = Count();
    goal = (unsigned long)(((double)goal) * p + 0.5);
    unsigned long count = 0;
    if (bin)
    {
        for (unsigned long i = 0; i < num_bins; i++)
        {
            count += bin[i].count;
            if (count >= goal)
            {
                double x = pow(((double)i) / ((double)num_bins-1), 1.0/q);
                x *= (max_val - min_val);
                x += min_val;
                return x;   
            }
        }
    }
    return max_val;
}  // end Histogram::Percentile()

int main(int argc, char* argv[])
{
    bool doNormalize = false;
    bool getPercentage = false;
    bool getCount = false;
    double rangeMin = 0.0;
    double rangeMax = 0.0;
    bool getPercentile = false;
    double pc = 0.0;
    double q = 0.5;  // default linearity
    
    bool presetRange = false;
    double presetRangeMin = 0.0;
    double presetRangeMax = 0.0;
    
    // Process command line options
    int i = 1;
    while(i < argc)
    {
        int len = strlen(argv[i]);
        if (!strncmp(argv[i], "normalize", len))
        {
            doNormalize = true;
            i++;
        }
        else if (!strncmp(argv[i], "percent", len))
        {
            getPercentage = true;
            i++;
        }
        else if (!strncmp(argv[i], "linear", len))
        {
            if (++i >= argc)
            {
                fprintf(stderr, "hcat: missing \"linear\" args!\n");
                usage();
                exit(-1); 
            }
            if (1 != sscanf(argv[i], "%lf", &q))
            {
                fprintf(stderr, "hcat: invalid linear <q>!\n");
                usage();
                exit(-1);
            }
            i++;
        }
        else if (!strncmp(argv[i], "count", len))
        {
            getCount = true;
            i++;
        }
        else if (!strncmp(argv[i], "pc", len))
        {
            getPercentile = true;
            if (++i >= argc)
            {
                fprintf(stderr, "hcat: missing \"pc\" args!\n");
                usage();
                exit(-1); 
            }
            if (1 != sscanf(argv[i], "%lf", &pc))
            {
                fprintf(stderr, "hcat: invalid <percentile>!\n");
                usage();
                exit(-1);
            }
            pc /= 100.0;
            i++;
        }
        else if (!strncmp(argv[i], "range", len))
        {
            if (++i >= argc)
            {
                fprintf(stderr, "hcat: missing \"range\" args!\n");
                usage();
                exit(-1);   
            } 
            char* ptr = strchr(argv[i], ':');
            if (ptr)
            {
                if (2 != sscanf(argv[i], "%lf:%lf", &rangeMin, &rangeMax))
                {
                    fprintf(stderr, "hcat: invalid <range>!\n");
                    usage();
                    exit(-1);   
                }  
            }
            else
            {
                rangeMin = 0.0;
                if (1 != sscanf(argv[i], "%lf", &rangeMax))
                {
                    fprintf(stderr, "hcat: invalid <range>!\n");
                    usage();
                    exit(-1);   
                } 
            } 
            i++;         
        }
        else if (!strncmp(argv[i], "prange", len))
        {
            presetRange = true;
            if (++i >= argc)
            {
                fprintf(stderr, "hcat: missing \"prange\" args!\n");
                usage();
                exit(-1);   
            } 
            char* ptr = strchr(argv[i], ':');
            if (ptr)
            {
                if (2 != sscanf(argv[i], "%lf:%lf", &presetRangeMin, &presetRangeMax))
                {
                    fprintf(stderr, "hcat: invalid <presetRange>!\n");
                    usage();
                    exit(-1);   
                }  
            }
            else
            {
                presetRangeMin = 0.0;
                if (1 != sscanf(argv[i], "%lf", &presetRangeMax))
                {
                    fprintf(stderr, "hcat: invalid <presetRange>!\n");
                    usage();
                    exit(-1);   
                } 
            } 
            i++;         
        }
        else
        {
            // Must be first of input file names
            break;   
        }
    }
    
    if (i >= argc)
    {
        fprintf(stderr, "hcat: no <files> given!\n");
        usage();
        exit(-1);  
    }
    
    Histogram h;
    h.Init(1000, q); // 1000 point, q-linear histogram 
    
    if (presetRange)
    {
        if (!h.InitBins(presetRangeMin, presetRangeMax))
        {
            fprintf(stderr, "hcat: error presetting range!\n");
            usage();
            exit(-1); 
        }   
    }
    
    bool firstBin = true;
    double minimum = 0.0;
    double mean = 0.0;
    int meanCount = 0;
    for (; i < argc; i++)
    {
        FILE* file = fopen(argv[i], "r");
        if (!file)
        {
            perror("hcat: Error opening input file");
            usage();
            exit(-1);   
        }
        FastReader reader;
        char buffer[MAX_LINE];
        unsigned int len = MAX_LINE;
        while (FastReader::OK == reader.Readline(file, buffer, &len))
        {
            // Skip blank and commented (leading `#` lines)
            if ((0 == len) || ('#' == buffer[0]))
            {
                len = MAX_LINE;
                continue;
            }
            len = MAX_LINE;
            double value;
            unsigned int count;
            
            int result = sscanf(buffer, "%lf, %lu", &value, &count);
            if (1 == result)
            {
                count = 1;  // assume single values
            }
            else if (2 != sscanf(buffer, "%lf, %lu", &value, &count))
            {
                fprintf(stderr, "hcat: Warning! Bad histogram line in file: %s\n", argv[i]);
                continue;   
            }
            if (doNormalize)
            {
                if (firstBin)
                {
                    minimum = value;
                    firstBin = false;
                    value = 0.0;   
                }   
                else
                {
                    value -= minimum;   
                }
            }
            if (!h.Tally(value, count))
            {
                fprintf(stderr, "hcat: Error adding tallying data point!\n");
                exit(-1);
            }
            mean += count * value;
            meanCount += count;
        }  // end while(reader.Readline())   
        fclose(file);  
        firstBin = true;   
    }  // end for(i=1..argc)
    
    mean /= meanCount;
    
    if (h.IsEmpty()) 
    {
        fprintf(stderr, "hcat: Warning! Empty histogram.\n");
        exit(0);  // nothing to output
    }
    
    if (getPercentage)
    {
        double percent = h.PercentageInRange(rangeMin, rangeMax);
        fprintf(stdout, "%lf\n", percent);
    }
    else if (getCount)
    {
        unsigned long count = h.CountInRange(rangeMin, rangeMax);
        fprintf(stdout, "%lu\n", count);
    }
    else if (getPercentile)
    {
        double percentile = h.Percentile(pc);
        fprintf(stdout, "%lf\n", percentile);
    }
    else
    {
        // Default output
        // Output new combined histogram w/ percentile info
        const double p[6] = {0.99, 0.95, 0.9, 0.8, 0.75, 0.5};
        fprintf(stdout, "#histogram: ");
        fprintf(stdout, "min:%f max:%f mean:%lf percentiles: ", h.Min(), h.Max(), mean);
        for (int j = 0; j < 6; j++)
        {
            double percentile = h.Percentile(p[j]);
            fprintf(stdout, "%2d>%f ", (int)(p[j]*100.0+0.5), percentile);
        }
        fprintf(stdout, "\n");
        h.Print(stdout, presetRange);
    }
    return 0;
}  // end main()


FastReader::FastReader()
    : savecount(0)
{
    
}

FastReader::Result FastReader::Read(FILE*           filePtr, 
                                    char*           buffer, 
                                    unsigned int*   len,
                                    double          timeout)
{
    unsigned int want = *len;   
    if (savecount)
    {
        unsigned int ncopy = MIN(want, savecount);
        memcpy(buffer, saveptr, ncopy);
        savecount -= ncopy;
        saveptr += ncopy;
        buffer += ncopy;
        want -= ncopy;
    }
    while (want)
    {
        unsigned int result;
#ifndef WIN32 // no real-time TRPR for WIN32 yet
        if (timeout >= 0.0)
        {
            int fd = fileno(filePtr);
            fd_set input;
            FD_ZERO(&input);
            struct timeval t;
            t.tv_sec = (unsigned long)timeout;
            t.tv_usec = (unsigned long)((1.0e+06 * (timeout - (double)t.tv_sec)) + 0.5);
            FD_SET(fd, &input);
            int status = select(fd+1, &input, NULL, NULL, &t);
            switch(status)
            {
                case -1:
                    if (EINTR != errno) 
                    {
                        perror("trpr: FastReader::Read() select() error");
                        return ERROR_; 
                    }
                    else
                    {
                        continue;   
                    }
                    break;
                    
                case 0:
                    return TIMEOUT;
                    
                default:
                    result = fread(savebuf, sizeof(char), 1, filePtr);
                    break;
            } 
        }
        else
#endif // !WIN32
        {
            // Perform buffered read when there is no "timeout"
            result = fread(savebuf, sizeof(char), BUFSIZE, filePtr);
        }
        if (result)
        {
            // This check skips NULLs that have been read on some
            // use of trpr via tail from an NFS mounted file
            if (!isprint(*savebuf) && 
                ('\t' != *savebuf) &&
                ('\n' != *savebuf) && 
                ('\r' != *savebuf))
                    continue;
            unsigned int ncopy= MIN(want, result);
            memcpy(buffer, savebuf, ncopy);
            savecount = result - ncopy;
            saveptr = savebuf + ncopy;
            buffer += ncopy;
            want -= ncopy;
        }
        else  // end-of-file
        {
#ifndef WIN32
            if (ferror(filePtr))
            {
                if (EINTR == errno) continue;   
            }
#endif // !WIN32
            *len -= want;
            if (*len)
                return OK;  // we read at least something
            else
                return DONE; // we read nothing
        }
    }  // end while(want)
    return OK;
}  // end FastReader::Read()

// An OK text readline() routine (reads what will fit into buffer incl. NULL termination)
// if *len is unchanged on return, it means the line is bigger than the buffer and 
// requires multiple reads

FastReader::Result FastReader::Readline(FILE*         filePtr, 
                                        char*         buffer, 
                                        unsigned int* len, 
                                        double        timeout)
{   
    unsigned int count = 0;
    unsigned int length = *len;
    char* ptr = buffer;
    while (count < length)
    {
        unsigned int one = 1;
        switch (Read(filePtr, ptr, &one, timeout))
        {
            case OK:
                if (('\n' == *ptr) || ('\r' == *ptr))
                {
                    *ptr = '\0';
                    *len = count;
                    return OK;
                }
                count++;
                ptr++;
                break;
                
            case TIMEOUT:
                // On timeout, save any partial line collected
                if (count)
                {
                    savecount = MIN(count, BUFSIZE);
                    if (count < BUFSIZE)
                    {
                        memcpy(savebuf, buffer, count);
                        savecount = count;
                        saveptr = savebuf;
                        *len = 0;
                    }
                    else
                    {
                        memcpy(savebuf, buffer+count-BUFSIZE, BUFSIZE);
                        savecount = BUFSIZE;
                        saveptr = savebuf;
                        *len = count - BUFSIZE;
                    }
                }
                return TIMEOUT;
                
            case ERROR_:
                return ERROR_;
                
            case DONE:
                return DONE;
        }
    }
    // We've filled up the buffer provided with no end-of-line 
    return ERROR_;
}  // end FastReader::Readline()
