/*********************************************************************
 *
 * AUTHORIZATION TO USE AND DISTRIBUTE
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: 
 *
 * (1) source code distributions retain this paragraph in its entirety, 
 *  
 * (2) distributions including binary code include this paragraph in
 *     its entirety in the documentation or other materials provided 
 *     with the distribution, and 
 *
 * (3) all advertising materials mentioning features or use of this 
 *     software display the following acknowledgment:
 * 
 *      "This product includes software written and developed 
 *       by Brian Adamson and Joe Macker of the Naval Research 
 *       Laboratory (NRL)." 
 *         
 *  The name of NRL, the name(s) of NRL  employee(s), or any entity
 *  of the United States Government may not be used to endorse or
 *  promote  products derived from this software, nor does the 
 *  inclusion of the NRL written and developed software  directly or
 *  indirectly suggest NRL or United States  Government endorsement
 *  of this product.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 ********************************************************************/
 
/* allow files >2GB */
#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>  // for PATH_MAX
#include <string.h>
#include <math.h>
#include <ctype.h>  // for isspace()

#include <assert.h>

#ifdef WIN32
#include <winsock2.h>
#include <float.h>  // for _isnan()
#define PATH_MAX MAX_PATH
inline int isnan(double x) {return _isnan(x);}
#else
#include <unistd.h>
#include <errno.h>       
#include <sys/time.h>  // for gettimeofday()
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif // !WIN32

#define VERSION "2.1b3"

#ifndef MIN
#define MIN(X,Y) ((X<Y)?X:Y)
#define MAX(X,Y) ((X>Y)?X:Y)
#endif // !MIN

const int MAX_LINE = 256;

enum TraceFormat {TCPDUMP, DREC, NS};
enum PlotMode {RATE, INTERARRIVAL, LATENCY, DROPS, LOSS, LOSS2, COUNT, VELOCITY};

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

#ifndef WIN32
// (No real-time TRPR support for WIN32 yet)
class Waiter
{
    public:
        Waiter();
        void Reset();
        bool Wait(double seconds);
    
            
    private:
        struct timeval last_time;
        double excess;
    
};  // end class Waiter


Waiter::Waiter()
  :  excess(0.0)
{
    Reset();
}

void Waiter::Reset()
{
    struct timezone tz;
    gettimeofday(&last_time, &tz);
    excess = 0.0;   
}  // end Waiter::Reset()

bool Waiter::Wait(double delay)
{
    delay -= excess;
    struct timeval timeout;
    if (delay >= (double)0.0)
	{
	    timeout.tv_sec = (unsigned long) delay;
	    timeout.tv_usec = (unsigned long)(1000000.0 * (delay - timeout.tv_sec));
        }
	else
	{
	    timeout.tv_sec = timeout.tv_usec = 0;
	}
    fd_set fdSet;
    FD_ZERO(&fdSet);
    select(0, (fd_set*)NULL, (fd_set*)NULL, (fd_set*)NULL, &timeout);
    
    struct timeval thisTime;
    struct timezone tz;
    gettimeofday(&thisTime, &tz);
    double actual = thisTime.tv_sec - last_time.tv_sec;
    if (thisTime.tv_usec < last_time.tv_usec)
        actual -= ((double)(thisTime.tv_usec - last_time.tv_usec)) * 1.0e-06;
    else
        actual += ((double)(thisTime.tv_usec - last_time.tv_usec)) * 1.0e-06;
    excess = actual - delay;
    if (excess < -2.0)
    {
        fprintf(stderr, "Waiter::Wait() Warning! dropping behind real time ...\n"); 
        excess = 0.0;
    }
    memcpy(&last_time, &thisTime, sizeof(struct timeval));
    return true;
}  // end Waiter::Wait()

#endif // !WIN32

class FlowId
{
    public:
        FlowId() : valid(false) {}
        FlowId(unsigned long x) : valid(true), value(x) {}    
        bool IsValid() const {return valid;}
        unsigned long Value() const {return value;}
        void Invalidate() {valid = false;}
        operator unsigned long() const {return value;}
        bool Match(unsigned long x) const;

    private:
        bool          valid;
        unsigned long value;
};  // end class FlowId

bool FlowId::Match(unsigned long x) const
{    
    if (!valid || (x == value))
        return true;
    else
        return false;
}  // end FlowId::Match()

class Address
{
    public:
        enum Domain {IPv4, IPv6, OTHER};
        Address() {addr[0] = '\0';}
        Address(unsigned long value, Domain domain) {Set(value, domain);}
        Address(const char* string) {Set(string);}
        void Set(const char* string)
        {
            strncpy(addr, string, 63);
            addr[63] = '\0';   
        }
        void Set(unsigned long value, Domain domain)
        {
            if (IPv4 == domain)
            {
                unsigned char* a = (unsigned char*)&value;
                sprintf(addr, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
            }
            else if (((unsigned long)-1) == value)
            {
                strcpy(addr, "-1");
            }
            else
            {
                sprintf(addr, "%lu", value);    
            }            
        }
        // buf is network order IPv6 address
        void SetIPv6(unsigned long* buf)
        {
            addr[0] = '\0';
            for (unsigned int i = 0; i < 4; i++)
            {
                unsigned short* a = (unsigned short*)(buf+i); 
                char temp[16];
                sprintf(temp, "%x:%x%s", ntohs(a[0]), ntohs(a[1]),
                               (i < 3) ? ":" : "");
                strcat(addr, temp);
            }  
        }
        void Invalidate() {addr[0] = '\0';}
        bool IsValid() const {return ('\0' != addr[0]);}
        
        bool operator==(const Address& x) const 
            {return (0 == strcmp(addr, x.addr));}
        void PrintDescription(FILE* f) const {fprintf(f, "%s", addr);}
        
    //private:
        char  addr[64]; 
};  // end class Address

        
class PacketEvent
{
    public:
        enum EventType {INVALID, RECEPTION, TRANSMISSION, DROP, LOSS, TIMEOUT};
    
        PacketEvent();
        ~PacketEvent();
        
        
        // Generalized tracepoint node(a,[b]) NS
        class TracePoint
        {
            public:
                TracePoint() : src_port(-1), dst_port(-1) {}
                TracePoint(const Address& sa) : src_addr(sa), src_port(-1), dst_port(-1) {}
                TracePoint(const Address& sa, unsigned short sp) : src_addr(sa), src_port(sp), dst_port(-1) {}
                TracePoint(const Address& sa, unsigned short sp, const Address& da, unsigned short dp) 
                 : src_addr(sa), src_port(sp), dst_addr(da), dst_port(dp) {}
                bool Match(const TracePoint& p) const;
                const Address& SrcAddr() const {return src_addr;}
                unsigned short SrcPort() const {return src_port;}
                const Address& DstAddr() const {return dst_addr;}
                unsigned short DstPort() const {return dst_port;}
                bool IsValid() const {return (src_addr.IsValid() || dst_addr.IsValid());}
                void Invalidate()
                {
                    src_addr.Invalidate();
                    src_port = -1;
                    dst_addr.Invalidate();
                    dst_port = -1;
                }
                void SetSrc(const Address& srcAddr) 
                {
                    src_addr = srcAddr; 
                    src_port = -1;
                }
                void SetSrc(const Address& srcAddr, unsigned short srcPort) 
                {
                    src_addr = srcAddr; 
                    src_port = srcPort;
                }
                void SetDst(const Address& dstAddr) 
                {
                    dst_addr = dstAddr; 
                    dst_port = -1;
                }
                void SetDst(const Address& dstAddr, unsigned short dstPort) 
                {
                    dst_addr = dstAddr; 
                    dst_port = -1;
                }
                void PrintDescription(FILE* f) const
                {
                    src_addr.PrintDescription(f);
                    if (src_port >= 0) fprintf(f, ":%d", src_port);
                    fprintf(f, ", ");
                    dst_addr.PrintDescription(f);
                    if (dst_port >= 0) fprintf(f, ":%d", dst_port);
                }
                       
            private:
                Address  src_addr;
                int      src_port;  // -1 is invalid
                Address  dst_addr;
                int      dst_port;  // -1 is invalid
        };  // end class TracePoint
        
        EventType Type() {return type;}
        void SetType(EventType theType) {type = theType;}
        double Time() {return time;}
        void SetTime(double theTime) {time = theTime;}
        
        PacketEvent::TracePoint& Link() {return link;}
        void LinkClear() {link.Invalidate();}
        void SetLinkSrc(const Address& srcAddr) 
            {link.SetSrc(srcAddr);}  
        void SetLinkSrc(const Address& srcAddr, unsigned short srcPort) 
            {link.SetSrc(srcAddr,srcPort);}
        void SetLinkDst(const Address& dstAddr) 
            {link.SetDst(dstAddr);}
        void SetLinkDst(const Address& dstAddr, unsigned short dstPort) 
            {link.SetDst(dstAddr, dstPort);}
        
        const Address& SrcAddr() {return src_addr;}
        void SetSrcAddr(const Address& theAddr) {src_addr = theAddr;}
        unsigned short SrcPort() {return src_port;}
        void SetSrcPort(unsigned short thePort) {src_port = thePort;}
        const Address& DstAddr() {return dst_addr;}
        void SetDstAddr(const Address& theAddr) {dst_addr = theAddr;}
        unsigned short DstPort() {return dst_port;}
        void SetDstPort(unsigned short thePort) {dst_port = thePort;}
        const char* Protocol() {return protocol;}
        bool SetProtocol(const char* name);    
        unsigned int Size() {return size;}
        void SetSize(unsigned int theSize) {size = theSize;}
        double RxTime() {return rx_time;}
        void SetRxTime(double theTime) {rx_time = theTime;}
        double TxTime() {return tx_time;}
        void SetTxTime(double theTime) {tx_time = theTime;}
        unsigned long Sequence() {return sequence;}
        void SetSequence(unsigned long theSequence) {sequence = theSequence;}    
        unsigned long FlowId() {return flow_id.Value();}
        void SetFlowId(unsigned long id) {flow_id = id;}
        void SetPosition(double x, double y) {pos_x = x; pos_y = y;}
        double PosX() {return pos_x;}
        double PosY() {return pos_y;}
        
    private:           
        EventType	    type;       
        double		    time;
        TracePoint      link;
        Address         src_addr;  // (TBD) Use NetworkAddress class here?
        int             src_port;
        Address         dst_addr;
        int             dst_port;
        unsigned int    size;
        char*		    protocol;
        double		    tx_time;
        double		    rx_time;
        unsigned long   sequence;
        ::FlowId        flow_id;
        double          pos_x;  // drec GPS only
        double          pos_y;  // drec GPS only
        
};  // end class PacketEvent

PacketEvent::PacketEvent()
: type(INVALID), time(-1.0), src_port(-1), dst_port(-1), size(0), protocol(NULL),
  pos_x(999.0), pos_y(999.0)
{
}

PacketEvent::~PacketEvent()
{
    if (protocol) delete protocol;
}

bool PacketEvent::SetProtocol(const char* name)
{
    if (protocol) delete protocol;
    unsigned int len = name ? strlen(name) + 1 : 0;
    if (len)
    {
        protocol = new char[len];
        if (protocol)
        {
            strcpy(protocol, name);
            return true;
        }
        else
        {
            perror("trpr: PacketEvent::SetProtocol() \"new()\" error");
            return false;
        }
    }
        else
    {
        protocol = NULL;
        return true;
    }
}  // end PacketEvent::SetProtocol()



bool PacketEvent::TracePoint::Match(const TracePoint& p) const
{
    if ((!src_addr.IsValid() || src_addr == p.SrcAddr()) &&
        ((-1 == src_port) || (src_port == p.SrcPort())) &&
        (!dst_addr.IsValid() || dst_addr == p.DstAddr()) &&
        ((-1 == dst_port) || (dst_port == p.DstPort())))
    {
        fprintf(stderr, "");
        return true;
    }
    else
    {
        return false;
    }   
}  // end PacketEvent::TracePoint::Match()

class EventParser
{
    public:
        virtual bool GetNextPacketEvent(FILE*           filePtr, 
                                        PacketEvent*    theEvent, 
                                        double          timeout = -1.0) = 0;
        
    protected:
        FastReader	reader;
        
};  // end class EventParser

class NsEventParser : public EventParser
{
    public:
        enum NodeType {AGT, RTR, MAC};
        bool GetNextPacketEvent(FILE*           filePtr, 
                                PacketEvent*    theEvent, 
                                double          timeout = -1.0);
        
};  // end class EventParser

class TcpdumpEventParser : public EventParser
{
    public:
        bool GetNextPacketEvent(FILE*           filePtr, 
                                PacketEvent*    theEvent, 
                                double          timeout = -1.0);
        unsigned int PackHexLine(char* text, char* buf, unsigned int buflen);

        unsigned int Version(const char* hdr) const
            {  return (((unsigned char)hdr[0] >> 4 ) & 0x0f);}

        unsigned int HeaderLength(const char* hdr) const
            {
	            if(Version(hdr) == 4)
	                return 4 * (((unsigned char)hdr[0]) & 0x0f);
                else return 40;
            }

        unsigned int PayloadLength(const char* hdr)
            {return (256 * (unsigned char)hdr[4] + (unsigned char)hdr[5]);}

        unsigned  int TotalLength(const char* hdr)
        {
	      if(Version(hdr) == 4)    
            return (256*((unsigned char)hdr[2]) + ((unsigned char)hdr[3]));
	      else
		    return (PayloadLength(hdr) + 40);
        }
        unsigned char Protocol(char* hdr)
        {
            if(Version(hdr) == 4)
                return ((unsigned char)hdr[9]);
            else
                return ((unsigned char)hdr[6]);
	    }
        
        const char* ProtocolType(unsigned char value) const;
                
        Address SourceAddress(const char* hdr) const
        {
	        if (Version(hdr) == 4)
            {   
	            unsigned long buf;
	            buf =  ((256*256*256)*((unsigned char)hdr[12]) +
                            (256*256)*((unsigned char)hdr[13]) +
                                (256)*((unsigned char)hdr[14]) +
                                      ((unsigned char)hdr[15]));
                return Address(htonl(buf), Address::IPv4);
	        }
	        else // (Version(hdr) == 6)
	        {
	            unsigned long buf[4];
	            Address theAddress;
	            for(unsigned int i =0; i < 4; i++)
	            {
                    buf[i] = ((256*256*256)*((unsigned char)hdr[(i*4)+8]) +
                                  (256*256)*((unsigned char)hdr[(i*4)+9]) +
                                      (256)*((unsigned char)hdr[(i*4)+10]) +
                                            ((unsigned char)hdr[(i*4)+11]));
                    buf[i] = htonl(buf[i]);
	            }
	            theAddress.SetIPv6(buf);
	            return theAddress;
	        }
	    }
        
        Address DestinationAddress(const char* hdr) const
        {
	        if(4 == Version(hdr))
            {
                unsigned long buf = (((256*256*256)*((unsigned char)hdr[16]) +
                                          (256*256)*((unsigned char)hdr[17]) +
                                              (256)*((unsigned char)hdr[18]) +
                                                    ((unsigned char)hdr[19])));
                return Address(htonl(buf), Address::IPv4);
	        }
	        else  // (6 == Version(hdr))
	        {
	            unsigned long buf[4];
	            Address theAddress;
	            for(unsigned int i = 0; i<=4 ; i++)
	            {

                    buf[i] = ((256*256*256)*((unsigned char)hdr[(i*4)+24]) +
                                  (256*256)*((unsigned char)hdr[(i*4)+25]) +
                                      (256)*((unsigned char)hdr[(i*4)+26]) +
                                            ((unsigned char)hdr[(i*4)+27]));
                    buf[i] = htonl(buf[i]);
                }
                theAddress.SetIPv6(buf);
	            return theAddress;
	        }    
        }
        
        unsigned short SourcePort(const char* hdr) const
        {
	        unsigned int ipHdrLen;
	        if(Version(hdr) == 4)
                ipHdrLen = 4 * (((unsigned char)hdr[0]) & 0x0f);
	        else
	            ipHdrLen = 40;
            hdr += ipHdrLen;
            return (256*((unsigned char)hdr[0]) + (unsigned char)hdr[1]);
        }
        
        unsigned short DestinationPort(const char* hdr) const
        {
	        unsigned int ipHdrLen;
	        if(Version(hdr) == 4)
                ipHdrLen = 4 * (((unsigned char)hdr[0]) & 0x0f);
            else
	            ipHdrLen = 40;
	        hdr += ipHdrLen;
            return (256*((unsigned char)hdr[2]) + (unsigned char)hdr[3]);
        }

      
};  // end class TcpdumpEventParser

class DrecEventParser : public EventParser
{
    public:
        bool GetNextPacketEvent(FILE*           filePtr, 
                                PacketEvent*    theEvent, 
                                double          timeout = -1.0);
};  // end class DrecEventParser


class Point
{
    friend class PointList;
    
    public:
        Point(double x, double y);
        Point(double x, unsigned long k);
        double X() {return xval;}
        double Y() {return yval;}
        double K() {return kval;}
        Point* Prev() {return prev;}
        Point* Next() {return next;}
    
    private:
        double          xval;
        double          yval;
        unsigned long   kval;
        Point*          prev;
        Point*          next;
};  // end class Point()

class PointList
{
    public:
        PointList();
        ~PointList();
        Point* Head() {return head;}
        Point* Tail() {return tail;}
        void Append(Point* thePoint);
        void Remove(Point* thePoint);
        void Destroy();
        void PruneData(double xMin);
        bool PrintData(FILE* filePtr);
        Point* FindPointByK(unsigned long k);
        
    private:
        Point* head;
        Point* tail;
    
};



class LossTracker
{
    public:
        LossTracker();
        void Reset()
        {
            loss_list.Destroy();
            packet_count = 0;
            loss_count = 0;
            duplicate_count = 0;
            late_count = 0;
            loss_fraction = 1.0;
        }
        
        void Init(unsigned long seqMax)
        {
            Reset();
            SetSeqMax(seqMax);
            resync_count = 0;
            first_packet = true;
        }
        bool Update(double theTime, unsigned long theSequence, unsigned long theFlow = 0);
        
        void SetSeqMax(unsigned long seqMax)
        {
            seq_max = seqMax;
            seq_hlf = seqMax >> 1;
            seq_qtr = seqMax >> 2; 
        }
        double LossFraction() {return loss_fraction;}
        unsigned long ResyncCount() {return resync_count;}
        unsigned long DuplicateCount() {return duplicate_count;}
        unsigned long LateCount() {return late_count;}
        
        
    private:
        PointList     loss_list;
        double        last_time;
        double        loss_fraction;
        long          loss_max;
        bool          first_packet;
        unsigned long packet_count;
        unsigned long loss_count;
        unsigned long resync_count;
        unsigned long duplicate_count;
        unsigned long late_count;
        
        unsigned long seq_max;
        unsigned long seq_hlf;
        unsigned long seq_qtr;
        unsigned long seq_last;
        
        unsigned long flow_id; // makes sure all drec packets from same flow
};  // end class LossTracker


// A data driven loss tracker, procrastinates as needed.
class LossTracker2
{
    public:
        LossTracker2();
        void Init(double windowSize, unsigned long seqMax = 0xffffffff)
        {
            window_size = windowSize;
            seq_max = seqMax;
            seq_hlf = seqMax >> 1;
            seq_qtr = seqMax >> 2;
            first_packet = true;
            packet_count = 0;
        }
        void Reset()
        {
            seq_first = seq_last;
            time_first = time_last;
            if (window_size > 0)
                window_end = time_first + window_size;
            packet_count = 1;      
            wrap = false;
            wrap_count = 0;
        }
        int Update(double theTime, unsigned long theSeq, unsigned long theFlow = 0);        
        double LossFraction();
        double LossWindowStart() {return time_first;}
        double LossWindowEnd() {return time_last;}
    
    private:
        bool            first_packet;
        bool            wrap;
        unsigned long   wrap_count;
        double          time_first;
        double          time_last;
        double          window_size;
        double          window_end;
        unsigned long   packet_count;
        unsigned long   seq_first;
        unsigned long   seq_last;
        
        unsigned long   duplicate_count;
        unsigned long   resync_count;
        
        unsigned long   seq_max;
        unsigned long   seq_hlf;
        unsigned long   seq_qtr;
        
        unsigned long   flow_id;  // to make sure all drec packets from same flow
    
};  // end class LossTracker2

class LossTracker3
{
    public:
        LossTracker3();
    
        void Init(double windowSize, unsigned long seqMax = 0xffffffff)
        {
            window_size = windowSize;
            seq_max = seqMax;
            seq_sign = (seqMax ^ (seqMax >> 1));  // sign bit for sequence space
            seq_qtr = seqMax >> 2;
            init = true;
            packet_count = 0;
        }
        void Reset()
        {
            packet_count = 1;  
            wrap_count = 0;
            seq_first = seq_last;
            time_first = time_last; 
        }
        int Update(double theTime, unsigned long theSeq, unsigned long theFlow = 0);
        bool IsDuplicate(double theTime, unsigned long theSeq, unsigned long theFlow = 0);
        double LossWindowStart() {return time_first;}
        double LossWindowEnd() {return time_last;}
        double LossFraction(); 
    
        enum {HISTORY_MAX = 32};
    private:
        long SeqDelta(unsigned long a, unsigned long b)
        {
            long result = a - b;
            return ((0 == (result & seq_sign)) ? 
                         (result & seq_max) :
                         ((((unsigned long)result != seq_sign) || (a < b)) ? 
                             (result | ~seq_max) : result));
        }   
         
            
        bool            init;
        unsigned long   history[HISTORY_MAX];
        unsigned long   offset;
        unsigned long   seq_max;
        unsigned long   seq_qtr;
        unsigned long   seq_sign;
        unsigned long   seq_first;
        unsigned long   seq_last;
        double          window_size;  // time window
        double          time_first;
        double          time_last;
        unsigned long   wrap_count;
        unsigned long   packet_count;      // make this longlong???
        unsigned long   duplicate_count;   // make this longlong???
       
};  // end class LossTracker3


LossTracker3::LossTracker3()
 : init(true)
{
    memset(history, 0, HISTORY_MAX*sizeof(unsigned long));  
}

bool LossTracker3::IsDuplicate(double theTime, unsigned long theSeq, unsigned long theFlow)
{
    unsigned long oldDupCount = duplicate_count;
    Update(theTime, theSeq, theFlow);
    return (oldDupCount != duplicate_count);
}  // end LossTracker3::IsDuplicate()


int LossTracker3::Update(double theTime, unsigned long theSeq, unsigned long theFlow)
{
    int result = 0;
    if (init)
    {
        memset(history, 0, HISTORY_MAX*sizeof(unsigned long)); 
        offset = (theSeq & 0xffffffc0) - 32*(HISTORY_MAX - 1);
        offset &= seq_max;
        packet_count = 0;
        seq_first = seq_last = theSeq;
        time_first = time_last = theTime;
        init = false;   
    }
    
    
    long index = SeqDelta(theSeq, offset);
    if (index < -((long)seq_qtr))
    {
        /// Assume large outage instead of old packet
        fprintf(stderr, "trpr: LossTracker3::Update() big outage? index:%ld seq_qtr:%lu, seq:%lu offset:%lu\n",
                index, seq_qtr, theSeq, offset);
        index += seq_max;
        seq_last = theSeq;
    }
    else if (index < 0)
    {
        // Packet is quite a bit old, so consider it lost?
        fprintf(stderr, "trpr: LossTracker3::Update() got very old packet (seq:%lu)?\n", theSeq);
        return 0;
    }
    else if (SeqDelta(theSeq, seq_last) > 0)
    {
        if (theSeq < seq_last) wrap_count++;
        seq_last = theSeq;   
    }
    
    unsigned long word = index >> 5;  // divide by 32
    
    if (word >= HISTORY_MAX)
    {
        //fprintf("shifting ...
        // Shift our bit mask, determining new "offset"
        unsigned long wordShift = word - HISTORY_MAX + 1;
        if (wordShift < HISTORY_MAX)
        {
            memmove(history, history+wordShift,(HISTORY_MAX - wordShift)*sizeof(unsigned long));
            memset(history+(HISTORY_MAX - wordShift), 0, wordShift * sizeof(unsigned long));
            offset += 32*wordShift;
            offset &= seq_max;
        }
        else
        {
            memset(history, 0, HISTORY_MAX*sizeof(unsigned long));
            offset = (theSeq & 0xffffffc0) - 32*(HISTORY_MAX - 1);
            offset &= seq_max;
        }
        word = HISTORY_MAX - 1;
    }
    
    unsigned long bit = index & 0x0000007f;
    bit = 0x00000001 << (31 - bit);
    
    // Have we seen this one before?
    if (0 != (history[word] & bit))
    {
        duplicate_count++;
    }
    else
    {
        // New packet
        packet_count++;
        history[word] |= bit;   
    }
    
    if (window_size > 0.0)
    {
        if ((theTime - time_first) >= window_size)
        {
            // Indicate that the window has past
            result = 1;
        }
    }
    time_last = theTime;
    return result;
}  // end LossTracker3::Update()

double LossTracker3::LossFraction()
{
    unsigned long pktsExpected = wrap_count * seq_max;
    pktsExpected += SeqDelta(seq_last, seq_first) + 1;
    double lossFraction =  (packet_count < pktsExpected) ?
                                (1.0 - ((double)packet_count) / ((double)pktsExpected)) : 0.0;
    return lossFraction;
}  // end LossTracker3::LossFraction()



// Simple self-scaling linear/non-linear histogram (one-sided)
class Histogram
{
    public:
        Histogram();
        void Init(unsigned long numBins, double linearity)
        {
            num_bins = numBins;
            q = linearity;
            if (bin) delete[] bin;
            bin = NULL;
        }
        bool Tally(double value, unsigned long count = 1);
        void Print(FILE* file);
        unsigned long Count();
        double PercentageInRange(double rangeMin, double rangeMax);
        double Min() {return min_val;}
        double Max() {return max_val;}
        double Percentile(double p);
               
    private:     
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

void Histogram::Print(FILE* file)
{
    if (bin)
    {
        for (unsigned int i = 0; i < num_bins; i++)
        {
            if (bin[i].count)
            {
                double x = bin[i].total / ((double)bin[i].count);
                fprintf(file, "%f, %lu\n", x, bin[i].count);    
            }
        }
    }
}  // end Histogram::Print()


unsigned long Histogram::Count()
{
    if (bin)
    {
        unsigned long total =0 ;
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
            double value = bin[i].total / ((double)bin[i].count);
            countTotal += bin[i].count;
            if (value < rangeMin)
                continue;
            else if (value > rangeMax)
                continue;
            else
                rangeTotal += bin[i].count;
        }
        return (100.0 * ((double)rangeTotal) / ((double)countTotal));
    }
    else
    {
        return 0.0;
    }         
}  // end Histogram::PercentageInRange()

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


class Flow
{
    friend class FlowList;
    
    public:
        Flow(bool presetFlow = false);
        ~Flow();        
        bool InitFromDescription(char* flowInfo);
        void PrintDescription(FILE* f);
        const char* Type() {return type;}
        bool SetType(const char* theType);
        const Address& SrcAddr() const {return src_addr;}
        void SetSrcAddr(const Address& value) {src_addr = value;}
        unsigned short SrcPort() const {return src_port;}
        void SetSrcPort(unsigned short value) {src_port = value;}
        const Address& DstAddr() const {return dst_addr;}
        void SetDstAddr(const Address& value) {dst_addr = value;}
        unsigned short DstPort() const {return dst_port;}
        void SetDstPort(unsigned short value) {dst_port = value;}
        void SetFlowId(unsigned long value) {flow_id = value;}
        unsigned long FlowId() {return flow_id.Value();}
        
        bool IsPreset() {return preset;}
        
        bool TypeMatch(const char* theType) const
        {
            if (theType && type)
                return (0 == strncmp(theType, type, type_len));
            else
                return (theType == type);
        }
        
        bool Match(const char* theType, 
                   const Address& srcAddr, unsigned short srcPort, 
                   const Address& dstAddr, unsigned short dstPort, 
                   unsigned long flowId) const;
#ifdef WIN32
        ULONGLONG Bytes() const {return byte_count;}
        ULONGLONG AccumulatorCount() {return accumulator_count;}
#else
        unsigned long long Bytes() const {return byte_count;}
        unsigned long long AccumulatorCount() {return accumulator_count;}
#endif // if/else WIN32/UNIX
        void AddBytes(unsigned long pktSize) 
            {byte_count = byte_count + pktSize;}        
        void ResetByteCount() {byte_count = 0;}
        
        double Accumulator() {return accumulator;}
        
        void ResetAccumulator() {accumulator = 0.0; accumulator_count = 0;}
        void Accumulate(double value) 
        {
            accumulator += value; 
            accumulator_count = accumulator_count + 1;
        }
        
        void InitLossTracker(unsigned long seqMax = 0xffffffff) {loss_tracker.Init(seqMax);}
        void ResetLossTracker() {loss_tracker.Reset();}
        bool UpdateLossTracker(double theTime, unsigned long seq, unsigned long theFlow = 0)
            {return loss_tracker.Update(theTime, seq, theFlow);}
        double LossFraction() {return loss_tracker.LossFraction();}
        
        void InitLossTracker2(double windowSize, unsigned long seqMax = 0xffffffff)
        {
            loss_tracker2.Init(windowSize, seqMax);
        }
        void ResetLossTracker2() 
            {loss_tracker2.Reset();}
        int UpdateLossTracker2(double theTime, unsigned long seq, unsigned long theFlow = 0)
            {return loss_tracker2.Update(theTime, seq, theFlow);}
        double LossFraction2() 
            {return loss_tracker2.LossFraction();}
        double LossWindowStart2() 
            {return loss_tracker2.LossWindowStart();}
        double LossWindowEnd2() 
            {return loss_tracker2.LossWindowEnd();}
        
        bool IsDuplicate(double theTime, unsigned long seq, unsigned long theFlow = 0)
            {return loss_tracker2.IsDuplicate(theTime, seq, theFlow);}
        
        
        Flow* Next() {return next;}
        bool AppendData(double x, double y);
        void PruneData(double xMin) {point_list.PruneData(xMin);}
        bool PrintData(FILE* filePtr) {return point_list.PrintData(filePtr);}
        
        double MarkReception(double theTime)
        {
            double currentDelay = ((last_time < 0.0) ? -1.0 : (theTime - last_time));
            last_time = theTime;
            return currentDelay;   
        }
        
        void UpdateSummary(double value, double weight = 1.0) 
        {
            if (sum_init)
            {
                sum_total = value * weight;
                sum_min = sum_max = value;
                sum_var = value*value*weight;
                sum_weight = weight;
                sum_init = false;
            }
            else
            {
                sum_weight += weight;
                sum_total += (value * weight);
                sum_var += (value*value*weight);
                if (value < sum_min) sum_min = value;
                if (value > sum_max) sum_max = value;
            }
            histogram.Tally(value);
        }
        double SummaryAverage() {return (sum_total / sum_weight);}
        double SummaryVariance() 
        {
            double mean = SummaryAverage();
            double variance = sum_var/((double)sum_weight) - (mean*mean);
            return variance;   
        }
        double SummaryMin() {return sum_min;}
        double SummaryMax() {return sum_max;}
        
        double PosX() {return pos_x;}
        double PosY() {return pos_y;}
        bool PositionIsValid() 
        {
            bool xvalid = ((pos_x <= 180.0) && (pos_x >= -180.0));
            bool yvalid = ((pos_y <= 90.0) && (pos_y >= -90.0));  
            return (xvalid && yvalid);
        }
        double UpdatePosition(double theTime, double x, double y);
        
        void PrintHistogram(FILE* file) {histogram.Print(file);}
        double Percentile(double p) {return histogram.Percentile(p);}
        
            
    private:
        bool           preset;  // used to mark preset flows from "flow" command
        char*          type;
        unsigned int   type_len;
        
        Address         src_addr;
        int             src_port;
        Address         dst_addr;
        int             dst_port;
        ::FlowId        flow_id;  // if applicable
        
        // Byte count accumulator
        double          last_time;  // used for inter-arrival delay plot
#ifdef WIN32
        ULONGLONG   byte_count;
        ULONGLONG   accumulator_count;
#else
        unsigned long long byte_count;
        unsigned long long accumulator_count;
#endif // if/lese WIN32/UNIX
        double          accumulator;  // for interarrival or latency accumulation
        PointList       point_list;
        LossTracker     loss_tracker;
        LossTracker3    loss_tracker2;
        
        // GPS Position
        double          pos_x;
        double          pos_y;
        
        // Summary data
        bool            sum_init;
        double          sum_total;
        double          sum_var;
        double          sum_min;
        double          sum_max;
        double          sum_weight;
        
        // histogram
        Histogram       histogram;
        
            
        Flow* prev;
        Flow* next;  
}; // end class Flow

class FlowList
{
    public:
        FlowList();
        ~FlowList();
        void Destroy();
        void Append(Flow* theFlow);
        void Remove(Flow* theFlow);
        Flow* Head() {return head;}
        unsigned long Count() {return count;}
    
    private:
        Flow*           head;
        Flow*           tail;
        unsigned long   count;
    
};  // end class FlowList

void UpdateWindowPlot(PlotMode plotMode, FlowList& flowList, FILE* outfile,
                      double theTime, double windowStart, double windowEnd, 
                      bool realTime, bool stairStep);
void UpdateGnuplot(PlotMode plotMode, FlowList* flowList, double xMin, double xMax, 
                   const char* pngFile, const char* postFile, bool scatter, 
                   bool autoScale, bool legend, double minYRange, double maxYRange);
void UpdateMultiGnuplot(PlotMode plotMode, FlowList* flowList, double xMin, double xMax, 
                        const char* pngFile, const char* postFile, bool scatter,
                        bool autoScale, bool legend, double minYRange, double maxYRange);



Point::Point(double x, double y)
    : xval(x), yval(y), kval(0), prev(NULL), next(NULL)
{
}

Point::Point(double x, unsigned long k)
    : xval(x), yval(0), kval(k), prev(NULL), next(NULL)
{
}

PointList::PointList()
    : head(NULL), tail(NULL)
{
}

PointList::~PointList()
{
    Destroy();
}

Point* PointList::FindPointByK(unsigned long k)
{
    Point* next = head;
    while (next)
    {
        if (k == next->K())
            return next;
        else
            next = next->Next();
    }   
    return NULL;
}  // end PointList::FindPointByK()

// This tries to leave only one point with X < xMin
// This assumes X data is in order min -> max
void PointList::PruneData(double xMin)
{
    Point* next = head;
    while ((next = head))
    {
        if (next->X() < xMin)
        {
            Remove(next);
            delete next;
        }
        else
        {
            break;
        }
    }
}  // end PointList::PruneData()

bool PointList::PrintData(FILE* filePtr)
{
    Point* next = head;
    while (next)
    {
        fprintf(filePtr, "%f, %f\n", next->X(), next->Y());
        next = next->Next();
    }
    if (head)
        return true;
    else
        return false;
}  // end PointList::PrintData()
   
void PointList::Append(Point* thePoint)
{
    if ((thePoint->prev = tail))
        tail->next = thePoint;
    else
        head = thePoint;
    thePoint->next = NULL;
    tail = thePoint;   
}  // end PointList::Append()


void PointList::Remove(Point* thePoint)
{
    if (thePoint->prev)
        thePoint->prev->next = thePoint->next;
    else
        head = thePoint->next;
    if (thePoint->next)
        thePoint->next->prev = thePoint->prev;
    else
        tail = thePoint->prev;
}  // end PointList::Remove()


void PointList::Destroy()
{
    Point* next;
    while ((next = head))
    {
        Remove(next);
        delete next;
    }
}  // end PointList::Destroy()


LossTracker::LossTracker()
    : last_time(0.0), loss_fraction(1.0), loss_max(16536),
      first_packet(true),  packet_count(0), loss_count(0), 
      resync_count(0), duplicate_count(0),
      late_count(0), seq_last(0), flow_id(0)
{
    SetSeqMax(0xffffffff);
}



bool LossTracker::Update(double theTime, unsigned long theSequence, unsigned long theFlow)
{
    if (theTime < last_time) 
    {
        fprintf(stderr, "trpr: LossTracker::Update() time out of order (thisTime:%f lastTime:%f)!\n",
                         theTime, last_time);
        return false;
    }
    
    if (first_packet)
    {
        first_packet = false;   
        seq_last = theSequence;
        packet_count = 1;
        loss_fraction = 0.0;
        flow_id = theFlow;
        return true;
    }
   
    // Process incoming sequence number
    // 1) Calc delta, handling wrap conditions
    long delta;
    if ((theSequence < seq_qtr) &&
        (seq_last > (seq_hlf+seq_qtr)))
        delta = seq_max - seq_last + theSequence + 1;
    else if ((theSequence > (seq_hlf+seq_qtr)) &&
             (seq_last < seq_qtr))
        delta = theSequence - seq_last - seq_max - 1;
    else
        delta = theSequence - seq_last;   
    
    
    // 2) Use "delta" to determine sync state, loss, etc
    if ((labs(delta) > loss_max) || (theFlow != flow_id))
    {
        // lost sync?
        resync_count++;
        fprintf(stderr, "trpr: LossTracker::Update() resync! (seq:%lu lseq:%lu delta:%ld max:%lu "
                        "flow:%lu oldFlow:%lu)\n", 
                        theSequence, seq_last, delta, loss_max, theFlow, flow_id);
        seq_last = theSequence;
        Update(theTime, theSequence, theFlow);
        return false;
    }
    else if (delta > 0)
    {
        if (delta > 1)
        {
            // possible loss
            while(seq_last++ != theSequence)
            {
                if (seq_last > seq_max) seq_last = 0;
                Point* lost = new Point(theTime, seq_last);
                if (!lost)
                {
                    perror("trpr: LossTracker::Update() Error adding point");
                    return false;   
                }  
                loss_list.Append(lost);
                loss_count++;    
            }
        }
        else
        {
            // No loss
        }
        seq_last = theSequence;
        packet_count++;
        
    }
    else if (delta < 0)
    {
        // Late arriving packet
        packet_count++;
        Point* oldLost = loss_list.FindPointByK(theSequence);
        if (oldLost)
        {
            loss_list.Remove(oldLost);
            loss_count--;
        }
        else
        {
            // Late packet (from previous window?)
            late_count++; 
        }
    }
    else
    {
        // duplicate packet?
        duplicate_count++;  
        packet_count++;  
    } 
    
    // 4) Compute current loss fraction value
    // (TBD) Fudge with late_count??
    //fprintf(stderr, "losses:%lu pkts:%lu\n", loss_count, packet_count);
    loss_fraction = ((double)loss_count) / 
                    ((double)(packet_count+loss_count));
    
    last_time = theTime;
    
    return true;
}  // end LossTracker::Update()


LossTracker2::LossTracker2()
    : first_packet(true), wrap(false), wrap_count(0),
      time_first(-1.0), time_last(-1.0), 
      window_size(1.0), window_end(-1.0),
      packet_count(0), seq_first(0), seq_last(0),
      duplicate_count(0), resync_count(0), seq_max(0xffffffff),
      flow_id(0)
      
{
       
}


int LossTracker2::Update(double theTime, unsigned long theSequence, unsigned long theFlow)
{
    if (theTime < time_last) 
    {
        fprintf(stderr, "trpr: LossTracker::Update() time out of order (thisTime:%f lastTime:%f)!\n",
                         theTime, time_last);
        //exit(-1);
    }
    
    if (first_packet)
    {
        first_packet = false;   
        seq_first = seq_last = theSequence;
        time_first = time_last = theTime;
        if (window_size > 0.0)
            window_end = theTime + window_size;
        packet_count = 1;
        wrap = false;
        wrap_count = 0;
        flow_id = theFlow;
        return 0;
    }
   
    // Process incoming sequence number
    
    // 1) Check for sequence wrap  & sync loss
    long delta;
    if ((theSequence < seq_qtr) &&
        (seq_last > (seq_hlf+seq_qtr)))
    {
        delta = seq_max - seq_last + theSequence + 1;
        wrap = true;
    }
    else if ((theSequence > (seq_hlf+seq_qtr)) &&
             (seq_last < seq_qtr))
    {
        delta = theSequence - seq_last - seq_max - 1;
    }
    else
    {
        delta = theSequence - seq_last;   
    }
    if (wrap && (theSequence >= seq_first))
    {
        wrap = false;
        wrap_count++;
           
    }
    
    if ((labs(delta) > (long)seq_qtr) || (theFlow != flow_id))
    {
        resync_count++;
        fprintf(stderr, "trpr: LossTracker2() resync! (thisSeq:%lu lastSeq:%lu theFlow:%lu lastFlow:%lu)\n",  
                        theSequence, seq_last, theFlow, flow_id);
        first_packet = true;
        Update(theTime, theSequence, theFlow);
        return -1; 
    }
    
    // 2) Is this packet "after" our first packet    
    if ((theSequence < seq_qtr) &&
        (seq_first > (seq_hlf+seq_qtr)))
    {
        delta = seq_max - seq_first + theSequence + 1;
    }
    else if ((theSequence > (seq_hlf+seq_qtr)) &&
             (seq_first < seq_qtr))
    {
        delta = theSequence - seq_first - seq_max - 1;
    }
    else
    {
        delta = theSequence - seq_first; 
    }
    if (wrap_count & (delta <= 0)) delta += seq_max;
    
    // 2) Does this packet count?
    if (delta > 0)
    {
        // It's a good packet
        packet_count++;
        seq_last = theSequence;
    }
    else if (delta < 0)
    {
        // Late packet, don't count
        //fprintf(stderr, "late packet (seq:%lu seq_first:%lu) ...\n", theSequence, seq_first);
    }
    else
    {
        duplicate_count++;
    } 
    
    time_last = theTime;  
     
    if ((window_end < 0.0) || (theTime < window_end) || (packet_count < 2))
        return 0;
    else
        return 1;
}  // end LossTracker2::Update()

double LossTracker2::LossFraction()
{
    long delta;
    if ((seq_last < seq_qtr) &&
        (seq_first > (seq_hlf+seq_qtr)))
    {
        delta = seq_max - seq_first + seq_last + 1;
    }
    else if ((seq_last > (seq_hlf+seq_qtr)) &&
             (seq_first < seq_qtr))
    {
        delta = seq_last - seq_first - seq_max - 1;
    }
    else
    {
        delta = seq_last - seq_first; 
    }
    unsigned long wraps = wrap_count;
    if (wraps & (delta <= 0)) 
    {
        delta += seq_max;
        wraps--;
    }
    
    if (delta < 0) return -1.0;  // this shouldn't happen!
    double packetsExpected = (double)delta + 1.0;
    if (wraps) packetsExpected += (((double)wraps) * ((double)seq_max));
    
    if (packet_count > 1)
    {
        double lossFraction = 1.0 - (((double)(packet_count-1)) / (packetsExpected - 1.0));
        return lossFraction;
    }
    else
    {
        fprintf(stderr, "Low packet count? %lu\n", packet_count);
        return -1.0;
    }
}  // end LossTracker2::LossFraction()

Flow::Flow(bool presetFlow)
    : preset(presetFlow), 
      type(NULL), type_len(0), src_port(-1), dst_port(-1),
      byte_count(0), accumulator(0.0), accumulator_count(0),
      last_time(-1.0), pos_x(999.0), pos_y(999.0),
      sum_init(true), sum_total(0.0), sum_var(0.0), 
      sum_min(0.0), sum_max(0.0), sum_weight(0.0),
      prev(NULL), next(NULL)
{
    histogram.Init(1000, 0.5);
}

Flow::~Flow()
{
    if (type) delete []type;
}

bool Flow::SetType(const char* theType)
{
    if (type) delete []type;
    int len = strlen(theType) + 1;
    if(!(type = new char[len]))
    {
        perror("trpr: Error allocating flow type storage");
        return false;
    }
    strcpy(type, theType);
    type_len = len - 1;
    return true;
}  // end Flow::SetName()

bool Flow::Match(const char* theType, 
                 const Address& srcAddr, unsigned short srcPort, 
                 const Address& dstAddr, unsigned short dstPort,
                 unsigned long flowId) const
{
    //fprintf(stderr, "Matching flow type:%s src:%s/%d dst:%s/%d ...\n",
    //        theType, srcAddr.addr, srcPort, dstAddr.addr, dstPort);
    if ((type && !TypeMatch(theType)) ||    
        ((dst_port >= 0) && (dst_port != dstPort)) ||
        ((dst_addr.IsValid()) && !(dst_addr == dstAddr)) ||
        ((src_port >= 0) && (src_port != srcPort)) ||
        ((src_addr.IsValid()) && !(src_addr == srcAddr)) ||
        ((flow_id.IsValid()) && (flow_id != flowId)))
    {
        //fprintf(stderr, "no match\n");
        return false;
    }
    else
    {
        //fprintf(stderr, "match\n");
        return true;
    }
}  // end Flow::Match()

void Flow::PrintDescription(FILE* f)
{
    if (type)
        fprintf(f, "%s,", type);
    else
        fprintf(f, "*,");
    
    if (src_addr.IsValid())
    {
        src_addr.PrintDescription(f);
        fprintf(f, "/");     
    }
    else
    {
        fprintf(f, "*/");
    }
    if (src_port >= 0)
        fprintf(f, "%lu->", (unsigned long)src_port);
    else
        fprintf(f, "*->");
    if (dst_addr.IsValid())
    {
        dst_addr.PrintDescription(f);
        fprintf(f, "/");
    }
    else
    {
        fprintf(f, "*/");
    }
    if (dst_port >= 0)
        fprintf(f, "%lu", (unsigned long)dst_port);
    else
        fprintf(f, "*");
    if (flow_id.IsValid())
        fprintf(f, "~%lu", (unsigned long)flow_id);
}  // end Flow::PrintDescription()

bool Flow::AppendData(double x, double y)
{
    Point* thePoint = new Point(x,y);
    if (thePoint)
    {
        point_list.Append(thePoint);
        return true;   
    }
    else
    {
        return false;
    }
}  // end Flow::AppendData()

double Flow::UpdatePosition(double theTime, double x, double y)
{
    if (PositionIsValid())
    {
        x = 0.25*pos_x + 0.75*x;
        y = 0.25*pos_y + 0.75*y;
        double dx = (pos_x - x);
        double dy = (pos_y - y);
        double dp = sqrt(dx*dx + dy*dy);
        double dt = theTime - last_time;
        if (dt > 0.0)
        {
            return (1.0e05*dp/dt); // to approx. meters/sec
        }
        else
        {
            fprintf(stderr, "trpr: Flow::UpdatePosition() time moved backwards!\n");  
            return -1.0;
        }
    }
    else
    {
        pos_x = x;
        pos_y = y;
        last_time = theTime;
        return -1.0;   
    }
}  // end Flow::UpdatePosition()

FlowList::FlowList()
    : head(NULL), tail(NULL), count(0)
{
}

FlowList::~FlowList()
{
    Destroy();
}

void FlowList::Append(Flow* theFlow)
{
    if ((theFlow->prev = tail))
        theFlow->prev->next = theFlow;
    else
        head = theFlow;
    theFlow->next = NULL;
    tail = theFlow;
    count++;
}  // end FlowList::Append()


void FlowList::Remove(Flow* theFlow)
{
    if (theFlow->prev)
        theFlow->prev->next = theFlow->next;
    else
        head = theFlow->next;
    
    if (theFlow->next)
        theFlow->next->prev = theFlow->prev;
    else
        tail = theFlow->prev;
    count--;
}  // end FlowList::Remove()
        

void FlowList::Destroy()
{
    Flow* next;
    while ((next = head))
    {
        Remove(next);
        delete next;
    }   
}  // end Destroy()


const char WILDCARD = 'X';

inline void usage()
{
    fprintf(stderr, "TRPR Version %s\n", VERSION);
    fprintf(stderr, "Usage: trpr [version][mgen][ns][raw][key][real][loss][latency|interarrival]\n"
                    "            [window <sec>] [history <sec>]\n"
                    "            [flow <type,srcAddr/port,dstAddr/port,flowId>]\n"
                    "            [auto <type,srcAddr/port,dstAddr/port,flowId>]\n"
                    "            [exclude <type,srcAddr/port,dstAddr/port,flowId>]\n"
                    "            [input <inputFile>] [output <outputFile>]\n"
                    "            [link <src>[,<dst>]][send|recv][nodup]\n"
                    "            [xrange <min>[:<max>]][yrange <min>[:<max>]\n"
                    "            [offset <hh:mm:ss>][absolute]\n"
                    "            [summary][histogram][replay <factor>]\n"
                    "            [png <pngFile>][post <postFile>][multiplot]\n"
                    "            [surname <titlePrefix>][ramp][scale]\n"
                    "            [nolegend]\n");
    fprintf(stderr, " (NOTE: 'Wildcard' type, addr, or port parameters with 'X'\n");
    fprintf(stderr, "         xrange parameters are in seconds\n");

}


bool Flow::InitFromDescription(char* flowInfo)
{
    flowInfo = strtok(flowInfo, ",");
    if (flowInfo) 
    {
        if(WILDCARD != flowInfo[0]) SetType(flowInfo);
    }
    else
    {
        fprintf(stderr, "trpr: Error parsing \"flow\" description!\n");
        return false;
    }
    // Pull out source addr/port, checking for wildcards
    if ((flowInfo = strtok(NULL, ",")))
    {
        // Parse source address/port
        char* ptr = strchr(flowInfo, '/');
        if (ptr) 
        {
            *ptr++ = '\0';
            if (WILDCARD != ptr[0]) SetSrcPort(atoi(ptr));
        }
        if (WILDCARD != flowInfo[0]) SetSrcAddr(flowInfo);

        // Pull out destination addr/port, checking for wildcards
        flowInfo = strtok(NULL, ",");
        if (flowInfo)
        {
            // Parse destination address/port
            char* ptr = strchr(flowInfo, '/');
            if (ptr) 
            {
                *ptr++ = '\0';
                if (WILDCARD != ptr[0]) SetDstPort(atoi(ptr));
            }
            if (WILDCARD != flowInfo[0]) SetDstAddr(flowInfo);
        }
        // An optional "flowId" can be specified, too
        if ((flowInfo = strtok(NULL, ",")))
        {
            if (WILDCARD != flowInfo[0])
            {
                unsigned long flowId;
                if (1 != sscanf(flowInfo, "%lu", &flowId))
                {
                    fprintf(stderr, "trpr: Error parsing \"flow\" flow id!\n");
                    return false;
                } 
                SetFlowId(flowId);
            }
        }
    }
    return true;
}  // end Flow::InitFromDescription()

static const double SECONDS_PER_DAY = (24.0 * 60.0 * 60.0);
                    
int main(int argc, char* argv[])
{ 
    FlowList flowList;
    FlowList autoList;
    FlowList excludeList;
    
    bool defaultMatching = true;
    double windowSize = 1.0;
    bool   use_default_window = true;
    double historyDepth = 20.0;
    char* input_file = NULL;
    char* output_file = NULL;
    char* png_file = NULL;
    char* post_file = NULL;
    bool use_gnuplot = true;
    bool multiplot = false;
    bool realTime = false;
    TraceFormat traceFormat = TCPDUMP;
    PlotMode plotMode = RATE;  
    bool replay = false; // real time playback mode
    double replayFactor = 1.0;
    double startTime = -1.0;
    double stopTime = -1.0;
    double minYRange = -1.0;
    double maxYRange = -1.0;
    bool print_key = false;
    bool legend = true;
    double offsetTime = -1.0;
    bool summarize = false;
    bool make_histogram = false;
    unsigned int detect_proto_len = 0;
    bool normalize = true;
    bool stairStep = true;
    bool autoScale = false;
    bool discardDuplicates = false;
    
    char* surname = NULL;
    
    PacketEvent::TracePoint link;   // Our tracepoint (wildcard default)
    char* linkSrc = NULL;
    char* linkDst = NULL;    
    enum EventMask {SEND = 0x01, RECV = 0x02, DROP = 0x04};
    int eventMask = (RECV | DROP);
    
    if (argc < 2)
    {
        usage();
        exit(-1);
    }
    
    fprintf(stderr, "TRPR Version %s\n", VERSION);
            
    // Parse command line
    int i = 1;
    while(i < argc)
    {
        if (!strcmp("window", argv[i]))
        {
            i++;
            float w;
            if (1 != sscanf(argv[i], "%f", &w))
            {
               fprintf(stderr, "trpr: Error parsing \"window\" size!\n");
               usage();
               exit(-1);
            }
            use_default_window = false;
            windowSize = w;
            i++;
        }
        else if (!strcmp("history", argv[i]))
        {
            i++;
            float w;
            if (1 != sscanf(argv[i], "%f", &w))
            {
               fprintf(stderr, "trpr: Error parsing \"history\" depth!\n");
               usage();
               exit(-1);
            }
            historyDepth = w;
            i++;
        }
        else if (!strcmp("flow", argv[i]))
        {
            defaultMatching = false;
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"flow\" arguments!\n");
                usage();
                exit(-1);
            }
            // Create & init new "preset" flow from description
            Flow* theFlow = new Flow(true);
            if (!theFlow)
            {
                perror("trpr: Error allocating memory for flow");
                exit(-1);
            }
            if (!theFlow->InitFromDescription(argv[i++]))
            {
                fprintf(stderr, "trpr: Error parsing \"flow\" description!\n");
                usage();
                exit(1);
            }
            flowList.Append(theFlow);
            fprintf(stderr, "trpr: Adding flow: ");
            theFlow->PrintDescription(stderr);
            fprintf(stderr, "\n");
        }
        else if (!strcmp("replay", argv[i]))
        {            
            replay = true;
            realTime = true;
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"replay\" arguments!\n");
                usage();
                exit(-1);
            }
            replayFactor = atof(argv[i]);
            i++;
        } 
        else if (!strcmp("absolute", argv[i]))
        {            
            normalize = false;
            i++;
        } 
        else if (!strcmp("nodup", argv[i]))
        {            
            discardDuplicates = true;
            i++;
        } 
        else if (!strcmp("range", argv[i]) || (!strcmp("xrange", argv[i])))
        {            
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"xrange\" arguments!\n");
                usage();
                exit(-1);
            }
            char *ptr = strchr(argv[i], ':');
            if (ptr)
            {
                *ptr++ = '\0';
                startTime = atof(argv[i]);
                stopTime = atof(ptr);
            }
            else
            {
                startTime = atof(argv[i]);
                stopTime = -1.0;  // startTime only
            }
            i++;
        }  
        else if (!strcmp("yrange", argv[i]))
        {            
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"yrange\" arguments!\n");
                usage();
                exit(-1);
            }
            char *ptr = strchr(argv[i], ':');
            if (ptr)
            {
                *ptr++ = '\0';
                minYRange = atof(argv[i]);
                maxYRange = atof(ptr);
            }
            else
            {
                minYRange = atof(argv[i]);
                maxYRange = -1.0;  // startTime only
            }
            i++;
        }  
        else if (!strncmp("multi", argv[i], 5))
        {
            i++;
            multiplot = true;
        }  
        else if (!strncmp("ramp", argv[i], 5))
        {
            i++;
            stairStep = false;
        } 
        else if (!strcmp("scale",argv[i]))
        {
            i++;
            // autoscale the y axis
            autoScale = true;
        }
        else if (!strcmp("drec", argv[i]))
        {
            i++;
            traceFormat = DREC;
        }  
        else if (!strcmp("mgen", argv[i]))
        {
            i++;
            traceFormat = DREC;
        }  
        else if (!strcmp("ns", argv[i]))
        {
            i++;
            traceFormat = NS;
            //domain = NUM;
        }   
        else if (!strncmp("real", argv[i], 4))
        {
            i++;
            realTime = true;
        }  
        else if (!strcmp("rate", argv[i]))
        {
            i++;
            plotMode = RATE;
        } 
        else if (!strcmp("latency", argv[i]))
        {
            i++;
            plotMode = LATENCY;
        } 
        else if (!strncmp("inter", argv[i], 5))
        {
            i++;
            plotMode = INTERARRIVAL;
        } 
        else if (!strncmp("drops", argv[i], 4))
	{
	    i++;
	    plotMode = DROPS;
	}
	else if (!strncmp("loss", argv[i], 5))
        {
            i++;
            plotMode = LOSS2;  // we're using LOSS2 as our default loss tracking algorithm
        } 
        else if (!strncmp("loss2", argv[i], 5))
        {
            i++;
            plotMode = LOSS;
        } 
        else if (!strncmp("count", argv[i], 5))
        {
            i++;
            plotMode = COUNT;
        }
        else if (!strncmp("velocity", argv[i], 5))
        {
            i++;
            plotMode = VELOCITY;
        }
        else if (!strcmp("raw", argv[i]))
        {
            i++;
            use_gnuplot = false;
        } 
        else if (!strcmp("key", argv[i]))
        {
            i++;
            print_key = true;
        }
	else if (!strcmp("nolegend", argv[i]))
	{
	    i++;
	    legend = false;
	}
        else if (!strcmp("png", argv[i]))
        {
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"png\" arguments!\n");
                usage();
                exit(-1);
            }
            png_file = argv[i++];
        }  
        else if (!strcmp("post", argv[i]))
        {
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"post\" arguments!\n");
                usage();
                exit(-1);
            }
            post_file = argv[i++];
        } 
        else if (!strcmp("input", argv[i]))
        {
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"input\" arguments!\n");
                usage();
                exit(-1);
            }
            input_file = argv[i++];
        }     
        else if (!strcmp("output", argv[i]))
        {
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"output\" arguments!\n");
                usage();
                exit(-1);
            }
            output_file = argv[i++];
        }       
        else if (!strcmp("surname", argv[i]))
        {
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"surname\" arguments!\n");
                usage();
                exit(-1);
            }
            surname = argv[i++];
        }    
        else if (!strcmp("auto", argv[i]))
        {
            defaultMatching = false;
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"auto\" arguments!\n");
                usage();
                exit(-1);
            }
            
            // Create & init new automatcher flow from description
            Flow* theFlow = new Flow(true);
            if (!theFlow)
            {
                perror("trpr: Error allocating memory for flow");
                exit(-1);
            }
            if (!theFlow->InitFromDescription(argv[i++]))
            {
                fprintf(stderr, "trpr: Error parsing \"auto\" flow description!\n");
                usage();
                exit(1);
            }
            autoList.Append(theFlow);
            fprintf(stderr, "trpr: Adding autoMatcher: ");
            theFlow->PrintDescription(stderr);
            fprintf(stderr, "\n");
        }      
        else if (!strncmp("ex", argv[i], 2))
        {
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"exclude\" arguments!\n");
                usage();
                exit(-1);
            }
            
            // Create & init new automatcher flow from description
            Flow* theFlow = new Flow(true);
            if (!theFlow)
            {
                perror("trpr: Error allocating memory for flow");
                exit(-1);
            }
            if (!theFlow->InitFromDescription(argv[i++]))
            {
                fprintf(stderr, "trpr: Error parsing \"exclude\" flow description!\n");
                usage();
                exit(1);
            }
            excludeList.Append(theFlow);
            fprintf(stderr, "trpr: Adding exclusion filter: ");
            theFlow->PrintDescription(stderr);
            fprintf(stderr, "\n");
        }       
        else if (!strcmp("link", argv[i]))
        {            
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"link\" arguments!\n");
                usage();
                exit(-1);
            }
            char *ptr = strchr(argv[i], ',');
            if (ptr == argv[i])
            {
                *ptr++ = '\0';
                linkSrc = NULL;
                linkDst = ptr;  // dst tracepoint only
            }
            else if (ptr)
            {
                *ptr++ = '\0';
                linkSrc = argv[i]; 
                linkDst = ptr; 
            }
            else
            {
                linkSrc = argv[i]; // src tracepoint only
                linkDst = NULL; 
            }
            i++;
        }  
        else if (!strcmp("send", argv[i]))
        {
            i++;
            eventMask = SEND;   
        }  
        else if (!strcmp("recv", argv[i]))
        {
            i++;
            eventMask = RECV;   
        }
        else if (!strcmp("offset", argv[i]))
        {
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "trpr: Insufficient \"exclude\" arguments!\n");
                usage();
                exit(-1);
            }
            int hour, min;
            float sec;
            if (3 != sscanf(argv[i], "%d:%d:%f", &hour, &min, &sec))
            {
                fprintf(stderr, "trpr: Error parsing \"exclude\" flow description!\n");
                usage();
                exit(1);
            }
            offsetTime = (double)(hour*3600 + 60*min) + sec;
            i++;
        }        
        else if (!strncmp("sum", argv[i], 3))
        {
            summarize = true;  
            i++; 
        }         
        else if (!strncmp("histogram", argv[i], 3))
        {
            make_histogram = true;  
            i++; 
        }     
        else if (!strcmp("version", argv[i]))
        {
            exit(0);   
        }
        else
        {
            fprintf(stderr, "trpr: Invalid command: %s\n", argv[i]);
            usage();
            exit(-1);
        }
    }   
    
    
    // If now "flow" or "auto" matching was specified,
    // the default behavior is total wildcard auto matching "auto X" ...
    if (defaultMatching)
    {
        Flow* theFlow = new Flow(true);
        if (!theFlow)
        {
            perror("trpr: Error allocating memory for flow");
            exit(-1);
        }
        char defaultMatcher[32];
        strcpy(defaultMatcher, "X");
        if (!theFlow->InitFromDescription(defaultMatcher))
        {
            fprintf(stderr, "trpr: Error parsing \"auto\" flow description!\n");
            usage();
            exit(-1);
        }
        autoList.Append(theFlow);
        fprintf(stderr, "trpr: Adding default autoMatcher: ");
        theFlow->PrintDescription(stderr);
        fprintf(stderr, "\n");
    }
    
    // Validate command combinations
    switch(plotMode)
    {
        case LOSS:
        case LOSS2:  
            if ((windowSize == 0.0))
            {
                fprintf(stderr, "trpr: LOSS plots require non-zero window size!\n"); 
                exit(-1);  
            } 
            if (DREC != traceFormat)
            {
                fprintf(stderr, "trpr: LOSS and LATENCY plots currently "
                                "available for \"drec\" only.\n");
                exit(-1);
            } 
            break;
                
        case LATENCY:
        case VELOCITY:
            if (DREC != traceFormat)
            {
                fprintf(stderr, "trpr: LATENCY and VELOCITY plots currently "
                                "available for \"drec\" only.\n");
                exit(-1);
            }
        case INTERARRIVAL:
            if (use_default_window) windowSize = 0.0;
            break;
            
        default:
            break;
    }

    if (linkSrc || linkDst)
    {
        if (!strcmp(linkSrc, "X")) linkSrc = NULL;
        if (!strcmp(linkDst, "X")) linkDst = NULL;
        if (DREC == traceFormat)
        {
            fprintf(stderr, "trpr: \"link\" tracepoint command not applicable to \"drec\"!\n");
            exit(-1);   
        }
        else if (TCPDUMP == traceFormat)
        {
            fprintf(stderr, "trpr: \"link\" tracepoint command not yet supported for \"tcpdump\"!\n");
            exit(-1);
        }
        else
        {
            // NS link or node tracepoint defined by node ids
            if (linkSrc) link.SetSrc(linkSrc);
            if (linkDst) link.SetDst(linkDst);
        }
    }
    
    // Init flows in lists as needed
    Flow* f = flowList.Head();
    while(f)
    {
        if ((LOSS2 == plotMode) || (discardDuplicates))
            f->InitLossTracker2(windowSize);
        f = f->Next();
    }
    

    // Open input trace file
    FILE* infile;
    if (input_file)
    {
        if(!(infile = fopen(input_file, "r")))
        {
            perror("trpr: Error opening input file");
            usage();
            exit(-1);
        }
    }
    else
    {
        fprintf(stderr, "trpr: Using stdin for input ...\n");
        infile = stdin;
    }
    
    // Open output file
    FILE* outfile = NULL;
    char temp_file[PATH_MAX];
    if (output_file)
    {
	    strcpy(temp_file, output_file);
	    if (use_gnuplot) strcat(temp_file, ".tmp");
        if(!(outfile = fopen(temp_file, "w+")))
        {
            perror("trpr: Error opening output file");
            usage();
            exit(-1);
        } 
    }

    // Print comment line with key to data columns
    if (outfile && print_key)
    {
        fprintf(outfile, "#Time");
        Flow* next = flowList.Head();
        while (next)
        {
            fprintf(outfile, ", ");  
            next->PrintDescription(outfile);
            next = next->Next(); 
        }   
        fprintf(outfile, "\n");
    }
    
    double updateWindow = 1.0;
    if (windowSize > 0.0) updateWindow = windowSize;
     
    double theTime = updateWindow;  
    double windowStart = -1.0;
    double windowEnd = -1.0;
    double minTime = 0.0;
    double maxTime = historyDepth;
    
    double refTime = 0.0;
    double lastTime = 0.0;
    
    bool firstTime = true;

    DrecEventParser drecParser;
    TcpdumpEventParser tcpdumpParser;
    NsEventParser nsParser;
    EventParser* parser = NULL;
    switch (traceFormat)
    {
        case TCPDUMP:
            parser = &tcpdumpParser;
            break;
        case DREC:
            parser = &drecParser;
            break;
        case NS:
            parser = &nsParser;
            break;
    }

    PacketEvent theEvent;
    double timeout = -1.0;   
#ifndef WIN32  // no real-time TRPR for WIN32 yet
    Waiter waiter;  // for realtime replay    
    if (realTime) timeout = updateWindow;
#endif // !WIN32
    bool noEvents = true;
    
    while (parser->GetNextPacketEvent(infile, &theEvent, timeout))
    {
        // Fill in values read from packet event
        const char* proto = theEvent.Protocol();
        const Address& srcAddr = theEvent.SrcAddr();
        unsigned short srcPort = theEvent.SrcPort();
        const Address& dstAddr = theEvent.DstAddr();
        unsigned short dstPort = theEvent.DstPort();
        unsigned int pktSize = theEvent.Size();
        theTime = theEvent.Time();
        double rxTime = theEvent.RxTime();
        double txTime = theEvent.TxTime();
        unsigned long sequence = theEvent.Sequence();
        unsigned long flowId = theEvent.FlowId();
        
        if (link.IsValid())
        {
            PacketEvent::TracePoint& t = theEvent.Link();
            if (!link.Match(t)) 
            {
                //fprintf(stderr, "link does not match event\n");
                continue;
            }
        }
        
        // Does it match our send/recv filter?
        switch (theEvent.Type())
        {
            case PacketEvent::TRANSMISSION:
                if (0 == (eventMask & SEND)) continue;
                break;
                
            case PacketEvent::RECEPTION:
                if (0 == (eventMask & RECV)) continue;
                break;
            
	        case PacketEvent::DROP:
                if (0 == (eventMask & DROP)) continue;
                break;
	        
            case PacketEvent::TIMEOUT:
                theTime = refTime + lastTime + timeout;
                break;
                
            default:
                // Other events not yet handled
                continue;
         }
                
         //fprintf(stderr, "Matched link\n");
         //theEvent.Link().PrintDescription(stderr);
         //fprintf(stderr, "\n");
        
       // Normalize time to start of data collection
        // (TBD) make normalization optional?
        if (firstTime)
        {
            // Wait for a real event to get going ..
            if (PacketEvent::TIMEOUT == theEvent.Type()) continue;
            if (normalize)
            {
                if (offsetTime >= 0.0)
                {
                    refTime = theTime - offsetTime;
                    if (refTime > (SECONDS_PER_DAY/2.0))
                        refTime = offsetTime - SECONDS_PER_DAY;
                    else if (refTime < (-SECONDS_PER_DAY/2.0))
                        refTime = offsetTime + SECONDS_PER_DAY;
                    else
                        refTime = offsetTime;
                    theTime -= refTime;
                    if (theTime < 0.0) continue;  // ignore events before "offsetTime"
                }
                else
                {
                    //if (PacketEvent::TIMEOUT != theEvent.Type())
                        refTime = theTime;
                        
                }
                theTime = 0.0;
            }  
#ifndef WIN32  // no real-time TRPR for WIN32 yet
            waiter.Reset();
#endif // !WIN32
            firstTime = false;
        }
        else
        {
            theTime -= refTime;
            // Handle wrap around midnight
            if ((lastTime - theTime) > (SECONDS_PER_DAY/2.0))
            {
                fprintf(stderr, "time wrap\n");
                while (lastTime > theTime) 
                    theTime += SECONDS_PER_DAY; 
            }
        }
        if (lastTime > theTime)
        {
            fprintf(stderr, "lastTime > theTime error: lastTime>%lf theTime>%lf refTime>%lf\n", lastTime, theTime, refTime);    
        }        
        
        assert(lastTime <= theTime);
        if (PacketEvent::TIMEOUT != theEvent.Type())
            lastTime = theTime;
        
        // Handle "range" args
        if (theTime < startTime) continue;  
        if ((stopTime >= 0.0) && (theTime > stopTime)) break;
                    
        //fprintf(stderr, "time>%f %x.%.5hu > %x.%.5hu proto>%s len>%u\n", 
        //        theTime, srcAddr, srcPort, dstAddr, dstPort, 
        //        proto, pktSize);
        
        // OK, we have the info; let's process it
        
        noEvents = false;
        // Init averaging/update time window boundaries
        if (windowStart < 0.0)
        {
            windowStart = theTime;
            windowEnd = windowStart + updateWindow;
        }
        
        // Do averages/update realtime output when end of window is reached
        if (theTime > windowEnd)
        { 
            // Slide realTime window as theTime progresses
            if (windowSize > 0.0)
            {
                UpdateWindowPlot(plotMode, flowList, outfile, theTime,
                             windowStart, windowEnd, realTime, stairStep);
                if (windowEnd > maxTime)
                {
                    maxTime = windowEnd;
                    minTime = maxTime - historyDepth;
                }                
            }
            else  // (0.0 == windowSize)
            {
                if (theTime > maxTime)
                {
                    maxTime = theTime;
                    minTime = theTime - historyDepth;
                }
            }
        }  // end if (theTime > windowEnd) && !(windowSize < 0.0)
        
        bool match = false;
        
        // Is this a flow we're excluding?
        bool exclude = false;
        Flow* nextFlow = excludeList.Head();

        while (nextFlow)
        {
            if (nextFlow->Match(proto, srcAddr, srcPort, dstAddr, dstPort, flowId))
            {
                exclude = true;
                break;
            }
            nextFlow = nextFlow->Next();
        }        
        
        // If not exluded, attempt match and incorporate data
        enum MatchingPhase {FLOW_MATCH, AUTO_MATCH, STOP_MATCH};
        
        // First match any already-discovered or preset flows
        MatchingPhase matchPhase = exclude ? STOP_MATCH : FLOW_MATCH;
        nextFlow = flowList.Head();
        bool matched = false;
        unsigned int flowNumber = 0;
        
        // No flow match for invalid events
        if (PacketEvent::TIMEOUT == theEvent.Type()) matchPhase = STOP_MATCH;
        while (STOP_MATCH != matchPhase)
        {         
            if (nextFlow)
            {
                if (FLOW_MATCH == matchPhase) flowNumber++;
                if (realTime) nextFlow->PruneData(minTime);  
                Flow* theFlow; 
                if (nextFlow->Match(proto, srcAddr, srcPort, dstAddr, dstPort, flowId))
                {
                    if (AUTO_MATCH == matchPhase)
                    {
                        theFlow = new Flow();
                        if (theFlow)
                        {
                            theFlow->SetType(proto);
                            theFlow->SetSrcAddr(srcAddr);
                            theFlow->SetSrcPort(srcPort);
                            theFlow->SetDstAddr(dstAddr);
                            theFlow->SetDstPort(dstPort);
                            theFlow->SetFlowId(flowId);
                            flowList.Append(theFlow);
                            
                            if ((LOSS2 == plotMode) || (discardDuplicates))
                                theFlow->InitLossTracker2(windowSize);

                            fprintf(stderr, "trpr: At time %f - Adding flow: ", theTime);
                            theFlow->PrintDescription(stderr);
                            fprintf(stderr, "\n");

                            // Print comment line with key to data columns
                            if (outfile && print_key)
                            {
                                fprintf(outfile, "#Time");
                                Flow* next = flowList.Head();
                                while (next)
                                {
                                    fprintf(outfile, ", "); 
                                    next->PrintDescription(outfile);
                                    next = next->Next();  
                                }   
                                fprintf(outfile, "\n");
                            }
                            flowNumber++;
                        }
                        else
                        {
                            perror("trpr: Error allocating memory for new flow");
                            fclose(infile);
                            if (outfile) fclose(outfile);
                            exit(-1);    
                        }                                
                    }
                    else // FLOW_MATCH == matchPhase
                    {
                        theFlow = nextFlow;
                        if (!nextFlow->IsPreset()) matched = true;
                    }
                }  // end if (nextFlow->Match()
                else
                {
                    theFlow = NULL;
                }
                // If we have a match, update the flow accordingly
                if (theFlow)
                {
                    if (discardDuplicates && ((LOSS != plotMode) || (LOSS2 != plotMode)))
                    {
                        if (theFlow->IsDuplicate(theTime, sequence))
                        {
                            break; 
                        }  
                    }
                    
                    switch(plotMode)
                    {

                        case RATE:
                            if (0.0 != windowSize)
                            {                            
                                theFlow->AddBytes(pktSize);
                            }
                            else
                            {
                                // Instantaneous data rate = pktSize/interarrival time
                                // (can't count first packet this way)
                                double delay = theFlow->MarkReception(theTime);
                                //if (delay > 0.0)
                                {
                                    //double rate = (8.0/1000.0) * ((double)pktSize) / delay;
                                    double rate = (8.0/1000.0) * ((double)pktSize);
                                    theFlow->UpdateSummary(rate);
                                    if (realTime)
                                    {
                                        if (stairStep)
                                            theFlow->AppendData(theTime, 0.0);
                                        if (!theFlow->AppendData(theTime, rate))
                                        {
                                            perror("trpr: Memory error adding data");
                                            exit(-1);
                                        }
                                        if (stairStep)
                                            theFlow->AppendData(theTime, 0.0);
                                    }
                                    if (outfile)
                                    {
                                        fprintf(outfile, "%7.3f", theTime);
                                        unsigned int n = flowNumber;
                                        while (--n) fprintf(outfile, ", ");
                                        fprintf(outfile, ", %7.3f\n", rate);
                                    }
                                }    
                            }                            
                            break;
                        case LOSS:
                            //fprintf(stderr, "UpdateLossTracker: t:%f s:%lu\n", theTime, sequence);
                            if (!theFlow->UpdateLossTracker(theTime, sequence))
                            {
                                
                                fprintf(stderr, "trpr: Loss tracker warning!\n");
                                fprintf(stderr, "trpr: flow ");
                                theFlow->PrintDescription(stderr);
                                fprintf(stderr, "\n");
                                //exit(-1);   
                            }
                            break;
                        case LOSS2:
                        {
                            // This one has it's own window
                            int result = theFlow->UpdateLossTracker2(theTime, sequence);
                            switch (result)
                            {
                                case 0:
                                    // Data not yet ready
                                    break;
                                case 1:
                                {
                                    // Loss tracker 2 has data ready
                                    double lossFraction = theFlow->LossFraction2();
                                    if (lossFraction < 0.0) lossFraction = 1.0;
                                    double weight = (theTime - theFlow->LossWindowStart2()) / windowSize;
                                    theFlow->UpdateSummary(lossFraction, weight);
                                    if (realTime)
                                    {
                                        if (!theFlow->AppendData(theFlow->LossWindowStart2(), lossFraction))
                                        {
                                            perror("trpr: Memory error adding data");
                                            exit(-1);
                                        }
                                        if (!theFlow->AppendData(theTime, lossFraction))
                                        {
                                            perror("trpr: Memory error adding data");
                                            exit(-1);
                                        }
                                    }
                                    if (outfile)
                                    {
                                        // Window start
                                        fprintf(outfile, "%7.3f", theFlow->LossWindowStart2());
                                        unsigned int n = flowNumber;
                                        while (--n) fprintf(outfile, ", ");
                                        fprintf(outfile, ", %7.3f\n", lossFraction);
                                        // Window end
                                        fprintf(outfile, "%7.3f", theTime);
                                        n = flowNumber;
                                        while (--n) fprintf(outfile, ", ");
                                        fprintf(outfile, ", %7.3f\n", lossFraction);
                                    }
                                    theFlow->ResetLossTracker2();
                                    break;
                                }
                                    
                                default:
                                    // Error/warning of some type occurred. 
                                    fprintf(stderr, "trpr: Loss tracker warning!\n");
                                    fprintf(stderr, "trpr: flow ");
                                    theFlow->PrintDescription(stderr);
                                    fprintf(stderr, "\n");
                                    break;  
                            }
                            break;
                        }
			
			            case DROPS:
			            {
                            if (0.0 != windowSize)
			                {
			    	            if (PacketEvent::DROP == theEvent.Type())
				                   theFlow->Accumulate(1.0);
				                else if (PacketEvent::RECEPTION == theEvent.Type())     
                                    theFlow->Accumulate(0.0);
			                }
			                else
			                {
                                if (PacketEvent::DROP == theEvent.Type())
                                { 
                                    theFlow->UpdateSummary(1);
                                    if (realTime)
                                    {
                                        if (!theFlow->AppendData(theTime, 1))
                                        {
                                            perror("trpr: Memory error adding data");
                                            exit(-1);
                                        }
                                    }
                                    if (outfile)
                                    {
                                        fprintf(outfile, "%7.3f", theTime);
                                        unsigned int n = flowNumber;
                                        while (--n) fprintf(outfile, ", ");
                                        fprintf(outfile, ", %7.3f\n", 1.0);
                                    }
                                }
			                }
                            break;
			            }
                        
                        case COUNT:
			            {
                            if (0.0 != windowSize)
			                {
			    	            if (PacketEvent::DROP != theEvent.Type())
				                   theFlow->Accumulate(1.0);
				                else // don't COUNT drops
				                   theFlow->Accumulate(0.0);
			                }
			                else
			                {
                                if (PacketEvent::DROP != theEvent.Type())
                                { 
                                    theFlow->UpdateSummary(1);
                                    if (realTime)
                                    {
                                        if (!theFlow->AppendData(theTime, 1))
                                        {
                                            perror("trpr: Memory error adding data");
                                            exit(-1);
                                        }
                                    }
                                    if (outfile)
                                    {
                                        fprintf(outfile, "%7.3f", theTime);
                                        unsigned int n = flowNumber;
                                        while (--n) fprintf(outfile, ", ");
                                        fprintf(outfile, ", %7.3f\n", 1.0);
                                    }
                                }
			                }
                            break;
			            }
			
			            case INTERARRIVAL:
                        {
                            double delay = theFlow->MarkReception(theTime);
                            if (0.0 != windowSize)
                            {
                                if (delay >= 0.0) nextFlow->Accumulate(delay);   
                            }
                            else
                            {
                                if (delay >= 0.0)
                                {
                                    theFlow->UpdateSummary(delay);
                                    if (realTime)
                                    {
                                        if (!theFlow->AppendData(theTime, delay))
                                        {
                                            perror("trpr: Memory error adding data");
                                            exit(-1);
                                        }
                                    }
                                    if (outfile)
                                    {
                                        fprintf(outfile, "%7.3f", theTime);
                                        unsigned int n = flowNumber;
                                        while (--n) fprintf(outfile, ", ");
                                        fprintf(outfile, ", %7.3f\n", delay);
                                    }
                                    
                                }
                            }
                            break;
                        }  // end case INTERARRIVAL

                        case LATENCY:
                        {
                            double delay = rxTime - txTime;
                            // Assume clock wrap if delay too negative
                            if (delay < -(SECONDS_PER_DAY/2.0)) delay += SECONDS_PER_DAY;
                            if (0.0 != windowSize)
                            {
                                nextFlow->Accumulate(delay);   
                            }
                            else
                            {
                                theFlow->UpdateSummary(delay);
                                if (realTime)
                                {
                                    if (!theFlow->AppendData(theTime, delay))
                                    {
                                        perror("trpr: Memory error adding data");
                                        exit(-1);
                                    }
                                }
                                if (outfile)
                                {
                                    fprintf(outfile, "%7.3f", theTime);
                                    unsigned int n = flowNumber;
                                    while (--n) fprintf(outfile, ", ");
                                    fprintf(outfile, ", %7.3f\n", delay);
                                }
                            }
                            break;
                        }  // end case LATENCY
                        
                        case VELOCITY:
                        {
                            double velocity = 
                                theFlow->UpdatePosition(theTime, theEvent.PosX(), theEvent.PosY());
                            
                            if (0.0 != windowSize)
                            {
                                if (velocity >= 0.0) theFlow->Accumulate(velocity);
                            }
                            else
                            {
                                if (velocity >= 0.0)
                                {
                                    theFlow->UpdateSummary(velocity);
                                    if (realTime)
                                    {
                                        if (!theFlow->AppendData(theTime, velocity))
                                        {
                                            perror("trpr: Memory error adding data");
                                            exit(-1);
                                        }
                                    }
                                    if (outfile)
                                    {
                                        fprintf(outfile, "%7.3f", theTime);
                                        unsigned int n = flowNumber;
                                        while (--n) fprintf(outfile, ", ");
                                        fprintf(outfile, ", %7.3e\n", velocity);
                                    }
                                }
                            }
                            break;
                        }
                        
                        default:
                            fprintf(stderr, "trpr: Unsupported plot mode!\n");
                            exit(-1);
                    }  // end switch(plotMode)
                }  // end if (theFlow)
                nextFlow = nextFlow->Next();
            }  // end if(nextFlow)
            //fprintf(stderr, "nextFlow:%p\n", nextFlow);
            if (!nextFlow)
            {
                switch (matchPhase)
                {
                    case FLOW_MATCH:
                        if (matched)
                        {
                            matchPhase = STOP_MATCH;
                        }
                        else
                        {
                            // Second, attempt auto match
                            nextFlow = autoList.Head();   
                            matchPhase = AUTO_MATCH;
                        }
                        break;
                        
                    case AUTO_MATCH:
                        // We're done
                        matchPhase = STOP_MATCH;
                        break;
                }
            }
        } // end while(STOP_MATCH != matchPhase)
        // Update window boundaries and any realTime output
        if (theTime > windowEnd)
        {
            // Update window start/end
            while (theTime > windowEnd) windowEnd += updateWindow;
            windowStart = windowEnd - updateWindow;
#ifndef WIN32  // no real-time TRPR for WIN32 yet
            if (realTime)
            {
                if (replay) waiter.Wait(updateWindow / replayFactor);
                if (multiplot)
                    UpdateMultiGnuplot(plotMode, &flowList, minTime, maxTime, 
                                       png_file, post_file, (windowSize == 0.0),
                                       autoScale, legend, minYRange, maxYRange);                
                else
                    UpdateGnuplot(plotMode, &flowList, minTime, maxTime, 
                                  png_file, post_file, (windowSize == 0.0),
                                  autoScale, legend, minYRange, maxYRange);                
            }
#endif // !WIN32
            if (outfile) fflush(outfile);
        }
    }  // end while (parser->GetNextPacketEvent())    
    fclose(infile);
    
    // Use this for a single window plot of the entire interval
    theTime = stopTime < 0.0 ? theTime : stopTime;
    double theStart, theEnd;
    if ((windowSize < 0.0) || noEvents || (windowStart < 0.0))
    {
        theStart = startTime < 0.0 ? 0.0 : startTime;
        theEnd = theTime;
    }
    else
    {
        theStart = windowStart;
        theEnd = windowStart + windowSize;
    }
    
    

    if ((0.0 != windowSize) && !noEvents) 
    {
        UpdateWindowPlot(plotMode, flowList, outfile, theTime+0.1, 
                         theStart, theEnd, realTime, stairStep); 
    } 

    if (LOSS2 == plotMode)
    {
        Flow* nextFlow = flowList.Head();
        unsigned int flowNumber = 0;
        while (nextFlow)
        {
            flowNumber++;
            double lossFraction = nextFlow->LossFraction2();
            if (lossFraction < 0.0) lossFraction = 1.0;  // assume total loss for no data
            double weight = (theTime - nextFlow->LossWindowStart2()) / windowSize;
            nextFlow->UpdateSummary(lossFraction, weight);
            if (realTime)
            {
                if (!nextFlow->AppendData(nextFlow->LossWindowStart2(), lossFraction))
                {
                    perror("trpr: Memory error adding data");
                    exit(-1);
                }
                if (!nextFlow->AppendData(nextFlow->LossWindowEnd2(), lossFraction))
                {
                    perror("trpr: Memory error adding data");
                    exit(-1);
                }
            }
            if (outfile)
            {
                // Window start
                fprintf(outfile, "%7.3f", nextFlow->LossWindowStart2());
                unsigned int n = flowNumber;
                while (--n) fprintf(outfile, ", ");
                fprintf(outfile, ", %7.3e\n", lossFraction);
                // Window end
                fprintf(outfile, "%7.3f", nextFlow->LossWindowEnd2());
                n = flowNumber;
                while (--n) fprintf(outfile, ", ");
                fprintf(outfile, ", %7.3e\n", lossFraction);
            }
            nextFlow = nextFlow->Next();
        } 
    }  // end if (LOSS2 == plotMode)

    if (realTime)
    {
        if (multiplot)
            UpdateMultiGnuplot(plotMode, &flowList, minTime, maxTime, 
                               png_file, post_file, (windowSize == 0.0),
                               autoScale, legend, minYRange, maxYRange);                
        else
            UpdateGnuplot(plotMode, &flowList, minTime, maxTime, 
                          png_file, post_file, (windowSize == 0.0),
                          autoScale, legend, minYRange, maxYRange);                
    }
    if (outfile) fflush(outfile);

    
    if (outfile) fclose(outfile);
    
    // Create final output file with gnuplot header if applicable
    if (output_file && use_gnuplot)
    {
    	if(!(outfile = fopen(output_file, "w+")))
	    {
	        perror("trpr: Error opening output file");
	        exit(-1);
	    }	
        if (post_file)
        {
            fprintf(outfile, "set term post color solid\n");
            fprintf(outfile, "set output '%s'\n", post_file); 
        }
        else if (png_file)
        {           
            fprintf(outfile, "set term png\n");
            fprintf(outfile, "set output '%s'\n", png_file);   
        }
        if (!multiplot)
            fprintf(outfile, "set title '%s %s'\n", 
                       surname? surname : "", output_file);
        fprintf(outfile, "set xlabel 'Time (sec)'\n");
        double min = 0.0, max = 0.0;
        switch (plotMode)
        {
            case RATE:            
                fprintf(outfile, "set ylabel 'Rate (kbps)'\n");
                fprintf(outfile, "set style data lines\n");
		min = minYRange < 0.0 ? 0.0 : minYRange;
		max = maxYRange < 0.0 ? -1.0 : maxYRange;
		if (max < 0.0)
		  fprintf(outfile, "set yrange[%f:*]\n",min);
		else 
		  fprintf(outfile, "set yrange[%f:%f]\n",min,max);
                break;
                
            case LOSS:            
            case LOSS2:            
                fprintf(outfile, "set ylabel 'Loss Fraction'\n");
                fprintf(outfile, "set style data lines\n");

		max = maxYRange < 0.0 ? 1.1 : maxYRange;
		if (autoScale)
		{
		  min = minYRange < 0.0 ? -0.01 : minYRange;
		  if (maxYRange < 0.0)
		    fprintf(outfile, "set yrange[%f:*]\n",min);
		  else
		    fprintf(outfile, "set yrange[%f:%f]\n",min,max);
		}
		else
		{
		  min = minYRange < 0.0 ? -0.1 : minYRange;
		  fprintf(outfile, "set yrange[%f:%f]\n",min,max);
		}
                break;
            
	        case DROPS:
	    	    fprintf(outfile, "set ylabel 'Drop Percentage'\n");
		        if (windowSize != 0.0)
                    fprintf(outfile, "set style data lines\n");
                else
                    fprintf(outfile, "set style data points\n");
                break;
                
            case COUNT:
	    	    fprintf(outfile, "set ylabel 'Packet Count'\n");
		        if (windowSize != 0.0)
                    fprintf(outfile, "set style data lines\n");
                else
                    fprintf(outfile, "set style data points\n");
                break;
	        
            case INTERARRIVAL:
                fprintf(outfile, "set ylabel 'Interarrival (sec)'\n");
                if (windowSize != 0.0)
                    fprintf(outfile, "set style data lines\n");
                else
                    fprintf(outfile, "set style data points\n");
                break;
                
            case LATENCY:
                fprintf(outfile, "set ylabel xx'Latency (sec)'\n");
                if (windowSize != 0.0)
                    fprintf(outfile, "set style data lines\n");
                else
                    fprintf(outfile, "set style data points\n");
                break;
                
            case VELOCITY:            
                fprintf(outfile, "set ylabel 'Velocity (meters/sec)'\n");
                fprintf(outfile, "set style data lines\n");
                break;
                
            default:
                fprintf(stderr, "trpr: Unsupport plotting mode!\n");
                exit(-1);
        }  // end switch(plotMode)
        
	if (legend)
	  fprintf(outfile, "set key bottom right\n");
	else
	  fprintf(outfile, "set key off\n");
        double origin = 0.0;
        double scale = 1.0 / ((double)flowList.Count());
        Flow* nextFlow = flowList.Head();
        if (nextFlow) 
        {
            if (multiplot)
            {
                fprintf(outfile, "set size 1.0,1.0\n");
                fprintf(outfile, "set multiplot\n");
            }
            else
            {
                fprintf(outfile, "plot ");
            }
        }
        int x = 2;
        while (nextFlow)
        {
            if (multiplot) 
            {
                fprintf(outfile, "set size 1.0,%f\n", scale);
                fprintf(outfile, "set origin 0.0,%f\n", origin);
                fprintf(outfile, "plot ");
                origin += scale;
            }
            fprintf(outfile, "\\\n'%s' index 1 using 1:%d t '",
                              output_file, x++);
            nextFlow->PrintDescription(outfile);
            fprintf(outfile, "'");
            nextFlow = nextFlow->Next();
            if (nextFlow)
            {
                if (multiplot) 
                    fprintf(outfile, "\n");
                else
                    fprintf(outfile, ", ");
            }
        }  // end while(nextFlow)
        fprintf(outfile, "\nexit\n\n\n");
        fflush(outfile);
	
	    // Append data from temp file to output file
	    if(!(infile = fopen(temp_file, "r")))
	    {
	        perror("trpr: Error opening our temp file");
	        exit(-1);
	    }
	    int result;
	    char buffer[1024];
	    while ((result = fread(buffer, sizeof(char), 1024, infile)))
	    {
	         fwrite(buffer, sizeof(char), result, outfile);
	    }
	    fclose(infile);
        unlink(temp_file);
	    fclose(outfile);
    }  // end if (output_file && use_gnuplot)
    
    
    if (summarize)
    {
        double total = 0.0;
        double variance = 0.0;
        double min = 0.0, max = 0.0;
        unsigned long count;
        bool init = true;
       
        fprintf(stdout, "#TRPR Summaries: ");
        double theStart = (startTime < 0.0) ? 0.0 : startTime;
        double theEnd = (stopTime < 0.0) ? theTime : stopTime;
        
        double window = (windowSize < 0.0) ? (theEnd - theStart) : windowSize;
        fprintf(stdout, "range>%.3f-%.3f, windowSize>%.3f\n", theStart,  theEnd, window);
        const char* type;
        const char* units;
        switch(plotMode)
        {
            case RATE:
                type = "rate";
                units = "kbps";
                break;
            case LOSS:
            case LOSS2:
                type = "loss fraction";
                units = "";
                break;
	        case DROPS:
	    	    type = "drop percentage";
		        units = "";
                break;
	        case COUNT:
	    	    type = "count";
		        units = "";
                break;
            case LATENCY:
                type = "latency";
                units = "sec";
                break;
            case INTERARRIVAL:
                type = "interarrival";
                units = "sec";
                break;
            case VELOCITY:
                type = "velocity";
                units = "meters/sec";
                break;
        }
        Flow* nextFlow = flowList.Head();
        while (nextFlow)
        {
            double fave = nextFlow->SummaryAverage();
            double fmin = nextFlow->SummaryMin();
            double fmax = nextFlow->SummaryMax();
            double fvar = nextFlow->SummaryVariance();
            if (isnan(fave))
            {
                switch (plotMode)
                {
                    case RATE:
                    case VELOCITY:
                    case COUNT:
                    case DROPS:
                        fave = fmin = fmax = fvar = 0.0;  // no packets for flow
                        break;
                    case LOSS:
                    case LOSS2:
                        fave = fmin = fmax = 1.0;  // no packets for flow
                        fvar = 0.0;
                        break;
                    case LATENCY:
                    case INTERARRIVAL:
                        nextFlow = nextFlow->Next();
                        continue;
                        break;
                }
            }
            
            fprintf(stdout, "#flow>", type, units);
            nextFlow->PrintDescription(stdout);            
            fprintf(stdout, ", %s(%s), ", type, units);
            fprintf(stdout, "ave>%lf, ", fave); 
            fprintf(stdout, "min>%lf, ", fmin);  
            fprintf(stdout, "max>%lf, ", fmax);  
            fprintf(stdout, "dev>%lf ", sqrt(fvar));  
            fprintf(stdout, "\n");
            
            if (init)
            {
                count = 1;
                total = fave;
                variance = total * total;
                min = fmin;
                max = fmax;
                init = false;
            }
            else
            {
                count++;
                total += fave;
                variance += (fave*fave);
                if (fmin < min) min = fmin;
                if (fmax > max) max = fmax;
            }           
            nextFlow = nextFlow->Next();           
        }   
        
        if (count > 1)
        {
            fprintf(stdout, "#flow>Summary, ");
            double mean = total/((double)count);
            variance = (variance/((double)count)) - (mean*mean);
            fprintf(stdout, "%s(%s), ", type, units);
            fprintf(stdout, "ave>%lf, ", mean);
            fprintf(stdout, "min>%lf, ", min);
            fprintf(stdout, "max>%lf, ", max);
            fprintf(stdout, "dev>%lf, ", sqrt(variance));  
            fprintf(stdout, "\n");
        }
    }  // end if (summarize)
    
    if (make_histogram)
    {
        fprintf(stdout, "#TRPR Histograms\n");
        const double p[6] = {0.99, 0.95, 0.9, 0.8, 0.75, 0.5};        
        Flow* nextFlow = flowList.Head();
        while (nextFlow)
        { 
            fprintf(stdout, "#flow>");
            nextFlow->PrintDescription(stdout);
            fprintf(stdout, " min>%f max>%f percentiles(", 
                    nextFlow->SummaryMin(), nextFlow->SummaryMax());
            for (int j = 0; j < 6; j++)
            {
                double percentile = nextFlow->Percentile(p[j]);
                fprintf(stdout, "%2d>%f ", (int)(p[j]*100.0+0.5), percentile);
            }
            fprintf(stdout, ")\n");
            nextFlow->PrintHistogram(stdout);
            fprintf(stdout, "\n\n\n");
            nextFlow = nextFlow->Next();
        }
    }  // end if (make_histogram)
    
    fflush(stdout);
    fprintf(stderr, "trpr: Done.\n");
    return 0;
}  // end main()


bool NsEventParser::GetNextPacketEvent(FILE*        inFile, 
                                       PacketEvent* theEvent, 
                                       double       timeout)
{
    char eventType = '\0';
    double eventTime;
    char srcNode[16], dstNode[16], flags1[8];
    unsigned long junk2;
    char pktType[40];
    unsigned long pktSize;
    int x1, x2, x3, x4;
    char flags2[8];
    unsigned long srcAddr, dstAddr;
    unsigned short srcPort, dstPort;
    unsigned long seq;
    unsigned int flow=0;
        
    char buffer[MAX_LINE];
    unsigned int len = MAX_LINE;
    theEvent->SetType(PacketEvent::INVALID);
    while (PacketEvent::INVALID == theEvent->Type())
    {
        // Don't "timeout" on NS files since they aren't "real time"
        switch (reader.Readline(inFile, buffer, &len, -1.0))
        {
            case FastReader::OK:
                break;
            case FastReader::ERROR_:
            case FastReader::DONE:
                return false;
            case FastReader::TIMEOUT:
                theEvent->SetType(PacketEvent::TIMEOUT);
                return true;  
        }
        // First, find a valid ns event line  
        if (len)
        {
            eventType = buffer[0];
	        if (strchr(buffer, '[' ))  // ns-mobile trace file
	        {
                switch (eventType)
                {
                    case 'f':
                    case 's':
                    	theEvent->SetType(PacketEvent::TRANSMISSION);
                    	break;
		            case 'r':
                    	theEvent->SetType(PacketEvent::RECEPTION);
                    	break;
		            case 'D':
		    	        theEvent->SetType(PacketEvent::DROP);
		    	        break;
                    default:
                    	len = MAX_LINE;
                    	continue;
                    	break;
            	}
	        }
	        else
	        {
	            switch (eventType)  // ns-static trace file
                {
                    case '-':
                        theEvent->SetType(PacketEvent::TRANSMISSION);
                        break;
                    case 'r':
                        theEvent->SetType(PacketEvent::RECEPTION);
                        break;
		            case 'd':
                        theEvent->SetType(PacketEvent::DROP);
		    	        break;
                    default:
                        len = MAX_LINE;
                        continue;
                        break;
                }
	        }
        }  // end if (len)
        
        // Read the NS (mobile) trace line fields
	    if (strchr(buffer, '[' ))
	    {
	    	if (strstr(buffer, "RTS" ) || strstr(buffer, "CTS" ) || strstr(buffer, "ACK") || strstr(buffer, "ARP"))
		    {
                //Handle RTS/CTS/ACK line format
                if (12 != sscanf(buffer, "%c %lf %s %s "
	                                 	  "%s %lu %s %lu "
                                          "[%x %lx %lx %x]",
                           	    &eventType, &eventTime, srcNode, dstNode,
                           	    flags1, &junk2, pktType, &pktSize,  
                           	    &x1, &srcAddr, &dstAddr, &x4))
                {
				    fprintf(stderr, "trpr: Invalid mobile RTS/CTS/ACK/ARP NS output: \"%s\"\n", buffer);
                }
		    }
            else // Handle standard line format
            {
                if (17 != sscanf(buffer, "%c %lf %s %s "
	                                     "%s %lu %s %lu "
                                         "[%x %x %x %x] %s "
                                         "[%lu:%hu %lu:%hu",
                            &eventType, &eventTime, srcNode, dstNode,
                            flags1, &junk2, pktType, &pktSize,  
                            &x1, &x2, &x3, &x4, flags2,
                            &srcAddr, &srcPort, &dstAddr, &dstPort))
                {
			        fprintf(stderr, "trpr: Invalid mobile NS output: \"%s\"\n", buffer);
                }
                // Get sequence number if "cbr"
                if (!strcmp("cbr", pktType))
                {
                    char* ptr = buffer;
                    for (unsigned int i = 0; i < 3; i++)
                    {
                        ptr = strchr(ptr, '[');
                        if (ptr)
                            ptr++;
                        else
                            break;
                    }
                    if (ptr)
                    {
                        if (1 != sscanf(ptr, "%lu", &seq))
                            fprintf(stderr, "trpr: Invalid NS \"cbr\" output: \"%s\"\n", buffer);

                    }
                    else
                    {
                        fprintf(stderr, "trpr: Invalid NS \"cbr\" output: \"%s\"\n", buffer);
                    }                    
                }
           }  // end if/else (RTS-CTS/standard)
       }   
	   else // Read the NS (static) trace line fields
	   {
	      if (14 != sscanf(buffer, "%c %lf %s %s "
				                   "%s %lu %s %u "
				                   "%lu.%hu %lu.%hu %lu %lu",
				&eventType, &eventTime, srcNode, dstNode,
				pktType, &pktSize, flags2, &flow,
				&srcAddr, &srcPort, &dstAddr, &dstPort, &seq, &junk2))
		    {
                fprintf(stderr, "trpr: Invalid static NS output: \"%s\"\n", buffer);
            }
	   }  // end if/else(mobile/static)
       len = MAX_LINE; 
    }  // end while (PacketEvent::INVALID == theEvent->Type())
        
    theEvent->SetProtocol(pktType);
    theEvent->SetTime(eventTime);
    switch (theEvent->Type())
    {
        case PacketEvent::TRANSMISSION:
            theEvent->SetTxTime(eventTime);
            theEvent->SetRxTime(-1.0);
            break;

        case PacketEvent::RECEPTION:
            theEvent->SetTxTime(-1.0);
            theEvent->SetRxTime(eventTime);
            break;

        default:
            theEvent->SetTxTime(-1.0);
            theEvent->SetRxTime(-1.0);
            break;
    }
    
    // Parse srcNode & dstNode fields for link src->dst
    theEvent->LinkClear();
    if (strchr(srcNode, '_'))
    {
        unsigned long linkSrc;
        if (1 == sscanf(srcNode, "_%lu_", &linkSrc))
            theEvent->SetLinkSrc(Address(linkSrc, Address::OTHER)); 
    }
    else
    {
        theEvent->SetLinkSrc(srcNode);
    }                
    unsigned long linkDst;
    if (!strcmp("AGT", dstNode) || 
        !strcmp("RTR", dstNode) ||
        !strcmp("MAC", dstNode))
    {
        theEvent->SetLinkDst(dstNode);
    }
    else if (1 == sscanf(dstNode, "%lu", &linkDst))
	{
        theEvent->SetLinkDst(Address(linkDst, Address::OTHER));   
    }
	else
	{
		theEvent->SetType(PacketEvent::INVALID);
		return true;
	}
    theEvent->SetSrcAddr(Address(srcAddr, Address::OTHER));
    theEvent->SetSrcPort(srcPort);
    theEvent->SetDstAddr(Address(dstAddr, Address::OTHER));
    theEvent->SetDstPort(dstPort);
    theEvent->SetSize(pktSize);
    theEvent->SetSequence(seq);
    theEvent->SetFlowId(flow);
    return true;   
}  // end NsEventParser::GetNextPacketEvent()

bool DrecEventParser::GetNextPacketEvent(FILE* inFile, PacketEvent* theEvent, double timeout)
{    
    while (1)
    {
        char buffer[MAX_LINE];
        unsigned int len = MAX_LINE;
        switch (reader.Readline(inFile, buffer, &len, timeout))
        {
            case FastReader::OK:
                break;
            case FastReader::ERROR_:
                fprintf(stderr, "trpr: warning: error reading mgen log input\n");
                continue;
            case FastReader::DONE:
                return false;
            case FastReader::TIMEOUT:
                theEvent->SetType(PacketEvent::TIMEOUT);
                return true;  
        }
        //fprintf(stderr, "%s\n", buffer);
        unsigned int TxHrs, RxHrs, TxMin, RxMin;
        double TxSec, RxSec;
        unsigned long pktSize, flow, seq;	
        char src[64], dst[64], proto[64], sendSrcPort[5];
        if (len)
        {
            PacketEvent::EventType eventType = PacketEvent::INVALID;
            bool mgen4 = false;
            if (!strncmp(buffer, "Flow", 4)) // DREC version 3.3 RECV event
            {
                //fprintf(stderr, "read: %s\n", buffer);
                if (11 != sscanf(buffer,"Flow>%lu Seq>%lu Src>%s Dest>%s TxTime>%u:%u:%lf "
                                        "RxTime>%u:%u:%lf Size>%lu",
                                        &flow, &seq, src, dst, &TxHrs, &TxMin, &TxSec,
                                        &RxHrs,&RxMin,&RxSec,&pktSize))
                {
                    fprintf(stderr, "trpr: Invalid DREC output: \"%s\"\n", buffer);
                    continue;
                }
                eventType = PacketEvent::RECEPTION;
            }
            else if (strstr(buffer, "RECV"))  // MGEN version 4.0 RECV event
            {
                mgen4 = true;
                // MGEN version 4.2b8 and above
		        if (12 != sscanf(buffer, "%u:%u:%lf RECV proto>%s flow>%lu seq>%lu src>%s dst>%s "
                                         "sent>%u:%u:%lf size>%lu ",
				                         &RxHrs, &RxMin, &RxSec, proto, &flow, &seq, src, dst, 
				                         &TxHrs, &TxMin ,&TxSec, &pktSize))
                {
		            // MGEN version 4.2b7 and below
                    if (11 != sscanf(buffer, "%u:%u:%lf RECV flow>%lu seq>%lu src>%s dst>%s "
                                         "sent>%u:%u:%lf size>%lu",
                                         &RxHrs,&RxMin,&RxSec,&flow, &seq, src, dst, 
                                         &TxHrs,&TxMin,&TxSec, &pktSize))
		            {
		                  fprintf(stderr, "trpr: Invalid MGEN output: \"%s\"\n", buffer);
		                  continue;       
		            }
                }
                eventType = PacketEvent::RECEPTION;
            }
            else if (strstr(buffer, "SEND"))  // MGEN version 4.0 SEND event
            {
                mgen4 = true;
		        // MGEN version 4.2b8 and above
                if (9 != sscanf(buffer, "%u:%u:%lf SEND proto>%s flow>%lu seq>%lu src>%s dst>%s size>%lu",
				                        &TxHrs,&TxMin,&TxSec, proto, &flow, &seq, sendSrcPort, dst, &pktSize))
                {
		            // MGEN version 4.2b7 and below
		            if (7 != sscanf(buffer, "%u:%u:%lf SEND flow>%lu seq>%lu dst>%s size>%lu",
                                             &TxHrs,&TxMin,&TxSec, &flow, &seq, dst, &pktSize))
                    {
		                  fprintf(stderr, "trpr: Invalid MGEN output: \"%s\"\n", buffer);
		                  continue;       
		            }
                }
                eventType = PacketEvent::TRANSMISSION;
                RxHrs = TxHrs;
                RxMin = TxMin;
                RxSec = TxSec;
                strcpy(src, "0.0.0.0/0");
            }
            else                            // not a DREC event
            {
                continue; 
            } 
            // Isolate src and dst addresses and ports  
            char* srcAddr = src;
            char* ptr = strchr(src, '/');
            unsigned short srcPort;
            if (ptr)
            {
                *ptr++ = '\0';
                srcPort = atoi(ptr);   
            }  
            else  
            {
                fprintf(stderr, "trpr: Bad trace file line\n");
                continue;   
            }      
            char* dstAddr = dst;
            ptr = strchr(dst, '/');
            unsigned short dstPort;
            if (ptr)
            {
                *ptr++ = '\0';
                dstPort = atoi(ptr);   
            }  
            else  
            {
                fprintf(stderr, "trpr: Bad trace file line\n");
                continue;   
            }              

            // Get GPS position, if availble
            ptr = strstr(buffer, "CURRENT");
            if (ptr)
            {
                if (mgen4)
                {
                    double x, y;
                    if (2 != sscanf(ptr, "CURRENT,%lf,%lf", &y, &x))
                    {
                        fprintf(stderr, "trpr: DrecEventParser::GetNextPacketEvent() Bad GPS info!\n");   
                        theEvent->SetPosition(999.0, 999.0);
                    }
                    else
                    {
                        theEvent->SetPosition(x,y);
                    }
                }
                else
                {
                    double x,y;
                    if (2 != sscanf(ptr, "CURRENT Long>%lf Lat>%lf\n", &x, &y))
                    {
                        fprintf(stderr, "trpr: DrecEventParser::GetNextPacketEvent() Bad GPS info!\n");   
                        theEvent->SetPosition(999.0, 999.0);
                    }
                    else
                    {
                        theEvent->SetPosition(x,y);
                    }
                }
            }
            else
            {
                theEvent->SetPosition(999.0, 999.0);  // INVALID, STALE, or case none given
            }

            theEvent->SetType(eventType);
            theEvent->SetProtocol("mgen");
            double rxTime = (((double)RxHrs) * 3600.0) + (((double)RxMin) * 60.0) + (double)RxSec;
            theEvent->SetTime(rxTime);
            theEvent->SetRxTime(rxTime);
            theEvent->SetTxTime((((double)TxHrs) * 3600.0) + (((double)TxMin) * 60.0) + (double)TxSec);
            theEvent->SetSrcAddr(srcAddr);
            theEvent->SetSrcPort(srcPort);
            theEvent->SetDstAddr(dstAddr);
            theEvent->SetDstPort(dstPort);
            theEvent->SetSize(pktSize);
            theEvent->SetSequence(seq);
            theEvent->SetFlowId(flow);
            break;
        }  // end if (len)
    }  // end while (1)
    return true;
}  // end DrecEventParser::GetNextPacketEvent()

// Should handle IPv4 and IPv6 events...
bool TcpdumpEventParser::GetNextPacketEvent(FILE*        inFile, 
                                            PacketEvent* theEvent, 
                                            double       timeout)
{
    while(1)
    {
        char buffer[MAX_LINE];
        unsigned int len = MAX_LINE;
        switch (reader.Readline(inFile, buffer, &len, timeout))
        {
            case FastReader::OK:
                break;
            case FastReader::ERROR_:
            case FastReader::DONE:
                return false;
            case FastReader::TIMEOUT:
                theEvent->SetType(PacketEvent::TIMEOUT);
                return true;  
        }

        // Look for leading tcpdump hex output content line
        if (len && !isspace(buffer[0]))//(' ' != buffer[0]) && '\t' != buffer[0])
        {
            unsigned int hrs, min;
            float sec;            
            if (3 != sscanf(buffer, "%u:%u:%f", &hrs, &min, &sec))
            {
                fprintf(stderr, "trpr: Invalid tcpdump output: \"%s\"\n", buffer);
                len = MAX_LINE;
                continue;
            }
            
            // Read in first line of tcpdump hex to get packet length
            len = MAX_LINE;
            switch (reader.Readline(inFile, buffer, &len, timeout))
            {
                case FastReader::OK:
                    break;
                case FastReader::ERROR_:
                case FastReader::DONE:
                    return false;
                case FastReader::TIMEOUT:
                    theEvent->SetType(PacketEvent::TIMEOUT);
                    return true;  
            }
            
            char headerBuffer[44];
            unsigned int byteCount = PackHexLine(buffer, headerBuffer, 44);
            unsigned int pktSize = TotalLength(headerBuffer);
            unsigned int maxBytes = MIN(44, pktSize);
            while (byteCount < maxBytes)
            {
                len = MAX_LINE;
                switch (reader.Readline(inFile, buffer, &len, timeout))
                {
                    case FastReader::OK:
                        break;
                    case FastReader::ERROR_:
                    case FastReader::DONE:
                        return false;
                    case FastReader::TIMEOUT:
                        theEvent->SetType(PacketEvent::TIMEOUT);
                        return true;  
                }                
                unsigned long remainder = maxBytes - byteCount;
                if (remainder > 1)
                    byteCount += PackHexLine(buffer, headerBuffer+byteCount, maxBytes - byteCount);
                else
                    break;
            }  // end while(byteCount < maxBytes)

            
            // Fill in values read from tcpdump line
            unsigned char protocol = Protocol(headerBuffer);
            theEvent->SetProtocol(ProtocolType(protocol));
            theEvent->SetSrcAddr(SourceAddress(headerBuffer));
            theEvent->SetDstAddr(DestinationAddress(headerBuffer));
            switch (protocol)
            {
                case 6:   // TCP
                case 17:  // UDP
                    theEvent->SetSrcPort(SourcePort(headerBuffer));
                    theEvent->SetDstPort(DestinationPort(headerBuffer));
                    break;

                default:
                    theEvent->SetSrcPort(0);
                    theEvent->SetDstPort(0);
                    break;
            }      
            theEvent->SetSize(pktSize); 
            double theTime = (((double)hrs) * 3600.0) +
                             (((double)min) * 60.0) +
                             (double)sec;
            theEvent->SetTime(theTime);
            theEvent->SetType(PacketEvent::RECEPTION);
            return true;
        }
    }  // end while(1)
    return true;
}  // end TcpdumpEventParser::GetNextPacketEvent()

const char* TcpdumpEventParser::ProtocolType(unsigned char value) const
{
    static char type[8];
    switch (value)
    {
        case 6:
            return "tcp";
                    
        case 17:
            return "udp";
            
        case 1:
            return "icmp";

        case 58:
	    return "icmp";
            
        default:
            sprintf(type, "%u", value);
            return type;           
    }
}  // end TcpdumpEventParser::ProtocolType()

// Pack white space delimited hex values from text into buf
// Return number of bytes packed.
unsigned int TcpdumpEventParser::PackHexLine(char* text, char* buf, unsigned int buflen)
{
    // Skip any leading white space
    while (isspace(*text)) text++; 
    unsigned int byteCount = 0; 
    //fprintf(stderr, "packing line: %s\n", text);
    unsigned int wordCount = 0;
    // Skip "offset" leader (if it's there)
    char* ptr = strchr(text, ':');
    if (ptr) text = ptr + 1;
    // Skip leading white space
    while (isspace(*text)) text++;

    while (text)
    {
        ptr = strchr(text, ' ');
        if (ptr) *ptr++ = '\0';   
        //fprintf(stderr, "   packing hex: %s\n", text);
        unsigned int value;
        char hex[32];
        hex[31] = '\0';
        strcpy(hex, "0x");
        strncat(hex, text, (32-3));
        if (1 != sscanf(hex, "%x", &value))
        {
            //fprintf(stderr, "PackHexLine: Invalid format!\n");
            fprintf(stderr, "PackHexline: end of road?\n");
            return byteCount;
        }
        // Assume 16-bit tuples for now, (TBD) generalize
        if ((byteCount+1) < buflen)
        {
            *buf++ = (value & 0x0000ff00) >> 8;
            *buf++ = value & 0x00ff;
            byteCount += 2;
            if (++wordCount >= 8) return byteCount;
        }
        else
        {
            // buf is full
            return byteCount;
        }
        text = ptr;
    }
    return byteCount;
}  // end TcpdumpEventParser::PackHexLine()


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


void UpdateWindowPlot(PlotMode plotMode, FlowList& flowList, FILE* outfile,
                      double theTime, double windowStart, double windowEnd, 
                      bool realTime, bool stairStep)
{
    double windowSize = windowEnd - windowStart;
    if (windowSize <= 0.0) return;
    
    switch(plotMode)
    {
        case RATE:
        case LOSS:
	    case DROPS:
        case COUNT:
        case LATENCY:
        case INTERARRIVAL:
        case VELOCITY:
        {
            if (stairStep)
            {
                // Plot window start point (also prune/add "realTime" data for all flows)
                Flow* nextFlow = flowList.Head();
                if (outfile) fprintf(outfile, "%7.3f", windowStart);
                while (nextFlow)
                {
                    double value;
                    switch (plotMode)
                    {
                        case RATE:
#ifdef WIN32
                            value = (8.0/1000.0) *((double)((LONGLONG)nextFlow->Bytes())/windowSize);
#else
                            value = (8.0/1000.0) *((double)nextFlow->Bytes())/windowSize;
#endif // if/else WIN32/UNIX
                            if (isnan(value)) value = 0.0;
                            break;
                        case LOSS:
                            value = nextFlow->LossFraction();
                            break;
                        case COUNT:
                            value = nextFlow->Accumulator();
                            break;
                        default:  // LATENCY/INTERARRIVAL/VELOCITY/DROPS
#ifdef WIN32
                            value = nextFlow->Accumulator()/((double)((LONGLONG)nextFlow->AccumulatorCount()));
#else
                            value = nextFlow->Accumulator()/((double)nextFlow->AccumulatorCount());
#endif // if/else WIN32/UNIX
                            break;
                    }
                 
                    // Prune & Append point for realTime plotting
                    // Need "isnan()" for non-existent latency/interarrival periods
                    if (realTime)
                    {
                        if (!isnan(value))
                        {
                            if (!nextFlow->AppendData(windowStart, value))
                            {
                                perror("trpr: Memory error adding data");
                                exit(-1);
                            }
                        }
                    }
                    if (outfile) 
                    {
                        if (isnan(value))
                            fprintf(outfile, ", ");
                        else   
                            fprintf(outfile, ", %7.3e",  value);
                    }
                    nextFlow = nextFlow->Next();
                }  // end while(nextFlow)
                if (outfile) fprintf(outfile, "\n");
            }  // end if (stairStep)
            
            // Window end point
            if (outfile) fprintf(outfile, "%7.3f", windowEnd);
            Flow* nextFlow = flowList.Head();
            unsigned int flowCount = 0;
            while (nextFlow)
            {
                double value;
                switch (plotMode)
                {
                    case RATE:
#ifdef WIN32
                        value = (8.0/1000.0) *((double)((LONGLONG)nextFlow->Bytes())/windowSize);
#else
                        value = (8.0/1000.0) *((double)nextFlow->Bytes())/windowSize;
#endif // if/else WIN32/UNIX
                         if (isnan(value)) value = 0.0;  
                        break;
                    case LOSS:
                        value = nextFlow->LossFraction();
                        break;
                    case COUNT:
                        value = nextFlow->Accumulator();
                        break;
                    default:  // LATENCY/INTERARRIVAL/DROPS
#ifdef WIN32
                        value = nextFlow->Accumulator()/((double)((LONGLONG)nextFlow->AccumulatorCount()));
#else
                        value = nextFlow->Accumulator()/((double)nextFlow->AccumulatorCount());
#endif // if/else WIN32/UNIX
                    break;    
                }
                
                // Append point for realTime plotting
                if (realTime)
                {
                    if (!isnan(value))
                    {
                        if (!nextFlow->AppendData(windowEnd, value))
                        {
                            perror("trpr: Memory error adding data for flow");
                            exit(-1);
                        }
                    }
                }
                if (outfile) 
                {
                    if (isnan(value))
                        fprintf(outfile, ", ");
                    else
                        fprintf(outfile, ", %7.3e", value);  
                }
                if (!isnan(value)) nextFlow->UpdateSummary(value);
                if (RATE == plotMode)
                    nextFlow->ResetByteCount();
                else if (LOSS == plotMode)
                    nextFlow->ResetLossTracker();
                else // LATENCY/INTERARRIVAL/DROPS/COUNT
                    nextFlow->ResetAccumulator();
                flowCount++;
                nextFlow = nextFlow->Next();
            }
            if (outfile) fprintf(outfile, "\n");   
            // Fill any time gap which has occurred
            unsigned int gapCount = 0;
            double tempEnd = windowEnd;
            tempEnd += windowSize;
            while (theTime > tempEnd)
            {
                 gapCount++;
                 tempEnd += windowSize;  
            }
            if (gapCount && ((COUNT == plotMode) || (DROPS == plotMode) || 
                             (RATE == plotMode) || (LOSS == plotMode)))
            {
                double value = (LOSS == plotMode) ? 1.0 : 0.0;
                if (outfile)
                {
                    if (stairStep)
                    {
                        fprintf(outfile, "%7.3f", windowEnd); 
                        for (unsigned int i = 0; i < flowCount; i++) 
                            fprintf(outfile, ", %7.3e", value);
                        fprintf(outfile, "\n");
                    }
                    fprintf(outfile, "%7.3f", (tempEnd - windowSize)); 
                    for (unsigned int i = 0; i < flowCount; i++) 
                        fprintf(outfile, ", %7.3e", value);
                    fprintf(outfile, "\n");
                }
                
                nextFlow = flowList.Head();
                while (nextFlow)
                {
                    nextFlow->UpdateSummary(value, (double)gapCount);
                    if (realTime)
                    {
                        // Append points for realTime plotting
                        if (stairStep)
                        {
                            if (!nextFlow->AppendData(windowEnd, value))
                            {
                                perror("trpr: Memory error adding data for flow");
                                exit(-1);
                            }
                        }
                        if (!nextFlow->AppendData((tempEnd - windowSize), value))
                        {
                            perror("trpr: Memory error adding data for flow");
                            exit(-1);
                        }
                    } // end if (realTime)
                    nextFlow = nextFlow->Next();
                }  // end while(nextFlow)
            }  // end if (gapCount && ...)
            break;  
        }  // end case RATE/LOSS/LATENCY/INTERARRIVAL/VELOCITY
  
        default:
            // non-windowed plot modes
            break;
    }  // end switch(plotMode)   
}  // end UpdateWindowPlot()


// Generates realTime update gnuplot commands
void UpdateGnuplot(PlotMode plotMode, FlowList* flowList, double xMin, double xMax, 
                   const char* pngFile, const char* postFile, bool scatter, 
                   bool autoScale, bool legend,double minYRange, double maxYRange)
{
    unsigned int flowCount = flowList->Count();
    Flow* nextFlow = flowList->Head();
    if (nextFlow)
    {
        if (postFile)
        {
            fprintf(stdout, "set term post color solid\n");
            fprintf(stdout, "set output '%s'\n", postFile); 
        }
        else if (pngFile)
        {
            fprintf(stdout, "set term png\n");
            fprintf(stdout, "set output '%s'\n", pngFile);  
        }
        fprintf(stdout, "set xlabel 'Time (sec)'\n");
	double min = 0.0, max = 0.0;
        switch (plotMode)
        {
            case RATE:
                fprintf(stdout, "set ylabel 'Rate (kbps)'\n");
                fprintf(stdout, "set style data lines\n");

		min = minYRange < 0.0 ? 0.0 : minYRange;
		max = maxYRange < 0.0 ? -1.0 : maxYRange;
		if (max < 0.0)
		  fprintf(stdout, "set yrange[%f:*]\n",min);
		else 
		  fprintf(stdout, "set yrange[%f:%f]\n",min,max);
                break;
                 
            case LOSS:
            case LOSS2:            
                fprintf(stdout, "set ylabel 'Loss Fraction'\n");
                fprintf(stdout, "set style data lines\n");

		max = maxYRange < 0.0 ? 1.1 : maxYRange;
		if (autoScale)
		{
		  min = minYRange < 0.0 ? -0.01 : minYRange;
		  if (maxYRange < 0.0)
		    fprintf(stdout, "set yrange[%f:*]\n",min);
		  else
		    fprintf(stdout, "set yrange[%f:%f]\n",min,max);
		}
		else
		{
		  min = minYRange < 0.0 ? -0.1 : minYRange;
		  fprintf(stdout, "set yrange[%f:%f]\n",min,max);
		}
                break;
                 
            case INTERARRIVAL:
                fprintf(stdout, "set ylabel 'Interarrival (sec)'\n");
                if (scatter)
                    fprintf(stdout, "set style data points\n");
                else
                    fprintf(stdout, "set style data lines\n");

		min = minYRange < 0.0 ? 0.0 : minYRange;
		max = maxYRange < 0.0 ? -1.0 : maxYRange;
		if (max < 0.0)
		  fprintf(stdout, "set yrange[%f:*]\n",min);
		else 
		  fprintf(stdout, "set yrange[%f:%f]\n",min,max);
                break;
            
	        case DROPS:
	            fprintf(stdout, "set ylabel 'Drops'\n");
		    if (scatter)
		      fprintf(stdout, "set style data points\n");
		    else
		      fprintf(stdout, "set style data lines\n");

		    min = minYRange < 0.0 ? 0.0 : minYRange;
		    max = maxYRange < 0.0 ? -1.0 : maxYRange;
		    if (max < 0.0)
		      fprintf(stdout, "set yrange[%f:*]\n",min);
		    else 
		      fprintf(stdout, "set yrange[%f:%f]\n",min,max);
                break; 
                
            case COUNT:
	            fprintf(stdout, "set ylabel 'Count'\n");
                if (scatter)
                    fprintf(stdout, "set style data points\n");
                else
                    fprintf(stdout, "set style data lines\n");

		min = minYRange < 0.0 ? 0.0 : minYRange;
		max = maxYRange < 0.0 ? -1.0 : maxYRange;
		if (max < 0.0)
		  fprintf(stdout, "set yrange[%f:*]\n",min);
		else 
		  fprintf(stdout, "set yrange[%f:%f]\n",min,max);
                break; 
		
            case LATENCY:
                fprintf(stdout, "set ylabel 'Latency (sec)'\n");
                if (scatter)
                    fprintf(stdout, "set style data points\n");
                else
                    fprintf(stdout, "set style data lines\n");

		min = minYRange < 0.0 ? -1.0 : minYRange;
		max = maxYRange < 0.0 ? -1.0 : maxYRange;
		if (min < 0.0)
		  fprintf(stdout, "set yrange[*:");
		else
		  fprintf(stdout, "set yrange[%f:",min);

		if (max < 0.0)
		  fprintf(stdout, "*]\n",max);
		else 
		  fprintf(stdout, "%f]\n",max);
                break;
                
            case VELOCITY:
                fprintf(stdout, "set ylabel 'Velocity (meters/sec)'\n");
                fprintf(stdout, "set style data lines\n");
		min = minYRange < 0.0 ? 0.0 : minYRange;
		max = maxYRange < 0.0 ? -1.0 : maxYRange;
		if (max < 0.0)
		  fprintf(stdout, "set yrange[%f:*]\n",min);
		else 
		  fprintf(stdout, "set yrange[%f:%f]\n",min,max);
                break;
                
            default:
                fprintf(stderr, "trpr: Unsupported plot mode!\n");
                exit(-1);
        }
        
	if (legend)
	  fprintf(stdout, "set key bottom right\n");
	else
	  fprintf(stdout, "set key off\n");
        fprintf(stdout, "set xrange[%f:%f]\n", xMin, xMax);        
        fprintf(stdout, "plot ");
        while (nextFlow)
        {
            fprintf(stdout, "'-' t '");
            nextFlow->PrintDescription(stdout);
            fprintf(stdout, "'");
            nextFlow = nextFlow->Next();
            if (nextFlow) fprintf(stdout, ", ");
        }
        fprintf(stdout, "\n");
        
        nextFlow = flowList->Head();
        while (nextFlow)
        {
            if (!nextFlow->PrintData(stdout))
            {
                double value;
                switch (plotMode)
                {
                    case RATE:
                    case LATENCY:
                    case INTERARRIVAL:
                    case VELOCITY:
                        value = 0.0;
                        break;

                    case LOSS:
                    case LOSS2: 
                        value = 1.0;
                         break;
                }
                fprintf(stdout, "%f, %f\n", xMin, value);
                fprintf(stdout, "%f, %f\n", xMax, value);
            }
            fprintf(stdout, "e\n");
            nextFlow = nextFlow->Next();
        }  // end while(nextFlow)
        fflush(stdout);
    }  // end if (nextFlow)
}  // end UpdateGnuplot()

// Generates realTime update multi-gnuplot commands
void UpdateMultiGnuplot(PlotMode plotMode, FlowList* flowList,
                        double xMin, double xMax, 
                        const char* pngFile, const char* postFile, bool scatter,
                        bool autoScale, bool legend, double minYRange, double maxYRange)
{
    unsigned int count = flowList->Count();
    double yMax = 0.0;
    double yMin = 0.0;
    Flow* nextFlow = flowList->Head();
    if (nextFlow)
    {
        if (postFile)
        {
            fprintf(stdout, "set term post color solid\n");
            fprintf(stdout, "set output '%s'\n", postFile); 
        }
        else if (pngFile)
        {
            fprintf(stdout, "set term png\n");
            fprintf(stdout, "set output '%s'\n", pngFile);  
        }
        //fprintf(stdout, "set xlabel 'Time (sec)'\n");
	double min = 0.0, max = 0.0;
        switch (plotMode)
        {
            case RATE:
                //fprintf(stdout, "set ylabel 'Rate (kbps)'\n");
                fprintf(stdout, "set style data lines\n");
		min = minYRange < 0.0 ? 0.0 : minYRange;
		max = maxYRange < 0.0 ? -1.0 : maxYRange;
		if (max < 0.0)
		  fprintf(stdout, "set yrange[%f:*]\n",min);
		else 
		  fprintf(stdout, "set yrange[%f:%f]\n",min,max);
                break;
                 
            case LOSS:
            case LOSS2:            
                //fprintf(stdout, "set ylabel 'Loss Fraction'\n");
                fprintf(stdout, "set style data lines\n");
		max = maxYRange < 0.0 ? 1.1 : maxYRange;
		if (autoScale)
		{
		  min = minYRange < 0.0 ? -0.01 : minYRange;
		  if (maxYRange < 0.0)
		    fprintf(stdout, "set yrange[%f:*]\n",min);
		  else
		    fprintf(stdout, "set yrange[%f:%f]\n",min,max);
		}
		else
		{
		  min = minYRange < 0.0 ? -0.1 : minYRange;
		  fprintf(stdout, "set yrange[%f:%f]\n",min,max);
		}
                break;
                 
            case INTERARRIVAL:
                //fprintf(stdout, "set ylabel 'Interarrival (sec)'\n");
                if (scatter)
                    fprintf(stdout, "set style data points\n");
                else
                    fprintf(stdout, "set style data lines\n");
		min = minYRange < 0.0 ? 0.0 : minYRange;
		max = maxYRange < 0.0 ? -1.0 : maxYRange;
		if (max < 0.0)
		  fprintf(stdout, "set yrange[%f:*]\n",min);
		else 
		  fprintf(stdout, "set yrange[%f:%f]\n",min,max);
                break;
            
	        case DROPS:
	            //fprintf(stdout, "set ylabel 'Drops'\n");
                if (scatter)
                    fprintf(stdout, "set style data points\n");
                else
                    fprintf(stdout, "set style data lines\n");
		    min = minYRange < 0.0 ? 0.0 : minYRange;
		    max = maxYRange < 0.0 ? -1.0 : maxYRange;
		    if (max < 0.0)
		      fprintf(stdout, "set yrange[%f:*]\n",min);
		    else 
		      fprintf(stdout, "set yrange[%f:%f]\n",min,max);
                break;
                
            case COUNT:
	            //fprintf(stdout, "set ylabel 'Count'\n");
                if (scatter)
                    fprintf(stdout, "set style data points\n");
                else
                    fprintf(stdout, "set style data lines\n");
		min = minYRange < 0.0 ? 0.0 : minYRange;
		max = maxYRange < 0.0 ? -1.0 : maxYRange;
		if (max < 0.0)
		  fprintf(stdout, "set yrange[%f:*]\n",min);
		else 
		  fprintf(stdout, "set yrange[%f:%f]\n",min,max);
                break;
		 
            case LATENCY:
                //fprintf(stdout, "set ylabel 'Latency (sec)'\n");
                if (scatter)
                    fprintf(stdout, "set style data points\n");
                else
                    fprintf(stdout, "set style data lines\n");

		min = minYRange < 0.0 ? -1.0 : minYRange;
		max = maxYRange < 0.0 ? -1.0 : maxYRange;
		if (min < 0.0)
		  fprintf(stdout, "set yrange[*:");
		else
		  fprintf(stdout, "set yrange[%f:",min);

		if (max < 0.0)
		  fprintf(stdout, "*]\n",max);
		else 
		  fprintf(stdout, "%f]\n",max);
                break;
            
            case VELOCITY:
                fprintf(stdout, "set style data lines\n");
		min = minYRange < 0.0 ? 0.0 : minYRange;
		max = maxYRange < 0.0 ? -1.0 : maxYRange;
		if (max < 0.0)
		  fprintf(stdout, "set yrange[%f:*]\n",min);
		else 
		  fprintf(stdout, "set yrange[%f:%f]\n",min,max);
                break;
                    
            default:
                fprintf(stderr, "trpr: Unsupported plot mode!\n");
                exit(-1);
        }
	if (legend)
	  fprintf(stdout, "set key bottom right\n");
	else
	  fprintf(stdout, "set key off\n");

        fprintf(stdout, "set xrange[%f:%f]\n", xMin, xMax);
        
        fprintf(stdout, "set size 1.0,1.0\n");
        double origin = 0.0;
        fprintf(stdout, "set origin 0.0,%f\n", origin);
        fprintf(stdout, "set multiplot\n");
        double scale = 1.0 / ((double)count);
                      
        nextFlow = flowList->Head();
        while (nextFlow)
        {
            fprintf(stdout, "set size 1.0,%f\n", scale);
            fprintf(stdout, "set origin 0.0,%f\n", origin);
            origin += scale;
            fprintf(stdout, "plot '-' t '");
            nextFlow->PrintDescription(stdout);
            fprintf(stdout, "'\n");
            if (!nextFlow->PrintData(stdout))
            {
                double value;
                switch (plotMode)
                {
                    case RATE:
		            case DROPS:
                    case COUNT:
                    case LATENCY:
                    case INTERARRIVAL:
                    case VELOCITY:
                        value = 0.0;
                        break;

                    case LOSS:
                    case LOSS2:            
                        value = 1.0;
                        break;
                }
                fprintf(stdout, "%f, %f\n", xMin, value);
                fprintf(stdout, "%f, %f\n", xMax, value);
            }
            fprintf(stdout, "e\n");
            nextFlow = nextFlow->Next();
        }  // end while(nextFlow)
        fprintf(stdout, "set nomultiplot\n");
        fflush(stdout);
    }  // end if (nextFlow)
}  // end UpdateMultiGnuplot()


