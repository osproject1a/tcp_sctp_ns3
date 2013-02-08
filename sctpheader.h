
#ifndef __sctpHeader_h__
#define __sctpHeader_h__

#include <sctpConstants.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* the sctp common header */

#ifdef TRU64
 #define _64BITS 1
#endif 

class sctp_Common_Header{
  unsigned short source;
  unsigned short destination;
  unsigned int verification_Tag;
  unsigned int check_sum;
};

/* various descriptor parsers */

class Sctp_Chunk_Desc{
  unsigned char chunk_Type;
  unsigned char chunk_Flag;
  unsigned short chunk_Length;
};

class Sctp_Param_Desc{
  unsigned short param_Type;
  unsigned short param_Length;
};

class Sctp_Payload:public Sctp_Chunk_Desc
{
unsigned int  TSN
unsigned short SI;
unsigned short SSN;
unsigned int Protocol_Id;

}

class Sctp_Init:public Sctp_Chunk_Desc
{
  unsigned short No_Of_Outbound;
  unsigned short No_Of_Inbound;
  unsigned int Initiate_Tag;
  unsigned int a_Rwnd;
  unsigned int initial_TSN;
};

class Sctp_Init_Ack:public Sctp_Chunk_Desc
{
  unsigned short No_Of_Outbound;
  unsigned short No_Of_Inbound;
  unsigned int Initiate_Tag;
  unsigned int a_Rwnd;
  unsigned int initial_TSN;
};

class Sctp_Cookie_Echo:public Sctp_Chunk_Desc
{
//unsigned int Data;
};

class Sctp_Cookie_Ack:public Sctp_Chunk_Desc
{

};

class Sctp_Abort:public Sctp_Chunk_Desc
{
//unsigned int info;
};


class SACK: public Sctp_Chunk_Desc{
   unsigned int Cumulative_TSN;
   unsigned short Number_Gap_Ack;
   unsigned int a_Rwnd;
   unsigned int Number_Dup_TSN;
   //unsigned short gap_start;
   //unsigned short gap_end;
};

class Sctp_Shutdown:public Sctp_Chunk_Desc{
 unsigned int Cumulative_TSN_Ack;
};

class Sctp_Shutdown_Ack:public Sctp_Chunk_Desc{

};

class Sctp_Error:public Sctp_Chunk_Desc,public Sctp_Param_Desc{

};

class Sctp_Shutdown_Complete:public Sctp_Chunk_Desc{

};

class Sctp_HeartBeat_request:public Sctp_Chunk_Desc,public Sctp_Param_Desc{

};

class Sctp_HeartBeat_ACK:public Sctp_Chunk_Desc,public Sctp_Param_Desc{

};

#ifdef	__cplusplus
}
#endif

#endif
