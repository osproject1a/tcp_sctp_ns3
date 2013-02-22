
#ifndef __sctpHeader_h__
#define __sctpHeader_h__

//#include <sctpConstants.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* the sctp common header */

#ifdef TRU64
 #define _64BITS 1
#endif 

/*class sctp_Common_Header{
  unsigned short source;
  unsigned short destination;
  unsigned int verification_Tag;
  unsigned int check_sum;
};
*/
/* various descriptor parsers */

typedef struct Sctp_Chunk_Desc{
  unsigned char chunk_Type;
  unsigned char chunk_Flag;
  unsigned short chunk_Length;
}*chk;
chk chunk1,chunk2;

typedef struct Sctp_Param_Desc{
  unsigned short param_Type;
  unsigned short param_Length;
}*param;
param p;

typedef struct Sctp_Payload
{
 chk chunk1;
unsigned int  TSN;
unsigned short SI;
unsigned short SSN;
unsigned int Protocol_Id;

}*payload;
payload pay;

typedef struct Sctp_Init
{
chk chunk1;
  unsigned short No_Of_Outbound;
  unsigned short No_Of_Inbound;
  unsigned int Initiate_Tag;
  unsigned int a_Rwnd;
  unsigned int initial_TSN;
}*init_sctp;

init_sctp init;
typedef struct Sctp_Init_Ack
{
chk chunk1;
  unsigned short No_Of_Outbound;
  unsigned short No_Of_Inbound;
  unsigned int Initiate_Tag;
  unsigned int a_Rwnd;
  unsigned int initial_TSN;
}*init_acknowledge;
init_acknowledge init_ack;

typedef struct Sctp_Cookie_Echo
{
chk chunk1;
//unsigned int Data;
}*cookie_echo;
cookie_echo cooki_echo;

typedef struct Sctp_Cookie_Ack
{
chk chunk1;
}*cookie_ack;
cookie_ack cooki_ack;

typedef struct Sctp_Abort
{
chk chunk1;
//unsigned int info;
}*abort_sctp;
abort_sctp abor;

typedef struct SACK{
chk chunk1;
   unsigned int Cumulative_TSN;
   unsigned short Number_Gap_Ack;
   unsigned int a_Rwnd;
   unsigned int Number_Dup_TSN;
   //unsigned short gap_start;
   //unsigned short gap_end;
}*sack;
sack ack;
typedef struct Sctp_Shutdown {
chk chunk1;
 unsigned int Cumulative_TSN_Ack;
}*shutdown;
shutdown shut;

typedef struct Sctp_Shutdown_Ack{
chk chunk1;

}*shutdown_ack;
shutdown_ack shut_ack;

typedef struct Sctp_Error{
chk chunk1;
struct Sctp_Param_Desc param;

}*error;
error err;
typedef struct Sctp_Shutdown_Complete{
chk chunk1;

}*shut_comp;
shut_comp cmpl;

typedef struct Sctp_HeartBeat_request{
chk chunk1;
struct Sctp_Param_Desc param;

}*heartb_req;
heartb_req hb_req;

typedef struct Sctp_HeartBeat_ACK{
chk chunk1;
struct Sctp_Param_Desc param;

}*heartb_ack;
heartb_ack hb_ack;
#ifdef	__cplusplus
}
#endif

#endif
