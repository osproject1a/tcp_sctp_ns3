/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2007 Georgia Tech Research Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Raj Bhattacharjea <raj.b@gatech.edu>
 */

#include <stdint.h>
#include <iostream>
#include "sctp-header.h"
#include "ns3/buffer.h"
#include "ns3/address-utils.h"
#include "sctp-typedefs.h"

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (SctpHeader);

SctpHeader::SctpHeader ()
  : m_sourcePort (0),
    m_destinationPort (0),
    m_verificationTag(0),
    m_calcChecksum (false),
    m_goodChecksum (true)
{
}




SctpHeader::~SctpHeader ()
{
}

void
SctpHeader::EnableChecksums (void)
{
  m_calcChecksum = true;
}
void SctpHeader::SetSourcePort (uint16_t port)
{
  m_sourcePort = port;
}
void SctpHeader::SetVerificationTag (uint32_t Tag)
{
 m_verificationTag=Tag;
}

/*void SctpHeader::SetChunkType (unsigned char chunk_Type)
{
  m_flags = flags;
}*/




uint16_t SctpHeader::GetSourcePort () const
{
  return m_sourcePort;
}
uint16_t SctpHeader::GetDestinationPort () const
{
  return m_destinationPort;
}

uint32_t SctpHeader::GetVerificationTag () const
{
  return m_verificationTag;
}


void 
SctpHeader::InitializeChecksum (Ipv4Address source, 
                               Ipv4Address destination,
                               uint8_t protocol)
{
  m_source = source;
  m_destination = destination;
  m_protocol = protocol;
}

uint16_t
SctpHeader::CalculateHeaderChecksum (uint16_t size) const
{
  /* Buffer size must be at least as large as the largest IP pseudo-header */
  /* [per RFC2460, but without consideration for IPv6 extension hdrs]      */
  /* Src address            16 bytes (more generally, Address::MAX_SIZE)   */
  /* Dst address            16 bytes (more generally, Address::MAX_SIZE)   */
  /* Upper layer pkt len    4 bytes                                        */
  /* Zero                   3 bytes                                        */
  /* Next header            1 byte                                         */

  uint32_t maxHdrSz = (2 * Address::MAX_SIZE) + 8;
  Buffer buf = Buffer (maxHdrSz);
  buf.AddAtStart (maxHdrSz);
  Buffer::Iterator it = buf.Begin ();
  uint32_t hdrSize = 0;

  WriteTo (it, m_source);
  WriteTo (it, m_destination);
  if (Ipv4Address::IsMatchingType(m_source))
    {
      it.WriteU8 (0); // protocol 
      it.WriteU8 (m_protocol); // protocol 
      it.WriteU8 (size >> 8); 
      it.WriteU8 (size & 0xff); 
      hdrSize = 12;
    }
  it = buf.Begin ();
  /* we don't CompleteChecksum ( ~ ) now */
  return ~(it.CalculateIpChecksum (hdrSize));
}

bool
SctpHeader::IsChecksumOk (void) const
{
  return m_goodChecksum;
}
TypeId 
SctpHeader::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SctpHeader")
    .SetParent<Header> ()
    .AddConstructor<SctpHeader> ()
  ;
  return tid;
}
TypeId 
SctpHeader::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
void SctpHeader::Print (std::ostream &os)  const
{
  os << m_sourcePort << " > " << m_destinationPort;
  os<<"Verification ="<<m_verificationTag;
}
uint32_t SctpHeader::GetSerializedSize (void)  const
{
  return 4*m_length;
}
void SctpHeader::Serialize (Buffer::Iterator start)  const
{
  
  Buffer::Iterator i = start;
  i.WriteHtonU16 (m_sourcePort);
  i.WriteHtonU16 (m_destinationPort);
  i.WriteHtonU32 (m_verificationTag);

  if(m_calcChecksum)
    {
      uint16_t headerChecksum = CalculateHeaderChecksum (start.GetSize ());
      i = start;
      uint16_t checksum = i.CalculateIpChecksum (start.GetSize (), headerChecksum);

      i = start;
      i.Next (8);
      i.WriteU32 (checksum);
    }
  

}

void SctpHeader::Serialize_init (Buffer::Iterator start) 
{

  Buffer::Iterator i = start;
  
  i.WriteU8(chunk1->chunk_Type);
  i.WriteU8(chunk1->chunk_Flag);
  i.WriteU16(chunk1->chunk_Length);

  i.WriteU32(init->Initiate_Tag);
  i.WriteU32(init->a_Rwnd);
  i.WriteU16(init->No_Of_Outbound);
  i.WriteU16(init->No_Of_Inbound);
  i.WriteU32(init->initial_TSN);
  

}

void SctpHeader::Serialize_init_ack (Buffer::Iterator start)  
 {

  Buffer::Iterator i = start;
     
  i.WriteU8(chunk1->chunk_Type);
  i.WriteU8(chunk1->chunk_Flag);
  i.WriteU16(chunk1->chunk_Length);

  i.WriteU32(init_ack->Initiate_Tag);
  i.WriteU32(init_ack->a_Rwnd);
  i.WriteU16(init_ack->No_Of_Outbound);
  i.WriteU16(init_ack->No_Of_Inbound);
  i.WriteU32(init_ack->initial_TSN);

}


void SctpHeader::Serialize_cookie_echo (Buffer::Iterator start)  
{

  Buffer::Iterator i = start;
     
  i.WriteU8(chunk1->chunk_Type);
  i.WriteU8(chunk1->chunk_Flag);
  i.WriteU16(chunk1->chunk_Length);

  i = start;
  i.Next (20);
  i.Next(chunk1->chunk_Length);
  i.WriteU8(chunk2->chunk_Type);
  i.WriteU8(chunk2->chunk_Flag);
  i.WriteU16(chunk2->chunk_Length);
        
}


void SctpHeader::Serialize_cookie_ack (Buffer::Iterator start)  
{

  Buffer::Iterator i = start;
     
  i.WriteU8(chunk1->chunk_Type);
  i.WriteU8(chunk1->chunk_Flag);
  i.WriteU16(chunk1->chunk_Length);

  i = start;
  i.Next (20);
  i.Next(chunk1->chunk_Length);
  i.WriteU8(chunk2->chunk_Type);
  i.WriteU8(chunk2->chunk_Flag);
  i.WriteU16(chunk2->chunk_Length);
        
}

void SctpHeader::Serialize_payload (Buffer::Iterator start)
{

  Buffer::Iterator i = start;
     
  i.WriteU8(chunk1->chunk_Type);
  i.WriteU8(chunk1->chunk_Flag);
  i.WriteU16(chunk1->chunk_Length);

  i.WriteU32(pay->TSN);
  i.WriteU8(pay->SI);
  i.WriteU8(pay->SSN);
  i.WriteU32(pay->Protocol_Id);
}   

uint32_t SctpHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  m_sourcePort = i.ReadNtohU16 ();
  m_destinationPort = i.ReadNtohU16 ();
  m_verificationTag = i.ReadNtohU32 ();


  if(m_calcChecksum)
    {
      uint16_t headerChecksum = CalculateHeaderChecksum (start.GetSize ());
      i = start;
      uint16_t checksum = i.CalculateIpChecksum (start.GetSize (), headerChecksum);
      m_goodChecksum = (checksum == 0);
    }

     return 20;
}
uint32_t SctpHeader::Deserialize_init (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  chunk1->chunk_Type=i.ReadU8 ();
  chunk1->chunk_Flag=i.ReadU8 ();
  chunk1->chunk_Length=i.ReadU16 ();

  init->Initiate_Tag=i.ReadU32();
  init->a_Rwnd=i.ReadU32();
  init->No_Of_Outbound=i.ReadU16();
  init->No_Of_Inbound=i.ReadU16();
  init->initial_TSN=i.ReadU32();
    return 20;
  
 
}

uint32_t SctpHeader::Deserialize_init_ack (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  chunk1->chunk_Type=i.ReadU8 ();
  chunk1->chunk_Flag=i.ReadU8 ();
  chunk1->chunk_Length=i.ReadU16 ();

  init_ack->Initiate_Tag=i.ReadU32();
  init_ack->a_Rwnd=i.ReadU32();
  init_ack->No_Of_Outbound=i.ReadU16();
  init_ack->No_Of_Inbound=i.ReadU16();
  init_ack->initial_TSN=i.ReadU32();
 return 20;
}  


uint32_t SctpHeader::Deserialize_cookie_echo (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  chunk1->chunk_Type=i.ReadU8 ();
  chunk1->chunk_Flag=i.ReadU8 ();
  chunk1->chunk_Length=i.ReadU16 ();

  chunk2->chunk_Type=i.ReadU8();
  chunk2->chunk_Flag=i.ReadU8();
  chunk2->chunk_Length=i.ReadU16();
 return 8;
}  






uint32_t SctpHeader::Deserialize_cookie_ack (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  chunk1->chunk_Type=i.ReadU8 ();
  chunk1->chunk_Flag=i.ReadU8 ();
  chunk1->chunk_Length=i.ReadU16 ();

     
  chunk2->chunk_Type=i.ReadU8();
  chunk2->chunk_Flag=i.ReadU8();
  chunk2->chunk_Length=i.ReadU16();
 return 8;
        
}


uint32_t SctpHeader::Deserialize_payload (Buffer::Iterator start)  {

  Buffer::Iterator i = start;
   
  chunk1->chunk_Type=i.ReadU8 ();
  chunk1->chunk_Flag=i.ReadU8 ();
  chunk1->chunk_Length=i.ReadU16 ();  

  pay->TSN=i.ReadU32();
  pay->SI=i.ReadU8();
  pay->SSN=i.ReadU8();
  pay->Protocol_Id=i.ReadU32();        
 
  return 14;
}




} // namespace ns3
