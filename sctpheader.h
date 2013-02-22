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

#ifndef SCTP_HEADER_H
#define SCTP_HEADER_H

#include <stdint.h>
#include "ns3/header.h"
#include "ns3/buffer.h"
#include "ns3/sctp-socket-factory.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/sequence-number.h"

namespace ns3 {

/**
 * \ingroup sctp
 * \brief Header for the Transmission Control Protocol
 *
 * This class has fields corresponding to those in a network SCTP header
 * (port numbers, sequence and acknowledgement numbers, flags, etc) as well
 * as methods for serialization to and deserialization from a byte buffer.
 */

class SctpHeader : public Header 
{
public:
  SctpHeader ();
  virtual ~SctpHeader ();

void EnableChecksums(void);
/**
 * \param port The source port for this SctpHeader
 */
  void SetSourcePort (uint16_t port);
  /**
   * \param port the destination port for this SctpHeader
   */
  void SetDestinationPort (uint16_t port);

  void SetVerificationTag (uint32_t m_verificationTag);
//  void SetChunkType (unsigned char chunk_Type);

typedef enum { PAYLOAD_DATA = 0, INIT = 1, INIT_ACK = 2,SACK = 3,HB = 4, HB_ACK = 5,ABORT = 6,SHUTDOWN = 7,SHUTDOWN_ACK = 8,ERROR = 9,COOKIE_ECHO = 10, COOKIE_ACK = 11, SHUTDOWN_COMP = 14} Chunks_t;
//Getters
/**
 * \return The source port for this SctpHeader
 */
  uint16_t GetSourcePort () const;
  /**
   * \return the destination port for this SctpHeader
   */
  uint16_t GetDestinationPort () const;
  uint32_t GetVerificationTag () const;
//  uint8_t  GetChunkType () const;

  void Serialize_init (Buffer::Iterator start) ;
  void Serialize_init_ack (Buffer::Iterator start) ;
  void Serialize_cookie_echo (Buffer::Iterator start) ;
  void Serialize_cookie_ack (Buffer::Iterator start) ;
  void Serialize_payload (Buffer::Iterator start) ;


  void InitializeChecksum (Ipv4Address source, 
                           Ipv4Address destination,
                           uint8_t protocol);
  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;
  virtual void Print (std::ostream &os) const;
  virtual uint32_t GetSerializedSize (void) const;
  virtual void Serialize (Buffer::Iterator start) const ;

  virtual uint32_t Deserialize (Buffer::Iterator start);
  uint32_t Deserialize_init (Buffer::Iterator start);
  uint32_t Deserialize_init_ack (Buffer::Iterator start);
  uint32_t Deserialize_cookie_echo (Buffer::Iterator start);
  uint32_t Deserialize_cookie_ack (Buffer::Iterator start);
  uint32_t Deserialize_payload (Buffer::Iterator start);
  /**
   * \brief Is the SCTP checksum correct ?
   * \returns true if the checksum is correct, false otherwise.
   */
  bool IsChecksumOk (void) const;

private:
  uint16_t CalculateHeaderChecksum(uint16_t size)const;
  uint16_t m_sourcePort;
  uint16_t m_destinationPort;
  uint32_t m_verificationTag;
  uint16_t m_initialChecksum;

  Address m_source;
  Address m_destination;
  uint8_t m_protocol;
  uint8_t m_length;
  bool m_calcChecksum;
  bool m_goodChecksum;

};

} 

#endif /* SCTP_HEADER */
