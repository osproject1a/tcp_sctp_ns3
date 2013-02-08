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
 * Edited by :Group 1a & 1b
 */

#ifndef COMMON_HEADER_H
#define COMMON_HEADER_H

#include <stdint.h>
#include "ns3/header.h"
#include "ns3/buffer.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"


namespace ns3 {

/**
 * \ingroup commonheader
 * \brief Header for the Stream Transmission Control Protocol
 *
 * This class has fields corresponding to those in a network SCTP header
 * (port numbers, sequence and acknowledgement numbers, flags, etc) as well
 * as methods for serialization to and deserialization from a byte buffer.
 */

class CommonHeader : public Header 
{
public:
  CommonHeader ();
  virtual ~CommonHeader ();

  /**
   * \brief Enable checksum calculation for TCP (XXX currently has no effect)
   */
  void EnableChecksums (void);
//Setters
/**
 * \param port The source port for this SctpHeader
 */
  void SetSourcePort (uint16_t port);
  /**
   * \param port the destination port for this SctpHeader
   */
  void SetDestinationPort (uint16_t port);
  /**
   * \param verificationTag. The receiver of this packet uses the Verification Tag to validate
the sender of this SCTP packet. On transmit, the value of this
Verification Tag MUST be set to the value of the Initiate Tag
received from the peer endpoint during the association
initialization(exception exists for some packets)
.This method sets the verificationTag field
   */
 
  void SetVerificationTag (uint32_t verificationTag) ;
 

//Getters
/**
 * \return The source port for this SctpHeader
 */
  uint16_t GetSourcePort () const;
  /**
   * \return the destination port for this SctpHeader
   */
  uint16_t GetDestinationPort () const;
 /**
   * \return the VerificationTag for this SctpHeader
   */

  uint32_t GetVerificationTag () const;

  

  
  
  /**
   * \param source the ip source to use in the underlying
   *        ip packet.
   * \param destination the ip destination to use in the
   *        underlying ip packet.
   * \param protocol the protocol number to use in the underlying
   *        ip packet.
   *
   * If you want to use sctp checksums, you should call this
   * method prior to adding the header to a packet.
   */
  void InitializeChecksum (Ipv4Address source, 
                           Ipv4Address destination,
                           uint8_t protocol);
  void InitializeChecksum (Ipv6Address source, 
                           Ipv6Address destination,
                           uint8_t protocol);
  void InitializeChecksum (Address source, 
                           Address destination,
                           uint8_t protocol);

  //Not sure abt these 
  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;
  virtual void Print (std::ostream &os) const;
  virtual uint32_t GetSerializedSize (void) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);

  /**
   * \brief Is the SCTP checksum correct ?
   * \returns true if the checksum is correct, false otherwise.
   */
  bool IsChecksumOk (void) const;

private:
  uint16_t CalculateHeaderChecksum (uint16_t size) const;
  uint16_t m_sourcePort;
  uint16_t m_destinationPort;
//not sure if these fields are required
  uint8_t m_length; // really a uint4_t
  uint8_t m_flags;      // really a uint6_t
  
  Address m_source;
  Address m_destination;
  uint8_t m_protocol;

  uint16_t m_initialChecksum;
  bool m_calcChecksum;
  bool m_goodChecksum;
  uint32_t m_verificationTag;
};

} // namespace ns3

#endif /* COMMON_HEADER */
