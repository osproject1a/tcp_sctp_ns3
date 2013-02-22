/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2007 INRIA
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
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#include "ns3/object.h"
#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/boolean.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/nstime.h"
#include "sctp-socket.h"

NS_LOG_COMPONENT_DEFINE ("SctpSocket");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (SctpSocket);

const char* const SctpSocket::SctpStateName[SCTP_LAST_STATE] = {   
  "SCTP_CLOSED",      
  "SCTP_COOKIE_WAIT", 
  "SCTP_COOKIE_ECHOED",
  "SCTP_ESTABLISHED",  
  "SCTP_SHUTDOWN_PENDING",   
  "SCTP_SHUTDOWN_RECEIVED",
  "SCTP_SHUTDOWN_SENT",
  "SCTP_SHUTDOWN_ACK_SENT",
  "SCTP_LAST_STATE" };

TypeId
SctpSocket::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SctpSocket")
    .SetParent<Socket> ()
    .AddAttribute ("SndBufSize",
                   "SctpSocket maximum transmit buffer size (bytes)",
                   UintegerValue (131072), // 128k
                   MakeUintegerAccessor (&SctpSocket::GetSndBufSize,
                                         &SctpSocket::SetSndBufSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("RcvBufSize",
                   "SctpSocket maximum receive buffer size (bytes)",
                   UintegerValue (131072),
                   MakeUintegerAccessor (&SctpSocket::GetRcvBufSize,
                                         &SctpSocket::SetRcvBufSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("SegmentSize",
                   "SCTP maximum segment size in bytes (may be adjusted based on MTU discovery)",
                   UintegerValue (536),
                   MakeUintegerAccessor (&SctpSocket::GetSegSize,
                                         &SctpSocket::SetSegSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("SlowStartThreshold",
                   "SCTP slow start threshold (bytes)",
                   UintegerValue (0xffff),
                   MakeUintegerAccessor (&SctpSocket::GetSSThresh,
                                         &SctpSocket::SetSSThresh),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("InitialCwnd",
                   "SCTP initial congestion window size (segments)",
                   UintegerValue (1),
                   MakeUintegerAccessor (&SctpSocket::GetInitialCwnd,
                                         &SctpSocket::SetInitialCwnd),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("ConnTimeout",
                   "SCTP retransmission timeout when opening connection (seconds)",
                   TimeValue (Seconds (3)),
                   MakeTimeAccessor (&SctpSocket::GetConnTimeout,
                                     &SctpSocket::SetConnTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("ConnCount",
                   "Number of connection attempts (SYN retransmissions) before returning failure",
                   UintegerValue (6),
                   MakeUintegerAccessor (&SctpSocket::GetConnCount,
                                         &SctpSocket::SetConnCount),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("DelAckTimeout",
                   "Timeout value for SCTP delayed acks, in seconds",
                   TimeValue (Seconds (0.2)),
                   MakeTimeAccessor (&SctpSocket::GetDelAckTimeout,
                                     &SctpSocket::SetDelAckTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("DelAckCount",
                   "Number of packets to wait before sending a SCTP ack",
                   UintegerValue (2),
                   MakeUintegerAccessor (&SctpSocket::GetDelAckMaxCount,
                                         &SctpSocket::SetDelAckMaxCount),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("SctpNoDelay", "Set to true to disable Nagle's algorithm",
                   BooleanValue (true),
                   MakeBooleanAccessor (&SctpSocket::GetSctpNoDelay,
                                        &SctpSocket::SetSctpNoDelay),
                   MakeBooleanChecker ())
    .AddAttribute ("PersistTimeout",
                   "Persist timeout to probe for rx window",
                   TimeValue (Seconds (6)),
                   MakeTimeAccessor (&SctpSocket::GetPersistTimeout,
                                     &SctpSocket::SetPersistTimeout),
                   MakeTimeChecker ())
  ;
  return tid;
}

SctpSocket::SctpSocket ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

SctpSocket::~SctpSocket ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

} // namespace ns3
