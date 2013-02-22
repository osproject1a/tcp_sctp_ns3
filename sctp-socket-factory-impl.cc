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
#include "sctp-socket-factory-impl.h"
#include "sctp-l4-protocol.h"
#include "ns3/socket.h"
#include "ns3/assert.h"

namespace ns3 {

SctpSocketFactoryImpl::SctpSocketFactoryImpl ()
  : m_sctp (0)
{
}
SctpSocketFactoryImpl::~SctpSocketFactoryImpl ()
{
  NS_ASSERT (m_sctp == 0);
}

void
SctpSocketFactoryImpl::SetSctp (Ptr<SctpL4Protocol> sctp)
{
  m_sctp = sctp;
}

Ptr<Socket>
SctpSocketFactoryImpl::CreateSocket (void)
{
  return m_sctp->CreateSocket ();
}

void 
SctpSocketFactoryImpl::DoDispose (void)
{
  m_sctp = 0;
  SctpSocketFactory::DoDispose ();
}

} // namespace ns3
