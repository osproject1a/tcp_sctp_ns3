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
#ifndef SCTP_SOCKET_FACTORY_IMPL_H
#define SCTP_SOCKET_FACTORY_IMPL_H

#include "ns3/sctp-socket-factory.h"
#include "ns3/ptr.h"

namespace ns3 {

class SctpL4Protocol;

/**
 * \ingroup internet
 * \defgroup sctp Sctp
 *
 * This class serves to create sockets of the SctpSocketBase type.
 */

/**
 * \ingroup sctp
 *
 * \brief socket factory implementation for native ns-3 SCTP
 *
 */
class SctpSocketFactoryImpl : public SctpSocketFactory
{
public:
  SctpSocketFactoryImpl ();
  virtual ~SctpSocketFactoryImpl ();

  void SetSctp (Ptr<SctpL4Protocol> sctp);

  virtual Ptr<Socket> CreateSocket (void);

protected:
  virtual void DoDispose (void);
private:
  Ptr<SctpL4Protocol> m_sctp;
};

} // namespace ns3

#endif /* SCTP_SOCKET_FACTORY_IMPL_H */
