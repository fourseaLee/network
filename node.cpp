#include "node.h"
#include "utiltime.h"
#include "netbase.h"

const static std::string NET_MESSAGE_COMMAND_OTHER = "*other*";
void CNode::CloseSocketDisconnect()
{
    fDisconnect = true;
    //LOCK(cs_hSocket);
    if (hSocket != INVALID_SOCKET)
    {
        //LogPrint(BCLog::NET, "disconnecting peer=%d\n", id);
        CloseSocket(hSocket);
    }
}

std::string CNode::GetAddrName() const {
    //LOCK(cs_addrName);
    return addrName;
}

void CNode::MaybeSetAddrName(const std::string& addrNameIn) {
    //LOCK(cs_addrName);
    if (addrName.empty()) {
        addrName = addrNameIn;
    }
}

CService CNode::GetAddrLocal() const {
    //LOCK(cs_addrLocal);
    return addrLocal;
}

void CNode::SetAddrLocal(const CService& addrLocalIn) {
    //LOCK(cs_addrLocal);
    if (addrLocal.IsValid()) {
        //error("Addr local already set for node: %i. Refusing to change from %s to %s", id, addrLocal.ToString(), addrLocalIn.ToString());
    } else {
        addrLocal = addrLocalIn;
    }
}

#undef X
#define X(name) stats.name = name
void CNode::copyStats(CNodeStats &stats)
{
    stats.nodeid = this->GetId();
    X(nServices);
    X(addr);
    X(addrBind);
    {
        //LOCK(cs_filter);
        //X(g_fRelayTxes);
    }
    X(nLastSend);
    X(nLastRecv);
    X(nTimeConnected);
    X(nTimeOffset);
    stats.addrName = GetAddrName();

    X(fInbound);

    {
        //LOCK(cs_vSend);
        X(mapSendBytesPerMsgCmd);
        X(nSendBytes);
    }
    {
        //LOCK(cs_vRecv);
        X(mapRecvBytesPerMsgCmd);
        X(nRecvBytes);
    }




    // Leave string empty if addrLocal invalid (not filled in yet)
    CService addrLocalUnLOCKed = GetAddrLocal();
    stats.addrLocal = addrLocalUnLOCKed.IsValid() ? addrLocalUnLOCKed.ToString() : "";
}
#undef X

bool CNode::ReceiveMsgBytes(const char *pch, unsigned int nBytes, bool& complete)
{
//    complete = false;
//    int64_t nTimeMicros = GetTimeMicros();
//    //LOCK(cs_vRecv);
//    nLastRecv = nTimeMicros / 1000000;
//    nRecvBytes += nBytes;
//    while (nBytes > 0) {

//        // get current incomplete message, or create a new one
//   /*     if (vRecvMsg.empty() ||
//            vRecvMsg.back().complete())
//            vRecvMsg.push_back(CNetMessage(Params().MessageStart(), SER_NETWORK, INIT_PROTO_VERSION));
//*/
//        CNetMessage/*&*/ msg ;//= vRecvMsg.back();

//        // absorb network data
//        int handled;
//        if (!msg.in_data)
//            handled = msg.readHeader(pch, nBytes);
//        else
//            handled = msg.readData(pch, nBytes);

//        if (handled < 0)
//            return false;
    // Maximum length of incoming protocol messages (no message over 4 MB is currently acceptable).
//    static const unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000;
//        if (msg.in_data && msg.hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH) {
//            //LogPrint(BCLog::NET, "Oversized message from peer=%i, disconnecting\n", GetId());
//            return false;
//        }

//        pch += handled;
//        nBytes -= handled;

//        if (msg.complete()) {

//            //store received bytes per message command
//            //to prevent a memory DOS, only allow valid commands
//            mapMsgCmdSize::iterator i = mapRecvBytesPerMsgCmd.find(msg.hdr.pchCommand);
//            if (i == mapRecvBytesPerMsgCmd.end())
//                i = mapRecvBytesPerMsgCmd.find(NET_MESSAGE_COMMAND_OTHER);
//            assert(i != mapRecvBytesPerMsgCmd.end());
//            i->second += msg.hdr.nMessageSize + CMessageHeader::HEADER_SIZE;

//            msg.nTime = nTimeMicros;
//            complete = true;
//        }
//    }

    return true;
}


CNode::~CNode()
{
    CloseSocket(hSocket);
}



CNode::CNode(NodeId idIn, ServiceFlags nLocalServicesIn,  SOCKET hSocketIn,
             const CAddress& addrIn, uint64_t nKeyedNetGroupIn, uint64_t nLocalHostNonceIn,
             const CAddress &addrBindIn, const std::string& addrNameIn, bool fInboundIn) :
    nTimeConnected(GetSystemTimeInSeconds()),
    addr(addrIn),
    addrBind(addrBindIn),
    fInbound(fInboundIn),
    nKeyedNetGroup(nKeyedNetGroupIn),

    id(idIn),
    nLocalHostNonce(nLocalHostNonceIn),
    nLocalServices(nLocalServicesIn),
    nSendVersion(0)
{
    nServices = NODE_NONE;
    hSocket = hSocketIn;

    nLastSend = 0;
    nLastRecv = 0;
    nSendBytes = 0;
    nRecvBytes = 0;
    nTimeOffset = 0;
    addrName = addrNameIn == "" ? addr.ToStringIPPort() : addrNameIn;

    fSuccessfullyConnected = false;
    fDisconnect = false;
    nRefCount = 0;
    nSendSize = 0;
    nSendOffset = 0;

    nStartingHeight = -1;

    fSendMempool = false;
    fGetAddr = false;
    nNextLocalAddrSend = 0;
    nNextAddrSend = 0;
    nNextInvSend = 0;

    fSentAddr = false;

    timeLastMempoolReq = 0;

    nLastTXTime = 0;
    nPingNonceSent = 0;
    nPingUsecStart = 0;
    nPingUsecTime = 0;
    fPingQueued = false;
    nMinPingUsecTime = std::numeric_limits<int64_t>::max();

    nextSendTimeFeeFilter = 0;
    fPauseRecv = false;
    fPauseSend = false;
    nProcessQueueSize = 0;

    for (const std::string &msg : getAllNetMessageTypes())
        mapRecvBytesPerMsgCmd[msg] = 0;
    mapRecvBytesPerMsgCmd[NET_MESSAGE_COMMAND_OTHER] = 0;


}
