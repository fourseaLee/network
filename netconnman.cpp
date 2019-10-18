#include "netconnman.h"
#include "net_args.h"
#include "net.h"
#include "netaddress.h"
#include "node.h"
#include "tinyformat.h"
#include "netbase.h"

static const uint64_t RANDOMIZER_ID_NETGROUP = 0x6c0edd8036ef4036ULL; // SHA256("netgroup")[0:8]
static const uint64_t RANDOMIZER_ID_LOCALHOSTNONCE = 0xd93e69e2bbfa5735ULL; // SHA256("localhostnonce")[0:8]
/** Time after which to disconnect, after waiting for a ping response (or inactivity). */
static const int TIMEOUT_INTERVAL = 20 * 60;
/** Run the feeler connection loop once every 2 minutes or 120 seconds. **/
static const int FEELER_INTERVAL = 120;

CNode* CConnman::FindNode(const CNetAddr& ip)
{
    //LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if ((CNetAddr)pnode->addr == ip) {
            return pnode;
        }
    }
    return nullptr;
}

CNode* CConnman::FindNode(const CSubNet& subNet)
{
    //LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (subNet.Match((CNetAddr)pnode->addr)) {
            return pnode;
        }
    }
    return nullptr;
}

CNode* CConnman::FindNode(const std::string& addrName)
{
    //LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (pnode->GetAddrName() == addrName) {
            return pnode;
        }
    }
    return nullptr;
}

CNode* CConnman::FindNode(const CService& addr)
{
    //LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if ((CService)pnode->addr == addr) {
            return pnode;
        }
    }
    return nullptr;
}

void CConnman::SetTryNewOutboundPeer(bool flag)
{
    m_try_another_outbound_peer = flag;
}

bool CConnman::BindListenPort(const CService &addrBind, std::string& strError, bool fWhitelisted)
{
    strError = "";
    int nOne = 1;

    // Create socket for listening for incoming connections
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrBind.GetSockAddr((struct sockaddr*)&sockaddr, &len))
    {
        strError = strprintf("Error: Bind address family for %s not supported", addrBind.ToString());
       ////LogPrintf("%s\n", strError);
        return false;
    }

    SOCKET hListenSocket = CreateSocket(addrBind);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %s)", NetworkErrorString(WSAGetLastError()));
       ////LogPrintf("%s\n", strError);
        return false;
    }
#ifndef WIN32
    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (void*)&nOne, sizeof(int));
#else
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&nOne, sizeof(int));
#endif

    // some systems don't have IPV6_V6ONLY but are always v6only; others do have the option
    // and enable it by default or not. Try to enable it, if possible.
    if (addrBind.IsIPv6()) {
#ifdef IPV6_V6ONLY
#ifdef WIN32
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&nOne, sizeof(int));
#else
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&nOne, sizeof(int));
#endif
#endif
#ifdef WIN32
        int nProtLevel = PROTECTION_LEVEL_UNRESTRICTED;
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, (const char*)&nProtLevel, sizeof(int));
#endif
    }

    if (::bind(hListenSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
//        if (nErr == WSAEADDRINUSE)
//            strError = strprintf(_("Unable to bind to %s on this computer. %s is probably already running."), addrBind.ToString(), _(PACKAGE_NAME));
//        else
//            strError = strprintf(_("Unable to bind to %s on this computer (bind returned error %s)"), addrBind.ToString(), NetworkErrorString(nErr));
//       ////LogPrintf("%s\n", strError);
//        CloseSocket(hListenSocket);
        return false;
    }
   ////LogPrintf("Bound to %s\n", addrBind.ToString());

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        //strError = strprintf(_("Error: Listening for incoming connections failed (listen returned error %s)"), NetworkErrorString(WSAGetLastError()));
       ////LogPrintf("%s\n", strError);
        CloseSocket(hListenSocket);
        return false;
    }

    vhListenSocket.push_back(ListenSocket(hListenSocket, fWhitelisted));

    if (addrBind.IsRoutable() )
        AddLocal(addrBind, LOCAL_BIND);

    return true;
}

bool CConnman::GetTryNewOutboundPeer()
{
    return m_try_another_outbound_peer;
}


CConnman::CConnman(uint64_t nSeed0In, uint64_t nSeed1In) : nSeed0(nSeed0In), nSeed1(nSeed1In)
{
    fNetworkActive = true;
    nLastNodeId = 0;
    nSendBufferMaxSize = 0;
    nReceiveFloodSize = 0;
    flagInterruptMsgProc = false;
    SetTryNewOutboundPeer(false);
    Options connOptions;
    Init(connOptions);
}

NodeId CConnman::GetNewNodeId()
{
    return nLastNodeId.fetch_add(1, std::memory_order_relaxed);
}


bool CConnman::Bind(const CService &addr, unsigned int flags)
{
    if (!(flags & BF_EXPLICIT) /*&& IsLimited(addr)*/)
        return false;
    std::string strError;
    if (!BindListenPort(addr, strError, (flags & BF_WHITELIST) != 0))
    {
        return false;
    }
    return true;
}

bool CConnman::InitBinds(const std::vector<CService>& binds, const std::vector<CService>& whiteBinds) {
    bool fBound = false;
    for (const auto& addrBind : binds) {
        fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR));
    }
    for (const auto& addrBind : whiteBinds) {
        fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR | BF_WHITELIST));
    }
    if (binds.empty() && whiteBinds.empty()) {
        struct in_addr inaddr_any;
        inaddr_any.s_addr = INADDR_ANY;
        fBound |= Bind(CService(in6addr_any, g_listen_port), BF_NONE);
        fBound |= Bind(CService(inaddr_any, g_listen_port), !fBound ? BF_REPORT_ERROR : BF_NONE);
    }
    return fBound;
}



void CConnman::DeleteNode(CNode* pnode)
{
    assert(pnode);
    bool fUpdateConnectionTime = false;
    if(fUpdateConnectionTime) {
        addrman.Connected(pnode->addr);
    }
    delete pnode;
}

CConnman::~CConnman()
{
    //Interrupt();
    //Stop();
}

size_t CConnman::GetAddressCount() const
{
    return addrman.size();
}

void CConnman::SetServices(const CService &addr, ServiceFlags nServices)
{
    addrman.SetServices(addr, nServices);
}

void CConnman::MarkAddressGood(const CAddress& addr)
{
    addrman.Good(addr);
}

void CConnman::AddNewAddresses(const std::vector<CAddress>& vAddr, const CAddress& addrFrom, int64_t nTimePenalty)
{
    addrman.Add(vAddr, addrFrom, nTimePenalty);
}

std::vector<CAddress> CConnman::GetAddresses()
{
    return addrman.GetAddr();
}

ServiceFlags CConnman::GetLocalServices() const
{
    return nLocalServices;
}

unsigned int CConnman::GetReceiveFloodSize() const
{
    return nReceiveFloodSize;
}

bool CConnman::NodeFullyConnected(const CNode* pnode)
{
    return pnode && pnode->fSuccessfullyConnected && !pnode->fDisconnect;
}



