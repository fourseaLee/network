// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_PROCESSING_H
#define BITCOIN_NET_PROCESSING_H

#include "net.h"
#include "network_macro.h"
#include <atomic>

class CConnman;
class CNode;
class PeerLogicValidation
{
private:
    CConnman* const connman;

public:
    explicit PeerLogicValidation(CConnman* _connman);
    //  explicit PeerLogicValidation(CConnman* connman, CScheduler &scheduler);

    //  void BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexConnected, const std::vector<CTransactionRef>& vtxConflicted) override;
    //  void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override;
    //  void BlockChecked(const CBlock& block, const CValidationState& state) override;
    //  void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& pblock) override;


    void InitializeNode(CNode* pnode) ;
    void FinalizeNode(NodeId nodeid, bool& fUpdateConnectionTime) ;
    /** Process protocol messages received from a given node */
    bool ProcessMessages(CNode* pfrom, std::atomic<bool>& interrupt) ;
    /**
    * Send queued protocol messages to be sent to a give node.
    *
    * @param[in]   pto             The node which we are sending messages to.
    * @param[in]   interrupt       Interrupt condition for processing threads
    * @return                      True if there is more work to be done
    */
    bool SendMessages(CNode* pto, std::atomic<bool>& interrupt);

    void ConsiderEviction(CNode *pto, int64_t time_in_seconds);
    //  void CheckForStaleTipAndEvictPeers(const Consensus::Params &consensusParams);
    void EvictExtraOutboundPeers(int64_t time_in_seconds);

private:
    int64_t m_stale_tip_check_time; //! Next time to check for stale tip
};



/** Get statistics from node state */
//bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats);
/** Increase a node's misbehavior score. */
//void Misbehaving(NodeId nodeid, int howmuch);

#endif // BITCOIN_NET_PROCESSING_H
