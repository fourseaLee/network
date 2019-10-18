#ifndef NETMESSAGE_H
#define NETMESSAGE_H
#include "protocol.h"

struct CSerializedNetMsg
{
    CSerializedNetMsg() = default;
    CSerializedNetMsg(CSerializedNetMsg&&) = default;
    CSerializedNetMsg& operator=(CSerializedNetMsg&&) = default;
    // No copying, only moves.
    CSerializedNetMsg(const CSerializedNetMsg& msg) = delete;
    CSerializedNetMsg& operator=(const CSerializedNetMsg&) = delete;

    std::vector<unsigned char> data;
    std::string command;
};


class CNetMessage {
private:
    //mutable CHash256 hasher;
    //mutable uint256 data_hash;
public:
    bool in_data;                   // parsing header (false) or data (true)

    //CDataStream hdrbuf;             // partially received header
    CMessageHeader hdr;             // complete header
    unsigned int nHdrPos;

   // CDataStream vRecv;              // received message data
    unsigned int nDataPos;

    int64_t nTime;                  // time (in microseconds) of message receipt.

    CNetMessage(const CMessageHeader::MessageStartChars& pchMessageStartIn, int nTypeIn, int nVersionIn) : /*hdrbuf(nTypeIn, nVersionIn),*/
        hdr(pchMessageStartIn)/*, vRecv(nTypeIn, nVersionIn)*/ {
      //  hdrbuf.resize(24);
        in_data = false;
        nHdrPos = 0;
        nDataPos = 0;
        nTime = 0;
    }

    bool complete() const
    {
        if (!in_data)
            return false;
        return (hdr.nMessageSize == nDataPos);
    }

    //const uint256& GetMessageHash() const;

//    void SetVersion(int nVersionIn)
//    {
//       // hdrbuf.SetVersion(nVersionIn);
//        //vRecv.SetVersion(nVersionIn);
//    }

    int readHeader(const char *pch, unsigned int nBytes);
    int readData(const char *pch, unsigned int nBytes);
};

#endif // NETMESSAGE_H
