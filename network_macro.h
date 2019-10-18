#ifndef CONFIG_NETWORK_H
#define CONFIG_NETWORK_H
#include <stddef.h>
#include <stdint.h>
#include <string>
//! total number of buckets for tried addresses
#define ADDRMAN_TRIED_BUCKET_COUNT_LOG2 8

//! total number of buckets for new addresses
#define ADDRMAN_NEW_BUCKET_COUNT_LOG2 10

//! maximum allowed number of entries in buckets for new and tried addresses
#define ADDRMAN_BUCKET_SIZE_LOG2 6

//! over how many buckets entries with tried addresses from a single group (/16 for IPv4) are spread
#define ADDRMAN_TRIED_BUCKETS_PER_GROUP 8

//! over how many buckets entries with new addresses originating from a single group are spread
#define ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP 64

//! in how many buckets for entries with new addresses a single address may occur
#define ADDRMAN_NEW_BUCKETS_PER_ADDRESS 8

//! how old addresses can maximally be
#define ADDRMAN_HORIZON_DAYS 30

//! after how many failed attempts we give up on a new node
#define ADDRMAN_RETRIES 3

//! how many successive failures are allowed ...
#define ADDRMAN_MAX_FAILURES 10

//! ... in at least this many days
#define ADDRMAN_MIN_FAIL_DAYS 7

//! the maximum percentage of nodes to return in a getaddr call
#define ADDRMAN_GETADDR_MAX_PCT 23

//! the maximum number of nodes to return in a getaddr call
#define ADDRMAN_GETADDR_MAX 2500

//! Convenience
#define ADDRMAN_TRIED_BUCKET_COUNT (1 << ADDRMAN_TRIED_BUCKET_COUNT_LOG2)
#define ADDRMAN_NEW_BUCKET_COUNT (1 << ADDRMAN_NEW_BUCKET_COUNT_LOG2)
#define ADDRMAN_BUCKET_SIZE (1 << ADDRMAN_BUCKET_SIZE_LOG2)


//extern limitedmap<uint256, int64_t> mapAlreadyAskedFor;

// Dump addresses to peers.dat and banlist.dat every 15 minutes (900s)
#define DUMP_ADDRESSES_INTERVAL 900

// We add a random period time (0 to 1 seconds) to feeler connections to prevent synchronization.
#define FEELER_SLEEP_WINDOW 1


#if !defined(HAVE_MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

// MSG_DONTWAIT is not available on some platforms, if it doesn't exist define it as 0
#if !defined(HAVE_MSG_DONTWAIT)
#define MSG_DONTWAIT 0
#endif

// Fix for ancient MinGW versions, that don't have defined these in ws2tcpip.h.
// Todo: Can be removed when our pull-tester is upgraded to a modern MinGW version.
#ifdef WIN32
    #ifndef PROTECTION_LEVEL_UNRESTRICTED
        #define PROTECTION_LEVEL_UNRESTRICTED 10
    #endif
    #ifndef IPV6_PROTECTION_LEVEL
        #define IPV6_PROTECTION_LEVEL 23
     #endif
#endif

//CCriticalSection cs_mapLocalHost;

//#define HAVE_DECL_STRNLEN 1;

#endif // CONFIG_NETWORK_H
