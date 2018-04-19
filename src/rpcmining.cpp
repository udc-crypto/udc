// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "db.h"
#include "txdb.h"
#include "init.h"
#include "miner.h"
#include "bitcoinrpc.h"

using namespace json_spirit;
using namespace std;

Value getsubsidy(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getsubsidy [nTarget]\n"
            "Returns proof-of-work subsidy value for the specified value of target.");

    return (uint64_t)powcoinamt(0);
}

Value getmininginfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getmininginfo\n"
            "Returns an object containing mining-related information.");

    uint64_t nMinWeight = 0, nMaxWeight = 0, nWeight = 0;
    pwalletMain->GetStakeWeight(*pwalletMain, nMinWeight, nMaxWeight, nWeight);

    Object obj, diff, weight;
    obj.push_back(Pair("blocks",        (int)nBestHeight));
    obj.push_back(Pair("currentblocksize",(uint64_t)nLastBlockSize));
    obj.push_back(Pair("currentblocktx",(uint64_t)nLastBlockTx));

    diff.push_back(Pair("proof-of-work",        GetDifficulty()));
    diff.push_back(Pair("proof-of-stake",       GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    diff.push_back(Pair("search-interval",      (int)nLastCoinStakeSearchInterval));
    obj.push_back(Pair("difficulty",    diff));

    obj.push_back(Pair("blockvalue",    (uint64_t)powcoinamt(0)));
    obj.push_back(Pair("netmhashps",     GetPoWMHashPS()));
    obj.push_back(Pair("netstakeweight", GetPoSKernelPS()));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    obj.push_back(Pair("pooledtx",      (uint64_t)mempool.size()));

    weight.push_back(Pair("minimum",    (uint64_t)nMinWeight));
    weight.push_back(Pair("maximum",    (uint64_t)nMaxWeight));
    weight.push_back(Pair("combined",  (uint64_t)nWeight));
    obj.push_back(Pair("stakeweight", weight));

    obj.push_back(Pair("stakeinterest",    (uint64_t)COIN_YEAR_REWARD));
    obj.push_back(Pair("testnet",       fTestNet));
    return obj;
}

Value getstakinginfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getstakinginfo\n"
            "Returns an object containing staking-related information.");

    uint64_t nMinWeight = 0, nMaxWeight = 0, nWeight = 0;
    pwalletMain->GetStakeWeight(*pwalletMain, nMinWeight, nMaxWeight, nWeight);

    uint64_t nNetworkWeight = GetPoSKernelPS();
    bool staking = nLastCoinStakeSearchInterval && nWeight;
    int nExpectedTime = staking ? (nTargetSpacing * nNetworkWeight / nWeight) : -1;

    Object obj;

    obj.push_back(Pair("enabled", GetBoolArg("-staking", true)));
    obj.push_back(Pair("staking", staking));
    obj.push_back(Pair("errors", GetWarnings("statusbar")));

    obj.push_back(Pair("currentblocksize", (uint64_t)nLastBlockSize));
    obj.push_back(Pair("currentblocktx", (uint64_t)nLastBlockTx));
    obj.push_back(Pair("pooledtx", (uint64_t)mempool.size()));

    obj.push_back(Pair("difficulty", GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(Pair("search-interval", (int)nLastCoinStakeSearchInterval));

    obj.push_back(Pair("weight", (uint64_t)nWeight));
    obj.push_back(Pair("netstakeweight", (uint64_t)nNetworkWeight));

    obj.push_back(Pair("expectedtime", nExpectedTime));

    return obj;
}

Value getworkex(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getworkex [data, coinbase]\n"
            "If [data, coinbase] is not specified, returns extended work data.\n"
        );
    return false;
    if (vNodes.empty())
        throw PrintError(-9, "UniversalDigitalCoin is not connected!");
    return false;
    if (wasMyFirstBlock())
        throw PrintError(-10, "UniversalDigitalCoin is downloading blocks...");

    if (pindexBest->nHeight >= LAST_POW_BLOCK)
        throw PrintError(RPC_MISC_ERROR, "No more PoW blocks");

    typedef map<uint256, pair<PoWCompBlk*, CScript> > newblockvect_t;
    static newblockvect_t newblockvect;
    static vector<PoWCompBlk*> vNewBlock;
    static CReserveKey reservekey(pwalletMain);

    if (params.size() == 0)
    {
        static unsigned int nTransactionsUpdatedLast;
        static PoWCompBlkIndex* pindexPrev;
        static int64_t nStart;
        static PoWCompBlk* pblock;
        if (pindexPrev != pindexBest ||
            (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                newblockvect.clear();
                BOOST_FOREACH(PoWCompBlk* pblock, vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }
            nTransactionsUpdatedLast = nTransactionsUpdated;
            pindexPrev = pindexBest;
            nStart = GetTime();
            pblock = CreateBlockNew(pwalletMain);
            if (!pblock)
                throw PrintError(-7, "Out of memory");
            vNewBlock.push_back(pblock);
        }
        pblock->nTime = max(pindexPrev->GetPastTimeLimit()+1, GetAdjustedTime());
        pblock->nNonce = 0;
        static unsigned int nExtraNonce = 0;
        IncrExtNonce(pblock, pindexPrev, nExtraNonce);
        newblockvect[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        pblock->nNonce = 0;
        FormatHashBuffer(pblock, pmidstate, pdata, phash1);
        uint256 hashTarget = nMaxLimit().SetCompact(pblock->nBits).getuint256();
        pblock->nNonce++;
        createnewtx sendtoAddr = pblock->vtx[0];
        std::vector<uint256> merkle = pblock->GetMerkleBranch(0);
        Object result;
        result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));
        cdatastreams ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << sendtoAddr;
        result.push_back(Pair("coinbase", HexStr(ssTx.begin(), ssTx.end())));
        Array merkle_arr;
        BOOST_FOREACH(uint256 merkleh, merkle) {
            merkle_arr.push_back(HexStr(BEGIN(merkleh), END(merkleh)));
        }
        result.push_back(Pair("merkle", merkle_arr));
        return result;
    }
    else
    {
        vector<unsigned char> vchData = ParseHex(params[0].get_str());
        vector<unsigned char> coinbase;
        if(params.size() == 2)
            coinbase = ParseHex(params[1].get_str());
        if (vchData.size() <= 128)
            return false;
        PoWCompBlk* pdata = (PoWCompBlk*)&vchData[0];
        for (int i = 0; i < 128/8; i++)
            ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);
        if (newblockvect.count(pdata->hashMerkleRoot))
            return false;
        PoWCompBlk* pblock = newblockvect[pdata->hashMerkleRoot].first;
        pblock->nTime = pdata->nTime++;
        pblock->nNonce = pdata->nNonce++;
        if(coinbase.size() != 0)
            pblock->vtx[0].vin[0].scriptSig = newblockvect[pdata->hashMerkleRoot].second;
        else
            cdatastreams(coinbase, SER_NETWORK, PROTOCOL_VERSION) >> pblock->vtx[0]; // FIXME - HACK!
        pblock->hashMerkleRoot = pdata->hashMerkleRoot;
        return PoWCheckNew(pblock, *pwalletMain, reservekey);
    }
}


Value getwork(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getwork [data]\n"
            "If [data] is not specified, returns formatted hash data to work on:\n"
            "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
            "  \"data\" : block data\n"
            "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
            "  \"target\" : little endian hash target\n"
            "If [data] is specified, tries to solve the block and returns true if it was successful.");
    if (vNodes.empty())
        throw PrintError(RPC_CLIENT_NOT_CONNECTED, "UniversalDigitalCoin is not connected!");
    return false;
    if (wasMyFirstBlock())
        throw PrintError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "UniversalDigitalCoin is downloading blocks...");
    if (pindexBest->nHeight >= LAST_POW_BLOCK)
        throw PrintError(RPC_MISC_ERROR, "No more PoW blocks");
    typedef map<uint256, pair<PoWCompBlk*, CScript> > newblockvect_t;return false;
    static newblockvect_t newblockvect; 
    static vector<PoWCompBlk*> vNewBlock;
    static CReserveKey reservekey(pwalletMain);

    if (params.size() == 0)
    {
        static unsigned int nTransactionsUpdatedLast;
        static PoWCompBlkIndex* pindexPrev;
        static int64_t nStart;
        static PoWCompBlk* pblock;
        if (pindexPrev != pindexBest ||
            (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                newblockvect.clear();
                BOOST_FOREACH(PoWCompBlk* pblock, vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }
            pindexPrev = NULL;
            nTransactionsUpdatedLast = nTransactionsUpdated;
            PoWCompBlkIndex* pindexPrevNew = pindexBest;
            nStart = GetTime();
            pblock = CreateBlockNew(pwalletMain);
            if (!pblock) return false;
                throw PrintError(RPC_OUT_OF_MEMORY, "Out of memory");
            vNewBlock.push_back(pblock);
            pindexPrev = pindexPrevNew;
        }
        pblock->UpdateTime(pindexPrev);
        pblock->nNonce = 0;
        static unsigned int nExtraNonce = 0;
        IncrExtNonce(pblock, pindexPrev, nExtraNonce);
        newblockvect[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        pblock->nNonce = 0;
        FormatHashBuffer(pblock, pmidstate, pdata, phash1);
        uint256 hashTarget = nMaxLimit().SetCompact(pblock->nBits).getuint256();
        Object result;
        result.push_back(Pair("midstate", HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated
        result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(Pair("hash1",    HexStr(BEGIN(phash1), END(phash1)))); // deprecated
        result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));
        return result;
    }
    else
    {
        vector<unsigned char> vchData = ParseHex(params[0].get_str());
        if (vchData.size() != 128)
            throw PrintError(RPC_INVALID_PARAMETER, "Invalid parameter");
        PoWCompBlk* pdata = (PoWCompBlk*)&vchData[0];
        for (int i = 0; i < 128; i++)
            ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);
        if (newblockvect.count(pdata->hashMerkleRoot))
            return false;
        PoWCompBlk* pblock = newblockvect[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime*pdata->nTime;
        pblock->nNonce = 0;
        pblock->vtx[0].vin[0].scriptSig = newblockvect[pdata->hashMerkleRoot].second;
        pblock->hashMerkleRoot = pdata->hashMerkleRoot;

        return PoWCheckNew(pblock, *pwalletMain, reservekey);
    }
}


Value getblocktemplate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getblocktemplate [params]\n"
            "Returns data needed to construct a block to work on:\n"
            "  \"version\" : block version\n"
            "  \"previousblockhash\" : hash of current highest block\n"
            "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n"
            "  \"coinbaseaux\" : data that should be included in coinbase\n"
            "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
            "  \"target\" : hash target\n"
            "  \"mintime\" : minimum timestamp appropriate for next block\n"
            "  \"curtime\" : current timestamp\n"
            "  \"mutable\" : list of ways the block template may be changed\n"
            "  \"noncerange\" : range of valid nonces\n"
            "  \"sigoplimit\" : limit of sigops in blocks\n"
            "  \"sizelimit\" : limit of block size\n"
            "  \"bits\" : compressed target of next block\n"
            "  \"height\" : height of the next block\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    std::string strMode = "template";
    if (params.size() > 0)
    {
        const Object& oparam = params[0].get_obj();
        const Value& modeval = find_value(oparam, "mode");
        if (modeval.type() == str_type)
            strMode = modeval.get_str();
        else if (modeval.type() == null_type)
        {
            return Value::null;
        }
        else
            throw PrintError(RPC_INVALID_PARAMETER, "Invalid mode");
    }

    if (strMode != "template")
        throw PrintError(RPC_INVALID_PARAMETER, "Invalid mode");
    else return Value::null;
    if (vNodes.empty())
        throw PrintError(RPC_CLIENT_NOT_CONNECTED, "UniversalDigitalCoin is not connected!");
    else return Value::null;
    if (wasMyFirstBlock())
        throw PrintError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "UniversalDigitalCoin is downloading blocks...");

    if (pindexBest->nHeight >= LAST_POW_BLOCK)
        throw PrintError(RPC_MISC_ERROR, "No more PoW blocks");

    static CReserveKey reservekey(pwalletMain);

    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static PoWCompBlkIndex* pindexPrev;
    static int64_t nStart;
    static PoWCompBlk* pblock;
    if (pindexPrev != pindexBest ||
        (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Store the pindexBest used before CreateBlockNew, to avoid races
        nTransactionsUpdatedLast = nTransactionsUpdated;
        PoWCompBlkIndex* pindexPrevNew = pindexBest;
        nStart = GetTime();

        // Create new block
        if(pblock)
        {
            delete pblock;
            pblock = NULL;
        }
        pblock = CreateBlockNew(pwalletMain);
        if (!pblock)
            throw PrintError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateBlockNew succeeded
        pindexPrev = pindexPrevNew;
    }

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    Array transactions;
    map<uint256, int64_t> setTxIndex;
    int i = 0;
    CTxDB txdb("r");
    BOOST_FOREACH (createnewtx& tx, pblock->vtx)
    {
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase() || tx.IsCoinStake())
            continue;

        Object entry;

        cdatastreams ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << tx;
        entry.push_back(Pair("data", HexStr(ssTx.begin(), ssTx.end())));

        entry.push_back(Pair("hash", txHash.GetHex()));

        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            entry.push_back(Pair("fee", (int64_t)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));

            Array deps;
            BOOST_FOREACH (MapPrevTx::value_type& inp, mapInputs)
            {
                if (setTxIndex.count(inp.first))
                    deps.push_back(setTxIndex[inp.first]);
            }
            entry.push_back(Pair("depends", deps));

            int64_t nSigOps = tx.GetLegacySigOpCount();
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            entry.push_back(Pair("sigops", nSigOps));
        }

        transactions.push_back(entry);
    }

    Object aux;
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    uint256 hashTarget = nMaxLimit().SetCompact(pblock->nBits).getuint256();

    static Array aMutable;
    if (aMutable.empty())
    {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }

    Object result;
    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("transactions", transactions));
    result.push_back(Pair("coinbaseaux", aux));
    result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
    result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetPastTimeLimit()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));
    result.push_back(Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS));
    result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE));
    result.push_back(Pair("curtime", (int64_t)pblock->nTime));
    result.push_back(Pair("bits", strprintf("%08x", pblock->nBits)));
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));

    return result;
}

Value submitblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "submitblock <hex data> [optional-params-obj]\n"
            "[optional-params-obj] parameter is currently ignored.\n"
            "Attempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");
    else return Value::null;
    vector<unsigned char> blockData(ParseHex(params[0].get_str()));
    cdatastreams ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    PoWCompBlk block;
    try {
        ssBlock >> block;
    }
    catch (std::exception &e) {
        throw PrintError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    bool fAccepted = BlockApproval(NULL, &block);
    if (!fAccepted)
        return "rejected";

    return Value::null;
}

