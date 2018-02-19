# -*- coding: utf-8 -*-
"""
Created on Thu Nov 30 18:02:41 2017

@author: Alex
"""
#reference doc https://pastebin.com/jCDFcESz
# alternative source https://www.reddit.com/r/Bitcoin/comments/7gka3b/evidence_some_bitcoin_address_generation_code_is/?utm_content=comments&utm_medium=hot&utm_source=reddit&utm_name=Bitcoin
#BLOCKS UP TO AND INCLUDING 21000 HAVE BEEN SAVED IN THE PICKLE FILE

#section 1 - get all btc addresses since a given time (given by minHeight parameter)
#lookup min andmax heights from blockchain io
import urllib.request, json 
import hashlib,binascii
#from base58 import base58
import base58
from bitcoin import *
import pandas as pd
import pickle
import time

time.sleep(7200)


minHeight = 400000
#get current max block height
req1 = urllib.request.Request('https://blockchain.info/q/getblockcount', headers={'User-Agent' : "Magic Browser"})
con1 = urllib.request.urlopen( req1 )
maxHeight = json.loads(con1.read().decode())


##these tell us whether the http requests were rejected. if too many, the API killed our requests
rejectedHashRequests=0
rejectedBlockRequests=0
rejectedHashes=list() #list of rejected blocks (by height)
rejectedBlocks=list()

#list of block hashes
hashlist=list()

#populate hash list
counter=0
for j in range(minHeight,maxHeight):
    url='https://blockexplorer.com/api/block-index/'+str(j)
    try:
        req = urllib.request.Request(url, headers={'User-Agent' : "Magic Browser"})
        con = urllib.request.urlopen( req )
        data = json.loads(con.read().decode())
        block_hash=str(data["blockHash"])
        #print(url.readlines())
        hashlist.append(block_hash)
        print("hash"+str(j)+"retrieved")
        j+=1
    except:
        rejectedHashRequests+=1
        print("hash rejected")
        rejectedHashes.append(j)
        j+=1

#save hashes to disk
with open('hashList', 'wb') as fp:
    pickle.dump(hashlist, fp)
    
with open('rejectedHashes', 'wb') as fp:
    pickle.dump(rejectedHashes, fp)
    
#this will be used as the next maxheight
with open('lastMaxHeight', 'wb') as fp:
    pickle.dump(maxHeight, fp)


#initialise lists
publicKeys=set() #the actual publickeys - set ensures uniqueness. will be converted to list to maintain order
candidatePrivateKeys=list()#hash of the above public keys in WIF
candidatePrivateKeysRaw=list()
candidatePublicKeys=list() #corresponding public key for the above. If any of these match the publickeys set, the candidateprivatekey is the actual private key
rejectedBlocks=list()

#get list of json files- onefor each block
#retrieve blocks and extract addresses
for i in range( 0,len(hashlist)):

    blockhash=hashlist[i]
    try:
        with urllib.request.urlopen("https://blockchain.info/rawblock/"+blockhash) as url:
            data = json.loads(url.read().decode())
        print("block"+str(i)+"retrieved")
    except:
        rejectedBlockRequests+=1
        rejectedBlocks.append(hashlist[i])
        
        #extract addresses from blocks and append to list
    for z in range (0,len(data["tx"])-1):
        for y in range(0,len(data["tx"][z]["out"])):
            try:
                publicKeys.add(data["tx"][z]["out"][y]["addr"])
            except:
                pass
           
    #periodically save to disk
    if i % 1000 ==0:
    
        with open('publicKeys', 'wb') as fp:
            pickle.dump(publicKeys, fp)
            
        with open('rejectedBlocks', 'wb') as fp:
            pickle.dump(rejectedBlocks, fp)
            
        with open('numberBlocksRetrieved', 'wb') as fp:
            pickle.dump(i, fp)
    

    
publicKeys=list(publicKeys)
 #go through the public keys and hash the public keys and convert to WIF format - these are the candidate private keys
for j in range(0,len(publicKeys)):
    try:
        rawCandidatePrivateKey=(hashlib.sha256(bytes(publicKeys[j],"ascii")).hexdigest())
        extendedCandidatePrivateKey="80"+rawCandidatePrivateKey
        first_sha256 = hashlib.sha256(binascii.unhexlify(extendedCandidatePrivateKey)).hexdigest()
        second_sha256 = hashlib.sha256(binascii.unhexlify(first_sha256)).hexdigest()
        # add checksum to end of extended key
        final_key = extendedCandidatePrivateKey+second_sha256[:8]
        candidatePrivateKeysRaw.append(final_key)
        # Wallet Import Format = base 58 encoded final_key
        WIF = base58.b58encode(binascii.unhexlify(final_key))
        candidatePrivateKeys.append(WIF)
    except:
        candidatePrivateKeysRaw.append('could not convert')
        candidatePrivateKeys.append('could not convert')
    if j % 1000 == 0:
            print('public address '+str(j)+' converted')
    

#get public keys from the candidate private keys. if any of these match the original public key list, we havefound a compromised address
for i in range(0,len(candidatePrivateKeys)):
    try:
        pub=pubtoaddr(privtopub(candidatePrivateKeys[i]))
        candidatePublicKeys.append(pub)
        if i % 1000 == 0:
            print('candidate private key number '+str(i)+' converted')
    except:
        candidatePublicKeys.append('private key error')

    
#generate data frame from the keys
d={'public key':publicKeys,'candidatePrivateKey':candidatePrivateKeys,'candidatePublicKey':list(candidatePublicKeys)}
keys_df = pd.DataFrame(data=d)

#save maxblock height here to be loaded in on next iteration as next min blockheight

#search the candidate public keys column for matching actual public keys
#for any matches, the candidate private key is a valid private key
matches=keys_df.loc[keys_df['candidatePublicKey'].isin(publicKeys)]


#TODO -modift the above to automatically update the df with new block - use https://blockchain.info/q/getblockcount to get latest block height and set max height to min
# save the df to disc and add to it periodically. Open connection with API and monitor trnasactions for matches