# -*- coding: utf-8 -*-
"""
Created on Thu Nov 30 18:02:41 2017

@author: Alex
"""
#reference doc https://pastebin.com/jCDFcESz
# alternative source https://www.reddit.com/r/Bitcoin/comments/7gka3b/evidence_some_bitcoin_address_generation_code_is/?utm_content=comments&utm_medium=hot&utm_source=reddit&utm_name=Bitcoin
import os
os.chdir('C:\\Users\\Alex\\Documents\\Python\\blockexplore')

#section 1 - get all btc addresses since a given time (given by minHeight parameter)
#lookup min andmax heights from blockchain io
import urllib.request, json 
import hashlib,binascii
from base58 import base58
from bitcoin import *
import pandas as pd
#import ecdsa
#import ecdsa.der
#import ecdsa.util
#import hashlib
#import re
#import struct
from pybitcoin import *



minHeight = 496800
maxHeight=496805

##these tell us whether the http requests were rejected. if too many, the API killed our requests
rejectedHashRequests=0
rejectedBlockRequests=0

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
        j+=1



#get list of json files- onefor each block
publicKeys=set() #the actual publickeys
candidatePrivateKeys=set()#hash of the above public kys in WIF format
candidatePrivateKeysRaw=set()#the candidate private keys in raw format
candidatePublicKeys=set() #corresponding public key for the above. If any of these match the publickeys set, the candidateprivatekey is the actual private key

for i in range( 0,len(hashlist)):
    addressList=set() #ensures unique values
    blockhash=hashlist[i]
    try:
        with urllib.request.urlopen("https://blockchain.info/rawblock/"+blockhash) as url:
            data = json.loads(url.read().decode())
        print("block"+str(i)+"retrieved")
    except:
        rejectedBlockRequests+=1
        
        #extract addresses from blocks and append to list
    for z in range (0,len(data["tx"])-1):
        for y in range(0,len(data["tx"][z]["out"])):
            try:
                addressList.add(data["tx"][z]["out"][y]["addr"])
                publicKeys.add(data["tx"][z]["out"][y]["addr"])
            except:
                pass
   
        #hash the public keys and convert to WIF format - these are the candidate private keys             
    for j in range(0,len(list(addressList))):
        rawCandidatePrivateKey=(hashlib.sha256(bytes(list(addressList)[j],"ascii")).hexdigest())
        extendedCandidatePrivateKey="80"+rawCandidatePrivateKey
        first_sha256 = hashlib.sha256(binascii.unhexlify(extendedCandidatePrivateKey)).hexdigest()
        second_sha256 = hashlib.sha256(binascii.unhexlify(first_sha256)).hexdigest()
        # add checksum to end of extended key
        final_key = extendedCandidatePrivateKey+second_sha256[:8]
        candidatePrivateKeysRaw.add(final_key)

        # Wallet Import Format = base 58 encoded final_key
        WIF = base58.b58encode(binascii.unhexlify(final_key))
        candidatePrivateKeys.add(WIF)
    
    

#get public keys from the candidate private keys. if any of these match the original public key list, we havefound a compromised address
#THIS IS FAR TOO SLOW - NEED TO FIND A QUICKER METHOD TO CONVERT PRIVATE TO PUBLIC


import key_tools as key_tools
for i in range(0,len(candidatePrivateKeysRaw)):
   # pub=key_tools.pubKeyToAddr(key_tools.privateKeyToPublicKey(list((candidatePrivateKeys))[i]))
   pub=key_tools.privateKeyToPublicKey(list((candidatePrivateKeys))[i])
   candidatePublicKeys.add(pub)
   print(i)
    
#generate data frame from the keys
d={'public key':list(publicKeys),'candidatePrivateKey':list(candidatePrivateKeys),'candidatePublicKey':list(candidatePublicKeys)}
keys_df = pd.DataFrame(data=d)

#search the candidate public keys column for matching actual public keys

matches=keys_df.loc[keys_df['candidatePublicKey'].isin(list(publicKeys))]

#TODO - save the df to disc and add to it periodically. Open connection with API and monitor trnasactions for matches