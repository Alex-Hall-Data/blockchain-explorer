# -*- coding: utf-8 -*-
"""
Created on Sun Feb 18 19:38:59 2018

@author: Alex
"""
import urllib.request, json 
import hashlib,binascii
#from base58 import base58
from base58 import base58
from bitcoin import *
import pandas as pd
import pickle
import re

#number of words to use in each seed and how far to offset start by
seed_length=12
offset=0


#read in dictionary and convert to alphanumeric lowercase
with open('C:\\Users\\Alex\\Documents\\Python\\blockexplore\\dictionaries\\mobydick.txt', 'r') as myfile:
    dictionary_text=myfile.read()
#strip out non alphanumeric
dictionary_text=re.sub(r'\W+', ' ', dictionary_text).lower()
dictionary_text = dictionary_text.split()

#list of seeds from the dictionary
seed_list=list()
i=offset
while(i<len(dictionary_text)):
    term=" ".join(dictionary_text[i:i+11])
    seed_list.append(term)
    i= i+seed_length

#this is the output - any keys added to this list havev a positive balance
non_empty_keys = list()

#go through entire list of seeds and generate pub/priv keys. then check to see if balance present
for j in range(len(seed_list)):
#seed term
    seed = seed_list[j]

    rawCandidatePrivateKey=(hashlib.sha256(bytes(seed,"ascii")).hexdigest())
    extendedCandidatePrivateKey="80"+rawCandidatePrivateKey
    first_sha256 = hashlib.sha256(binascii.unhexlify(extendedCandidatePrivateKey)).hexdigest()
    second_sha256 = hashlib.sha256(binascii.unhexlify(first_sha256)).hexdigest()
    final_key = extendedCandidatePrivateKey+second_sha256[:8]

#outputs - the private and public key from the specified seed
    WIF_private_key = base58.b58encode(binascii.unhexlify(final_key))
    pub=pubtoaddr(privtopub(WIF_private_key))

#to look at the address visit https://blockchain.info/address/pub
    try:
        with urllib.request.urlopen("https://blockchain.info/q/addressbalance/"+pub) as url:
            data = json.loads(url.read().decode())
    except:
        print(j , "rejected by API")

    
    if(data>0):
        print(WIF_private_key)    
        print(pub)
        print("balance" , data)
        non_empty_keys.append(WIF_private_key)
    else:
        print(j , "of" , len(seed_list) , "terms tried")
        
print("the following privat keys have positive balances")        
print(non_empty_keys)