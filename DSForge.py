#!/usr/bin/env python
# coding: utf-8

# In[1]:

#Shreyansh Kansara

import hashlib
import rsa
import os
from gmpy2 import mpz, iroot   # For taking the ith root of large numbers


# In[2]:


def to_bytes(n):
    return n.to_bytes((n.bit_length() // 8) + 1, byteorder='big')
    
def from_bytes(n):
    return int.from_bytes(n,byteorder='big')

def get_bit(n, b):
    # Returns bth bit from the least significant bit starting from zero
    return ((1 << b) & n) >> b

def set_bit(n,b):
    # Returns the number after changing bth bit to 1 from least significant bit
    return (1<<b) | n

def cube_root(n):
    # Returns ith Root of Large Numbers
    return int(iroot(mpz(n),3)[0])


# In[3]:


print(cube_root(8))


# In[4]:


message = "My name is Shreyansh!".encode("ASCII")
print(message)
message_hash = hashlib.sha256(message).digest()
print(message_hash)


# In[117]:


ASN1_blob = rsa.pkcs1.HASH_ASN1['SHA-256']
print(ASN1_blob.hex())
suffix = b'\x00' + ASN1_blob + message_hash
print(suffix.hex())


# In[9]:


#This has to be 1 because if the last bit is zero, then it becomes impossible to forge a suffix using this method.
print(get_bit(from_bytes(suffix),0))


# In[10]:


new_sig_suffix=1

for i in range(len(suffix)*8):
    if get_bit(new_sig_suffix**3,i) != get_bit(from_bytes(suffix),i):
        new_sig_suffix=set_bit(new_sig_suffix,i)
        #print(bin(start_sig))


# In[11]:


print(len(to_bytes((new_sig_suffix))))


# In[121]:


print(to_bytes(new_sig_suffix**3).hex())


# In[12]:


print(to_bytes((new_sig_suffix)**3).endswith(suffix))


# In[115]:


while True:
    # os.urandom for getting Random Bytes of specific length suitable for cryptography
    new_sig_prefix=b'\x00\x01'+os.urandom(2048//8 - 2)
   
    
    # Generating Prefix and taking the prefix upto the length of suffix
    
    new_sig_prefix=to_bytes(cube_root(from_bytes(new_sig_prefix)))[:-len(suffix)]
    #print(len(to_bytes(from_bytes(new_sig_prefix)**3)))
    
    new_sig=new_sig_prefix+to_bytes(new_sig_suffix)
    
    # We want length to be 85, because 256/3 is almost 85.
    if len(new_sig) > 85:
        new_sig=new_sig_prefix[:-(len(new_sig)-85)]+to_bytes(new_sig_suffix)
    elif len(new_sig) < 85:
        new_sig=new_sig_prefix+'\xFF'*(85-len(new_sig))+to_bytes(new_sig_suffix)
    else:
        new_sig=new_sig_prefix+to_bytes(new_sig_suffix)
        
    #There should be no \x00 in the cube of the signature otherwise verify function will fail 
    if b'\x00' not in to_bytes(from_bytes(new_sig)**3)[2:-len(suffix)]:
        print(new_sig.hex())
        #print(len(to_bytes(from_bytes(new_sig)**3)))
        break


# In[113]:


#Hex value of the signature seen on the victim side after decryption i.e. sig**3
print(to_bytes(from_bytes(new_sig)**3).hex())


# In[77]:


# Generating new Keys
key=rsa.newkeys(2048)[0]


# In[78]:


# Changing public key component to 3
key.e=3


# In[109]:


print(key)


# In[80]:


print(rsa.verify(message,new_sig,key))

