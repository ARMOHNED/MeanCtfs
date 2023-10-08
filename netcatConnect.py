import socket
import time
import pwn
from Crypto.Util.number import  long_to_bytes , bytes_to_long
from secrets import randbelow

result=""
#######
with open("file.txt","r") as f :
    result=f.readline()
##########
list=result.split(",")
word1=list[-1][:-1]
list1=list[1:-1]
list1.append(word1)
researched_primes=[]
###############
def bruteForceprimes(list1):
    base=2
    FLAG=b"BHFLAGY{}"
    testFragment=int.from_bytes(FLAG[0:7], 'big')
    cryptedFragment=int(0x7e147eb53df90e41bb1091726464fc083d64ab85147db7a)
    print(f"cruptedFragment : {cryptedFragment}")
    for word in range(len(list1)):
        result=1
        primes=[]
        for i in range(8):
            index=randbelow(len(list1))
            word=list1[index]
            result=result*int(word)
            primes.append(word)
        print(f"result==>{result}")
        res=pow(base,testFragment,result)
        if(res==cryptedFragment):
            print("success")
            print(primes)
            break

bruteForceprimes(list1)

###############################
def netcat(host,port):
    remote = pwn.remote(host, port)
    text=remote.recvuntil("|  > (int)")
    with open('info.txt',"w") as f :
        f.write(text.decode())
    for word in range(len(list1)):
        index=randbelow(len(list1))
        print(word)
        value=word.encode()
        remote.sendline(value)
        alice_ciphertext =remote.recvuntil(b'\n',timeout=5)
        print(alice_ciphertext)
        length=len(alice_ciphertext)
        result=int(alice_ciphertext.decode().strip()[8:])
        if(result==-7):
            print(f"result==>{result}")
            researched_primes.append(result)
        remote.recvuntil("|  > (int)",timeout=20)
    remote.close()

#netcat("54.78.163.105",30211)
#print(researched_primes)


