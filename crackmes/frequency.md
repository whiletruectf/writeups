### [ZED-Frequency](https://crackmes.one/crackme/5ed17e1633c5d449d91ae68e)

# slopey | 6/11/2020

We are given a binary which asks us for an input and then outputs the key. Inside the binary, we find that if they key is `01234567890123456789012345`, we pass. I use Ghidra for static analysis. The equivalent python code looks roughly like this:

```python
import sys
import string

arr = [0 for _ in range(26)]
with open(sys.argv[1], "r") as f:
    for c in f.read():
        if c in string.ascii_lowercase:
            arr[string.ascii_lowercase.index(c)] += 1
arr = "".join(arr)
print(arr)
if arr == "01234567890123456789012345":
    print("correct")
```

Basically, the key generated is a frequency table for each letter of the alphabet, where the ith number represents how many times the ith letter of the alphabet appears in the input file. So we can write a quick solver script:

```python
from string import ascii_lowercase

freq = "01234567890123456789012345"
freq_table = {k: int(v) for k, v in zip(ascii_lowercase, freq)}
with open("flag.txt", "w") as f:
    for k in freq_table:
        for _ in range(freq_table[k]):
            f.write(k)

```

And we get the following output:

```
bccdddeeeefffffgggggghhhhhhhiiiiiiiijjjjjjjjjlmmnnnoooopppppqqqqqqrrrrrrrsssssssstttttttttvwwxxxyyyyzzzzz
```

Passing this to the binary, we get the success message.


