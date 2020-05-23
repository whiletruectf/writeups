# Andry
## slopey | 5/22/2020

We are given an Android app. I used [Appetize](https://appetize.io) to run the Android app on my browser. There's nothing complicated about the app. It looks like a simple keygen problem. However, it turned out it was much more nuanced than that. I decompile the APK using [Java Decompilers](http://www.javadecompilers.com/). 

The main logic for checking the password is in `/sources/com/andry/MainActivity.java`. The `check_password` function is the function of interest. Here is the first snippet:
```java
...
String input = ((EditText) findViewById(C0046R.C0048id.editPassword1)).getText().toString();
Integer count = Integer.valueOf(0);
Integer valueOf = Integer.valueOf(0);
ListIterator<String> it = splitBySize(input, 2).listIterator();
while (it.hasNext()) {
    Integer index = Integer.valueOf(it.nextIndex());
    int d = Integer.parseInt((String) it.next(), 16);
...
```
- Line 1 takes the password entered into the form and converts it into a string.
- Line 4 takes the password and splits it into blocks of two. So "deadbeef" becomes "de, ad, be, ef."
- Line 5 iterates over every block in the input.
- The last line converts the block to hexadecimal.

From this information, we now know that the password input expects a hex string. Now let's take a look at how the application validates the password.
```java
switch (index.intValue() + 1) {
    case 1:
        if (mo2c1(d) != 6326) {
            break;
        } else {
            count = Integer.valueOf(count.intValue() + 1);
            break;
        }
...
```
There are 32 total cases. The index is switched. Basicaly each case follows a format like this: `checkI(I) == constant`. `MainActivity.java` uses JNI. We can see the system call in this snippet:
```java
static {
    System.loadLibrary("andry-lib");
}
```
The TL;DR of this code is that it calls a shared library file that has already been compiled. I find the shared library file in `resources/lib`. There are many differend shared library files for different architectures. I chose to analyze the x86_64 version because I am most familiar with it. I find an so file called libandry-lib.so. 

Opening up Ghidra, I find 32 different checks, each one for every byte in the 32 byte key. This part of the challenge was very tedious. You can find the code I used to solve it [here](andry.py). I had to manually decompile 32 of these checks.

I get the key to be `48bb6e862e54f2a795ffc4e541caed4d0bf985de4d3d7c5df73cf960638b4bf2`. If you enter this password into the app, it will crash. This can be explained by these two functions in `DynamicLoaderService.java`:
```java
private void handleActionFoo(String password_key) {
    try {
        byte[] byteArray = IOUtils.toByteArray(getApplicationContext().getAssets().open("enc_payload"));
        XORDecrypt(byteArray, password_key);
        String response = DynamicDecode(byteArray, "decrypt", "EASYPEASY");
        StringBuilder sb = new StringBuilder();
        sb.append("ptm{");
        sb.append(response);
        sb.append("}");
        Log.i("FLAG: ", sb.toString());
    } catch (IOException e) {
        e.printStackTrace();
    }
}

private void XORDecrypt(byte[] data, String key) {
    throw new UnsupportedOperationException("NOT IMPLEMENTED YET! PURE GUESSING!");
}

private String DynamicDecode(byte[] callCode, String method, String decode_key) {
    throw new UnsupportedOperationException("NOT IMPLEMENTED YET! PURE GUESSING!");
}
```
In `MainActivity.java`, basically this code is run when the password is successful. But as you can see, the `handleActionFoo` function calls code that will throw an error. We are supposed to guess how the functions were implemented. 

`XORDecrypt` is easy to guess. We see that the encrypted data is stored in `resources/assets/enc_payload`. Again, you can see my code [here](andry.py). However, after decryption, I get a bunch of gibberish. This is the only readable output I get:
```
<init>CCIILLCLInner;LLLLLLjava/lang/Object;Ljava/lang/String;Ljava/lang/StringBuilder;NUKRPFUFALOXYLJUDYRDJMXHMWQWVappendcharAtdecryptencryptkeeplengttoString
```
Most likely, this is an executable. I go [here](https://en.wikipedia.org/wiki/List_of_file_signatures) and search up the first few bytes of the output, and I find that it is a Dalvik executable. Honestly, I have no idea what this is. After doing some research, I figure out I can convert it to a jar file. I output the file and use [this](https://github.com/pxb1988/dex2jar) toolchain to convert the Dalvik executable to a jar file. Then, I go back to [Java Decompilers](http://www.javadecompilers.com/) to decompile the jar file. Finally, we get an `Inner` class and inside there is this function:
```java
public static String decrypt(final String s) {
    int index = 0;
    final String upperCase = "NUKRPFUFALOXYLJUDYRDJMXHMWQW".toUpperCase();
    String string = "";
    for (int i = 0; i < upperCase.length(); ++i) {
        string += (char)((upperCase.charAt(i) - s.charAt(index) + 26) % 26 + 65);
        index = (index + 1) % s.length();
    }
    return string;
}
```
We go back to `DynamicLoaderService.java` and find the key is "EASYPEASY". After using that function to decrypt "EASYPEASY", we get the flag.
```
ptm{JUSTABUNCHOFAWFULANDROIDMESS}
```
