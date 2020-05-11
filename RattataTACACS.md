We are given a pcapng file. There are two things of interest: a TFTP file transfer and a TACAS+ authentication. TFTP is a simpler version of FTP and is commonly used to transfer router configuration information. TACAS+ is an authentication protocol to let users authenticate to servers (think SSH.) TACAS+ packets are encrypted, but since we have the router configuration information, we may be able to find the key to the packets.

I click File > Export Objects > TFTP to find all the files that have been transferred. We see that a file called R1config is transferred three times. Going through it and googling random keywords, we fidn that this is a Cisco configuration file. Moreover, there is one very interesting line in particular:
```
tacacs-server host 192.168.1.100 key 7 0325612F2835701E1D5D3F2033
```
This is the key to the TACAS+ packets. However, the key is encrypted using Cisco type 7 password. Looking online, it seems like this is easily crackable. I used [this](https://www.ifm.net.nz/cookbooks/passwordcracker.html) website to do it, and we get the key to be `ZDNZ1234FED`.

Next, we can simply decrypt all TACAS+ packets. This is very simple to do on Wireshark. I click Edit > Preferences > Protocols > TACAS+ and enter my encryption key. I walk through the packets, and we find that the username of the user is the flag.
