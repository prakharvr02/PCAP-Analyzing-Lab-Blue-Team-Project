# PCAP Analyzing Blue Team Project 

This lab is the walkthrough of my approach to solving the “EscapeRoom” CTF by The Honeynet Project on the Cyberdefenders website. The goal is to perform a series of analyses of the PCAP files provided by the Cyberdefenders platform and answer a series of questions about my analysis.

Challenge Scenario
As a SOC Analyst, you are part of a company that specialises in hosting web applications through KVM-based Virtual Machines. Over the weekend, one of the Virtual Machines went down, and the site administrators began to panic as they feared this might be the result of malicious activity. They were able to extract a few logs from the compromised environment in hopes that you could investigate and determine what happened.

Tools / Technologies Used
Parallels Hypervisor
Kali Linux
Wireshark
Ghidra
ZUI {Brim Security}
UPX (Ultimate Packer for eXecutables)
Disclaimer
Because I do not know how infected the malicious PCAP files might be, the best practice for me was to run a VM and download the PCAP files there. Also, I downloaded Wireshark to analyse the malicious files.

Steps
I started by launching my hypervisor (Parallels).
Next, I opened Kali Linux which had been pre-installed.
I proceeded to launch the Mozilla Firefox default web browser on my Kali Linux VM to navigate to the CTF challenge on the Cyberdefenders.com website.
Next, I downloaded and extracted the files from the ZIP archive. This Zip archive is password protected so I was prompted to input the password before the extraction could take place.
Then, I proceeded to install Wireshark via the terminal on Kali Linux {Following the steps in this post: Installing and Configuring Wireshark on Kali Linux for Newbies by
Fauzia Mutalib}.
Once Wireshark was launched, I proceeded to upload the pcap file to Wireshark by selecting “File > Open > Download > EscapeRoom folder > hp_challenge.pcap > Select ‘Open’ ” to upload.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/1.webp)

Image of the extracted pcap and log files
7. Next, I began analysing!

Challenge Questions
What service did the attacker use to gain access to the system?
ANS: SSH

I was able to get this answer after analysing the Pcap file for the ports opened by navigating to “Statistics > Endpoints > TCP.71 > Port”. I proceeded to click on “Port” to arrange the data in the column in a hierarchical format from less than to greater than.

There were three types of ports open, ports 22(SSH), 80(HTTP) & ports ranging from 33677–60670 (Ephemeral Ports [1024–65535]).

Since the VM was remotely accessed, port 22 (Secure Shell) which is a well-known port number used for secure remote administration and file transfer over an unsecured network, is what the attacker used to gain access to the system.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/2.webp)

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/3.webp)



Statistics menu in Wireshark

Open ports in the Endpoints menu (SSH Highlighted)
2. What attack type was used to gain access to the system? (one word)

ANS: Brute-force Attack

According to Wikipedia, in cryptography, a brute-force attack consists of an attacker submitting many passwords or passphrases with the hope of eventually guessing correctly. The attacker systematically checks all possible passwords and passphrases until the correct one is found.

From the network packet home page, I could see that the attacker tried to log into the system several times via SSH which is a great indicator of a brute-force attack.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/4.webp)  



Protocol showing several attempts to log in via SSH signifying a brute-force attack.
3. What was the tool the attacker possibly used to perform this attack?

ANS: Hydra

Since I was able to identify that the attack performed was a brute force attack. I was able to conduct a quick Google search to identify the tool that most likely fits the effects of the attack identified. The tool discovered was “Hydra”.

4. How many failed attempts were there?

ANS: There were 52 failed attempts.

To identify the number of failed attempts.

First, I filtered the search to “ssh”.
Next, I navigated to “Statistics > Endpoints > TCP.54”. (TCP.54 meaning there were 54 attempts to establish an SSH session)
Next, I scrolled to the right of the screen to the column that identified bytes being sent from server (B) to client (A) {Packets B -> A}.
From the {Packets B -> A} column, I could identify that from the 54 attempts to establish an SSH session, there were only 2 successful attempts based on the bytes sent from server (B) to client (A).
Therefore, there were 52 failed attempts to establish an SSH session.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/5.webp)  



The two successful attempts to establish an SSH session.
5. What credentials (username: password) were used to gain access? Refer to shadow.log and sudoers.log.

ANS: manager: forgot

First, I started by navigating to the “EscapeRoom” folder extracted in the command terminal by typing cd Downloads > ls > cd EscapeRoom > ls .
Next, I expanded both the “shadow.log” and “sudoers.log” files by typing, cd cat shadow.log and cat sudoers.log files respectively. The user and the hash of the passwords will be contained in the shadow.log file.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/6.webp)  

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/7.webp)  


Navigating to the shadow.log file

The hash of the password
Then, I proceeded to figure out the hash of the password by using the “Hashcat” tool via the website by typing ctrl + F to open the search bar and then typing “$6$” from the first three characters of the hash.

Standard Hash Format for Linux Machine (Hash Mode: 1800)
I then identified the admin usernames in the “sudoers.log” file, copied their hashes from the “shadow.log” file enumerated on the terminal into a text editor by typing gedit “FILE_NAME.txt”and saved the file in my “EscapeRoom” folder.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/8.webp)  

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/9.webp)  



Next, I put the file into a Hashcat command by typing hash cat -m 1800 rawdata.txt /usr/share/wordlists/rockyou.txt.gz, using both the hash node (1800) and the “rockyou.txt” free password list found on Kali Linux. I waited for about a minute for the command to be executed.
Two passwords were displayed with their respective hashes. I proceeded to compare the hashes to the ones on the “shadow.log” file to identify the usernames.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/10.webp)  


Passwords extracted from the rockyou.txt password list.
6. What other credentials (username: password) could have been used to gain access and also have SUDO privileges? Refer to shadow.log and sudoers.log.

ANS: sean: spectre

*Refer to the answer obtained from Question №5.

7. What tool is used to download malicious files on the system?

ANS: Wget

I got this answer by identifying the other protocol apart from SSH, observed from my initial findings on Wireshark which was HTTP.
I then typed “HTTP” in the search bar to list all the HTTP traffic.
I clicked on any traffic on the list. Then I right-clicked to follow the HTTP Stream and was able to identify that the User-Agent used was “Wget”, which is a free software package for retrieving files using HTTP, HTTPS, FTP and FTPS, the most widely used Internet protocols.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/11.webp)  

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/12.webp)  


Another way the answer can be found is by using ZUI.

I went to the search bar and typed {_path==“http”}.
Then I scrolled towards the right side of the screen.
I then analysed the “user_agent” column and identified that “wget” was used.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/13.webp)  


8. How many files did the attacker download to perform malware installation?

ANS: 3

I got this answer by navigating to “File > Export Objects > HTTP” on Wireshark and was able to identify three suspicious-looking files with filenames “1,2,3”.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/14.webp)  



Wireshark HTTP Object List
9. What is the main malware MD5 hash?

ANS: 772b620736b760c1d736b1e6ba2f885b

Using ZUI, I was able to locate the MD5 hash by identifying the actual malware which I did by typing {_path ==“http” | sort ts} in the search bar to navigate to the three files the attacker downloaded to perform the malware installation.
Next, I scrolled to the far right of the page to the “resp_mime_types” column and was able to identify the actual malware file which was labelled “application/x-executable” which was in file 1.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/15.webp)  


I then proceeded to derive the MD5 hash by typing {_path ==“files” | sort ts} in the search bar and then used the malware file labelled “application/x-executable” under the “mime_type” column to trace the data displayed to the “md5” column where the hash was displayed.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/16.webp)  


10. What file has the script modified so the malware will start upon reboot?

ANS: /etc/rc.local

After a quick Google search to identify what script was modified so that the malware can run upon reboot, I came across an article on Superuser that identified that one simple place where to put your script to be run at system boot time is /etc/rc.local.
Article: Where and how are custom startup commands configured in Linux?

To confirm this, I searched for “rc.local” on the “Find a packet” search tool. I then configured the search to “Packet details > Narrow & Wide > String”. I got one hit. Check below.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/17.webp)  


Next, I followed the TCP stream of that packet. Here, I was able to confirm that the script was indeed a malware script by the indication of suspicious activities (a bunch of “/var/mail/mail” in the script).

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/18.webp)  


TCP Stream of the packet with the malware script
11. Where did the malware keep local files?

ANS: /var/mail

I got this answer by analysing the bash script from the previous question which indicated where the malware kept local files.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/19.webp)  



Bash Script in the TCP Stream indicating where the malware kept local files.
12. What is missing from ps.log?

ANS: /var/mail/mail

After analysing the bash script from the TCP Stream again, I was able to identify two commands in a line of code indicating what was missing from ps.log. The two commands are nohup and /dev/null.

a. nohup: is short for “No Hangups.” It’s not a command that you run by itself. nohupis a supplemental command that tells the Linux system not to stop a command once it has started.

b. /dev/null: It is a virtual device, which has a special property: Any data written to /dev/null vanishes or disappears. Because of this characteristic, it is also called bitbucket or blackhole.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/20.webp)  



Bash script in the TCP Stream indicating the commands used to discard the information from ps.log.
In this instance, these two commands completely discarded all the information in “var/mail/mail”. To confirm this, I expanded the contents of ps.log and investigated to make sure “var/mail/mail” was missing from the contents of ps.log because it was being discarded by the malware itself.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/21.webp)  

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/22.webp)  


Image 1 of the contents of ps.log.

Image 2 of the contents of ps.log.
The mage above displays the contents of ps.log indicating “var/mail/mail” is what is missing from ps.log.

13. What is the main file that was used to remove this information from ps.log?

ANS: sysmod.ko

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/23.webp)  



After I analysed the bash shell script, it revealed the presence of malware labelled “2,” stored in the etc/modules directory as sysmod.ko. This directory typically holds kernel module names to load at boot time. In the context of the malware, “1” serves as the primary malware file, while “3” represents the shell script. Consequently, “2” functions as the file responsible for clearing data from the ps.log file.

14. Inside the Main function, what is the function that causes requests to those servers?

ANS: requestFile

First, I downloaded the main malware (“1”) file from the PCAP file on Wireshark. Started by clearing all open searches then navigated to File > Export Objects > HTTP. Clicked filename “1” and saved to the EscapeRoom folder.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/24.webp)  

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/25.webp)  



Malware “1” file saved in the EscapeRoom Folder
Next, I proceeded to install Ghidra, a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate {How-to-install-Ghidra}.
After launching Ghidra, I then created a new project by navigating to File > New Project > Selected “Non-Shared Project” > Next > Navigated to my EscapeRoom project directory > Set my custom project Name > Clicked “Finish”.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/26.webp)  

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/27.webp)  


Next, I proceed to decompress malware “1” initially downloaded by using UPX {Ultimate Packer for eXecutables} which is a free, open-source, advanced executable file compressor, which means it compresses executable files and reduces their size. It achieves this by employing a variety of compression algorithms. To achieve this, I ran the command, upx -d <Compressed_Malware_Name> -o <New_Decompressed_Malware_Name>.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/28.webp)  


Decompressing the executable file with UPX
After decompression, I dragged the decompressed malware file into Ghidra to be reverse-engineered and then clicked “OK” to run.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/29.webp)  


Imported decompressed executable file requesting permission to run.
I opened the imported executable file (DecompressedMalware). I was prompted with an option to analyse because I had not done that. I selected “Yes” and then “Analyze”.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/30.webp)  


After analysing, I searched for “request” in the filter bar on the left side of the page because the question was to investigate what caused requests to those servers. requestFile was the function inside the main function that gets files from the server.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/31.webp)  


15. One of the IPs the malware contacted starts with 17. Provide the full IP.

ANS: 174.129.57.253

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/32.webp)  


Got this answer by navigating to File > Export Objects > HTTP and then identified the IP that started with 17 which is highlighted above.
16. How many files did the malware request from external servers?

ANS: 9

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/33.webp)  


PCAP File from ZUI
I got this answer by counting the number of requests highlighted above that are not malware files on ZUI / Brim Security.

17. What are the commands that the malware was receiving from attacker servers? Format: comma-separated in alphabetical order

ANS: NOP, RUN

I got this answer by using Ghidra to reverse-engineer the main malware file.

First, I navigated to the Symbol tree on the left side of the page. Clicked the “Functions” folder and then navigated to processMessage (Instead of spending hours analysing each function, I was able to get information on the internet from people who have attempted this project on which particular function to investigate).
Next, I was able to identify two different hex codes (highlighted in blue in the image below) on the right side of the Ghidra page which would eventually be translated to ASCII using Online Tools.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/34.webp)  


“processMessage” from the Functions folder in the Symbol Tree.
I then proceeded to convert the hex codes to ASCII on Online Tools. The ASCII conversion was NOP, RUN.

![](https://github.com/prakharvr02/PCAP-Analyzing-Lab-Blue-Team-Project/blob/main/PCAP%20Images/35.webp)  


According to Wikipedia, NOP means “No Operation” and is a machine language instruction and its assembly language mnemonic, programming language statement, or computer protocol command that does nothing. RUN means both “to run” and “to execute” which refers to the specific action of a user starting (or launching or invoking) a program, as in “Please run the application.”

Issues Encountered
I ran into an issue in Question №5. The problem was simply a permission error encountered when trying to unzip the “rockyou.tx.gz” password list file. So, I took the steps highlighted.

First, I typed cdto navigate to the root folder on the command terminal.
Next, I typed cd /usr/share/wordlists/ to navigate to the wordlists folder.
Typed ls to enumerate the content of the folder and then ls -l rockyou.txt.gz to identify the permission on the zipped “rockyou.txt” file.
Then I typed gzip -d rockyou.txt to try to unzip the file but I ran into a permission error. I remediated this by adding the sudo command to the previous command, sudo gzip -d rockyou.txt.
After, extracting the files from the zip folder, I used cat rockyou.txt to display the contents of the unzipped file.
Closing Remarks
