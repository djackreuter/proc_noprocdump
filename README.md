# proc_noprocdump

Dump LSASS by spoofing command line arguments to _procdump_. Copies LSASS dump file created by procdump as it's written and saves it to an Rc4 encrypted file. Works on fully updated Windows 10 and Windows 11 as of December 2023. Undetected on Windows 10, but Defender will detect the procdump dump file on Windows 11. That's why it get's encrypted and written to a new file. the encrypted file does not get detected.

![image](https://github.com/djackreuter/proc_noprocdump/assets/27731554/040dfcc9-9741-4a09-a41e-7dd77054572e)
