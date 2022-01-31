# schannel-decrypt
Schannel is the Windows Native SSL/TLS implementation.  

This project builds a DLL that when injected into a process, it hooks Schannel's DecryptMessage function and logs the decrypted message.
