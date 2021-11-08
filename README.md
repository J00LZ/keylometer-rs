# Keylometer-rs
> pronounced as the Dutch word "kilometers"

In case you were wondering, yes I am overengineering this.

Keylometer is an application used to pull keys from Github as an AuthorizedKeysCommand for openssh. 
The architecture is very complicated, insanely more so than needed, but that's just for fun :p

The application consists of a frontend and a backend, both in the same file, but the backend has a classic
`-d` flag to enable it. This choice was made to facilitate automatic upgrades without needing to have
the actual application run as root. Since the automatic upgrade calls `execve` on a potentially malicious
executable this needs to be relatively secure. 

To make sure that not just anyone can update the application a key is needed, which is stored in the 
config file. This is the main reason why it's so complicated. A regular user needs to be able to 
execute the program and get ssh keys, but not read the config with the update key. 