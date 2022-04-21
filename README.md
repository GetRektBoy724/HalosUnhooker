# HalosUnhooker 
HalosUnhooker is an unhooker that will help you to remove AVs/EDRs hooks from NT API. Whats special about HalosUnhooker is that it uses Halo's Gate technique to get the original syscall ID of a hooked NT API which will be used to restore the NT API stub, effectively removing the hooks. Because HalosUnhooker uses Halo's Gate technique to get the original syscall ID, it doesnt touch anything from disk. The only way to break HalosUnhooker is to modify the NTDLL using [SyscallShuffler](https://github.com/GetRektBoy724/SyscallShuffler) since Halo's Gate technique relies on sorting/walking through the neighbouring syscall stubs, if the syscall stubs are shuffled, it cant get the correct syscall ID.

# Demonstration
We're going to use [NiceTryDLL](https://github.com/GetRektBoy724/NiceTryDLL)'s NtReadFile hook in this demonstration.

https://user-images.githubusercontent.com/41237415/164456259-32b37028-1efa-4543-b318-dd5cc1594ffa.mp4

As you can see, HalosUnhooker successfully removed the NiceTryDLL's hook on NtReadFile without getting caught by the NiceTryDLL itself since HalosUnhooker doesnt read anything from disk.
