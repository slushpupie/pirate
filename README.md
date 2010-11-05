## pirate

pirate is a Linux Kernel Module (LKM) that makes use of the Linux Security Module (LSM) framework.  It places hooks in strategic locations, right before privilege escalation, and reports to the kernel log.  This is *very* alpha software, its really just a proof of concept at this point. So dont go and run it on anything production quality.  I dont have any real documentation yet, but here is what I can tell you about it right now:

Once you build it (just run "make", make sure you have the kernel headers installed), just insert the module.  It will create a /proc/pirate interface that allows you to maintain an ignorelist.   Run "echo /bin/su > /proc/pirate" to add the su binary to the ignorelist.  To remove something from the ignorelist put a - in front of the path: "echo -/bin/su > /proc/pirate"  You can "cat /proc/pirate" to see the current ignorelist. Binaries must be given as absolute paths from the kernel's perspective (ie, outside any chroot).  The ignorelist is of course not maintained over reboot, so some startup script would need to be crafted. 

There are a handful of syscalls that get reported on, the exact format of the output is likely to change in future versions, and in fact I would like some feedback on what it should look like to be most useful to people.  There is a lot of information available, but perhaps its not all useful. 

It would be possible to modify pirate to additionally prevent these syscalls from succeeding.  Keep in mind this can be dangerous and potentially lock you out of the system if you are not careful.  

* It is not removable from the kernel once inserted. It does some funky magic to get itself wedged into the right place, and undoing that is not simple.  Maybe a future version will solve this problem.  
* Kernel API's for things Im doing changed quite a bit over the years.  The most significant was at 2.6.29, so pre and post 2.6.29 versions work differently.  Vendor kernels that backport features might not detect this correctly.
* The oldest I tested on was 2.6.26, but it should work on any kernel that has LSM support (very early 2.6.x days) I plan to test on CentOS 4.8 (a 2.6.9 kernel) soon.  The newest kernel I tested was 2.6.32.
* I tested on i386 and x86_64.  It may not work on other archs, because of some of the black magic involved.
* This *should* cooperate with SELinux, AppArmour, or any other LSM.  This is untested at this time.
* There might be some bugs lurking that cause a kernel panic.  Keep the reboot button near by. 

