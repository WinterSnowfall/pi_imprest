# pi_imprest
_By mere good fortune, recent experiments in conjuration had ensnared me this imp_

Sacrifice game intro, Shiny Entertainment

## Wait, what? A utility that runs commands via ssh and then emits REST calls? You can do that in bash!
Yes, you certainly can. But this is portable and can run on a toaster as long as it has python3. And it has imps. I hope you are now imprest!

## What do I need to do to get it running on my Raspberry Pi?

Paramiko is used for implementing the ssh client connections to remote hosts. You can install it manually on Debian/Ubuntu, as follows:
```
sudo apt-get install python3-paramiko
```

## Do I need to run it on a Raspberry Pi?

No, not really. Any OS with a working python3.6+ installation will do.

## How do I configure this thing?

Look under the /conf folder for a sample config file. You can add as many task entries as you like, just number them incrementally, as per the sample. The right number of imps will be summoned automatically.

## What's with the wierd passwords?

I've written a separate module to encrypt the ssh user passwords of the monitored hosts using a master password. To generate the encrypted text that you need to add in the config file just run pi_password.py and follow the on-screen prompts.
