Terminal BookMARKer
===================

https://github.com/user-attachments/assets/55f800b4-0df8-428c-a987-3e88a061b35c

**Terminal BookMARKer**, or **tbmark** for short, provides a way of saving the state of opened terminal tabs to disk and restoring them at a later time. **tbmark** works exclusively on *Linux* distros with a desktop environment by obtaining terminal tab data from the *virtual proc filesystem* when saving tabs. The configuration file containing your saved terminal tabs can then be found in `~/.tbmark/`. As for the latter operation, that is restoring terminal tabs, **tbmark** makes use of [xdotool](https://github.com/jordansissel/xdotool)'s *libxdo* library to fake keyboard input and the *ioctl* interface for restoring saved terminal programs (commands sent straight to *standard input*). 

The main motivation behind this project was to boost productivity since my workflow usually involves multiple opened tabs, and for learning purposes of course! Any form of feedback is thus greatly appreciated!

> [!IMPORTANT]
> **tbmark** is meant to be used in a *desktop* environment on Linux. Do note that if you have a different bind for opening new tabs in your terminal program, **tbmark** might not be able to restore tabs properly (uses `Ctrl+Shift+T` by default). This project is largely specific (to my use case) and experimental, so do expect some bugs and ugly-looking code for the time being.

Installation
============
```
 sudo apt-get install libxdo-dev make gcc   # Adjust according to package manager of choice
 git clone https://github.com/eehs/tbmark.git
 cd tbmark
 make
```

Usage
=====
> [!NOTE]
> CLI programs that fall under tbmark's umbrella are ones that are **interactive** (`vim`, `less`, `tmux`) and **NOT** 'one-off' programs (`ls`, `grep`, `cat`). I intend to add support for these non-interactive programs by looking up the shell history and provide the option of running them (or not) in the near future.

```
Usage: tbmark [OPTION] [FILE]

Available options:
  -s, --save        saves opened terminal tabs to file (excluding tab where tbmark ran)
  -r, --restore     restores saved terminal tabs from file
  -l, --list        displays saved terminal tabs given a file
  -v, --verbose     show verbose information
  -h, --help        display help message and exits
```

TODO
====
- [ ] Halt a restore action if user switches focus from current terminal to other desktop programs (another terminal instance, web browser, etc).
- [ ] Restore non-interactive programs from a tab's shell history.
- [ ] Get rid of the horrible hardcoded mess when restoring terminal tabs using `tmux` panes (create a custom `tmux` command builder).
- [ ] Find a way to capture and restore output buffer of saved terminal tabs.
- [ ] Make `tbmark` aware of piped commands.
- [ ] Save terminal tab titles (if any).
- [ ] Add shell completion support for subcommands.
- [ ] Assign more helpful error messages.
- [ ] Refactor, refactor, refactor.
