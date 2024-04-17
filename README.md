Terminal BookMARKer
===================

https://github.com/eehs/tbmark/assets/70907396/1f761572-77af-47fb-887b-cb8a055afdbd

**Terminal BookMARKer**, or **tbmark** for short, provides a way of saving the state of opened terminal tabs to disk and restoring them at a later time. **tbmark** works exclusively on *Linux* distros with a desktop environment by obtaining terminal tab data from the *virtual proc filesystem* when saving tabs. The configuration file containing your saved terminal tabs can then be found in `~/.tbmark/`. As for the latter operation, that is restoring terminal tabs, **tbmark** makes use of [xdotool](https://github.com/jordansissel/xdotool)'s *libxdo* library to fake keyboard input and the *ioctl* interface for restoring saved terminal programs (commands sent straight to *standard input*). 

The main motivation behind this project was to boost productivity since my workflow usually involves multiple opened tabs, and for learning purposes of course! Any form of feedback is thus greatly appreciated!

> [!IMPORTANT]
> **tbmark** is meant to be used in a *desktop* environment on Linux. Do note only a handful of terminal programs are supported at the moment due to varying program semantics. This is also largely due to the fact **tbmark** is a personal project.

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
> CLI programs that fall under tbmark's umbrella are ones that are **interactive** (`vim`, `less`, `tmux`) and **NOT** 'one-off' programs (`ls`, `grep`, `cat`). The intended behaviour for the latter is to **NOT** save their commands, but instead, save the terminal tab's output buffer (still WIP), which should occur for all programs regardless of their type.

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
- [ ] Add a `list` subcommand that displays saved terminal tabs from their config files
- [ ] Assign more helpful error messages
- [ ] Make `tbmark` aware of piped commands
- [ ] Find a way to capture and restore output buffer of saved terminal tabs
- [ ] Get rid of the horrible hardcoded mess when restoring terminal tabs using `tmux` panes (create a custom `tmux` command builder)
- [ ] Refactor `tbmark`
