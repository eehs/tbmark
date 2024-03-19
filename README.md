Terminal BookMARKer
===================

https://github.com/eehs/tbmark/assets/70907396/1f761572-77af-47fb-887b-cb8a055afdbd

**Terminal BookMARKer**, or ***tbmark*** for short, provides a way of saving the state of opened terminal tabs to disk and restoring them at a later time. ***tbmark*** works exclusively on *Linux* (tested on *x86-64* thus far) by obtaining terminal tab data from the *virtual proc filesystem* when saving tabs. As for the latter, that is, restoring tabs, my current solution makes use of [xdotool](https://github.com/jordansissel/xdotool)'s *libxdo* library to fake keyboard input. This is responsible for the restoration of terminal tabs, along with their saved commands sent directly to *standard input*. The configuration file containing your saved terminal tabs can be found in `~/.tbmark/`.

The main motivation behind this project was to boost productivity since my workflow usually involves multiple opened tabs, and for learning purposes of course! Any form of feedback is thus greatly appreciated!

> [!IMPORTANT]
> Do note that only a handful of programs running in terminal tabs can be saved/restored at the moment due to varying program semantics, and also largely due to the fact ***tbmark*** is a personal project.

Installation
============
> Compiling works with `gcc` too.
```
 sudo apt-get install libxdo-dev make clang     # Adjust according to package manager of choice
 git clone https://github.com/eehs/tbmark.git
 cd tbmark
 make
```

Usage
=====
> [!NOTE]
> CLI programs that fall under tbmark's umbrella are ones that are **interactive**, like `vim`, `less`, `tmux`, and **NOT** `ls`, `grep` and `cat`. The intended behaviour for those 'one-off' programs is to **NOT** save their commands, but instead save the terminal tab's output buffer (still a WIP), which should occur regardless of it being interactive or not.

```
 ./tbmark <subcommand> [config file]
➥ save: Saves currently opened terminal tabs to a file (excluding tab where `tbmark` ran)
➥ open: Opens saved tabs from a tbmark config file
➥ delete: Deletes a tbmark config file
➥ help: Prints this help message and exits
```

TODO
====
- [ ] Make `tbmark` aware of piped commands
- [ ] Find a way to capture and restore output buffer of saved terminal tabs
- [ ] Get rid of the horrible hardcoded mess when restoring terminal tabs using `tmux` panes (create a custom `tmux` command builder)
- [ ] Refactor `tbmark`
