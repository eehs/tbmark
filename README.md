Terminal BookMARKer
===================

https://github.com/user-attachments/assets/55f800b4-0df8-428c-a987-3e88a061b35c

**Terminal BookMARKer**, or **tbmark** for short, provides a way of saving the state of opened terminal tabs to disk and restoring them at a later time. **tbmark** works exclusively on *Linux* distros using the [X Window System](https://en.wikipedia.org/wiki/X_Window_System), by obtaining terminal tab data from the *virtual proc filesystem* when saving tabs. As for the latter operation, that is restoring terminal tabs, **tbmark** makes use of [xdotool](https://github.com/jordansissel/xdotool)'s *libxdo* library to fake keyboard input and the *ioctl* interface for restoring saved terminal programs (commands sent straight to *standard input*). The configuration file containing your saved terminal tabs can then be found in `~/.tbmark/`.

The main motivation behind this project was to boost productivity since my workflow usually involves multiple opened tabs, and for learning purposes of course! Any form of feedback is thus greatly appreciated!

> [!IMPORTANT]
> **tbmark** is meant to be used in a *desktop* environment on Linux. Do note that if your terminal emulator does not support shortcuts for opening new terminal tabs (like [Alacritty](https://alacritty.org/index.html)), **tbmark** will not restore tabs properly (uses `Ctrl+Shift+T` by default, this value is hardcoded at the moment). This project is largely specific to my use case and experimental, so do expect bugs and ugly-looking code for the time being.

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
> CLI programs that fall under tbmark's umbrella are ones that are long-running (`vim`, `less`), and **NOT** short-lived programs (`ls`, `grep`). Check out [Limitations](#Limitations) for more context. 

```
Usage: tbmark [OPTION] [FILE]

Available options:
  -s, --save        saves opened terminal tabs to file (excluding tab where tbmark ran)
  -r, --restore     restores saved terminal tabs from file
  -l, --list        displays saved terminal tabs given a file
  -v, --verbose     show verbose information
  -h, --help        display help message and exits
```

Limitations
===========
The fact that the saving function in `tbmark` collects process information post-execution, handy features such as *restoring short-lived programs, piped commands* and the *terminal output buffer* can prove tricky (near impossible) to implement. With this in mind, there might be plans in the future to rewrite `tbmark` to *watch* these commands as they're being executed. Something like that can be done by attaching to the shell process right from the get-go, before even executing said commands, so that `tbmark` can obtain the appropriate process information before *saving* your terminal tabs. But hey, I might as well use [screen](https://www.gnu.org/software/screen/) or a [tmux](https://github.com/tmux/tmux) plugin to do the job :)

TODO
====
- [ ] Get rid of the horrible hardcoded mess when restoring terminal tabs using `tmux` panes (create a custom `tmux` command builder).
- [ ] Save terminal tab titles (if any).
- [ ] Add shell completion support for subcommands.
- [ ] Assign more helpful error messages.
- [ ] Refactor, refactor, refactor.
