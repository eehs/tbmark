Terminal BookMARKer
===================
Terminal BookMARKer (abbreviated to just *tbmark*), provides a way of saving opened terminal tabs (*and their commands*) to disk and restoring them upon startup. *tbmark* works exclusively on *Linux* (tested on *x86-64* thus far) by obtaining terminal tab data from the **virtual proc filesystem** when saving tabs. As for the latter, restoring tabs that is, my current solution makes use of [xdotool](https://github.com/jordansissel/xdotool)'s **libxdo** library to fake keyboard input. This is responsible for the creation of new tabs with their respective commands sent directly to a process's stdin. Saved terminal tabs can be found at `~/.tbmark/`.

The main motivation behind this project was to boost productivity since my workflow usually involves multiple opened tabs, and of course, learning purposes :)

Any form of feedback is welcomed!

> NOTE: Shell programs that fall under tbmark's umbrella are ones that are **interactive** and **long-running**, like vim, less, tmux, and **NOT** ls, grep and cat. I intend to add support for these 'one-off' programs in the future, that is, by retrieving them directly from the shell history.

Installation
============
```
 sudo apt-get install libxdo-dev make
 git clone https://github.com/eehs/tbmark.git
 cd tbmark/
 make
```

Usage
=====
```
 ./tbmark <subcommand> <config file (optional)>
➥ save: Saves currently opened terminal tabs to a file (excluding tab where tbmark was ran)
➥ open: Opens saved tabs from a tbmark config file
➥ delete: Deletes a tbmark config file
```
