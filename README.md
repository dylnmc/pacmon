pacmon
======

## About

Pacmon is a pun on pacman, a package manager for archlinux. It uses pyalpm, which is a python binding for libalpm, which is what pacman uses to manager pacakges on archlinux.

## Setup and Run

```sh
python -m venv env  # set up virtual environment (1 time only)
source env/bin/activate  # ** start python virtual environment (1 time per shell only)
pip install pyalpm  # install pyalpm as a package
python -m pacmon -h  # run pacmon with --help
```

`**` `call env\Scripts\activate.bat` on Windows
