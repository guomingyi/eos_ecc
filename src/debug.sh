#!/bin/bash

echo "-" > ~/.gdbinit

gdb ./ecc/test_auth

rm -rf ~/.gdbinit
