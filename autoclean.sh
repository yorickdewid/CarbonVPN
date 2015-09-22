#! /bin/sh

make clean
for f in $(find . -name '.deps' -or -name 'Makefile.in' -or -name 'Makefile'); do
  rm -rf $f;
done

rm -rf *~
rm -rf aclocal.m4
rm -rf autom4te.cache/
rm -rf compile
rm -rf config.h
rm -rf config.h.in
rm -rf config.status
rm -rf configure
rm -rf depcomp
rm -rf install-sh
rm -rf missing
rm -rf stamp-h1
rm -rf config.log
