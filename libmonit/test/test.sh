#!/bin/sh

PATH="$PATH:."
export PATH

StrTest && \
FmtTest && \
TimeTest && \
SystemTest && \
RandomTest && \
ArrayTest && \
ListTest && \
StringBufferTest && \
DirTest && \
InputStreamTest && \
OutputStreamTest && \
FileTest && \
ExceptionTest && \
NetTest && \
CommandTest
