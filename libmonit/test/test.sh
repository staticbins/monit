#!/bin/sh

PATH="$PATH:."
export PATH

StrTest && \
FmtTest && \
TimeTest && \
SystemTest && \
ListTest && \
StringBufferTest && \
DirTest && \
InputStreamTest && \
OutputStreamTest && \
FileTest && \
ExceptionTest && \
NetTest && \
CommandTest
