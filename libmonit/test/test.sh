#!/bin/sh

PATH="$PATH:."
export PATH

StrTest && \
FmtTest && \
TimeTest && \
SystemTest && \
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
