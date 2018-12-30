#!/bin/sh

PATH="$PATH:."
export PATH

StrTest && \
FmtTest && \
TimeTest && \
SystemTest && \
ListTest && \
LinkTest && \
StringBufferTest && \
DirTest && \
InputStreamTest && \
OutputStreamTest && \
FileTest && \
ExceptionTest && \
NetTest && \
CommandTest
