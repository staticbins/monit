#!/bin/sh

PATH="$PATH:."
export PATH

StrTest && \
ConvertTest && \
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
