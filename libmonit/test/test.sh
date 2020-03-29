#!/bin/sh

PATH="$PATH:."
export PATH

StrTest && \
ConvertTest && \
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
