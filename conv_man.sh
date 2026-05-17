#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright contributors to the libzpc project

SRCDIR=${1}
DSTDIR=${2}

[ -z "${SRCDIR}" ] || [ -z "${DSTDIR}" ] && exit 1
command -v pandoc >/dev/null 2>&1 || exit 1

for MD in "${SRCDIR}"/*.md; do
  [ -r "${MD}" ] || continue
  MAN=$(basename "${MD}" .md)
  pandoc			\
    --standalone		\
    --to man			\
    --out "${DSTDIR}/${MAN}"	\
    "${MD}"
done
exit 0
