#!/bin/bash

gendef libbequic.dll
dlltool --kill-at -d libbequic.def --dllname libbequic.dll -l libbequic.a
