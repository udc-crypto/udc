#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/logo.ico

convert ../../src/qt/res/icons/logo-16.png ../../src/qt/res/icons/logo-32.png ../../src/qt/res/icons/logo-48.png ${ICON_DST}
