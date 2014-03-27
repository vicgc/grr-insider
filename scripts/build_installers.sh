#!/bin/sh

export PYTHONPATH='.:grr/bulk_extractor/python/module'
export LD_LIBRARY_PATH='grr/bulk_extractor/src'

python2 grr/client/client_build.py --config=grr/config/client_build.yaml build
