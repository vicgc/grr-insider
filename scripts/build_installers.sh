#!/bin/sh

PYTHONPATH=. python2 grr/client/client_build.py --config=grr/config/client_build.yaml build
