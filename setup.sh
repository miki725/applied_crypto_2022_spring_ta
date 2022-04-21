#!/usr/bin/env bash
cd /autograder/source
python3 -m pip install 'pipenv<2022.4.20'
pipenv install --system
