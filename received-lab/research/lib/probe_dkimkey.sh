#!/bin/sh
docker exec msl-opendkim opendkim-testkey -d lab.test -s cal -vvv
