#!/bin/bash
export PYTHONUSERBASE=/opt/venvs/laikaboss
export PATH="/opt/venvs/laikaboss/bin:${PATH}"
export LAIKA_GIT="example.com:4567"
export LAIKA_IMAGE_BASE="${LAIKA_GIT}/laikaboss/laikaboss-oss"
export LAIKA_IMAGE="${LAIKA_IMAGE_BASE}:latest"
