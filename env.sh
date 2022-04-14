#!/bin/bash
export PYTHONUSERBASE=/opt/venvs/laikaboss
export PATH="/opt/venvs/laikaboss/bin:${PATH}"
export LAIKA_GIT="docker.example.com:1234"
export LAIKA_IMAGE_BASE="${LAIKA_GIT}/laikaboss/laikaboss"
export LAIKA_IMAGE="${LAIKA_IMAGE_BASE}:latest"
