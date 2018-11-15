#!/bin/bash
build_image="centos/go-toolset-7-centos7:latest"
curpath=`pwd`
docker run -v $curpath:/opt/buildir $build_image sh -c "cd /opt/buildir; ls; go build"
