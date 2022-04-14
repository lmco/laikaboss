docker run --rm -it -v /malware:/home/laikaboss/workdir -v /etc/laikaboss:/etc/laikaboss -v /etc/yara/:/etc/yara "${LAIKA_IMAGE}" file2scan.in
