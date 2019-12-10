FROM python:2.7-slim

ARG workdir=juniper-config-parser

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y vim openssh-client iputils-ping dnsutils graphviz

RUN mkdir -p /$workdir
ADD . /$workdir
WORKDIR /$workdir

RUN pip install --upgrade pip
RUN pip install lxml netaddr beautifulsoup4 pillow pexpect
