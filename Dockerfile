FROM ubuntu
# Simple dockerfile for testing policies


ENV INHERITED_ENV true
# add some tools for testing ...
RUN apt-get update; apt-get -y install strace curl netcat net-tools

COPY restrict /bin/
COPY seccomp.yml /

CMD ["/bin/restrict", "-policy=/seccomp.yml", "-uid=65534", "-gid=65534", "-env=false", "/bin/dash"]

