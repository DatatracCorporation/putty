FROM fedora:latest

# make a simple init program (until we are using docker 1.13+)
ENV TINI_VERSION v0.18.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ENTRYPOINT ["/tini", "--"]

# install our dev tools
RUN dnf install -y \
        perl \
    && dnf install -y \
        mingw32-gcc \
    && dnf clean all

# putty's mingw makefile need to know how to find the mingw tools
ENV TOOLPATH=i686-w64-mingw32-

# the multimon header is broken in mingw 5.0.4
ENV COMPAT=-DNO_MULTIMON
