FROM golang:1.5.1

ENV GO15VENDOREXPERIMENT 1

RUN go get github.com/mitchellh/gox \
           github.com/Masterminds/glide \
           github.com/tcnksm/ghr

# Trust everyone to allow glide to execute `hg paths` on mounted volumes
# https://www.mercurial-scm.org/wiki/Trust
RUN echo "[trusted]\nusers=*" > /etc/mercurial/hgrc
