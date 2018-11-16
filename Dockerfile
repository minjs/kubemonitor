FROM centos:7

RUN yum -y update && yum clean all

RUN mkdir -p /go && chmod -R 777 /go && \
    yum -y install git golang && yum clean all

ENV GOPATH /go
RUN yum install -y libmnl-devel-1.0.3
RUN mkdir -p /go/src/github.com/minjs/kubemonitor
WORKDIR /go/src/github.com/minjs/kubemonitor
COPY . .
RUN go build -o main .

CMD ["/go/src/github.com/minjs/kubemonitor/main"]
