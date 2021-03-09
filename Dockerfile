FROM centos:8
WORKDIR /app
COPY . .
RUN yum update -y
RUN yum install -y gcc make gcc-c++ openssl-devel boost-devel
CMD ["tail", "-f", "/dev/null"]
