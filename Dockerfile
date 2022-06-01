FROM centos:8
WORKDIR /app
COPY . .
RUN cd /etc/yum.repos.d/ &&  \
    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
RUN yum update -y
RUN yum install -y gcc make gcc-c++ openssl-devel boost-devel
CMD ["tail", "-f", "/dev/null"]
