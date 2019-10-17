FROM ubuntu:xenial

########################################################
# Essential packages for remote debugging and login in
########################################################

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    apt-utils gcc g++ openssh-server cmake build-essential gdb gdbserver rsync vim libtool m4 automake

RUN mkdir /var/run/sshd
RUN echo 'root:root' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

# 22 for ssh server. 7777 for gdb server.
EXPOSE 22 7777

RUN useradd -ms /bin/bash debugger
RUN echo 'debugger:pwd' | chpasswd

########################################################
# Add custom packages and development environment here
########################################################

# libevent
RUN apt-get update && apt install libssl-dev libevent-dev -y

# libuc
RUN wget https://github.com/libuv/libuv/archive/v1.29.1.tar.gz && \
    tar -xzvf v1.29.1.tar.gz && \
    cd libuv-1.29.1/ && \
    sh autogen.sh && \
    ./configure && \
    make \
    make install

########################################################

CMD ["/usr/sbin/sshd", "-D"]