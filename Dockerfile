FROM sysrepo/sysrepo-netopeer2

RUN apt update && apt install -y libpthread-stubs0-dev

# Setup netconf user
RUN adduser --system netconf
RUN mkdir -p /home/netconf/.ssh
RUN echo "netconf:netconf" | chpasswd && adduser netconf sudo;

ADD . /cfgipsec2
WORKDIR /cfgipsec2

# Install yang models
RUN sysrepoctl -i yang/ietf-inet-types.yang  --permissions=666 -v3 && \ 
sysrepoctl -i yang/ietf-netconf-acm.yang  --permissions=666 -v3 && \
sysrepoctl -i yang/ietf-yang-types.yang  --permissions=666 -v3 && \
sysrepoctl -i yang/ietf-i2nsf-ikec.yang  --permissions=666 -v3 && \
sysrepoctl -i yang/ietf-i2nsf-ikeless.yang  --permissions=666 -v3

RUN sysrepoctl -c ietf-i2nsf-ikeless -e ikeless-notification  -v3

RUN rm -rf parson && git clone https://github.com/kgabis/parson
RUN mkdir -p build && cd build && rm -rf * &&  cmake  .. && make

ADD supervisord.conf /etc/supervisord.conf

RUN echo '<nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm"><enable-nacm>false</enable-nacm></nacm>' > /disable-acm.xml
RUN sysrepocfg --import=/disable-acm.xml -f xml --datastore startup --module ietf-netconf-acm -v3 && \
sysrepocfg --import=/disable-acm.xml -f xml --datastore running --module ietf-netconf-acm -v3 