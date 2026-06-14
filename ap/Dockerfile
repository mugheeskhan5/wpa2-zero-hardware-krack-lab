FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    hostapd \
    tcpdump \
    iproute2 \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY hostapd.conf /etc/hostapd/hostapd.conf
COPY start_ap.sh /start_ap.sh
RUN chmod +x /start_ap.sh

CMD ["/start_ap.sh"]
