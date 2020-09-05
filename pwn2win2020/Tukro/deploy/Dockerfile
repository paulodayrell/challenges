FROM ubuntu:16.04

RUN apt update

RUN apt install -y \
  xinetd \
  rsyslog

copy files/tukro /tukro

ARG FLAG="CTF-BR{orku7_w4s_als0_us3d_by_andr0id3s_t0_s3nd_scr4ps_l0l}"
RUN touch /flag.txt && chmod 644 /flag.txt && echo $FLAG > /flag.txt

copy files/tukro.conf /tukro.conf
copy files/wrapper /wrapper

expose 1337

cmd ["/usr/sbin/xinetd", "-syslog", "local0", "-dontfork", "-f", "/tukro.conf"]