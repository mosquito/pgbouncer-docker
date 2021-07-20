FROM snakepacker/python:3.8

RUN apt-install pgbouncer
RUN apt-install \
    python3-setproctitle \
    python3-prometheus-client \
    python3-werkzeug \
    python3-psycopg2

COPY entrypoint.py /usr/local/sbin/entrypoint.py
RUN chmod a+x /usr/local/sbin/entrypoint.py

ENV FORKS=2

CMD ["/usr/local/sbin/entrypoint.py"]
