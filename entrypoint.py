#!/usr/bin/env python3
import logging
import os
import pwd
import sys
import uuid
from configparser import ConfigParser
from contextlib import contextmanager
from copy import copy
from decimal import Decimal
from functools import lru_cache
from multiprocessing import Process
from pathlib import Path
from shutil import which
from tempfile import mktemp
from threading import Thread
from time import sleep, monotonic
from typing import MutableMapping, Type, TypeVar

import psycopg2
import psycopg2.pool
from prometheus_client import Counter, make_wsgi_app, Gauge
from psycopg2.extras import RealDictCursor
from setproctitle import setproctitle
from werkzeug.serving import ThreadedWSGIServer


log = logging.getLogger(__name__)
T = TypeVar("T")


def log_reader(log_file):
    setproctitle("pgbouncer log reader")
    os.nice(20)
    try:
        with open(log_file, "rb") as fp:
            while True:
                sys.stderr.buffer.write(fp.read(1024))
    except KeyboardInterrupt:
        return
    finally:
        sys.stderr.flush()


def pgbouncer_exporter(port, address, *dsns: str, update_interval=15):
    os.nice(10)

    setproctitle("pgbouncer exporter http://{}:{}".format(
        address, port)
    )

    app = make_wsgi_app()
    server = ThreadedWSGIServer(app=app, port=port, host=address)

    @lru_cache(2 ** 20)
    def make_metric(klass: Type[T], *args, **kwargs) -> T:
        return klass(*args, **kwargs)

    pool_min_conn = 1
    pool_max_conn = 2

    @lru_cache(65535)
    def make_connection_pool(dsn):
        return psycopg2.pool.SimpleConnectionPool(
            pool_min_conn, pool_max_conn, dsn,
            cursor_factory=RealDictCursor
        )

    @contextmanager
    def get_conn(dsn):
        pool = make_connection_pool(dsn)

        while True:
            conn = pool.getconn()

            try:
                conn.autocommit = True

                try:
                    with conn.cursor() as cur:
                        cur.execute("SHOW VERSION")
                except:
                    continue
                else:
                    yield conn
                    return
            finally:
                pool.putconn(conn)

    def metrics_updater(dsn: str):
        with get_conn(dsn) as conn:
            log.debug("Gathering metrics for %r", dsn)

            def show(topic: str, *ignores):
                with conn.cursor() as cur:
                    cur.execute("SHOW {}".format(topic.upper()))
                    records = [dict(record) for record in cur]

                for record in records:
                    label_values = {}

                    for name, value in tuple(record.items()):
                        if isinstance(value, (int, Decimal, float)):
                            continue

                        if name in ignores:
                            record.pop(name)
                            continue

                        label_values[name] = record.pop(name)

                    if not record:
                        metric = make_metric(
                            Gauge,
                            documentation=(
                                "Result of query \"show {topic}\""
                            ).format(
                                topic=topic
                            ),
                            name=topic,
                            namespace="pgbouncer",
                            labelnames=tuple(label_values.keys()),
                        )
                        metric.labels(**{
                            k: v if v is not None else ''
                            for k, v in label_values.items()
                        }).set(1)
                        continue

                    for name, value in record.items():
                        metric = make_metric(
                            Counter,
                            documentation=(
                                "\"{name}\" field for record query "
                                "\"show {topic}\""
                            ).format(
                                name=name, topic=topic
                            ),
                            name=name,
                            namespace="pgbouncer",
                            subsystem=topic,
                            labelnames=tuple(label_values.keys()),
                        )

                        metric.labels(**label_values).inc(float(value))

            common_ignored_labels = ("connect_time", "request_time", "ptr")

            topics = {
                "stats": common_ignored_labels,
                "clients": common_ignored_labels,
                "pools": common_ignored_labels,
                "lists": common_ignored_labels,
                "users": common_ignored_labels,
                "databases": common_ignored_labels,
                "fds": common_ignored_labels,
                "sockets": common_ignored_labels,
                "active_sockets": common_ignored_labels,
                "dns_hosts": common_ignored_labels,
                "dns_zones": common_ignored_labels,
                "version": common_ignored_labels,
            }

            for topic, ignores in topics.items():
                show(topic, *ignores)

    def updater():
        while True:
            for dsn in dsns:
                try:
                    metrics_updater(dsn)
                except Exception:
                    log.exception("Failed to update metrics")
            sleep(update_interval)

    Thread(target=updater, name="statistic updater", daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        exit(0)


def exec_process(pgbouncer_executable, config, env) -> int:
    pid = os.fork()
    if pid == 0:
        cmdline = [pgbouncer_executable, str(config)]

        log.debug("Executing %r", cmdline)
        os.execve(pgbouncer_executable, cmdline, env)
    return pid


class Entrypoint:
    def __init__(
        self, user: str = "postgres",
        ececutable: str = "pgbouncer",
        config_path: str = "/etc/pgbouncer",
        base_config: str = "pgbouncer.ini",
        run_path: str = "/var/run/pgbouncer/",
        forks: int = 0,
        env: MutableMapping[str, str] = None,
    ):
        self.user = pwd.struct_passwd = pwd.getpwnam(user)
        self.executable = which(ececutable)
        self.path = Path(config_path)
        self.instance_path = self.path / str(uuid.uuid4())
        self.instance_path.mkdir()
        self.instance_path.chmod(0o700)
        os.chown(self.instance_path, self.user.pw_uid, self.user.pw_gid)

        self.run_path = Path(run_path)
        self.run_path.mkdir(exist_ok=True, parents=True)
        self.run_path.chmod(0o700)
        os.chown(self.run_path, self.user.pw_uid, self.user.pw_gid)

        self.auth_file = self.instance_path / "userlist.txt"
        self.forks = forks

        self.config = ConfigParser()
        self.config.read(self.path / base_config)

        # Useful defaults
        self.config['pgbouncer']['listen_addr'] = "::"
        self.config['pgbouncer']['listen_port'] = str(6432)
        self.config['pgbouncer']['so_reuseport'] = "1"
        self.config['pgbouncer']['unix_socket_mode'] = "0700"
        self.config['pgbouncer']['pidfile'] = ""
        self.config['pgbouncer']['auth_type'] = "pam"
        self.config['pgbouncer']['listen_backlog'] = str(
            max((4, 32 // self.forks))
        )

        self.exec_env = {}
        self.auth = {}

        self._parse_env(env or dict(os.environ))

        self.log_file = self._make_log_file()
        self.config['pgbouncer']['logfile'] = str(self.log_file)

        self.write_users()

    def _make_log_file(self):
        fname = mktemp(suffix=".log", prefix="pgbouncer-")
        os.mkfifo(fname)
        os.chmod(fname, 0o744)
        os.chown(fname, self.user.pw_uid, self.user.pw_gid)
        return fname

    def _parse_env(self, environ):
        sections = set(self.config.sections())
        sections.add("auth")

        for name, value in environ.items():
            if "_" not in name:
                self.exec_env[name] = value
                continue

            section, param = name.split("_", 1)
            section = section.lower()

            if section == 'auth':
                self.auth[param] = value
                continue

            if section not in sections:
                self.exec_env[name] = value
                continue

            self.config[section][param.lower()] = value

    def write_users(self):
        # write users configs
        if self.config['pgbouncer']['auth_type'] not in {
            "pam", "md5", "scram-sha-256", "trust"
        }:
            return

        with open(self.auth_file, "w") as fp:
            os.chmod(fp.fileno(), 0o400)
            os.chown(fp.fileno(), self.user.pw_uid, self.user.pw_gid)

            for user, password in self.auth.items():
                fp.write('"{}"'.format(user))
                if self.config['pgbouncer']['auth_type'] != 'trust':
                    fp.write(' "{}"'.format(password))
                fp.write('\n')

        self.config['pgbouncer']['auth_file'] = str(self.auth_file)

    def make_config(self, id: int) -> str:
        fname = self.instance_path / "pgbouncer-{}.conf".format(id)
        config = copy(self.config)

        with open(fname, "w") as fp:
            os.chmod(fp.fileno(), 0o600)

            path = self.run_path / str(id)
            path.mkdir(exist_ok=False, parents=True)
            config['pgbouncer']['unix_socket_dir'] = str(path)
            config.write(fp)
        return fname

    def supervise(self):
        setproctitle("pgbouncer supervisor")

        # change current user and start
        os.setgid(self.user.pw_gid)
        os.setuid(self.user.pw_uid)

        def start_log_reader_process() -> Process:
            process = Process(
                target=log_reader, args=(self.log_file,), daemon=True
            )
            process.start()
            return process

        # start log reader
        log_reader_process = start_log_reader_process()

        configs = [self.make_config(i + 1) for i in range(self.forks)]
        processes = {}

        def parse_dsn(config) -> str:
            parser = ConfigParser()
            parser.read(config)

            dsn = (
                'host={path} '
                'port={port} '
                'user=pgbouncer '
                'dbname=pgbouncer'
            )
            return dsn.format(
                path=Path(parser['pgbouncer']['unix_socket_dir']),
                port=parser['pgbouncer']['listen_port'],
            )

        def wait_socket(config, pid, timeout=30):
            parser = ConfigParser()
            parser.read(config)

            path = Path(parser['pgbouncer']['unix_socket_dir'])
            path = path / ".s.PGSQL.{}".format(
                parser['pgbouncer']['listen_port']
            )

            start = monotonic()
            while not path.is_socket():
                status, _ = os.waitpid(pid, os.P_NOWAIT)
                if status > 0:
                    raise ChildProcessError(status)
                sleep(0.1)

                if start + timeout < monotonic():
                    raise TimeoutError

        dsn_list = []
        for config in configs:
            log.info("Starting pgbouncer process")

            pid = exec_process(self.executable, config, self.exec_env)
            dsn = parse_dsn(config)

            try:
                wait_socket(config, pid)
            except ChildProcessError as e:
                exit(1 if not e.args else e.args[0])
            except TimeoutError:
                log.info("Timeout when waiting pgbouncer bind unix socket")
                exit(128)

            dsn_list.append(dsn)
            processes[pid] = config

        def start_metrics_process() -> Process:
            process = Process(
                target=pgbouncer_exporter,
                daemon=True,
                args=(int(os.getenv("METRICS_PORT", "8080")),
                      os.getenv("METRICS_ADDR", "::")) + tuple(dsn_list)
            )
            process.start()
            return process

        metrics_process = start_metrics_process()

        try:
            while True:
                pid, status = os.wait()

                if pid == log_reader_process.pid:
                    log_reader_process = start_log_reader_process()
                    continue

                if pid == metrics_process.pid:
                    metrics_process = start_metrics_process()
                    continue

                config = processes.pop(pid, None)
                pid = exec_process(self.executable, config, self.exec_env)
                processes[pid] = config
        except KeyboardInterrupt:
            exit(0)


def main():
    logging.basicConfig(
        format="%(asctime)s [%(process)d] %(message)s",
        level=getattr(
            logging,
            os.getenv("LOG_LEVEL", "info").upper(),
            logging.INFO
        )
    )

    ep = Entrypoint(forks=int(os.getenv("FORKS", "2")))
    ep.supervise()


if __name__ == '__main__':
    main()
