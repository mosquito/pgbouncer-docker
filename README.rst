PGBouncer
=========

PGBouncer Docker image with prometheus exporter and dynamic
configuration from environment.

A distinctive feature of this image is the ``entrypoint``, which provides:

* Multiprocessing support. Several PgBouncer processes are started on the
  same port, which ensures the utilization of more than one core.
* Support for metrics in prometheus format.
* Fully dynamic configuration from environment variables.

Example
-------

Minimal config:

.. code:: bash

   docker run --rm -it --name pgbouncer \
       -p 8080:8080 \
       -p 6432:6432 \
       -e DATABASES_template1="host=127.0.0.1 dbname=template1 auth_user=someuser" \
       -e PGBOUNCER_POOL_MODE="session" \
       -e AUTH_user="secret" \


Configuration
-------------

Description
~~~~~~~~~~~

The configuration is set in the environment variables. All environment
variables are built according to the same principle,
``{SECTION}_{PARAMETER_NAME}={VALUE}``, where ``{SECTION}`` is the name
of the section from the configuration file pgbouncer.ini,
``{PARAMETER_NAME}`` is the value of the parameter, and ``{VALUE}`` is a
parameter value.

Entrypoint specific settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ENV: ``FORKS``
^^^^^^^^^^^^^^

Number of pgbouncer processes.

ENV: ``LOG_LEVEL``
^^^^^^^^^^^^^^^^^^

Entrypoint log level. Possible values is:

-  critical
-  fatal
-  error
-  warning
-  warn
-  info
-  debug

User authentication settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ENV: ``AUTH_{username}={password}``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Adds the user ``{username}`` with the password ``{password}`` to
userlist.txt to the file. The password can be hashed, and
``PGBOUNCER_AUTH_TYPE`` must be set accordingly.

Generic settings
~~~~~~~~~~~~~~~~

ENV: ``PGBOUNCER_LISTEN_ADDR``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Specifies a list of addresses where to listen for TCP connections. You
may also use ``*`` meaning "listen on all addresses". When not set, only
Unix socket connections are accepted.

Addresses can be specified numerically (IPv4/IPv6) or by name.

Default: not set

ENV: ``PGBOUNCER_LISTEN_PORT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Which port to listen on. Applies to both TCP and Unix sockets.

Default: ``6432``

ENV: ``PGBOUNCER_AUTH_HBA_FILE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HBA configuration file to use when ``auth_type`` is ``hba``.

Default: not set

ENV: ``PGBOUNCER_AUTH_TYPE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

How to authenticate users.

``pam`` : PAM is used to authenticate users, ``auth_file`` is ignored.
This method is not compatible with databases using the ``auth_user``
option. The service name reported to PAM is "pgbouncer". ``pam`` is not
supported in the HBA configuration file.

``hba`` : The actual authentication type is loaded from
``auth_hba_file``. This allows different authentication methods for
different access paths, for example: connections over Unix socket use
the ``peer`` auth method, connections over TCP must use TLS.

``cert`` : Client must connect over TLS connection with a valid client
certificate. The user name is then taken from the CommonName field from
the certificate.

``md5`` : Use MD5-based password check. This is the default
authentication method. ``auth_file`` may contain both MD5-encrypted and
plain-text passwords. If ``md5`` is configured and a user has a SCRAM
secret, then SCRAM authentication is used automatically instead.

``scram-sha-256`` : Use password check with SCRAM-SHA-256. ``auth_file``
has to contain SCRAM secrets or plain-text passwords. Note that SCRAM
secrets can only be used for verifying the password of a client but not
for logging into a server. To be able to use SCRAM on server
connections, use plain-text passwords.

``plain`` : The clear-text password is sent over the wire. Deprecated.

``trust`` : No authentication is done. The user name must still exist in
``auth_file``.

``any`` : Like the ``trust`` method, but the user name given is ignored.
Requires that all databases are configured to log in as a specific user.
Additionally, the console database allows any user to log in as admin.

ENV: ``PGBOUNCER_AUTH_QUERY``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Query to load user's password from database.

Direct access to pg_shadow requires admin rights. It's preferable to use
a non-superuser that calls a SECURITY DEFINER function instead.

Note that the query is run inside the target database. So if a function
is used, it needs to be installed into each database.

Default: ``SELECT usename, passwd FROM pg_shadow WHERE usename=$1``

ENV: ``PGBOUNCER_AUTH_USER``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If ``auth_user`` is set, then any user not specified in ``auth_file``
will be queried through the ``auth_query`` query from pg_shadow in the
database, using ``auth_user``. The password of ``auth_user`` will be
taken from ``auth_file``.

Direct access to pg_shadow requires admin rights. It's preferable to use
a non-superuser that calls a SECURITY DEFINER function instead.

Default: not set

ENV: ``PGBOUNCER_POOL_MODE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Specifies when a server connection can be reused by other clients.

``session`` : Server is released back to pool after client disconnects.
Default.

``transaction`` : Server is released back to pool after transaction
finishes.

``statement`` : Server is released back to pool after query finishes.
Transactions spanning multiple statements are disallowed in this mode.

ENV: ``PGBOUNCER_MAX_CLIENT_CONN``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Maximum number of client connections allowed. When increased then the
file descriptor limits should also be increased. Note that the actual
number of file descriptors used is more than ``max_client_conn``. The
theoretical maximum used is:

::

   max_client_conn + (max pool_size * total databases * total users)

if each user connects under its own user name to the server. If a
database user is specified in the connection string (all users connect
under the same user name), the theoretical maximum is:

::

   max_client_conn + (max pool_size * total databases)

The theoretical maximum should be never reached, unless somebody
deliberately crafts a special load for it. Still, it means you should
set the number of file descriptors to a safely high number.

Search for ``ulimit`` in your favorite shell man page. Note: ``ulimit``
does not apply in a Windows environment.

Default: ``100``

ENV: ``PGBOUNCER_DEFAULT_POOL_SIZE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

How many server connections to allow per user/database pair. Can be
overridden in the per-database configuration.

Default: ``20``

ENV: ``PGBOUNCER_MIN_POOL_SIZE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add more server connections to pool if below this number. Improves
behavior when usual load comes suddenly back after period of total
inactivity. The value is effectively capped at the pool size.

Default: ``0`` (disabled)

ENV: ``PGBOUNCER_RESERVE_POOL_SIZE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

How many additional connections to allow to a pool (see
``reserve_pool_timeout``). 0 disables.

Default: ``0`` (disabled)

ENV: ``PGBOUNCER_RESERVE_POOL_TIMEOUT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a client has not been serviced in this many seconds, use additional
connections from the reserve pool. 0 disables.

Default: ``5.0``

ENV: ``PGBOUNCER_MAX_DB_CONNECTIONS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Do not allow more than this many server connections per database
(regardless of user). This considers the PgBouncer database that the
client has connected to, not the PostgreSQL database of the outgoing
connection.

This can also be set per database in the ``[databases]`` section.

Note that when you hit the limit, closing a client connection to one
pool will not immediately allow a server connection to be established
for another pool, because the server connection for the first pool is
still open. Once the server connection closes (due to idle timeout), a
new server connection will immediately be opened for the waiting pool.

Default: ``0`` (unlimited)

ENV: ``PGBOUNCER_MAX_USER_CONNECTIONS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Do not allow more than this many server connections per user (regardless
of database). This considers the PgBouncer user that is associated with
a pool, which is either the user specified for the server connection or
in absence of that the user the client has connected as.

This can also be set per user in the ``[users]`` section.

Note that when you hit the limit, closing a client connection to one
pool will not immediately allow a server connection to be established
for another pool, because the server connection for the first pool is
still open. Once the server connection closes (due to idle timeout), a
new server connection will immediately be opened for the waiting pool.

Default: ``0`` (unlimited)

ENV: ``PGBOUNCER_SERVER_ROUND_ROBIN``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, PgBouncer reuses server connections in LIFO (last-in,
first-out) manner, so that few connections get the most load. This gives
best performance if you have a single server serving a database. But if
there is TCP round-robin behind a database IP address, then it is better
if PgBouncer also uses connections in that manner, thus achieving
uniform load.

Default: ``0``

ENV: ``PGBOUNCER_IGNORE_STARTUP_PARAMETERS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, PgBouncer allows only parameters it can keep track of in
startup packets: ``client_encoding``, ``datestyle``, ``timezone`` and
``standard_conforming_strings``. All others parameters will raise an
error. To allow others parameters, they can be specified here, so that
PgBouncer knows that they are handled by the admin and it can ignore
them.

Default: empty

ENV: ``PGBOUNCER_DISABLE_PQEXEC``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable Simple Query protocol (PQexec). Unlike Extended Query protocol,
Simple Query allows multiple queries in one packet, which allows some
classes of SQL-injection attacks. Disabling it can improve security.
Obviously this means only clients that exclusively use the Extended
Query protocol will stay working.

Default: ``0``

ENV: ``PGBOUNCER_APPLICATION_NAME_ADD_HOST``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add the client host address and port to the application name setting set
on connection start. This helps in identifying the source of bad queries
etc. This logic applies only on start of connection. If
``application_name`` is later changed with SET, PgBouncer does not
change it again.

Default: ``0``

ENV: ``PGBOUNCER_CONFFILE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Show location of current config file. Changing it will make PgBouncer
use another config file for next ``RELOAD`` / ``SIGHUP``.

Default: file from command line

ENV: ``PGBOUNCER_SERVICE_NAME``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Used on win32 service registration.

Default: ``pgbouncer``

ENV: ``PGBOUNCER_JOB_NAME``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Alias for ``service_name``.

ENV: ``PGBOUNCER_STATS_PERIOD``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets how often the averages shown in various ``SHOW`` commands are
updated and how often aggregated statistics are written to the log (but
see ``log_stats``). [seconds]

Default: ``60``

Log settings
~~~~~~~~~~~~

ENV: ``PGBOUNCER_LOG_CONNECTIONS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Log successful logins.

Default: ``1``

ENV: ``PGBOUNCER_LOG_DISCONNECTIONS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Log disconnections with reasons.

Default: ``1``

ENV: ``PGBOUNCER_LOG_POOLER_ERRORS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Log error messages the pooler sends to clients.

Default: ``1``

ENV: ``PGBOUNCER_LOG_STATS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Write aggregated statistics into the log, every ``stats_period``. This
can be disabled if external monitoring tools are used to grab the same
data from ``SHOW`` commands.

Default: ``1``

ENV: ``PGBOUNCER_VERBOSE``
^^^^^^^^^^^^^^^^^^^^^^^^^^

Increase verbosity. Mirrors the "-v" switch on the command line. Using
"-v -v" on the command line is the same as ``verbose=2``.

Default: ``0``

Console access control
~~~~~~~~~~~~~~~~~~~~~~

ENV: ``PGBOUNCER_ADMIN_USERS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Comma-separated list of database users that are allowed to connect and
run all commands on the console. Ignored when ``auth_type`` is ``any``,
in which case any user name is allowed in as admin.

Default: empty

ENV: ``PGBOUNCER_STATS_USERS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Comma-separated list of database users that are allowed to connect and
run read-only queries on the console. That means all SHOW commands
except SHOW FDS.

Default: empty

Connection sanity checks, timeouts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ENV: ``PGBOUNCER_SERVER_RESET_QUERY``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Query sent to server on connection release, before making it available
to other clients. At that moment no transaction is in progress so it
should not include ``ABORT`` or ``ROLLBACK``.

The query is supposed to clean any changes made to the database session
so that the next client gets the connection in a well-defined state. The
default is ``DISCARD ALL`` which cleans everything, but that leaves the
next client no pre-cached state. It can be made lighter, e.g.
``DEALLOCATE ALL`` to just drop prepared statements, if the application
does not break when some state is kept around.

When transaction pooling is used, the ``server_reset_query`` is not
used, as clients must not use any session-based features as each
transaction ends up in a different connection and thus gets a different
session state.

Default: ``DISCARD ALL``

ENV: ``PGBOUNCER_SERVER_RESET_QUERY_ALWAYS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Whether ``server_reset_query`` should be run in all pooling modes. When
this setting is off (default), the ``server_reset_query`` will be run
only in pools that are in sessions-pooling mode. Connections in
transaction-pooling mode should not have any need for a reset query.

This setting is for working around broken setups that run applications
that use session features over a transaction-pooled PgBouncer. It
changes non-deterministic breakage to deterministic breakage: Clients
always lose their state after each transaction.

Default: ``0``

ENV: ``PGBOUNCER_SERVER_CHECK_DELAY``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

How long to keep released connections available for immediate re-use,
without running sanity-check queries on it. If 0 then the query is ran
always.

Default: ``30.0``

ENV: ``PGBOUNCER_SERVER_CHECK_QUERY``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Simple do-nothing query to check if the server connection is alive.

If an empty string, then sanity checking is disabled.

Default: ``SELECT 1;``

ENV: ``PGBOUNCER_SERVER_FAST_CLOSE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disconnect a server in session pooling mode immediately or after the end
of the current transaction if it is in "close_needed" mode (set by
``RECONNECT``, ``RELOAD`` that changes connection settings, or DNS
change), rather than waiting for the session end. In statement or
transaction pooling mode, this has no effect since that is the default
behavior there.

If because of this setting a server connection is closed before the end
of the client session, the client connection is also closed. This
ensures that the client notices that the session has been interrupted.

This setting makes connection configuration changes take effect sooner
if session pooling and long-running sessions are used. The downside is
that client sessions are liable to be interrupted by a configuration
change, so client applications will need logic to reconnect and
reestablish session state. But note that no transactions will be lost,
because running transactions are not interrupted, only idle sessions.

Default: ``0``

ENV: ``PGBOUNCER_SERVER_LIFETIME``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The pooler will close an unused server connection that has been
connected longer than this. Setting it to 0 means the connection is to
be used only once, then closed. [seconds]

Default: ``3600.0``

ENV: ``PGBOUNCER_SERVER_IDLE_TIMEOUT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a server connection has been idle more than this many seconds it will
be dropped. If 0 then timeout is disabled. [seconds]

Default: ``600.0``

ENV: ``PGBOUNCER_SERVER_CONNECT_TIMEOUT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If connection and login won't finish in this amount of time, the
connection will be closed. [seconds]

Default: ``15.0``

ENV: ``PGBOUNCER_SERVER_LOGIN_RETRY``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If login failed, because of failure from connect() or authentication
that pooler waits this much before retrying to connect. [seconds]

Default: ``15.0``

ENV: ``PGBOUNCER_CLIENT_LOGIN_TIMEOUT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a client connects but does not manage to log in in this amount of
time, it will be disconnected. Mainly needed to avoid dead connections
stalling SUSPEND and thus online restart. [seconds]

Default: ``60.0``

ENV: ``PGBOUNCER_AUTODB_IDLE_TIMEOUT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the automatically created (via "*") database pools have been unused
this many seconds, they are freed. The negative aspect of that is that
their statistics are also forgotten. [seconds]

Default: ``3600.0``

ENV: ``PGBOUNCER_DNS_MAX_TTL``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

How long the DNS lookups can be cached. If a DNS lookup returns several
answers, PgBouncer will robin-between them in the meantime. The actual
DNS TTL is ignored. [seconds]

Default: ``15.0``

ENV: ``PGBOUNCER_DNS_NXDOMAIN_TTL``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

How long error and NXDOMAIN DNS lookups can be cached. [seconds]

Default: ``15.0``

ENV: ``PGBOUNCER_DNS_ZONE_CHECK_PERIOD``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Period to check if a zone serial has changed.

PgBouncer can collect DNS zones from host names (everything after first
dot) and then periodically check if the zone serial changes. If it
notices changes, all host names under that zone are looked up again. If
any host IP changes, its connections are invalidated.

Works only with UDNS and c-ares backends (``--with-udns`` or
``--with-cares`` to configure).

Default: ``0.0`` (disabled)

ENV: ``PGBOUNCER_RESOLV_CONF``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The location of a custom ``resolv.conf`` file. This is to allow
specifying custom DNS servers and perhaps other name resolution options,
independent of the global operating system configuration.

Requires evdns (>= 2.0.3) or c-ares (>= 1.15.0) backend.

The parsing of the file is done by the DNS backend library, not
PgBouncer, so see the library's documentation for details on allowed
syntax and directives.

Default: empty (use operating system defaults)

TLS settings
~~~~~~~~~~~~

ENV: ``PGBOUNCER_CLIENT_TLS_SSLMODE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TLS mode to use for connections from clients. TLS connections are
disabled by default. When enabled, ``client_tls_key_file`` and
``client_tls_cert_file`` must be also configured to set up the key and
certificate PgBouncer uses to accept client connections.

``disable`` : Plain TCP. If client requests TLS, it's ignored. Default.

``allow`` : If client requests TLS, it is used. If not, plain TCP is
used. If the client presents a client certificate, it is not validated.

``prefer`` : Same as ``allow``.

``require`` : Client must use TLS. If not, the client connection is
rejected. If the client presents a client certificate, it is not
validated.

``verify-ca`` : Client must use TLS with valid client certificate.

``verify-full`` : Same as ``verify-ca``.

ENV: ``PGBOUNCER_CLIENT_TLS_KEY_FILE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Private key for PgBouncer to accept client connections.

Default: not set

ENV: ``PGBOUNCER_CLIENT_TLS_CERT_FILE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Certificate for private key. Clients can validate it.

Default: not set

ENV: ``PGBOUNCER_CLIENT_TLS_CA_FILE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Root certificate file to validate client certificates.

Default: not set

ENV: ``PGBOUNCER_CLIENT_TLS_PROTOCOLS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Which TLS protocol versions are allowed. Allowed values: ``tlsv1.0``,
``tlsv1.1``, ``tlsv1.2``, ``tlsv1.3``. Shortcuts: ``all``
(tlsv1.0,tlsv1.1,tlsv1.2,tlsv1.3), ``secure`` (tlsv1.2,tlsv1.3),
``legacy`` (all).

Default: ``secure``

ENV: ``PGBOUNCER_CLIENT_TLS_CIPHERS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Default: ``fast``

ENV: ``PGBOUNCER_CLIENT_TLS_ECDHCURVE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Elliptic Curve name to use for ECDH key exchanges.

Allowed values: ``none`` (DH is disabled), ``auto`` (256-bit ECDH),
curve name.

Default: ``auto``

ENV: ``PGBOUNCER_CLIENT_TLS_DHEPARAMS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

DHE key exchange type.

Allowed values: ``none`` (DH is disabled), ``auto`` (2048-bit DH),
``legacy`` (1024-bit DH).

Default: ``auto``

ENV: ``PGBOUNCER_SERVER_TLS_SSLMODE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TLS mode to use for connections to PostgreSQL servers. TLS connections
are disabled by default.

``disable`` : Plain TCP. TCP is not even requested from the server.
Default.

``allow`` : FIXME: if server rejects plain, try TLS?

``prefer`` : TLS connection is always requested first from PostgreSQL,
when refused connection will be established over plain TCP. Server
certificate is not validated.

``require`` : Connection must go over TLS. If server rejects it, plain
TCP is not attempted. Server certificate is not validated.

``verify-ca`` : Connection must go over TLS and server certificate must
be valid according to ``server_tls_ca_file``. Server host name is not
checked against certificate.

``verify-full`` : Connection must go over TLS and server certificate
must be valid according to ``server_tls_ca_file``. Server host name must
match certificate information.

ENV: ``PGBOUNCER_SERVER_TLS_CA_FILE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Root certificate file to validate PostgreSQL server certificates.

Default: not set

ENV: ``PGBOUNCER_SERVER_TLS_KEY_FILE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Private key for PgBouncer to authenticate against PostgreSQL server.

Default: not set

ENV: ``PGBOUNCER_SERVER_TLS_CERT_FILE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Certificate for private key. PostgreSQL server can validate it.

Default: not set

ENV: ``PGBOUNCER_SERVER_TLS_PROTOCOLS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Which TLS protocol versions are allowed. Allowed values: ``tlsv1.0``,
``tlsv1.1``, ``tlsv1.2``, ``tlsv1.3``. Shortcuts: ``all``
(tlsv1.0,tlsv1.1,tlsv1.2,tlsv1.3), ``secure`` (tlsv1.2,tlsv1.3),
``legacy`` (all).

Default: ``all``

ENV: ``PGBOUNCER_SERVER_TLS_CIPHERS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Default: ``HIGH:MEDIUM:+3DES:!aNULL``

Dangerous timeouts
~~~~~~~~~~~~~~~~~~

Setting the following timeouts can cause unexpected errors.

ENV: ``PGBOUNCER_QUERY_TIMEOUT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Queries running longer than that are canceled. This should be used only
with slightly smaller server-side statement_timeout, to apply only for
network problems. [seconds]

Default: ``0.0`` (disabled)

ENV: ``PGBOUNCER_QUERY_WAIT_TIMEOUT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Maximum time queries are allowed to spend waiting for execution. If the
query is not assigned to a server during that time, the client is
disconnected. This is used to prevent unresponsive servers from grabbing
up connections. [seconds]

It also helps when the server is down or database rejects connections
for any reason. If this is disabled, clients will be queued
indefinitely.

Default: ``120``

ENV: ``PGBOUNCER_CLIENT_IDLE_TIMEOUT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Client connections idling longer than this many seconds are closed. This
should be larger than the client-side connection lifetime settings, and
only used for network problems. [seconds]

Default: ``0.0`` (disabled)

ENV: ``PGBOUNCER_IDLE_TRANSACTION_TIMEOUT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a client has been in "idle in transaction" state longer, it will be
disconnected. [seconds]

Default: ``0.0`` (disabled)

ENV: ``PGBOUNCER_SUSPEND_TIMEOUT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

How many seconds to wait for buffer flush during SUSPEND or reboot (-R).
A connection is dropped if the flush does not succeed.

Default: ``10``

Low-level network settings
~~~~~~~~~~~~~~~~~~~~~~~~~~

ENV: ``PGBOUNCER_PKT_BUF``
^^^^^^^^^^^^^^^^^^^^^^^^^^

Internal buffer size for packets. Affects size of TCP packets sent and
general memory usage. Actual libpq packets can be larger than this, so
no need to set it large.

Default: ``4096``

ENV: ``PGBOUNCER_MAX_PACKET_SIZE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Maximum size for PostgreSQL packets that PgBouncer allows through. One
packet is either one query or one result set row. Full result set can be
larger.

Default: ``2147483647``

ENV: ``PGBOUNCER_LISTEN_BACKLOG``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Backlog argument for listen(2). Determines how many new unanswered
connection attempts are kept in queue. When the queue is full, further
new connections are dropped.

Default: ``128``

ENV: ``PGBOUNCER_SBUF_LOOPCNT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

How many times to process data on one connection, before proceeding.
Without this limit, one connection with a big result set can stall
PgBouncer for a long time. One loop processes one ``pkt_buf`` amount of
data. 0 means no limit.

Default: ``5``

ENV: ``PGBOUNCER_TCP_DEFER_ACCEPT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For details on this and other TCP options, please see ``man 7 tcp``.

Default: ``45`` on Linux, otherwise ``0``

ENV: ``PGBOUNCER_TCP_SOCKET_BUFFER``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Default: not set

ENV: ``PGBOUNCER_TCP_KEEPALIVE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Turns on basic keepalive with OS defaults.

On Linux, the system defaults are tcp_keepidle=7200, tcp_keepintvl=75,
tcp_keepcnt=9. They are probably similar on other operating systems.

Default: ``1``

ENV: ``PGBOUNCER_TCP_KEEPCNT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Default: not set

ENV: ``PGBOUNCER_TCP_KEEPIDLE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Default: not set

ENV: ``PGBOUNCER_TCP_KEEPINTVL``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Default: not set

ENV: ``PGBOUNCER_TCP_USER_TIMEOUT``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the ``TCP_USER_TIMEOUT`` socket option. This specifies the maximum
amount of time in milliseconds that transmitted data may remain
unacknowledged before the TCP connection is forcibly closed. If set to
0, then operating system's default is used.

This is currently only supported on Linux.

Default: ``0``

Section [databases]
~~~~~~~~~~~~~~~~~~~

This contains key=value pairs where the key will be taken as a database
name and the value as a libpq connection string style list of key=value
pairs. Not all features known from libpq can be used (service=,
.pgpass), since the actual libpq is not used.

The database name can contain characters ``_0-9A-Za-z`` without quoting.
Names that contain other characters need to be quoted with standard SQL
identifier quoting: double quotes, with "" for a single instance of a
double quote.

"*" acts as a fallback database: if the exact name does not exist, its
value is taken as connection string for requested database. Such
automatically created database entries are cleaned up if they stay idle
longer than the time specified by the ``autodb_idle_timeout`` parameter.

ENV: ``DATABASES_DBNAME``
^^^^^^^^^^^^^^^^^^^^^^^^^

Destination database name.

Default: same as client-side database name

ENV: ``DATABASES_HOST``
^^^^^^^^^^^^^^^^^^^^^^^

Host name or IP address to connect to. Host names are resolved at
connection time, the result is cached per ``dns_max_ttl`` parameter.
When a host name's resolution changes, existing server connections are
automatically closed when they are released (according to the pooling
mode), and new server connections immediately use the new resolution. If
DNS returns several results, they are used in round-robin manner.

Default: not set, meaning to use a Unix socket

ENV: ``DATABASES_PORT``
^^^^^^^^^^^^^^^^^^^^^^^

Default: ``5432``

ENV: ``DATABASES_USER``
^^^^^^^^^^^^^^^^^^^^^^^

If ``user=`` is set, all connections to the destination database will be
done with the specified user, meaning that there will be only one pool
for this database.

Otherwise, PgBouncer logs into the destination database with the client
user name, meaning that there will be one pool per user.

ENV: ``DATABASES_PASSWORD``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The length for ``password`` is limited to 160 characters maximum.

If no password is specified here, the password from the ``auth_file`` or
``auth_query`` will be used.

ENV: ``DATABASES_AUTH_USER``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Override of the global ``auth_user`` setting, if specified.

ENV: ``DATABASES_POOL_SIZE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the maximum size of pools for this database. If not set, the
``default_pool_size`` is used.

ENV: ``DATABASES_RESERVE_POOL``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set additional connections for this database. If not set,
``reserve_pool_size`` is used.

ENV: ``DATABASES_CONNECT_QUERY``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Query to be executed after a connection is established, but before
allowing the connection to be used by any clients. If the query raises
errors, they are logged but ignored otherwise.

ENV: ``DATABASES_POOL_MODE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the pool mode specific to this database. If not set, the default
``pool_mode`` is used.

ENV: ``DATABASES_MAX_DB_CONNECTIONS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Configure a database-wide maximum (i.e. all pools within the database
will not have more than this many server connections).

ENV: ``DATABASES_CLIENT_ENCODING``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Ask specific ``client_encoding`` from server.

ENV: ``DATABASES_DATESTYLE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Ask specific ``datestyle`` from server.

ENV: ``DATABASES_TIMEZONE``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Ask specific ``timezone`` from server.

Section [users]
~~~~~~~~~~~~~~~

This contains key=value pairs where the key will be taken as a user name
and the value as a libpq connection string style list of key=value pairs
of configuration settings specific for this user. Only a few settings
are available here.

ENV: ``USERS_POOL_MODE``
^^^^^^^^^^^^^^^^^^^^^^^^

Set the pool mode to be used for all connections from this user. If not
set, the database or default ``pool_mode`` is used.

ENV: ``USERS_MAX_USER_CONNECTIONS``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Configure a maximum for the user (i.e. all pools with the user will not
have more than this many server connections).

HBA file format
~~~~~~~~~~~~~~~

It follows the format of the PostgreSQL ``pg_hba.conf`` file (see
https://www.postgresql.org/docs/current/auth-pg-hba-conf.html).

-  Supported record types: ``local``, ``host``, ``hostssl``,
   ``hostnossl``.
-  Database field: Supports ``all``, ``sameuser``, ``@file``, multiple
   names. Not supported: ``replication``, ``samerole``, ``samegroup``.
-  User name field: Supports ``all``, ``@file``, multiple names. Not
   supported: ``+groupname``.
-  Address field: Supports IPv4, IPv6. Not supported: DNS names, domain
   prefixes.
-  Auth-method field: Only methods supported by PgBouncer's
   ``auth_type`` are supported, except ``any`` and ``pam``, which only
   work globally. User name map (``map=``) parameter is not supported.

Metrics configurations
~~~~~~~~~~~~~~~~~~~~~~

The image includes a metric provider in prometheus format, metrics are
collected aggregated from all instances of ``pgbouncer``.

ENV: ``METRICS_ADDR``
^^^^^^^^^^^^^^^^^^^^^

Address of listening to metrics provider

Default: ``::1``

ENV: ``METRICS_PORT``
^^^^^^^^^^^^^^^^^^^^^

Port of listening to metrics provider

Default: ``8080``

Provided metrics
~~~~~~~~~~~~~~~~

-  ``pgbouncer_stats_total_xact_count`` - "total_xact_count" field for
   record query "show stats"

   -  ``pgbouncer_stats_total_xact_count_total`` - ``counter``
   -  ``pgbouncer_stats_total_xact_count_created`` - ``gauge``

-  ``pgbouncer_stats_total_query_count`` - "total_query_count" field for
   record query "show stats"

   -  ``pgbouncer_stats_total_query_count_total`` - ``counter``
   -  ``pgbouncer_stats_total_query_count_created`` - ``gauge``

-  ``pgbouncer_stats_total_received`` - "total_received" field for
   record query "show stats"

   -  ``pgbouncer_stats_total_received_total`` - ``counter``
   -  ``pgbouncer_stats_total_received_created`` - ``gauge``

-  ``pgbouncer_stats_total_sent`` - "total_sent" field for record query
   "show stats"

   -  ``pgbouncer_stats_total_sent_total`` - ``counter``
   -  ``pgbouncer_stats_total_sent_created`` - ``gauge``

-  ``pgbouncer_stats_total_xact_time`` - "total_xact_time" field for
   record query "show stats"

   -  ``pgbouncer_stats_total_xact_time_total`` - ``counter``
   -  ``pgbouncer_stats_total_xact_time_created`` - ``gauge``

-  ``pgbouncer_stats_total_query_time`` - "total_query_time" field for
   record query "show stats"

   -  ``pgbouncer_stats_total_query_time_total`` - ``counter``
   -  ``pgbouncer_stats_total_query_time_created`` - ``gauge``

-  ``pgbouncer_stats_total_wait_time`` - "total_wait_time" field for
   record query "show stats"

   -  ``pgbouncer_stats_total_wait_time_total`` - ``counter``
   -  ``pgbouncer_stats_total_wait_time_created`` - ``gauge``

-  ``pgbouncer_stats_avg_xact_count`` - "avg_xact_count" field for
   record query "show stats"

   -  ``pgbouncer_stats_avg_xact_count_total`` - ``counter``
   -  ``pgbouncer_stats_avg_xact_count_created`` - ``gauge``

-  ``pgbouncer_stats_avg_query_count`` - "avg_query_count" field for
   record query "show stats"

   -  ``pgbouncer_stats_avg_query_count_total`` - ``counter``
   -  ``pgbouncer_stats_avg_query_count_created`` - ``gauge``

-  ``pgbouncer_stats_avg_recv`` - "avg_recv" field for record query
   "show stats"

   -  ``pgbouncer_stats_avg_recv_total`` - ``counter``
   -  ``pgbouncer_stats_avg_recv_created`` - ``gauge``

-  ``pgbouncer_stats_avg_sent`` - "avg_sent" field for record query
   "show stats"

   -  ``pgbouncer_stats_avg_sent_total`` - ``counter``
   -  ``pgbouncer_stats_avg_sent_created`` - ``gauge``

-  ``pgbouncer_stats_avg_xact_time`` - "avg_xact_time" field for record
   query "show stats"

   -  ``pgbouncer_stats_avg_xact_time_total`` - ``counter``
   -  ``pgbouncer_stats_avg_xact_time_created`` - ``gauge``

-  ``pgbouncer_stats_avg_query_time`` - "avg_query_time" field for
   record query "show stats"

   -  ``pgbouncer_stats_avg_query_time_total`` - ``counter``
   -  ``pgbouncer_stats_avg_query_time_created`` - ``gauge``

-  ``pgbouncer_stats_avg_wait_time`` - "avg_wait_time" field for record
   query "show stats"

   -  ``pgbouncer_stats_avg_wait_time_total`` - ``counter``
   -  ``pgbouncer_stats_avg_wait_time_created`` - ``gauge``

-  ``pgbouncer_clients_port`` - "port" field for record query "show
   clients"

   -  ``pgbouncer_clients_port_total`` - ``counter``
   -  ``pgbouncer_clients_port_created`` - ``gauge``

-  ``pgbouncer_clients_local_port`` - "local_port" field for record
   query "show clients"

   -  ``pgbouncer_clients_local_port_total`` - ``counter``
   -  ``pgbouncer_clients_local_port_created`` - ``gauge``

-  ``pgbouncer_clients_wait`` - "wait" field for record query "show
   clients"

   -  ``pgbouncer_clients_wait_total`` - ``counter``
   -  ``pgbouncer_clients_wait_created`` - ``gauge``

-  ``pgbouncer_clients_wait_us`` - "wait_us" field for record query
   "show clients"

   -  ``pgbouncer_clients_wait_us_total`` - ``counter``
   -  ``pgbouncer_clients_wait_us_created`` - ``gauge``

-  ``pgbouncer_clients_close_needed`` - "close_needed" field for record
   query "show clients"

   -  ``pgbouncer_clients_close_needed_total`` - ``counter``
   -  ``pgbouncer_clients_close_needed_created`` - ``gauge``

-  ``pgbouncer_clients_remote_pid`` - "remote_pid" field for record
   query "show clients"

   -  ``pgbouncer_clients_remote_pid_total`` - ``counter``
   -  ``pgbouncer_clients_remote_pid_created`` - ``gauge``

-  ``pgbouncer_pools_cl_active`` - "cl_active" field for record query
   "show pools"

   -  ``pgbouncer_pools_cl_active_total`` - ``counter``
   -  ``pgbouncer_pools_cl_active_created`` - ``gauge``

-  ``pgbouncer_pools_cl_waiting`` - "cl_waiting" field for record query
   "show pools"

   -  ``pgbouncer_pools_cl_waiting_total`` - ``counter``
   -  ``pgbouncer_pools_cl_waiting_created`` - ``gauge``

-  ``pgbouncer_pools_sv_active`` - "sv_active" field for record query
   "show pools"

   -  ``pgbouncer_pools_sv_active_total`` - ``counter``
   -  ``pgbouncer_pools_sv_active_created`` - ``gauge``

-  ``pgbouncer_pools_sv_idle`` - "sv_idle" field for record query "show
   pools"

   -  ``pgbouncer_pools_sv_idle_total`` - ``counter``
   -  ``pgbouncer_pools_sv_idle_created`` - ``gauge``

-  ``pgbouncer_pools_sv_used`` - "sv_used" field for record query "show
   pools"

   -  ``pgbouncer_pools_sv_used_total`` - ``counter``
   -  ``pgbouncer_pools_sv_used_created`` - ``gauge``

-  ``pgbouncer_pools_sv_tested`` - "sv_tested" field for record query
   "show pools"

   -  ``pgbouncer_pools_sv_tested_total`` - ``counter``
   -  ``pgbouncer_pools_sv_tested_created`` - ``gauge``

-  ``pgbouncer_pools_sv_login`` - "sv_login" field for record query
   "show pools"

   -  ``pgbouncer_pools_sv_login_total`` - ``counter``
   -  ``pgbouncer_pools_sv_login_created`` - ``gauge``

-  ``pgbouncer_pools_maxwait`` - "maxwait" field for record query "show
   pools"

   -  ``pgbouncer_pools_maxwait_total`` - ``counter``
   -  ``pgbouncer_pools_maxwait_created`` - ``gauge``

-  ``pgbouncer_pools_maxwait_us`` - "maxwait_us" field for record query
   "show pools"

   -  ``pgbouncer_pools_maxwait_us_total`` - ``counter``
   -  ``pgbouncer_pools_maxwait_us_created`` - ``gauge``

-  ``pgbouncer_lists_items`` - "items" field for record query "show
   lists"

   -  ``pgbouncer_lists_items_total`` - ``counter``
   -  ``pgbouncer_lists_items_created`` - ``gauge``

-  ``pgbouncer_users`` Result of query "show users"

   -  ``pgbouncer_users`` - ``gauge``

-  ``pgbouncer_databases_port`` - "port" field for record query "show
   databases"

   -  ``pgbouncer_databases_port_total`` - ``counter``
   -  ``pgbouncer_databases_port_created`` - ``gauge``

-  ``pgbouncer_databases_pool_size`` - "pool_size" field for record
   query "show databases"

   -  ``pgbouncer_databases_pool_size_total`` - ``counter``
   -  ``pgbouncer_databases_pool_size_created`` - ``gauge``

-  ``pgbouncer_databases_reserve_pool`` - "reserve_pool" field for
   record query "show databases"

   -  ``pgbouncer_databases_reserve_pool_total`` - ``counter``
   -  ``pgbouncer_databases_reserve_pool_created`` - ``gauge``

-  ``pgbouncer_databases_max_connections`` - "max_connections" field for
   record query "show databases"

   -  ``pgbouncer_databases_max_connections_total`` - ``counter``
   -  ``pgbouncer_databases_max_connections_created`` - ``gauge``

-  ``pgbouncer_databases_current_connections`` - "current_connections"
   field for record query "show databases"

   -  ``pgbouncer_databases_current_connections_total`` - ``counter``
   -  ``pgbouncer_databases_current_connections_created`` - ``gauge``

-  ``pgbouncer_databases_paused`` - "paused" field for record query
   "show databases"

   -  ``pgbouncer_databases_paused_total`` - ``counter``
   -  ``pgbouncer_databases_paused_created`` - ``gauge``

-  ``pgbouncer_databases_disabled`` - "disabled" field for record query
   "show databases"

   -  ``pgbouncer_databases_disabled_total`` - ``counter``
   -  ``pgbouncer_databases_disabled_created`` - ``gauge``

-  ``pgbouncer_fds_fd`` - "fd" field for record query "show fds"

   -  ``pgbouncer_fds_fd_total`` - ``counter``
   -  ``pgbouncer_fds_fd_created`` - ``gauge``

-  ``pgbouncer_fds_port`` - "port" field for record query "show fds"

   -  ``pgbouncer_fds_port_total`` - ``counter``
   -  ``pgbouncer_fds_port_created`` - ``gauge``

-  ``pgbouncer_fds_cancel`` - "cancel" field for record query "show fds"

   -  ``pgbouncer_fds_cancel_total`` - ``counter``
   -  ``pgbouncer_fds_cancel_created`` - ``gauge``

-  ``pgbouncer_fds_link`` - "link" field for record query "show fds"

   -  ``pgbouncer_fds_link_total`` - ``counter``
   -  ``pgbouncer_fds_link_created`` - ``gauge``

-  ``pgbouncer_sockets_port`` - "port" field for record query "show
   sockets"

   -  ``pgbouncer_sockets_port_total`` - ``counter``
   -  ``pgbouncer_sockets_port_created`` - ``gauge``

-  ``pgbouncer_sockets_local_port`` - "local_port" field for record
   query "show sockets"

   -  ``pgbouncer_sockets_local_port_total`` - ``counter``
   -  ``pgbouncer_sockets_local_port_created`` - ``gauge``

-  ``pgbouncer_sockets_wait`` - "wait" field for record query "show
   sockets"

   -  ``pgbouncer_sockets_wait_total`` - ``counter``
   -  ``pgbouncer_sockets_wait_created`` - ``gauge``

-  ``pgbouncer_sockets_wait_us`` - "wait_us" field for record query
   "show sockets"

   -  ``pgbouncer_sockets_wait_us_total`` - ``counter``
   -  ``pgbouncer_sockets_wait_us_created`` - ``gauge``

-  ``pgbouncer_sockets_close_needed`` - "close_needed" field for record
   query "show sockets"

   -  ``pgbouncer_sockets_close_needed_total`` - ``counter``
   -  ``pgbouncer_sockets_close_needed_created`` - ``gauge``

-  ``pgbouncer_sockets_remote_pid`` - "remote_pid" field for record
   query "show sockets"

   -  ``pgbouncer_sockets_remote_pid_total`` - ``counter``
   -  ``pgbouncer_sockets_remote_pid_created`` - ``gauge``

-  ``pgbouncer_sockets_recv_pos`` - "recv_pos" field for record query
   "show sockets"

   -  ``pgbouncer_sockets_recv_pos_total`` - ``counter``
   -  ``pgbouncer_sockets_recv_pos_created`` - ``gauge``

-  ``pgbouncer_sockets_pkt_pos`` - "pkt_pos" field for record query
   "show sockets"

   -  ``pgbouncer_sockets_pkt_pos_total`` - ``counter``
   -  ``pgbouncer_sockets_pkt_pos_created`` - ``gauge``

-  ``pgbouncer_sockets_pkt_remain`` - "pkt_remain" field for record
   query "show sockets"

   -  ``pgbouncer_sockets_pkt_remain_total`` - ``counter``
   -  ``pgbouncer_sockets_pkt_remain_created`` - ``gauge``

-  ``pgbouncer_sockets_send_pos`` - "send_pos" field for record query
   "show sockets"

   -  ``pgbouncer_sockets_send_pos_total`` - ``counter``
   -  ``pgbouncer_sockets_send_pos_created`` - ``gauge``

-  ``pgbouncer_sockets_send_remain`` - "send_remain" field for record
   query "show sockets"

   -  ``pgbouncer_sockets_send_remain_total`` - ``counter``
   -  ``pgbouncer_sockets_send_remain_created`` - ``gauge``

-  ``pgbouncer_sockets_pkt_avail`` - "pkt_avail" field for record query
   "show sockets"

   -  ``pgbouncer_sockets_pkt_avail_total`` - ``counter``
   -  ``pgbouncer_sockets_pkt_avail_created`` - ``gauge``

-  ``pgbouncer_sockets_send_avail`` - "send_avail" field for record
   query "show sockets"

   -  ``pgbouncer_sockets_send_avail_total`` - ``counter``
   -  ``pgbouncer_sockets_send_avail_created`` - ``gauge``

-  ``pgbouncer_active_sockets_port`` - "port" field for record query
   "show active_sockets"

   -  ``pgbouncer_active_sockets_port_total`` - ``counter``
   -  ``pgbouncer_active_sockets_port_created`` - ``gauge``

-  ``pgbouncer_active_sockets_local_port`` - "local_port" field for
   record query "show active_sockets"

   -  ``pgbouncer_active_sockets_local_port_total`` - ``counter``
   -  ``pgbouncer_active_sockets_local_port_created`` - ``gauge``

-  ``pgbouncer_active_sockets_wait`` - "wait" field for record query
   "show active_sockets"

   -  ``pgbouncer_active_sockets_wait_total`` - ``counter``
   -  ``pgbouncer_active_sockets_wait_created`` - ``gauge``

-  ``pgbouncer_active_sockets_wait_us`` - "wait_us" field for record
   query "show active_sockets"

   -  ``pgbouncer_active_sockets_wait_us_total`` - ``counter``
   -  ``pgbouncer_active_sockets_wait_us_created`` - ``gauge``

-  ``pgbouncer_active_sockets_close_needed`` - "close_needed" field for
   record query "show active_sockets"

   -  ``pgbouncer_active_sockets_close_needed_total`` - ``counter``
   -  ``pgbouncer_active_sockets_close_needed_created`` - ``gauge``

-  ``pgbouncer_active_sockets_remote_pid`` - "remote_pid" field for
   record query "show active_sockets"

   -  ``pgbouncer_active_sockets_remote_pid_total`` - ``counter``
   -  ``pgbouncer_active_sockets_remote_pid_created`` - ``gauge``

-  ``pgbouncer_active_sockets_recv_pos`` - "recv_pos" field for record
   query "show active_sockets"

   -  ``pgbouncer_active_sockets_recv_pos_total`` - ``counter``
   -  ``pgbouncer_active_sockets_recv_pos_created`` - ``gauge``

-  ``pgbouncer_active_sockets_pkt_pos`` - "pkt_pos" field for record
   query "show active_sockets"

   -  ``pgbouncer_active_sockets_pkt_pos_total`` - ``counter``
   -  ``pgbouncer_active_sockets_pkt_pos_created`` - ``gauge``

-  ``pgbouncer_active_sockets_pkt_remain`` - "pkt_remain" field for
   record query "show active_sockets"

   -  ``pgbouncer_active_sockets_pkt_remain_total`` - ``counter``
   -  ``pgbouncer_active_sockets_pkt_remain_created`` - ``gauge``

-  ``pgbouncer_active_sockets_send_pos`` - "send_pos" field for record
   query "show active_sockets"

   -  ``pgbouncer_active_sockets_send_pos_total`` - ``counter``
   -  ``pgbouncer_active_sockets_send_pos_created`` - ``gauge``

-  ``pgbouncer_active_sockets_send_remain`` - "send_remain" field for
   record query "show active_sockets"

   -  ``pgbouncer_active_sockets_send_remain_total`` - ``counter``
   -  ``pgbouncer_active_sockets_send_remain_created`` - ``gauge``

-  ``pgbouncer_active_sockets_pkt_avail`` - "pkt_avail" field for record
   query "show active_sockets"

   -  ``pgbouncer_active_sockets_pkt_avail_total`` - ``counter``
   -  ``pgbouncer_active_sockets_pkt_avail_created`` - ``gauge``

-  ``pgbouncer_active_sockets_send_avail`` - "send_avail" field for
   record query "show active_sockets"

   -  ``pgbouncer_active_sockets_send_avail_total`` - ``counter``
   -  ``pgbouncer_active_sockets_send_avail_created`` - ``gauge``

-  ``pgbouncer_version`` Result of query "show version"

   -  ``pgbouncer_version`` - ``gauge``
