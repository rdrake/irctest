"""irctest controller for Nefarious IRCd (evilnet/nefarious2, ircv3.2-upgrade).

Nefarious is an ircu derivative with an extensive IRCv3 stack. This
controller replaces upstream's stub (a bare Ircu2Controller subclass) so that
irctest exercises those extensions.

Services: Nefarious links to services over P10, so the services package has to
speak P10 too. Run with ``--services-controller=irctest.controllers.x3_services``
to get AuthServ (accounts, SASL) from X3.
"""

import shutil
from typing import Optional, Type

from irctest.basecontrollers import (
    BaseServerController,
    DirectoryBasedController,
    NotImplementedByController,
)
from irctest.specifications import Capabilities, OptionalBehaviors

TEMPLATE_CONFIG = """\
General {{
    name = "My.Little.Server";
    numeric = 42;
    description = "irctest instance";
}};

Port {{
    vhost = "{hostname}";
    port = {port};
}};

{extra_ports}

Class {{
    name = "Client";
    pingfreq = 5 minutes;
    sendq = 160000;
    recvq = 10240;
    maxlinks = 1024;
    fakelagminimum = 0;
    fakelagfactor = 0;
}};

Client {{
    username = "*";
    class = "Client";
    {password_field}
}};

Operator {{
    local = no;
    host = "*@*";
    password = "$PLAIN$operpassword";
    name = "operuser";
    class = "Client";
}};

{services_config}

features {{
    "PPATH" = "{pidfile}";
    "HIS_SERVERNAME" = "My.Little.Server";
    "MSGID" = "TRUE";
    "HOST_HIDING" = "FALSE";
    # Otherwise a login sets +x even with HOST_HIDING off, and the 396 that
    # follows 903 is read as the reply to the client's next command.
    "SASL_AUTOHIDEHOST" = "FALSE";
    "NOIDENT" = "TRUE";
    # The default 30s NICKDELAY breaks tests that change nick quickly
    # (e.g. MONITOR's testNickChange).
    "NICKDELAY" = "0";
    "CONNEXIT_NOTICES" = "FALSE";
    "CAP_server_time" = "TRUE";
    "CAP_echo_message" = "TRUE";
    "CAP_batch" = "TRUE";
    "CAP_labeled_response" = "TRUE";
    "CAP_message_tags" = "TRUE";
    "CAP_account_tag" = "TRUE";
    "CAP_setname" = "TRUE";
    "CAP_multi_prefix" = "TRUE";
    "CAP_extended_join" = "TRUE";
    "CAP_away_notify" = "TRUE";
    "CAP_account_notify" = "TRUE";
    "CAP_cap_notify" = "TRUE";
    "CAP_standard_replies" = "TRUE";
    "CAP_chghost" = "TRUE";
    "CAP_invite_notify" = "TRUE";
    "CAP_sasl" = "TRUE";
    "CAP_draft_multiline" = "TRUE";
    "CAP_draft_message_redaction" = "TRUE";
    "CAP_draft_chathistory" = "TRUE";
    "CAP_draft_read_marker" = "TRUE";
    "CAP_draft_channel_rename" = "TRUE";
    "CAP_draft_metadata_2" = "TRUE";
    "EXCEPTS" = "TRUE";
    # CHATHISTORY_DB is a path (default "history"), not a boolean. Keep the
    # RocksDB store inside the per-test directory.
    "CHATHISTORY_DB" = "{chathistory_db}";
    "CHATHISTORY_STORE" = "TRUE";
    "CHATHISTORY_PRIVATE" = "TRUE";
    "CHATHISTORY_REQUIRE_AUTH" = "FALSE";
    "SSL_CERTFILE" = "{ssl_pem}";
    "SSL_KEYFILE" = "{ssl_pem}";
    {ssl_features}
    {services_features}
}};
"""

TEMPLATE_SSL_PORT = """\
Port {{
    vhost = "{hostname}";
    port = {ssl_port};
    ssl = yes;
}};
"""

TEMPLATE_WEBSOCKET_PORT = """\
Port {{
    vhost = "{hostname}";
    port = {websocket_port};
    websocket = yes;
}};
"""

TEMPLATE_SERVICES_CONFIG = """\
Port {{
    vhost = "{hostname}";
    port = {services_port};
    server = yes;
}};

Class {{
    name = "Server";
    pingfreq = 1 minutes;
    connectfreq = 5 minutes;
    maxlinks = 1;
    sendq = 9000000;
}};

Connect {{
    name = "My.Little.Services";
    host = "{services_ip}";
    password = "password";
    port = {services_port};
    class = "Server";
    hub;
    autoconnect = no;
}};

UWorld {{
    name = "My.Little.Services";
}};
"""

TEMPLATE_SERVICES_FEATURES = """\
    "SASL_SERVER" = "My.Little.Services";
    # X3 does not announce its mechanisms over P10 (SASL M), so Nefarious
    # advertises sasl only when a default list is configured.
    "SASL_DEFAULT_MECHANISMS" = "{sasl_mechanisms}";
    "LOC_DEFAULT_SERVICE" = "{nickserv}";
"""


class NefariousController(BaseServerController, DirectoryBasedController):
    software_name = "Nefarious"
    supports_sts = False
    extban_mute_char = None
    # Overridden by the services controller's choice of AuthServ nick.
    nickserv = "AuthServ"
    # SASL is relayed to services over P10; X3 implements PLAIN (and
    # EXTERNAL, which irctest does not test against servers).
    supported_sasl_mechanisms = {"PLAIN"}

    # The IRCv3 capabilities in irctest's Capabilities enum that Nefarious
    # implements. Not listed: EXTENDED_MONITOR and STS (not implemented).
    # draft/metadata-3 is not in the enum; Nefarious offers draft/metadata-2.
    capabilities = frozenset(
        {
            Capabilities.ACCOUNT_NOTIFY,
            Capabilities.ACCOUNT_TAG,
            Capabilities.AWAY_NOTIFY,
            Capabilities.BATCH,
            Capabilities.ECHO_MESSAGE,
            Capabilities.EXTENDED_JOIN,
            Capabilities.LABELED_RESPONSE,
            Capabilities.MESSAGE_REDACTION,
            Capabilities.MESSAGE_TAGS,
            Capabilities.MULTILINE,
            Capabilities.MULTI_PREFIX,
            Capabilities.READ_MARKER,
            Capabilities.SERVER_TIME,
            Capabilities.SETNAME,
        }
    )

    optional_behaviors = frozenset(
        {
            OptionalBehaviors.BAN_EXCEPTION_MODE,
            OptionalBehaviors.INVITE_OVERRIDES_LIMIT,
        }
    )

    def create_config(self) -> None:
        super().create_config()
        with self.open_file("server.conf"):
            pass

    def run(
        self,
        hostname: str,
        port: int,
        *,
        password: Optional[str],
        ssl: bool,
        run_services: bool,
        faketime: Optional[str],
        websocket_hostname: Optional[str],
        websocket_port: Optional[int],
    ) -> None:
        if run_services and not hasattr(self, "services_controller_class"):
            raise NotImplementedByController("Services")
        assert self.proc is None
        self.port = port
        self.hostname = hostname
        self.create_config()

        password_field = 'password = "{}";'.format(password) if password else ""
        assert self.directory
        pidfile = self.directory / "ircd.pid"

        # Nefarious loads SSL_CERTFILE at startup even without an SSL
        # listener, and exits ("Failed to initialize SSL contexts") if it is
        # missing, so the PEM (key + cert in one file) is always written.
        self.gen_ssl()
        ssl_pem = self.directory / "ircd.pem"
        with open(ssl_pem, "w") as out:
            out.write(self.key_path.read_text())
            out.write(self.pem_path.read_text())

        extra_ports = ""
        ssl_features = ""
        if ssl:
            (_, ssl_port) = self.get_hostname_and_port()
            extra_ports += TEMPLATE_SSL_PORT.format(
                hostname=hostname, ssl_port=ssl_port
            )
            ssl_features = '"CAP_tls" = "TRUE";'

        if websocket_hostname is not None and websocket_port is not None:
            extra_ports += TEMPLATE_WEBSOCKET_PORT.format(
                hostname=websocket_hostname, websocket_port=websocket_port
            )

        services_config = ""
        services_features = ""
        services_port = None
        if run_services:
            (_, services_port) = self.get_hostname_and_port()
            self.nickserv = getattr(
                self.services_controller_class, "nickserv", self.nickserv
            )
            services_config = TEMPLATE_SERVICES_CONFIG.format(
                hostname=hostname,
                services_port=services_port,
                services_ip=getattr(
                    self.services_controller_class, "bind_address", "127.0.0.1"
                ),
            )
            services_features = TEMPLATE_SERVICES_FEATURES.format(
                nickserv=self.nickserv,
                sasl_mechanisms=",".join(
                    getattr(
                        self.services_controller_class,
                        "sasl_mechanisms",
                        sorted(self.supported_sasl_mechanisms),
                    )
                ),
            )

        with self.open_file("server.conf") as fd:
            fd.write(
                TEMPLATE_CONFIG.format(
                    hostname=hostname,
                    port=port,
                    password_field=password_field,
                    pidfile=pidfile,
                    extra_ports=extra_ports,
                    ssl_pem=ssl_pem,
                    ssl_features=ssl_features,
                    services_config=services_config,
                    services_features=services_features,
                    chathistory_db=self.directory / "history",
                )
            )

        if faketime and shutil.which("faketime"):
            faketime_cmd = ["faketime", "-f", faketime]
            self.faketime_enabled = True
        else:
            faketime_cmd = []

        self.proc = self.execute(
            [
                *faketime_cmd,
                "ircd",
                "-n",  # don't detach
                "-f",
                self.directory / "server.conf",
                "-x",
                "DEBUG",
            ],
        )

        if run_services:
            assert services_port is not None
            self.wait_for_port()
            self.services_controller = self.services_controller_class(
                self.test_config, self
            )
            self.services_controller.run(
                protocol="nefarious",
                server_hostname=hostname,
                server_port=services_port,
            )


def get_irctest_controller_class() -> Type[NefariousController]:
    return NefariousController
