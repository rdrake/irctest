"""irctest services controller for X3 (https://github.com/evilnet/x3).

X3 speaks P10 only, so it pairs with P10 servers (Nefarious). Accounts and
SASL (PLAIN, EXTERNAL) come from AuthServ, X3's account service.
"""

import os
from pathlib import Path
import shutil
import socket
import time
from typing import List, Optional, Type

import irctest
from irctest.basecontrollers import BaseServicesController, DirectoryBasedController
from irctest.client_mock import ClientMock
from irctest.irc_utils.message_parser import Message

TEMPLATE_CONFIG = """\
"uplinks" {{
    "uplink" {{
        "address" "{server_address}";
        "port" "{server_port}";
        "password" "password";
        "uplink_password" "password";
        "enabled" "1";
        "max_tries" "10";
    }};
}};

"server" {{
    "hostname" "My.Little.Services";
    "description" "irctest services";
    "network" "irctest";
    "hidden_host" "users.irctest";
    "hidden_host_type" "1";
    "numeric" "10";
    "type" "9";
    "max_users" "256";
    "force_n2k" "1";
    "ping_freq" "60";
    "ping_timeout" "90";
    "max_cycles" "30";
    "admin" ("irctest", "irctest", "irctest <irctest@example.org>");
    "extended_accounts" "1";
    "reliable_clock" "1";
}};

"services" {{
    "nickserv" {{
        "nick" "{nickserv}";
        "default_hostmask" "1";
        "warn_clone_auth" "0";
        "default_maxlogins" "10";
        "hard_maxlogins" "100";
        "password_min_length" "1";
        "password_min_digits" "0";
        "password_min_upper" "0";
        "password_min_lower" "0";
        "valid_account_regex" "^[-_a-z0-9A-Z]{{2,30}}$";
        "valid_nick_regex" "^[-_a-z][-_a-z0-9]*$";
        "valid_fakehost_regex" "^[-_a-zA-Z0-9.]+$";
        "force_handles_lowercase" "0";
        "disable_nicks" "1";
        "email_enabled" "0";
        "email_required" "0";
        "accounts_per_email" "100";
        "autogag_enabled" "0";
        "auth_policer" {{
            "size" "1000";
            "drain-rate" "100";
        }};
        "flag_levels" {{
            "g" "800";
            "lc_h" "800";
            "uc_H" "800";
            "S" "999";
            "b" "1";
            "I" "999";
        }};
        "sync_log" "0";
        "default_style" "n";
    }};
    "opserv" {{
        "nick" "O3";
        "privileged" "1";
        "debug_channel" "#opserv";
        "alert_channel" "#opserv";
        "staff_auth_channel" "#opserv";
    }};
}};

"policers" {{
    "commands-luser" {{
        "size" "1000";
        "drain-rate" "100";
    }};
}};

"mail" {{
    "enable" "0";
}};

"dbs" {{
    "mondo" {{
        "filename" "x3.db";
        "frequency" "30m";
    }};
}};

"logs" {{
    "*.*" ("std:out", "file:everything.log");
}};
"""


class X3Controller(BaseServicesController, DirectoryBasedController):
    """Collaborator for P10 server controllers (Nefarious) that rely on X3."""

    software_name = "X3"
    nickserv = "AuthServ"
    saslserv = "AuthServ"
    # What AuthServ implements (nickserv.c, sasl_packet)
    sasl_mechanisms = ("PLAIN", "EXTERNAL")
    bind_address = "127.0.0.1"

    def run(self, protocol: str, server_hostname: str, server_port: int) -> None:
        assert protocol == "nefarious", protocol
        self.create_config()
        assert self.directory

        services_path = shutil.which("x3")
        assert services_path, "x3 not found in $PATH"

        with self.open_file("x3.conf") as fd:
            fd.write(
                TEMPLATE_CONFIG.format(
                    server_address=socket.gethostbyname(server_hostname),
                    server_port=server_port,
                    nickserv=self.nickserv,
                )
            )

        # X3 loads its *.help files from its working directory.
        share_dir = Path(services_path).parent.parent / "share" / "x3"
        for help_file in share_dir.glob("*.help"):
            (self.directory / help_file.name).symlink_to(help_file)

        self.proc = self.execute(
            ["x3", "-c", "x3.conf", "-f", *(["-d"] if self.debug_mode else [])],
            cwd=self.directory,
        )

    def wait_for_services(self) -> None:
        """Like the base method, but the account service is AuthServ, not
        NickServ, and X3 answers HELP with NOTICEs prefixed AuthServ."""
        if self.services_up:
            return
        self.server_controller.wait_for_port()

        c = ClientMock(name="chkNS", show_io=True)
        c.connect(self.server_controller.hostname, self.server_controller.port)
        c.sendLine("NICK chkNS")
        c.sendLine("USER chk chk chk chk")
        got_end_of_motd = False
        while not got_end_of_motd:
            for msg in c.getMessages(synchronize=False):
                if msg.command == "PING":
                    c.sendLine("PONG :" + msg.params[0])
                if msg.command in ("376", "422"):
                    got_end_of_motd = True

        timeout = time.time() + 30
        while not self.services_up:
            if time.time() > timeout:
                raise Exception(f"Timeout while waiting for {self.nickserv}")
            c.sendLine(f"PRIVMSG {self.nickserv} :help")
            for msg in self.getNickServResponse(c, timeout=1):
                if msg.command == "NOTICE" and (msg.prefix or "").lower().startswith(
                    self.nickserv.lower()
                ):
                    self.services_up = True

        # X3 only lets an IRC operator register the first account (which
        # then owns services). Do that here, so that registerUser() works.
        c.sendLine("OPER operuser operpassword")
        deadline = time.time() + 10
        while not any(m.command == "381" for m in c.getMessages(synchronize=False)):
            if time.time() > deadline:
                raise Exception("Timeout while opering to seed X3's first account")
            time.sleep(0.05)
        c.sendLine(
            f"PRIVMSG {self.nickserv} :REGISTER irctestadmin {os.urandom(8).hex()}"
        )
        deadline = time.time() + 10
        while not any(
            m.command == "NOTICE" and "registered" in m.params[-1].lower()
            for m in self.getNickServResponse(c, timeout=1)
        ):
            if time.time() > deadline:
                raise Exception("Timeout while seeding X3's first account")

        c.sendLine("QUIT")
        c.getMessages()
        c.disconnect()

    def registerUser(
        self,
        case: irctest.cases.BaseServerTestCase,  # type: ignore
        username: str,
        password: Optional[str] = None,
    ) -> None:
        if not case.run_services:
            raise ValueError(
                "Attempted to register a nick, but `run_services` it not True."
            )
        assert password
        client = case.addClient(show_io=True)
        case.sendLine(client, "NICK " + username)
        case.sendLine(client, "USER r e g :user")
        while case.getRegistrationMessage(client).command != "001":
            pass
        case.getMessages(client)
        case.sendLine(
            client, f"PRIVMSG {self.nickserv} :REGISTER {username} {password}"
        )
        msgs: List[Message] = []
        deadline = time.time() + 10
        # X3 answers with a NOTICE, then logs the client in (900 if the ircd
        # sends it). Wait until the account is set so that SASL works at once.
        while time.time() < deadline:
            msgs.extend(self.getNickServResponse(case.clients[client], timeout=1))
            if any(m.command == "900" for m in msgs):
                break
            if any(
                m.command == "NOTICE" and "registered" in m.params[-1].lower()
                for m in msgs
            ):
                break
        assert "NOTICE" in {m.command for m in msgs}, msgs
        case.sendLine(client, "QUIT")
        case.assertDisconnected(client)


def get_irctest_controller_class() -> Type[X3Controller]:
    return X3Controller
