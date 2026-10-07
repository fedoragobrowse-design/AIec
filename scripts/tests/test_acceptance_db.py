"""The acceptance database helpers, exercised through a real shell.

Every case here runs the shell functions the acceptance launchers run, in a
bash that has sourced `scripts/acceptance-db.sh`, and reads what that same bash
then sees: the status of the export, the value of `PGPASSWORD` in that shell -
the export dies with a subshell, so a test that cannot see it there proves
nothing - and the URL a client would be handed. The passwords are synthetic and
belong to no server; what is under test is where a credential may appear.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "acceptance-db.sh"

# The harness is one real shell, because the two things under test are
# properties of that shell: `export` in the shell that reads PGPASSWORD, and a
# value printed for the command line of a client started from it.
HARNESS = r"""
set -u
source "$1"
url=$2
status=0
acceptance_database_export_password "$url" || status=$?
strip=0
argv=$(acceptance_database_url_without_password "$url") || strip=$?
printf 'STATUS=%s\n' "$status"
printf 'STRIP=%s\n' "$strip"
printf 'PGPASSWORD=%s\n' "${PGPASSWORD-<unset>}"
printf 'ARGV=%s\n' "$argv"
"""


class AcceptanceDatabaseHelpersTest(unittest.TestCase):
    def run_helpers(self, url, *, path=None):
        environment = {name: value for name, value in os.environ.items()
                       if name != "PGPASSWORD"}
        # Minted here so sourcing the shared file does not read /dev/urandom and
        # so the value is fixed by the test rather than by the host.
        environment["AIEC_ACCEPTANCE_RUN_ID"] = "synthetic-acceptance-run"
        if path is not None:
            environment["PATH"] = path
        result = subprocess.run(
            ["bash", "-c", HARNESS, "acceptance-db-harness", str(SCRIPT), url],
            capture_output=True, text=True, env=environment, timeout=60,
        )
        fields = {}
        for line in result.stdout.splitlines():
            key, _, value = line.partition("=")
            fields[key] = value
        return result, fields

    def assertRefused(self, result, fields, *secrets):
        # Nothing was exported, so the credential must appear nowhere at all.
        self.assertEqual(fields.get("STATUS"), "2", result.stdout + result.stderr)
        self.assertEqual(fields.get("PGPASSWORD"), "<unset>", result.stdout)
        self.assertEqual(fields.get("STRIP"), "0", result.stdout + result.stderr)
        diagnostics = result.stdout + result.stderr
        for secret in secrets:
            self.assertNotIn(secret, diagnostics)

    def assertNotOnTheCommandLine(self, fields, *secrets):
        # The effective password is printed on purpose - that is the export
        # being observed - so what must stay out of it is the argv URL, where
        # any local account can read it through /proc.
        argv = fields.get("ARGV", "")
        for secret in secrets:
            self.assertNotIn(secret, argv)


    def test_a_query_password_is_the_credential_and_never_reaches_argv(self):
        result, fields = self.run_helpers(
            "postgresql://fixture@127.0.0.1:5432/aiec?password=synthetic-query-password"
        )
        self.assertEqual(fields.get("STATUS"), "0", result.stdout + result.stderr)
        self.assertEqual(fields.get("PGPASSWORD"), "synthetic-query-password")
        self.assertEqual(fields.get("ARGV"),
                         "postgresql://fixture@127.0.0.1:5432/aiec")
        self.assertNotOnTheCommandLine(fields, "synthetic-query-password")

    def test_the_last_query_password_overrides_the_userinfo_password(self):
        result, fields = self.run_helpers(
            "postgresql://fixture:synthetic-userinfo-secret@127.0.0.1/aiec"
            "?password=synthetic-query-secret"
        )
        self.assertEqual(fields.get("STATUS"), "0", result.stdout + result.stderr)
        self.assertEqual(fields.get("PGPASSWORD"), "synthetic-query-secret")
        self.assertEqual(fields.get("ARGV"), "postgresql://fixture@127.0.0.1/aiec")
        self.assertNotOnTheCommandLine(fields, "synthetic-query-secret")
        self.assertNotIn("synthetic-userinfo-secret", result.stdout + result.stderr)

    def test_a_userinfo_password_is_still_the_credential(self):
        result, fields = self.run_helpers(
            "postgresql://fixture:synthetic-userinfo-secret@127.0.0.1/aiec")
        self.assertEqual(fields.get("STATUS"), "0", result.stdout + result.stderr)
        self.assertEqual(fields.get("PGPASSWORD"), "synthetic-userinfo-secret")
        self.assertEqual(fields.get("ARGV"), "postgresql://fixture@127.0.0.1/aiec")

    def test_every_password_component_goes_and_the_rest_stays_verbatim(self):
        # Duplicate parameters, an encoded parameter name, a value carrying an
        # `=`, and two unrelated parameters whose order and spelling have to
        # survive: a client pointed at this URL must reach the same server.
        result, fields = self.run_helpers(
            "postgresql://fixture:synthetic-userinfo-secret@127.0.0.1:5433/aiec"
            "?application_name=drill&password=first-secret"
            "&pass%77ord=second-secret&options=-c%20search_path%3Dpublic"
            "&sslmode=disable"
        )
        self.assertEqual(fields.get("STATUS"), "0", result.stdout + result.stderr)
        self.assertEqual(fields.get("PGPASSWORD"), "second-secret")
        self.assertEqual(
            fields.get("ARGV"),
            "postgresql://fixture@127.0.0.1:5433/aiec"
            "?application_name=drill&options=-c%20search_path%3Dpublic&sslmode=disable",
        )
        self.assertNotOnTheCommandLine(
            fields, "synthetic-userinfo-secret", "first-secret", "second-secret")

    def test_a_plus_in_a_query_value_is_a_plus(self):
        # libpq reads a URI query literally: `+` is a plus, not a space, so a
        # password handed over with one is the password and not a mangled one.
        result, fields = self.run_helpers(
            "postgresql://fixture@127.0.0.1/aiec"
            "?application_name=a+b&password=plus+secret+value"
        )
        self.assertEqual(fields.get("STATUS"), "0", result.stdout + result.stderr)
        self.assertEqual(fields.get("PGPASSWORD"), "plus+secret+value")
        self.assertEqual(fields.get("ARGV"),
                         "postgresql://fixture@127.0.0.1/aiec?application_name=a+b")
        self.assertNotOnTheCommandLine(fields, "plus+secret+value")

    def test_a_socket_url_keeps_its_query(self):
        for url, password, argv in (
            ("postgres://fixture@/aiec?host=/run/postgresql&password=synthetic-socket",
             "synthetic-socket",
             "postgres://fixture@/aiec?host=/run/postgresql"),
            ("postgresql://drill_role@127.0.0.1:5432/aiec?password=synthetic-tcp",
             "synthetic-tcp",
             "postgresql://drill_role@127.0.0.1:5432/aiec"),
        ):
            with self.subTest(url=url):
                result, fields = self.run_helpers(url)
                self.assertEqual(fields.get("STATUS"), "0", result.stdout + result.stderr)
                self.assertEqual(fields.get("PGPASSWORD"), password)
                self.assertEqual(fields.get("ARGV"), argv)

    def test_an_encoded_effective_password_is_refused_and_not_named(self):
        # The refusal names the problem, never the value: the decoded spelling
        # of the password must not turn up in it either.
        for url in (
            "postgresql://fixture@127.0.0.1/aiec?password=synthetic%2Dsecret",
            "postgresql://fixture:synthetic%2Dsecret@127.0.0.1/aiec",
        ):
            with self.subTest(url=url):
                result, fields = self.run_helpers(url)
                self.assertRefused(result, fields, "synthetic%2Dsecret", "synthetic-secret")
                self.assertEqual(fields.get("ARGV"), "postgresql://fixture@127.0.0.1/aiec")

    def test_an_encoded_password_a_plain_one_overrides_goes_silently(self):
        # Nothing authenticates with the encoded values any more, so refusing
        # here would refuse a URL whose effective credential is plain.
        result, fields = self.run_helpers(
            "postgresql://fixture:synthetic%2Dsecret@127.0.0.1/aiec"
            "?password=also%2Dencoded&password=final-secret-value"
        )
        self.assertEqual(fields.get("STATUS"), "0", result.stdout + result.stderr)
        self.assertEqual(fields.get("PGPASSWORD"), "final-secret-value")
        self.assertEqual(fields.get("ARGV"), "postgresql://fixture@127.0.0.1/aiec")
        self.assertNotOnTheCommandLine(
            fields, "synthetic%2Dsecret", "also%2Dencoded", "final-secret-value")
        diagnostics = result.stdout + result.stderr
        for secret in ("synthetic-secret", "also-encoded"):
            self.assertNotIn(secret, diagnostics)

    def test_a_url_without_a_password_is_untouched(self):
        url = "postgresql://fixture@127.0.0.1/aiec?application_name=drill"
        result, fields = self.run_helpers(url)
        self.assertEqual(fields.get("STATUS"), "0", result.stdout + result.stderr)
        self.assertEqual(fields.get("PGPASSWORD"), "<unset>")
        self.assertEqual(fields.get("ARGV"), url)

    def test_the_url_reaches_the_parser_on_stdin_and_never_in_argv(self):
        # The URL is a credential, so what a helper process is invoked with is
        # the thing /proc would show to another account. A `python3` earlier on
        # PATH records that invocation and runs the real interpreter.
        real_python = shutil.which("python3")
        if real_python is None:
            self.skipTest("python3 is not on PATH")
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "argv"
            shim = Path(directory) / "python3"
            shim.write_text(
                "#!/usr/bin/env bash\n"
                f'printf "%s\\n" "$@" >> "{record}"\n'
                f'exec "{real_python}" "$@"\n'
            )
            shim.chmod(0o755)
            path = directory + os.pathsep + os.environ.get("PATH", "")
            result, fields = self.run_helpers(
                "postgresql://fixture@127.0.0.1/aiec?password=synthetic-argv-secret",
                path=path,
            )
            recorded = record.read_text() if record.exists() else ""
        self.assertEqual(fields.get("PGPASSWORD"), "synthetic-argv-secret",
                         result.stdout + result.stderr)
        self.assertNotIn("synthetic-argv-secret", recorded)

    def run_url_helper(self, helper, url, *args):
        return subprocess.run(
            ["bash", "-c", 'source "$1"; shift; "$@"',
             "acceptance-db-url", str(SCRIPT), helper, url, *args],
            capture_output=True, text=True, timeout=10,
            env={**os.environ, "AIEC_ACCEPTANCE_RUN_ID": "synthetic-acceptance-run"},
        )

    def test_isolation_checks_the_decoded_effective_database(self):
        for url in (
            "postgresql://fixture@localhost/aiec_guard_owned?dbna%6de=aiec",
            "postgresql://fixture@localhost/%61iec",
            "postgresql://fixture@localhost/aiec_guard_owned?dbname=",
        ):
            with self.subTest(url=url):
                result = self.run_url_helper("acceptance_database_is_isolated", url)
                self.assertNotEqual(result.returncode, 0)
        result = self.run_url_helper(
            "acceptance_database_is_isolated",
            "postgresql://fixture@localhost/aiec?dbname=postgres&dbname=aiec_guard_owned",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rewriting_replaces_query_database_overrides_without_losing_options(self):
        result = self.run_url_helper(
            "acceptance_database_url_with_name",
            "postgresql://fixture@localhost/path?dbname=first&dbna%6de=aiec"
            "&application_name=restore%2Faudit&sslmode=disable",
            "aiec_guard_restored",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "postgresql://fixture@localhost/aiec_guard_restored"
            "?application_name=restore%2Faudit&sslmode=disable",
        )

    def test_relay_uses_effective_destination_and_preserves_database_and_options(self):
        url = ("postgresql://fixture@wrong.invalid:5432/aiec_guard_path"
               "?ho%73t=127.0.0.1&port=5441&dbname=aiec_guard_query"
               "&application_name=relay%2Faudit&sslmode=disable")
        endpoint = self.run_url_helper("acceptance_database_url_tcp_endpoint", url)
        self.assertEqual(endpoint.returncode, 0, endpoint.stderr)
        self.assertEqual(endpoint.stdout, "127.0.0.1:5441")
        relayed = self.run_url_helper(
            "acceptance_database_url_for_socket", url, "/tmp/aiec-relay",
        )
        self.assertEqual(relayed.returncode, 0, relayed.stderr)
        self.assertEqual(
            relayed.stdout,
            "postgresql://fixture@127.0.0.1/aiec_guard_path"
            "?dbname=aiec_guard_query&application_name=relay%2Faudit"
            "&sslmode=disable&host=/tmp/aiec-relay",
        )

    def test_socket_detection_honors_encoded_keys_and_last_host(self):
        result = self.run_url_helper(
            "acceptance_database_is_socket_url",
            "postgresql://fixture@localhost/aiec_guard_owned?ho%73t=%2Frun%2Fpostgresql",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_url_helper(
            "acceptance_database_is_socket_url",
            "postgresql://fixture@localhost/aiec_guard_owned?host=/tmp&host=127.0.0.1",
        )
        self.assertNotEqual(result.returncode, 0)

    def test_disagreeing_sqlx_and_libpq_transports_are_refused_before_setup(self):
        for suffix in (
            "host=/tmp/fixture&host=127.0.0.1",
            "host=/tmp/fixture&hostaddr=127.0.0.1",
            "hostaddr=127.0.0.1&host=127.0.0.2",
        ):
            url = "postgresql://fixture@localhost/aiec_guard_owned?" + suffix
            with self.subTest(suffix=suffix):
                for helper, args in (
                    ("acceptance_database_url_name", ()),
                    ("acceptance_database_url_with_name", ("aiec_guard_copy",)),
                    ("acceptance_database_url_tcp_endpoint", ()),
                    ("acceptance_database_url_for_socket", ("/tmp/relay",)),
                ):
                    result = self.run_url_helper(helper, url, *args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    result = subprocess.run(
                        ["bash", "-c",
                         'source "$1"; acceptance_prepare_database "$2" "$2/pg" "$2/socket" "$2/bin"',
                         "transport-refusal", str(SCRIPT), directory],
                        env={**os.environ, "AIEC_ACCEPTANCE_DATABASE_URL": url,
                             "ACCEPTANCE_DB_NAME_PATTERN": "aiec_guard_*"},
                        capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertFalse((root / "socket").exists())

        # Both clients select the final hostaddr when no sticky socket or
        # later conflicting host overrides it.
        result = self.run_url_helper(
            "acceptance_database_url_tcp_endpoint",
            "postgresql://fixture@localhost/aiec_guard_owned"
            "?host=127.0.0.2&hostaddr=127.0.0.1",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "127.0.0.1:5432")


class BackupRestoreDrillOwnershipTest(unittest.TestCase):
    """A stateful database boundary: failed CREATE confers no DROP authority."""

    def run_drill(self, target, *, source="source_audit", existing=(), fail_recovery=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            databases = root / "databases"
            databases.mkdir()
            for name in (source, *existing):
                database = databases / name
                database.mkdir()
                (database / "foreign-state").write_text("preserve")
            psql = root / "psql"
            psql.write_text(
                "#!/usr/bin/env python3\n"
                "import os, shlex, shutil, sys\n"
                "from pathlib import Path\n"
                "root = Path(os.environ['DRILL_TEST_DATABASES'])\n"
                "sql = sys.argv[sys.argv.index('-c') + 1]\n"
                "tokens = shlex.split(sql)\n"
                "if tokens[0] in ('CREATE', 'DROP'):\n"
                "    name = tokens[-1][:63]\n"
                "    database = root / name\n"
                "    if tokens[0] == 'CREATE':\n"
                "        if database.exists(): sys.exit(1)\n"
                "        database.mkdir()\n"
                "    elif database.exists(): shutil.rmtree(database)\n"
                "else:\n"
                "    url = next(arg for arg in sys.argv if arg.startswith('postgres'))\n"
                "    if '_recovery' in url and os.environ.get('DRILL_TEST_FAIL_RECOVERY'):\n"
                "        sys.exit(43)\n"
                "    print(1)\n"
            )
            dump = root / "pg_dump"
            dump.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "from pathlib import Path\n"
                "path = next(arg[7:] for arg in sys.argv if arg.startswith('--file='))\n"
                "Path(path).write_bytes(b'disposable-dump')\n"
            )
            restore = root / "pg_restore"
            restore.write_text("#!/usr/bin/env bash\nexit 0\n")
            for executable in (psql, dump, restore):
                executable.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": directory + os.pathsep + os.environ["PATH"],
                "DATABASE_URL": f"postgresql://fixture@localhost/{source}",
                "AIEC_DRILL_DB": target,
                "AIEC_ACCEPTANCE_RUN_ID": "synthetic-acceptance-run",
                "DRILL_TEST_DATABASES": str(databases),
            }
            for name in ("AIEC_DRILL_ADMIN_URL", "AIEC_DRILL_BIND", "AIEC_DRILL_CA",
                         "PGPASSWORD", "DRILL_TEST_FAIL_RECOVERY"):
                environment.pop(name, None)
            if fail_recovery:
                environment["DRILL_TEST_FAIL_RECOVERY"] = "1"
            result = subprocess.run(
                ["bash", str(REPO / "scripts/backup-restore-drill.sh")],
                capture_output=True, text=True, timeout=30, env=environment,
            )
            state = {path.name: (path / "foreign-state").exists()
                     for path in databases.iterdir()}
        return result, state

    def test_a_drill_cannot_drop_its_source_or_a_protected_database(self):
        for source, target in (("aiec", "aiec"), ("source_audit", "source_audit"),
                               ("source_audit_recovery", "source_audit")):
            with self.subTest(source=source, target=target):
                result, state = self.run_drill(target, source=source)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(state, {source: True})

    def test_a_preexisting_target_is_not_replaced_or_cleaned_up(self):
        result, state = self.run_drill("audit_restore", existing=("audit_restore",))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state, {"source_audit": True, "audit_restore": True})

    def test_a_preexisting_recovery_target_remains_untouched(self):
        result, state = self.run_drill(
            "audit_restore", existing=("audit_restore_recovery",),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state, {"source_audit": True, "audit_restore_recovery": True})

    def test_a_failed_recovery_read_cleans_up_both_owned_databases(self):
        result, state = self.run_drill("audit_restore", fail_recovery=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state, {"source_audit": True})

    def test_recovery_suffix_cannot_truncate_into_another_database(self):
        name = "a" * 63
        result, state = self.run_drill(name, existing=(name,))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state, {"source_audit": True, name: True})


if __name__ == "__main__":
    unittest.main()