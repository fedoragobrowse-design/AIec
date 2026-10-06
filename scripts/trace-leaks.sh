#!/usr/bin/env python3
"""Traces sandboxes that outlived the run that created them.

The cleanup guarantee says a run's machine does not outlive it, so this asks the
database directly which sandboxes are still alive, which run owned them, and
whether that run is finished. Anything in the last group is a leak.
"""
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import paramiko

nc = paramiko.SSHClient()
# Use the operator's verified known_hosts; retain SSHClient's reject policy.
nc.load_system_host_keys()
nc.connect("192.168.1.250", username="gobrowse",
           key_filename=os.path.expanduser("~/.ssh/id_ed25519"), timeout=30)

# Send the current shared helpers, rather than assuming a matching remote copy.
script = Path(__file__).with_name("acceptance-db.sh").read_text() + r'''
set -euo pipefail
set -a; . /home/gobrowse/aiec/env.systemd; set +a
acceptance_database_export_password "$DATABASE_URL" || exit 2
SQL_ARGV_URL=$(acceptance_database_url_without_password "$DATABASE_URL")
psql_out() {
  podman run --rm --network host -e PGPASSWORD docker.io/library/postgres:16 \
    psql "$SQL_ARGV_URL" -t -A -F ' | ' -c "$1"
}

echo "== live sandboxes, their owning run, and whether that run is finished"
psql_out "
select s.id, s.state, coalesce(r.state, 'no-run'),
       coalesce(r.retention, '-'), r.id is not null and r.state in ('succeeded','failed','cancelled') as run_finished
from sandboxes s
left join run_sandboxes rs on rs.sandbox_id = s.id
left join runs r on r.id = rs.run_id
where s.state not in ('destroyed','failed')
order by s.created_at"

echo
echo "== LEAKS: finished run, retention=destroy, machine still alive"
psql_out "
select r.id, r.state, r.retention, rs.sandbox_id, s.state
from runs r
join run_sandboxes rs on rs.run_id = r.id
join sandboxes s on s.id = rs.sandbox_id
where r.state in ('succeeded','failed','cancelled')
  and r.retention = 'destroy'
  and s.state not in ('destroyed','failed')"

echo
echo "== capacity"
psql_out "select name, available_vcpus, total_vcpus, sandbox_count from nodes order by name"
'''

try:
    i, o, e = nc.exec_command("bash -s", timeout=600)
    i.write(script)
    i.channel.shutdown_write()
    # Drain both streams together: SSH flow control shares their channel window.
    with ThreadPoolExecutor(max_workers=2) as readers:
        stdout = readers.submit(o.read)
        stderr = readers.submit(e.read)
        print(stdout.result().decode(), end="")
        print(stderr.result().decode(), end="", file=sys.stderr)
    status = o.channel.recv_exit_status()
    if status != 0:
        print(f"Trace diagnostics failed (remote exit {status}).", file=sys.stderr)
        raise SystemExit(status if status > 0 else 1)
finally:
    nc.close()
