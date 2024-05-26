from core.core30_context.context_dependency_graph import context_dependencies
from core.core30_context.context import Context

from . import control_server  # ssh_ok dependency

from typing import Callable


@context_dependencies(('.systemctxt.controlled.ssh_ok', bool), ('.systemctxt.controlled.create_ssh_client', Callable))
def execute_command(ctxt: Context, command: str):
    print(f"[.] Attempting to execute {command}")
    ssh_client = ctxt['systemctxt']['controlled']['create_ssh_client']()
    stdin, stdout, stderr = ssh_client.exec_command(command.encode())
    out, err = ''.join(iter(stdout.readline, '')), ''.join(iter(stderr.readline, ''))
    print(f"[+] Command result: STDOUT={out} STDERR={err}")
    ssh_client.close()
    return {'stdout': out, 'stderr': err}
