from core.core30_context.context_dependency_graph import context_dependencies
from core.core30_context.context import Context

from docker import DockerClient


@context_dependencies(('.systemctxt.docker.engine', DockerClient))
def check_running_with_options(ctxt: Context, **kwargs):
    client: DockerClient = ctxt['systemctxt']['docker']['engine']
    #TODO: implement it
    #ctxt.setdefault('systemctxt', {}).setdefault('docker', {})['engine'] = client
    #return client
    raise NotImplementedError


def check_and_run():
    # TODO: implement it
    raise NotImplementedError


@context_dependencies(('.systemctxt.docker.engine', DockerClient))
def docker_run(ctxt: Context, image, command, with_stderr=True, **kwargs):
    client: DockerClient = ctxt['systemctxt']['docker']['engine']
    out = client.containers.run(image, command, stderr=with_stderr, **kwargs)
    return out
