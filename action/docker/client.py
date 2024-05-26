from core.core30_context.context_dependency_graph import context_producer, context_dependencies
from core.core30_context.context import Context

from docker.models.containers import Container
from docker import DockerClient
from typing import Dict, List
from functools import reduce
from os import path
import docker


@context_dependencies(('.executor.os', str))
def socket_paths_to_try(ctxt: Context, check_os=True, env_fallback=True):
    env = [] if not env_fallback else [None]
    if not check_os:
        return ['/var/run/docker.sock', path.expanduser('~/.docker/run/docker.sock'), *env]
    else:
        os = ctxt['executor']['os']
        if 'darwin' in os:
            return [path.expanduser('~/.docker/run/docker.sock'), '/var/run/docker.sock', *env]
        elif 'windows' in os:
            return env
        else:
            return ['/var/run/docker.sock', *env]


@context_producer(('.systemctxt.docker.engine', DockerClient))
def docker_client(ctxt: Context, check_os=True, from_env=False, **kwargs):
    if from_env:
        client = docker.from_env()
    elif kwargs:
        client = docker.DockerClient(**kwargs)
    else:
        excs = []
        client = None
        for path in socket_paths_to_try(check_os):
            try:
                client = docker.DockerClient(base_url=f"unix:/{path}") if path is not None else docker.from_env()
            except Exception as e:
                excs.append(e)
            if client:
                break
        if not client:
            raise Exception(*excs)
    ctxt.setdefault('systemctxt', {}).setdefault('docker', {})['engine'] = client
    return client


@context_producer(('.systemctxt.docker.containers_list.per_image', Dict[str, List[Container]]),
                  ('.systemctxt.docker.containers_list.per_name', Dict[str, Container]))
@context_dependencies(('.systemctxt.docker.engine', DockerClient))
def list_containers(ctxt: Context):
    client: DockerClient = ctxt['systemctxt']['docker']['engine']
    containers = client.containers.list()

    def reduce_images(cur_dict, container: Container):
        cur_dict.setdefault(container.image.name, []).append(container)

    per_image = reduce(reduce_images, containers, {})
    per_name = {c.name: c for c in containers}
    ctxt['systemctxt']['docker'].setdefault('containers_list', {})['per_image'] = per_image
    ctxt['systemctxt']['docker']['containers_list']['per_name'] = per_name
    return {
        'per_image': per_image,
        'per_name': per_name
    }
