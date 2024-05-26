from core.core30_context.context_dependency_graph import context_producer, context_dependencies
from core.core02_model.typed.file import File, file_content, inode_name
from core.core11_config.config import config_dependencies, Config
from core.core30_context.context import Context

from ..docker.container import docker_run

from docker import DockerClient
from typing import Container
from pathlib import Path
from shlex import join
import datetime
import os


wasm_suffix = 'WASM'
input_suffix = 'input'
output_suffix = 'output'
wasm_suffix_input = os.path.join(wasm_suffix, input_suffix)
wasm_suffix_output = os.path.join(wasm_suffix, output_suffix)
source_directory = '/src'


@context_producer(('.localfs.tempdir.wasm_input', Path), ('.localfs.tempdir.wasm_output', Path),
                  ('.localfs.tempdir.wasm_root', Path))
@config_dependencies(('.localfs.tempdir', str))
def wasm_dir(config: Config, ctxt: Context):
    for ctxt_name, suffix in {'wasm_input': wasm_suffix_input, 'wasm_output': wasm_suffix_output}.items():
        fullpath = os.path.join(config['localfs']['tempdir'], suffix)
        if not os.path.isdir(fullpath):
            os.makedirs(fullpath, exist_ok=True)
        path = Path(fullpath)
        ctxt.setdefault('localfs', {}).setdefault('tempdir', {})[ctxt_name] = path
    path = Path(os.path.join(config['localfs']['tempdir'], wasm_suffix))
    ctxt.setdefault('localfs', {}).setdefault('tempdir', {})['wasm_root'] = path
    return path


@context_producer(('.systemctxt.docker.container.wabt', Container | None))
@context_dependencies(('.systemctxt.docker.engine', DockerClient))
@config_dependencies(('.systemctxt.docker.keep_background', bool))
def background_container(config: Config, ctxt: Context):
    # TODO: do it: make a background running container and then exec on it below
    ctxt['systemctxt']['docker'].setdefault('container', {})['wabt'] = None


@context_dependencies(('.localfs.tempdir.wasm_root', Path),
                      ('.systemctxt.docker.engine', DockerClient),
                      ('.systemctxt.docker.container.wabt', Container | None))
def compile_wasm(ctxt: Context, content: File):
    basepath = ctxt['localfs']['tempdir']['wasm_root']
    content_to_upload = file_content(content)

    try:
        fname = os.path.basename(inode_name(content))
    except:
        fname = 'wat_in'
    fname = fname + '-' + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + '.wat'
    with open(os.path.join(basepath, input_suffix, fname), 'wb') as f:
        f.write(content_to_upload)

    if ctxt['systemctxt']['docker']['container']['wabt'] is None:
        docker_run('thearqsz/wabt',
                   join(['wat2wasm', os.path.join(source_directory, input_suffix, fname), '-o',
                         os.path.join(source_directory, output_suffix, fname), '--no-check']),
                   volumes={os.path.abspath(basepath): {'bind': source_directory, 'mode': 'rw'}})
    else:
        # TODO: implement this
        docker_exec([...])

    with open(os.path.join(basepath, output_suffix, fname), 'rb') as f:
        compiled = f.read()
    return compiled
