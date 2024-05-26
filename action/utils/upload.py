from core.core30_context.context_dependency_graph import context_producer
from core.core11_config.config import config_dependencies, Config
from core.core30_context.context import Context

from . import control_server  # ssh_ok dependency

from pathlib import Path
import os.path


# For upload:
# we check we have ssh access to the provided server in config
# if we do not have, we generate a key and wait for it to be pushed
# when ok, scp-ing the desired file with paramiko
# then launching command on powershell to download from url

upload_suffix = 'uploads'


@context_producer(('.localfs.tempdir.uploads', Path))
@config_dependencies(('.localfs.tempdir', str))
def upload_dir(config: Config, ctxt: Context):
    fullpath = os.path.join(config['localfs']['tempdir'], upload_suffix)
    if not os.path.isdir(fullpath):
        os.makedirs(fullpath, exist_ok=True)
    path = Path(fullpath)
    ctxt.setdefault('localfs', {}).setdefault('tempdir', {})['uploads'] = path
    return path

