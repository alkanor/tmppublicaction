from core.core30_context.context_dependency_graph import context_producer
from core.core11_config.config import Config, config_dependencies
from core.core30_context.context import Context

from pathlib import Path
import os


download_suffix = 'downloads'


@context_producer(('.localfs.tempdir.downloads', Path))
@config_dependencies(('.localfs.tempdir', str))
def download_dir(config: Config, ctxt: Context):
    fullpath = os.path.join(config['localfs']['tempdir'], download_suffix)
    if not os.path.isdir(fullpath):
        os.makedirs(fullpath, exist_ok=True)
    path = Path(fullpath)
    ctxt.setdefault('localfs', {}).setdefault('tempdir', {})['downloads'] = path
    return path

