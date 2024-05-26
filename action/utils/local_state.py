from core.core30_context.context_dependency_graph import context_producer, context_dependencies
from core.core11_config.config import config_dependencies, Config
from core.core30_context.context import Context

from pathlib import Path
import yaml
import os


states_suffix = 'states'


@context_producer(('.localfs.tempdir.state_root', Path))
@config_dependencies(('.localfs.tempdir', str))
def state_root(config: Config, ctxt: Context):
    fullpath = os.path.join(config['localfs']['tempdir'], states_suffix)
    if not os.path.isdir(fullpath):
        os.makedirs(fullpath, exist_ok=True)
    path = Path(fullpath)
    ctxt.setdefault('localfs', {}).setdefault('tempdir', {})['state_root'] = path
    return path


from contextlib import contextmanager
import fcntl


@contextmanager
def locked_open(filename):
    with open(filename, 'a') as fd:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
        fcntl.flock(fd, fcntl.LOCK_UN)


class Store:
    def __init__(self, context, base_root, erase_manifest_if_fail=True):
        self.context = context
        self.base_root = base_root
        os.makedirs(self.base_root, exist_ok=True)
        self.main_path = os.path.join(self.base_root, 'main.yml')
        self.resolved = {}
        self.erase_manifest_if_fail = erase_manifest_if_fail
        self.try_load_main_manifest()
        self.resolved = self.resolved or {}
        if 'autoload' in self.resolved:
            for item in self.resolved['autoload']:
                self[item]

    def path_for(self, fname):
        return os.path.join(self.base_root, fname)

    def yaml_path_for(self, fname):
        return os.path.join(self.base_root, f"{fname}.yml")

    def try_load_main_manifest(self):
        try:
            with open(self.main_path, 'r') as main:
                self.resolved = yaml.safe_load(main)
        except Exception as e:
            if self.erase_manifest_if_fail:
                print("OMG ERASE BAD BAD BAD ")
                print(e)
                with open(self.main_path, 'w') as main:
                    main.write(yaml.dump(self.resolved))
            else:
                raise

    def save_manifest(self, modified_key: str | None = None):
        manifest_dict = {
            'autoload': self.resolved.get('autoload', []),
            'manifest_keys': self.resolved.get('manifest_keys', []),
            **{k: self.resolved[k] for k in self.resolved.get('manifest_keys', [])}
        }
        with locked_open(f"{self.main_path}.lock"):
            if modified_key:
                with open(self.main_path, 'r') as main:  # reloaded to handle if any other execution modified the file
                    previous = yaml.safe_load(main)
                if modified_key in ['autoload', 'manifest_keys']:
                    manifest_dict[modified_key] = list(sorted(set([*manifest_dict[modified_key],
                                                                   *previous.get(modified_key, [])])))
                elif previous:
                    for k in previous:
                        if k in previous.get('manifest_keys', []) and k != modified_key:
                            manifest_dict[k] = previous[k]
            with open(self.main_path, 'w') as main:
                main.write(yaml.dump(manifest_dict))

    def __getitem__(self, item):
        if item in self.resolved:
            return self.resolved[item]
        else:
            if os.path.isfile(self.path_for(item)):
                return open(self.path_for(item), 'rb').read()
            elif os.path.isfile(self.yaml_path_for(item)):
                return yaml.safe_load(open(self.yaml_path_for(item), 'rb'))
            else:
                return None

    def __setitem__(self, key, value):
        self.resolved[key] = value
        self.resolved.setdefault('manifest_keys', [])

        if key in ['autoload', 'manifest_keys', *self.resolved['manifest_keys']]:
            manifest_or_yaml_or_raw = 0
        else:
            if isinstance(value, int) or isinstance(value, float) or isinstance(value, bool) or \
                    (isinstance(value, str) and len(value) < 0x60):
                manifest_or_yaml_or_raw = 0
            elif isinstance(value, list) and len(value) < 0x20:
                if sum(map(len, value)) < 0x200:
                    manifest_or_yaml_or_raw = 0
                else:
                    manifest_or_yaml_or_raw = 1
            elif isinstance(value, dict) and len(value) < 0x10:
                if sum(map(len, value.items())) < 0x300:
                    manifest_or_yaml_or_raw = 0
                else:
                    manifest_or_yaml_or_raw = 1
            elif value is None:
                manifest_or_yaml_or_raw = 3
            else:
                manifest_or_yaml_or_raw = 2

            if manifest_or_yaml_or_raw == 0 and key not in self.resolved['manifest_keys']:
                self.resolved['manifest_keys'].append(key)

        match manifest_or_yaml_or_raw:
            case 0:
                self.save_manifest(key)
            case 1:
                try:
                    with open(self.yaml_path_for(key), 'w') as f:
                        f.write(yaml.dump(value))
                except:
                    with open(self.path_for(key), 'wb') as f:
                        f.write(value if isinstance(value, bytes) else str(value))
            case 2:
                with open(self.path_for(key), 'wb') as f:
                    f.write(value if isinstance(value, bytes) else str(value).encode())

    def __contains__(self, item):
        return item in self.resolved or self[item] is not None


@context_producer(('.state.store', Store))
@context_dependencies(('.localfs.tempdir.state_root', Path), ('.systemctxt.execution_context_id', str))
def store_for_context(ctxt: Context):
    ctxt_id = ctxt['systemctxt']['execution_context_id']
    store = Store(ctxt_id, os.path.join(ctxt['localfs']['tempdir']['state_root'], ctxt_id))
    ctxt.setdefault('state', {})['store'] = store
