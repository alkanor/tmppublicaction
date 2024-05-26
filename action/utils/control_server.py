from core.core30_context.context_dependency_graph import context_producer, context_dependencies
from core.core02_model.typed.service import url_to_service, AuthenticatedDirectService
from core.core11_config.config import config_dependencies, Config
from core.core02_model.typed.file import File, file_content
from core.core30_context.context import Context

import action.utils.upload  # to trigger load of tmpfs

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric
from contextlib import contextmanager
from io import StringIO, BytesIO
from typing import Callable
from pathlib import Path
import threading
import paramiko
import select
import socket
import base64
import time
import os



def generate_ed25519_key():
    c_ed25519key = asymmetric.ed25519.Ed25519PrivateKey.generate()
    privpem = c_ed25519key.private_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PrivateFormat.OpenSSH,
                                         encryption_algorithm=serialization.NoEncryption())

    pub = c_ed25519key.public_key()
    openssh_pub = pub.public_bytes(encoding=serialization.Encoding.OpenSSH,
                                   format=serialization.PublicFormat.OpenSSH)
    return (privpem, openssh_pub)


@context_producer(('.localfs.tempdir.utils', Path))
@config_dependencies(('.localfs.tempdir', str))
def utils_dir(config: Config, ctxt: Context):
    fullpath = os.path.join(config['localfs']['tempdir'], 'utils')
    if not os.path.isdir(fullpath):
        os.makedirs(fullpath, exist_ok=True)
    path = Path(fullpath)
    ctxt.setdefault('localfs', {}).setdefault('tempdir', {})['utils'] = path
    return path


privkey_path = 'ssh_key.priv'
pubkey_path = 'ssh_key.pub'


class RemoteSSHManager:

    per_host = {}

    def __init__(self, ssh_url):
        ssh_service = url_to_service(ssh_url)
        # TODO: handle no authentication object (even if this has no sense regarding SSH)
        self.remote_ip = ssh_service.authenticated_object.endpoint.ip_address
        self.remote_port = ssh_service.authenticated_object.port
        self.remote_ip_path = str(self.remote_ip).replace('.', '-')
        base_path = f".systemctxt.controlled.{self.remote_ip_path}"


        if base_path in RemoteSSHManager.per_host:
            for m in RemoteSSHManager.per_host[base_path].__dict__:
                setattr(self, m, RemoteSSHManager.per_host[base_path].__dict__[m])
            return

        @context_producer((f"{base_path}.ssh_manager", RemoteSSHManager),)
        def manager_for_ip(ctxt: Context):
            ctxt.setdefault('systemctxt', {}).setdefault('controlled', {}) \
                .setdefault(self.remote_ip_path, {})['ssh_manager'] = self


        @context_producer((f"{base_path}.private_key", bytes), (f"{base_path}.public_key", bytes))
        @context_dependencies(('.localfs.tempdir.utils', Path))
        def ssh_key(ctxt: Context):
            basepath = ctxt['localfs']['tempdir']['utils']
            if not os.path.isfile(os.path.join(basepath, privkey_path)):
                privkey, pubkey = generate_ed25519_key()
                with open(os.path.join(basepath, privkey_path), 'wb') as f:
                    f.write(privkey)
                with open(os.path.join(basepath, pubkey_path), 'wb') as f:
                    f.write(pubkey)
            else:
                with open(os.path.join(basepath, privkey_path), 'rb') as f:
                    privkey = f.read()
                with open(os.path.join(basepath, pubkey_path), 'rb') as f:
                    pubkey = f.read()
            ctxt.setdefault('systemctxt', {}).setdefault('controlled', {}) \
                .setdefault(self.remote_ip_path, {})['private_key'] = privkey.decode()
            ctxt['systemctxt']['controlled'][self.remote_ip_path]['public_key'] = pubkey.decode()
            return privkey, pubkey


        @context_producer((f"{base_path}.create_ssh_client", Callable),
                          (f"{base_path}.ssh_service", AuthenticatedDirectService))
        @context_dependencies((f"{base_path}.private_key", bytes),
                              (f"{base_path}.public_key", bytes))
        @config_dependencies(('.systemctxt.controlled.timeout_conn', int), )
        def check_ssh_key(config: Config, ctxt: Context, ed25519_key=None, ed25519_key_password=None, erase=False):
            private_key = ctxt['systemctxt']['controlled'][self.remote_ip_path]['private_key']
            url_with_privkey = ssh_url.replace('PRIVATE_KEY', base64.b64encode(private_key.encode()).decode())
            self.ssh_service = url_to_service(url_with_privkey)

            uname = self.ssh_service.identity_proof.identity.username

            string_buf = StringIO()
            string_buf.write(private_key if not ed25519_key else ed25519_key)
            string_buf.seek(0)
            k = paramiko.Ed25519Key.from_private_key(string_buf, password=ed25519_key_password)
            string_buf.close()

            def create_and_connect_ssh_client():
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
                ssh.connect(str(self.remote_ip), port=self.remote_port, username=uname, pkey=k,
                            timeout=config['systemctxt']['controlled']['timeout_conn'])
                return ssh

            try:
                ssh = create_and_connect_ssh_client()
                ssh.close()
                res = (True, None)
            except Exception as e:
                res = (False, e)

            if erase or 'create_ssh_client' not in ctxt['systemctxt']['controlled'][self.remote_ip_path]:
                ctxt['systemctxt']['controlled'][self.remote_ip_path]['create_ssh_client'] = \
                    create_and_connect_ssh_client
                ctxt['systemctxt']['controlled'][self.remote_ip_path]['ssh_service'] = self.ssh_service
            return res


        # TODO: add interact policy
        @context_producer((f"{base_path}.ssh_ok", bool))
        @context_dependencies((f"{base_path}.public_key", bytes),
                              (f"{base_path}.ssh_service", AuthenticatedDirectService))
        def wait_for_ssh_access(ctxt: Context):
            bad_one = True
            while True:
                ok, exc = self.check_ssh_key()
                if ok:
                    break
                else:
                    if bad_one:
                        bad_one = False
                        ssh_service = ctxt['systemctxt']['controlled'][self.remote_ip_path]['ssh_service']
                        public_key = ctxt['systemctxt']['controlled'][self.remote_ip_path]['public_key']
                        ip_addr = ssh_service.authenticated_object.endpoint.ip_address
                        uname = ssh_service.identity_proof.identity.username
                        print(f"[.] Please ensure SSH port is open on {ip_addr}, user {uname} is allowed with "
                              f"{public_key}")
                    print(f"[-] SSH access failed: {exc}, retrying in 10s")
                    time.sleep(10)
            ctxt['systemctxt']['controlled'][self.remote_ip_path]['ssh_ok'] = True
            return True


        @context_dependencies((f"{base_path}.create_ssh_client", Callable), (f"{base_path}.ssh_ok", bool),)
        def create_ssh_client(ctxt: Context):
            return ctxt['systemctxt']['controlled'][self.remote_ip_path]['create_ssh_client']()


        @context_dependencies(('.localfs.tempdir.uploads', Path),
                              (f"{base_path}.ssh_ok", bool),
                              (f"{base_path}.create_ssh_client", Callable))
        @config_dependencies(('.systemctxt.controlled.upload_dir', str),)
        def upload_data(config: Config, ctxt: Context, content: File, filename: str | None, write_copy: bool = True):
            ensure_fname = filename.split(os.path.sep)[-1]
            content_to_upload = file_content(content)
            if write_copy:
                with open(os.path.join(ctxt['localfs']['tempdir']['uploads'], ensure_fname), 'wb') as f:
                    f.write(content_to_upload)

            out_fullpath = os.path.join(config['systemctxt']['controlled']['upload_dir'], ensure_fname)

            # first upload the file on the controlled server
            ssh_client = ctxt['systemctxt']['controlled'][self.remote_ip_path]['create_ssh_client']()
            sftp = ssh_client.open_sftp()
            local_data = BytesIO()
            local_data.write(content_to_upload)
            local_data.seek(0)
            sftp.putfo(local_data, out_fullpath)
            sftp.close()
            ssh_client.close()
            return out_fullpath


        @context_dependencies(('.localfs.tempdir.downloads', Path),
                              (f"{base_path}.create_ssh_client", Callable))
        def download_data(ctxt: Context, filename: str):
            remote_upload_dir = '/tmp/downloads'
            remote_fname = filename.split('\\')[-1].split('/')[-1]

            # first upload the file on the controlled server
            ssh_client = ctxt['systemctxt']['controlled'][self.remote_ip_path]['create_ssh_client']()
            sftp = ssh_client.open_sftp()
            sftp.get(os.path.join(remote_upload_dir, remote_fname),
                     os.path.join(ctxt['localfs']['tempdir']['downloads'], remote_fname))
            sftp.close()
            ssh_client.close()

            print(f"[+] Download finished, check {os.path.join(ctxt['localfs']['tempdir']['downloads'], remote_fname)}")


        @context_dependencies((f"{base_path}.ssh_ok", bool),
                              (f"{base_path}.create_ssh_client", Callable))
        @config_dependencies(('.systemctxt.controlled.timeout_command', int), )
        def execute_command(config: Config, ctxt: Context, command: str, timeout: int | None = None):
            print(f"[.] Attempting to execute {command} on {self.remote_ip}")
            ssh_client = ctxt['systemctxt']['controlled'][self.remote_ip_path]['create_ssh_client']()
            stdin, stdout, stderr = ssh_client.exec_command(command.encode(),
                                                            timeout=timeout or
                                                                    config['systemctxt']['controlled']['timeout_command'])
            status = stdout.channel.recv_exit_status()
            out, err = ''.join(iter(stdout.readline, '')), ''.join(iter(stderr.readline, ''))
            print(f"[+] Command result: STDOUT={out} STDERR={err} STATUS={status}")
            ssh_client.close()
            return {'stdout': out, 'stderr': err, 'status': status}


        @contextmanager
        @context_dependencies((f"{base_path}.ssh_ok", bool),
                              (f"{base_path}.create_ssh_client", Callable))
        def with_ssh(ctxt: Context):
            ssh_client = ctxt['systemctxt']['controlled'][self.remote_ip_path]['create_ssh_client']()
            yield ssh_client
            ssh_client.close()


        @contextmanager
        @context_dependencies((f"{base_path}.ssh_ok", bool),
                              (f"{base_path}.create_ssh_client", Callable))
        def with_ssh_forward(ctxt: Context, listen_port, remote_host, remote_port):
            ssh_client = ctxt['systemctxt']['controlled'][self.remote_ip_path]['create_ssh_client']()
            transport = ssh_client.get_transport()
            revport_handler = SSHReversePort(ssh_client, transport, listen_port, remote_host, remote_port)
            yield revport_handler
            revport_handler.stop()
            ssh_client.close()


        self.generate_ssh_key = ssh_key
        self.check_ssh_key = check_ssh_key
        self.wait_for_ssh_access = wait_for_ssh_access
        self.upload = upload_data
        self.download = download_data
        self.create_ssh_client = create_ssh_client
        self.execute_command = execute_command
        self.with_ssh = with_ssh
        self.with_ssh_forward = with_ssh_forward

        RemoteSSHManager.per_host[base_path] = self


class SSHReversePort(threading.Thread):

    def __init__(self, ssh_client, transport, listen_port, remote_host, remote_port, autorun=True):
        threading.Thread.__init__(self)
        self.ssh_client = ssh_client  # the client may be to close at the end
        self.transport = transport
        self.listen_port = listen_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        if autorun:
            self.init_and_start()

    def init_and_start(self):
        print(f"[.] Requesting SSH forward from {self.listen_port}")
        self.transport.request_port_forward('127.0.0.1', self.listen_port)
        self.finished = False
        self.start()

    def run(self):
        while not self.finished:
            chan = self.transport.accept(20)
            if chan is None:
                continue
            thr = threading.Thread(
                target=SSHReversePort.basic_rev_tcp_handler, args=(chan, self.remote_host, self.remote_port)
            )
            thr.daemon = True
            thr.start()

    def stop(self):
        self.finished = True
        self.transport.cancel_port_forward('127.0.0.1', self.listen_port)
        self.join()

    @staticmethod
    def basic_rev_tcp_handler(chan, host, port):
        sock = socket.socket()
        sock.connect((host, port))
        while True:
            r, w, x = select.select([sock, chan], [], [])
            if sock in r:
                data = sock.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                sock.send(data)
        chan.close()
        sock.close()


@context_producer(('.systemctxt.controlled.create_ssh_client', Callable),
                  #('.systemctxt.controlled.ssh_service', AuthenticatedDirectService), # for this we can go from rsm
                  ('.systemctxt.controlled.ssh_ok', bool), ('.systemctxt.controlled.ssh_manager', RemoteSSHManager))
@context_dependencies(('.localfs.tempdir.utils', Path))
@config_dependencies(('.systemctxt.controlled.server_url', str))
def default_ssh_manager(config: Config, ctxt: Context):
    rsm = RemoteSSHManager(config['systemctxt']['controlled']['server_url'])
    ctxt.setdefault('systemctxt', {}).setdefault('controlled', {})['create_ssh_client'] = rsm.create_ssh_client
    ctxt['systemctxt']['controlled']['ssh_manager'] = rsm
    #ctxt['systemctxt']['controlled']['ssh_service'] = rsm.ssh_service
    ctxt['systemctxt']['controlled']['ssh_ok'] = rsm.wait_for_ssh_access()
    return rsm


@context_dependencies(('.systemctxt.controlled.ssh_manager', RemoteSSHManager))
def upload_on_controlled(ctxt: Context, content: File, filename: str | None, write_copy: bool = True):
    rsm = ctxt['systemctxt']['controlled']['ssh_manager']
    return rsm.upload(content, filename, write_copy)

@context_dependencies(('.systemctxt.controlled.ssh_manager', RemoteSSHManager))
def execute_on_controlled(ctxt: Context, command: str, timeout=None):
    rsm = ctxt['systemctxt']['controlled']['ssh_manager']
    return rsm.execute_command(command, timeout)


if __name__ == '__main__':
    print(generate_ed25519_key())

    from core.core30_context.policy.common_contexts import load_local_context
    from core.core31_policy.entrypoint.entrypoint import cli_entrypoint
    from core.core30_context.context import current_ctxt

    load_local_context()
    cli_entrypoint(at_least_one_action=True)

    rsm = default_ssh_manager()
    ctxt = current_ctxt()['systemctxt']['controlled']
    ssh_manager = ctxt['ssh_manager']

    out = ssh_manager.execute_command('ls -al')
    print(out)

    ctxt = current_ctxt()['systemctxt']['controlled']['3-249-217-59']
    print(ctxt)

    with rsm.with_ssh_forward(38277, '127.0.0.1', 4567) as fwd:
        time.sleep(20)
