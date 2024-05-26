from core.core11_config.config import register_config_default, Config, config_dependencies
from core.core30_context.context_dependency_graph import context_dependencies, context_producer
from core.core02_model.typed.file import FileContent, File, file_content
from core.core30_context.context import Context

from action.utils.control_server import execute_on_controlled, upload_on_controlled

from z3 import Ast, Z3_benchmark_to_smtlib_string
from typing import Callable
import datetime


#example_url = 'https://github.com/msoos/cryptominisat/releases/download/5.11.21/cryptominisat5-linux-amd64.zip'
example_url = 'https://github.com/stp/stp/releases/download/smtcomp2020/smtcomp-2020-cms.zip'

install_instructions = '''sudo apt-get install -y git cmake bison flex libboost-all-dev python2 perl
git clone https://github.com/stp/stp
cd stp
git submodule init && git submodule update
./scripts/deps/setup-gtest.sh
./scripts/deps/setup-outputcheck.sh
./scripts/deps/setup-cms.sh
./scripts/deps/setup-minisat.sh
mkdir build
cd build
cmake ..
cmake --build .'''

example_test = '''; benchmark
(set-info :status unknown)
(set-logic QF_ABV)
(declare-fun b () (_ BitVec 32))
(declare-fun a () (_ BitVec 32))
(assert
 (let ((?x32 (bvadd a b)))
 (let (($x38 (= ?x32 (_ bv33138 32))))
 (and $x38 $x38))))
(check-sat)
(get-model)'''

default_cryptominisat_path = '~/stp/build/stp_simple'
register_config_default('.systemctxt.satsolver.stp_path', str, default_cryptominisat_path)


@config_dependencies(('.systemctxt.satsolver.stp_path', str))
def execute_stp_attempt(config: Config, content: File, fname_base: str | None = None):
    cryptominisat_path = config['systemctxt']['satsolver']['stp_path']

    fname = (fname_base or 'stp_problem') + '-' + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + '.txt'
    out_path = upload_on_controlled(FileContent(content=file_content(content)), fname)
    return execute_on_controlled(f"time {cryptominisat_path} {out_path}")


@config_dependencies(('.systemctxt.satsolver.stp_path', str))
@context_producer(('.systemctxt.controlled.satsolver.stp_ok', bool))
@context_dependencies(('.interactor.ask_boolean', Callable[[...], bool]))
def ensure_cryptominisat(ctxt: Context, config: Config):
    cryptominisat_path = config['systemctxt']['satsolver']['stp_path']
    out = execute_on_controlled(f"which {cryptominisat_path}")
    if out['status'] != 0:
        print(f"Failed to locate {cryptominisat_path}")
        install = ctxt['interactor']['ask_boolean']({'i': True, 'm': False})('Install (i) or manual (m)?')
        if install:
            print(f"[.] Will execute following commands:\n{install_instructions}")
            log = execute_on_controlled(install_instructions, timeout=600)
        else:
            print(f"[.] Please execute following commands and input when ok:\n{install_instructions}")
            input()
        copy_to_dst = execute_on_controlled(f"cp stp/build/stp_simple {cryptominisat_path}")

    out = execute_on_controlled(f"which {cryptominisat_path}")
    if out['status'] != 0:
        print(f"[-] Not able to locate {cryptominisat_path} after installing")
        ctxt.setdefault('systemctxt', {}).setdefault('controlled', {}).setdefault('satsolver', {})['stp_ok'] = False
        return False

    out = execute_stp_attempt(FileContent(content=example_test.encode()), 'example_test_stp_basic')
    ctxt.setdefault('systemctxt', {}).setdefault('controlled', {}).setdefault('satsolver', {})['stp_ok'] = \
        'sat' in out['stdout'] and out['status'] == 0
    return ctxt['systemctxt']['controlled']['satsolver']['stp_ok']


def toSMT2Benchmark(f, status="unknown", name="benchmark", logic="QF_ABV"):
    v = (Ast * 0)()
    return Z3_benchmark_to_smtlib_string(f.ctx_ref(), name, logic, status, "", 0, v, f.as_ast()) + '\n(get-model)'


def solve_z3_problem(z3_equations):
    return solve_stp_problem(FileContent(content=toSMT2Benchmark(z3_equations).encode()))

def solve_stp_problem(content: File):
    out = execute_stp_attempt(content, 'stp_problem')
    if out['status'] != 0:
        if not ensure_cryptominisat():
            print("[-] STP not installed")
            return False
        out = execute_stp_attempt(content, 'stp_problem')
    return out
