import os
import re
import lit.llvm

LLVM_TOOLS_DIR = os.environ.get("LLVM_TOOLS_DIR", "/usr/lib/llvm-21/bin")

lit.llvm.initialize(lit_config, config)
config.llvm_tools_dir = LLVM_TOOLS_DIR
config.llvm_build_dir = LLVM_TOOLS_DIR

config.lld_obj_root = os.environ.get("LLD_OBJ_ROOT", "/tmp/lld-obj")
config.llvm_src_root = "/tmp/llvm-src"
config.have_libxml2 = False
config.have_dia_sdk = False
config.enable_backtrace = False
config.sizeof_void_p = 8
config.has_plugins = False
config.build_examples = False
config.linked_bye_extension = False
config.enable_threads = True
config.ld_lld_default_mingw = False
config.llvm_shlib_dir = "/tmp"
config.llvm_shlib_ext = ".so"
config.host_triple = os.environ.get("HOST_TRIPLE", "x86_64-unknown-linux-gnu")
config.target_triple = os.environ.get("TARGET_TRIPLE", "aarch64-unknown-linux-gnu")

# Set lld_tools_dir BEFORE load_config so use_lld() inside lit.cfg.py
# picks up our fakes directory containing symlinks to Wild.
FAKES_DIR = os.environ.get("WILD_FAKES_DIR", "")
if FAKES_DIR:
    config.lld_tools_dir = FAKES_DIR

lit_config.load_config(config, os.path.join(os.path.dirname(__file__), 'lit.cfg.py'))

# If no fakes dir, fall back to text substitution
if not FAKES_DIR:
    EMULATION = os.environ.get("WILD_EMULATION", "aarch64elf")
    new_subs = []
    for pat, sub in config.substitutions:
        if re.search(r'ld\.lld', sub):
            new_subs.append((pat, f'{WILD} -m {EMULATION}'))
        else:
            new_subs.append((pat, sub))
    config.substitutions = new_subs
