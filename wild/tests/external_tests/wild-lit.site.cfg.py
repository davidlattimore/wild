import os
import re
import lit.llvm

LLVM_TOOLS_DIR = os.environ.get("LLVM_TOOLS_DIR", "/usr/lib/llvm-21/bin")
WILD = os.environ.get("WILD_BIN", "wild")

lit.llvm.initialize(lit_config, config)
config.llvm_tools_dir = LLVM_TOOLS_DIR
config.llvm_build_dir = LLVM_TOOLS_DIR

config.lld_obj_root = "/tmp/lld-obj"
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
config.host_triple = "x86_64-unknown-linux-gnu"
config.target_triple = "aarch64-unknown-linux-gnu"

lit_config.load_config(config, os.path.join(os.path.dirname(__file__), 'lit.cfg.py'))

# Override ld.lld with Wild
new_subs = []
for pat, sub in config.substitutions:
    if re.search(r'ld\.lld', sub):
        new_subs.append((pat, f'{WILD} -m aarch64elf'))
    else:
        new_subs.append((pat, sub))
config.substitutions = new_subs