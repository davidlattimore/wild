import os
import lit.llvm

LLVM_TOOLS_DIR = os.environ.get("LLVM_TOOLS_DIR", "/usr/lib/llvm-21/bin")
FAKES_DIR = os.environ.get("WILD_FAKES_DIR", "")

if not FAKES_DIR:
    raise Exception("WILD_FAKES_DIR must be set. Run tests via cargo test.")

lit.llvm.initialize(lit_config, config)
config.llvm_tools_dir = LLVM_TOOLS_DIR
config.llvm_build_dir = LLVM_TOOLS_DIR
config.lld_tools_dir = FAKES_DIR
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

LIT_CFG = os.environ.get("WILD_LIT_CFG", os.path.join(os.path.dirname(__file__), 'lit.cfg.py'))
lit_config.load_config(config, LIT_CFG)
