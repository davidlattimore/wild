//#Config:default
//#LinkArgs: --import-memory
//#NoSection: Memory
//#ExpectSection: Import
//#ExpectMemoryImport: env/memory
//#NoSym: memory
//#RunEnabled: false

//#Config:shared
//#CompArgs: -matomics
//#LinkArgs: --import-memory --shared-memory --initial-memory=131072 --max-memory=196608
//#NoSection: Memory
//#ExpectSection: Import
//#ExpectMemoryImport: env/memory initial=2,max=3,shared=true
//#NoSym: memory
//#RunEnabled: false

//#Config:import-max
//#LinkArgs: --import-memory --initial-memory=131072 --max-memory=196608 -z stack-size=65536 --stack-first
//#NoSection: Memory
//#ExpectMemoryImport: env/memory initial=2,max=3,shared=false
//#NoSym: memory
//#RunEnabled: false

//#Config:exported
//#LinkArgs: --import-memory --export-memory
//#RunEnabled: false
//#NoSection: Memory
//#ExpectMemoryImport: env/memory
//#ExpectSection: Export
//#ExpectSym: memory

void _start(void) {}
