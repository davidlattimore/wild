.section .tbss,"awT",@nobits
.globl tbss_a
tbss_a:
.zero 1024

.section .tcustom,"awT",@nobits
.globl tcustom_a
tcustom_a:
.zero 1024

.section .tcustomdata,"awT",@bits
.globl tcustomdata_a
tcustomdata_a:
.fill 2048,1,42
