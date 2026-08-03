SECTIONS {
	.section.readonly (READONLY) : { *(.section.readonly) }
	.section.noload (NOLOAD) : { *(.section.noload) }
	.section.dsect (DSECT) : { *(.section.dsect) }
	.section.copy (COPY) : { *(.section.copy) }
	.section.info (INFO) : { *(.section.info) }
	.section.overlay (OVERLAY) : { *(.section.overlay) }
}
