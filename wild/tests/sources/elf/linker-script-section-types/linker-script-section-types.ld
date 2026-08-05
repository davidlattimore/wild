SECTIONS {
    .section.readonly.wa (READONLY) : { *(.section.readonly.wa) }
    .section.noload.wa (NOLOAD) : { *(.section.noload.wa) }
    .section.dsect.wa (DSECT) : { *(.section.dsect.wa) }
    .section.copy.wa (COPY) : { *(.section.copy.wa) }
    .section.info.wa (INFO) : { *(.section.info.wa) }
    .section.overlay.wa (OVERLAY) : { *(.section.overlay.wa) }

    .section.readonly.ax (READONLY) : { *(.section.readonly.ax) }
    .section.noload.ax (NOLOAD) : { *(.section.noload.ax) }
    .section.dsect.ax (DSECT) : { *(.section.dsect.ax) }

    .section.readonly.a (READONLY) : { *(.section.readonly.a) }
    .section.noload.a (NOLOAD) : { *(.section.noload.a) }
    .section.dsect.a (DSECT) : { *(.section.dsect.a) }
}
