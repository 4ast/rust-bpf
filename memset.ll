; SPDX-License-Identifier: GPL-2.0
;
; memset for BPF. llc expands a short llvm.memset inline and calls memset for
; the rest, e.g. to zero a struct of 280 bytes or the elements of a new Vec.
;
; Hidden and with debug info for the same reasons as __multi3.

target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define hidden ptr @memset(ptr %dst, i32 %c, i64 %n) !dbg !4 {
entry:
  %b = trunc i32 %c to i8
  %empty = icmp eq i64 %n, 0
  br i1 %empty, label %done, label %loop

loop:
  %i = phi i64 [ 0, %entry ], [ %next, %loop ]
  %p = getelementptr inbounds i8, ptr %dst, i64 %i
  store i8 %b, ptr %p, align 1
  %next = add nuw i64 %i, 1
  %more = icmp ult i64 %next, %n
  br i1 %more, label %loop, label %done

done:
  ret ptr %dst
}

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "memset.ll", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug)
!1 = !DIFile(filename: "memset.ll", directory: ".")
!2 = !{i32 7, !"Dwarf Version", i32 4}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "memset", scope: !1, file: !1, line: 11, type: !5, scopeLine: 11, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !7, !8, !9}
!7 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !DIBasicType(name: "unsigned long", size: 64, encoding: DW_ATE_unsigned)
