// SPDX-License-Identifier: BSD-2-Clause-Patent
// C2 root-only, an explicit C2/C3 batch (root -> open UID122 -> release), the
// same batch plus loader lookup of keymaster64/keymaster, or the same batch
// with one loadFromBuffer of the keymaster_a extent. No key, no command, no
// callback execution or retry.
#if FUXI_M3_SMCI_ROOT && !FUXI_M3_SMC_CONTEXT
STATIC EFI_STATUS mSmciStatus = EFI_NOT_READY;
STATIC UINT32 SmciU32(CONST UINT8 *P) {
  return P[0] | ((UINT32)P[1]<<8) | ((UINT32)P[2]<<16) | ((UINT32)P[3]<<24);
}
STATIC VOID SmciPut32(UINT8 *P, UINT32 Value) {
  UINTN I; for (I=0; I<4; ++I) P[I]=(UINT8)(Value>>(I*8));
}
STATIC BOOLEAN SmciZero(CONST UINT8 *P, UINTN N) {
  UINTN I; for (I=0; I<N; ++I) if (P[I]) return FALSE; return TRUE;
}
STATIC UINT32 SmciNonZero(CONST UINT8 *P, UINTN N) {
  UINTN I; UINT32 C=0; for (I=0; I<N; ++I) if (P[I]) ++C; return C;
}
#if FUXI_M3_SMCI_LOAD
// The image is plain RAM owned by this probe and was never registered with
// secure world; wipe and release it on every exit path.
STATIC VOID SmciReleaseTaImage(VOID) {
  if (mTaImage == NULL) return;
  ZeroMem(mTaImage, EFI_PAGES_TO_SIZE(mTaImagePages));
  gBS->FreePages((EFI_PHYSICAL_ADDRESS)(UINTN)mTaImage, mTaImagePages);
  FnuLog(L"FUXIM3 TA extent released bytes=%x", (UINT32)EFI_PAGES_TO_SIZE(mTaImagePages));
  mTaImage=NULL; mTaImageBytes=0; mTaImagePages=0;
}
#endif
#if FUXI_M3_SMCI_RESUME
// Resume only the same interrupted SMC, with the returned Qualcomm x6 state.
// The shared buffers remain owned and unchanged until a terminal result.
#define FUXI_M3_SCM_RESUME_LIMIT 8U
STATIC UINT32 SmciCallWithResume(CONST UINT64 Regs[8], ARM_SMC_ARGS *Out) {
  UINT64 Next[8]; UINT32 Count=0;
  FnuSmc64(Regs,Out);
  while (Out->Arg0==1 && Count<FUXI_M3_SCM_RESUME_LIMIT) {
    CopyMem(Next,Regs,sizeof(Next));
    Next[0]=1; Next[6]=(UINT64)Out->Arg6; Next[7]=0;
    ++Count; FnuSmc64(Next,Out);
  }
  return Count;
}
#endif
STATIC EFI_STATUS SmciInvoke(UINT64 Raw, UINT8 *Page, UINTN Bytes, UINT32 Object,
                              UINT32 Kind, UINT32 *Returned) {
  UINT64 Regs[8]; ARM_SMC_ARGS Out;
  UINTN I, OutOff=4096, InLen=4096;
  BOOLEAN Register=(Kind==1), Open=FALSE, Load=FALSE;
#if FUXI_M3_SMCI_VERSION
  BOOLEAN Version=(Kind==6);
#if FUXI_M3_SMCI_DATE
  BOOLEAN Date=(Kind==8);
#endif
#if FUXI_M3_SMCI_SETVER
  BOOLEAN SetVersion=(Kind==7);
#endif
#endif
  CONST CHAR8 *Stage=Register ? "register" : "release";
  UINT32 Op=Register ? 5 : 0xffffU, Counts=Register ? 0x1100 : 0;
#if FUXI_M3_SMCI_LOAD
  UINT32 ElfOff=0, NameOff=0, BoOff=0;
  Load=(Kind==5);
  // The TA message needs ~100 pages; its layout is fixed in the request block.
  if (Load) { Op=1; Counts=0x1012; Stage="loader-load"; }
#endif
#if FUXI_M3_SMCI_VERSION
  if (Version) { Op=0; Counts=0x424; Stage="get-version"; }
#if FUXI_M3_SMCI_DATE
  if (Date) { Op=0; Counts=0x424; Stage="date-support"; }
#endif
#if FUXI_M3_SMCI_SETVER
  if (SetVersion) { Op=0; Counts=0x424; Stage="set-version"; }
#endif
#endif
#if FUXI_M3_SMCI_LOADER
  Open=(Kind==2);
  if (Open) { Op=0;Counts=0x1001;Stage="loader-open"; }
#endif
#if FUXI_M3_SMCI_LOOKUP
  BOOLEAN Lookup=FALSE;
  CONST CHAR8 *Name = (Kind==3) ? "keymaster64" : (Kind==4) ? "keymaster" : NULL;
  UINTN NameLen=0;
  if (Name) {
    while (Name[NameLen]) ++NameLen;
    Lookup=TRUE;Op=2;Counts=0x1001;
    Stage=(Kind==3) ? "lookup-keymaster64" : "lookup-keymaster";
  }
#endif
  ZeroMem(Page, 4096);
  ZeroMem(Page+OutOff, 4096);
  SmciPut32(Page, Object); SmciPut32(Page+4, Op); SmciPut32(Page+8, Counts);
#if FUXI_M3_SMCI_LOADER
  if (Open) {
    // BI1/OO1: 12-byte header + two 8-byte descriptors = 28, align8 -> 32.
    // Fixed IClientEnv_open: uint32 UID122, op0, counts0x1001. No TA name.
    SmciPut32(Page+12,32);SmciPut32(Page+16,4);SmciPut32(Page+32,122);
    FnuLog(L"FUXIM3 SMCI loader-open BI offset=20 size=4 uid=7A; no TA load");
  }
#endif
#if FUXI_M3_SMCI_LOOKUP
  if (Lookup) {
    // IQSEEComCompatAppLoader_lookupTA(handle, name): BI1/OO1 at op2. The BI
    // descriptor sits at +12 and the ASCII name at +32 (12 + 16 aligned to 8).
    // Name is bounded to < 64 bytes and carries no path separator.
    SmciPut32(Page+12,32);SmciPut32(Page+16,(UINT32)NameLen);
    for (I=0; I<NameLen; ++I) Page[32+I]=(UINT8)Name[I];
    FnuLog(L"FUXIM3 SMCI %a BI offset=32 bytes=%u name=%a; lookup only, no load", Stage, (UINT32)NameLen, Name);
  }
#endif
#if FUXI_M3_SMCI_LOAD
  if (Load) {
    // IQSEEComCompatAppLoader_loadFromBuffer: op1, counts BI2/BO1/OO1 = 0x1012.
    // Header 12 + four 8-byte {offset,size} descriptors = 44, payload at 48.
    // Filename is the TA's own metadata name; the BO is the 64-byte distName.
    CONST CHAR8 *Name="keymaster64";
    UINTN NameLen=11;
    if (mTaImage==NULL || mTaImageBytes==0) return EFI_NOT_READY;
    ElfOff=48; NameOff=ElfOff+(UINT32)mTaImageBytes;
    BoOff=(NameOff+(UINT32)NameLen+7U)&~7U;
    // Keep the shape the four small calls already proved: a page-rounded
    // message with the out page on the page directly after it.
    InLen=(UINTN)((BoOff+64U+4095U)&~(UINTN)4095U);
    OutOff=InLen;
    if (OutOff+4096U>Bytes) return EFI_BAD_BUFFER_SIZE;
    ZeroMem(Page+OutOff,4096);
    SmciPut32(Page+12,ElfOff); SmciPut32(Page+16,(UINT32)mTaImageBytes);
    SmciPut32(Page+20,NameOff); SmciPut32(Page+24,(UINT32)NameLen);
    SmciPut32(Page+28,BoOff);   SmciPut32(Page+32,64);
    SmciPut32(Page+36,0);
    CopyMem(Page+ElfOff,mTaImage,mTaImageBytes);
    CopyMem(Page+NameOff,Name,NameLen);
    FnuLog(L"FUXIM3 SMCI loader-load elf=%x name=%x bo=%x msg=%x; no key, no decrypt",
           ElfOff,NameOff,BoOff,(UINT32)InLen);
  }
#endif
#if FUXI_M3_SMCI_VERSION
  if (Version) {
    // Fixed getVersion: BI4/BO2/OI4; the response page follows 0x15000 input.
    if (mTaImage==NULL || mTaImageBytes<6 || mTaImage[0]!=0x7f ||
        mTaImage[1]!='E' || mTaImage[2]!='L' || mTaImage[3]!='F' ||
        mTaImage[4]!=2 || mTaImage[5]!=1) return EFI_COMPROMISED_DATA;
    InLen=0x15000; OutOff=InLen;
    if (OutOff+4096U>Bytes) return EFI_BAD_BUFFER_SIZE;
    ZeroMem(Page,InLen+4096U);
    SmciPut32(Page,Object); SmciPut32(Page+4,Op); SmciPut32(Page+8,Counts);
    SmciPut32(Page+12,0x60); SmciPut32(Page+16,4);
    SmciPut32(Page+20,0x68); SmciPut32(Page+24,0x9ffc);
    SmciPut32(Page+28,0xa068); SmciPut32(Page+32,0);
    SmciPut32(Page+36,0xa068); SmciPut32(Page+40,4);
    SmciPut32(Page+44,0xa070); SmciPut32(Page+48,4);
    SmciPut32(Page+52,0xa078); SmciPut32(Page+56,0x9ffc);
    SmciPut32(Page+0x60,0x200); SmciPut32(Page+0xa068,1);
  }
#endif
#if FUXI_M3_SMCI_DATE
  if (Date) {
    // Independent vendor legacy_get_date_support: cmd 0x215, 12 zeroed
    // request bytes, 0x9ff4 response; no setVersion, configure or keys.
    InLen=0x15000; OutOff=InLen;
    if (OutOff+4096U>Bytes) return EFI_BAD_BUFFER_SIZE;
    ZeroMem(Page,InLen+4096U);
    SmciPut32(Page,Object); SmciPut32(Page+4,Op); SmciPut32(Page+8,Counts);
    SmciPut32(Page+12,0x60); SmciPut32(Page+16,12);
    SmciPut32(Page+20,0x70); SmciPut32(Page+24,0x9ff4);
    SmciPut32(Page+28,0xa068); SmciPut32(Page+32,0);
    SmciPut32(Page+36,0xa068); SmciPut32(Page+40,4);
    SmciPut32(Page+44,0xa070); SmciPut32(Page+48,12);
    SmciPut32(Page+52,0xa080); SmciPut32(Page+56,0x9ff4);
    SmciPut32(Page+0x60,0x215); SmciPut32(Page+0xa068,1);
  }
#endif
#if FUXI_M3_SMCI_SETVER
  if (SetVersion) {
    // Fixed candidate CBOR map {11:200}; equivalence to vendor encoder not executed.
    InLen=0x15000; OutOff=InLen;
    if (OutOff+4096U>Bytes) return EFI_BAD_BUFFER_SIZE;
    ZeroMem(Page,InLen+4096U);
    SmciPut32(Page,Object); SmciPut32(Page+4,Op); SmciPut32(Page+8,Counts);
    SmciPut32(Page+12,0x60); SmciPut32(Page+16,8);
    SmciPut32(Page+20,0x68); SmciPut32(Page+24,0x9ff8);
    SmciPut32(Page+28,0xa060); SmciPut32(Page+32,0);
    SmciPut32(Page+36,0xa060); SmciPut32(Page+40,4);
    SmciPut32(Page+44,0xa068); SmciPut32(Page+48,8);
    SmciPut32(Page+52,0xa070); SmciPut32(Page+56,0x9ff8);
    SmciPut32(Page+0x60,0x3121); SmciPut32(Page+0x64,0xc8180ba1U);
    SmciPut32(Page+0xa060,1);
  }
#endif
  // Two 4096-byte buffers in one registered 8192-byte contiguous range.
  // qcom-scm.ko: svc=6, cmd=0 or 2, owner=0x32, arginfo=0x224, call type=2.
  // __scm_smc_call: bit31=(type==1), bit30=SMC64, owner in [29:24].
  ZeroMem(Regs, sizeof(Regs));
  Regs[0]=FUXI_M3_SMCI_OBJECT ? 0x72000602ULL : 0x72000600ULL; Regs[1]=0x224;
  Regs[2]=Raw; Regs[3]=(UINT64)InLen; Regs[4]=Raw+OutOff; Regs[5]=4096;
  #if FUXI_M3_SMCI_VERSION
#if FUXI_M3_SMCI_DATE
  FnuCacheCiv(&mOps, Page, (Load || Version || Date) ? Bytes : 8192);
#elif FUXI_M3_SMCI_SETVER
  FnuCacheCiv(&mOps, Page, (Load || Version || SetVersion) ? Bytes : 8192);
#else
  FnuCacheCiv(&mOps, Page, (Load || Version) ? Bytes : 8192);
#endif
#else
  FnuCacheCiv(&mOps, Page, Load ? Bytes : 8192);
#endif
  FnuLog(L"FUXIM3 SMCI %a begin x0=%lx x1=%lx in=%lx out=%lx handle=%x op=%x counts=%x",
         Stage, Regs[0], Regs[1], Regs[2], Regs[4], Object, Op, Counts);
#if FUXI_M3_SMCI_RESUME
  {
    UINT32 Count=SmciCallWithResume(Regs,&Out);
    FnuLog(L"FUXIM3 SMCI %a resume-count=%u final-a0=%lx",Stage,Count,(UINT64)Out.Arg0);
  }
#else
  FnuSmc64(Regs, &Out);
#endif
  #if FUXI_M3_SMCI_VERSION
#if FUXI_M3_SMCI_DATE
  FnuCacheInv(&mOps, Page, (Load || Version || Date) ? Bytes : 8192);
#elif FUXI_M3_SMCI_SETVER
  FnuCacheInv(&mOps, Page, (Load || Version || SetVersion) ? Bytes : 8192);
#else
  FnuCacheInv(&mOps, Page, (Load || Version) ? Bytes : 8192);
#endif
#else
  FnuCacheInv(&mOps, Page, Load ? Bytes : 8192);
#endif
  FnuLog(L"FUXIM3 SMCI %a return a0=%lx a1=%lx a2=%lx a3=%lx",
         Stage, (UINT64)Out.Arg0, (UINT64)Out.Arg1,
         (UINT64)Out.Arg2, (UINT64)Out.Arg3);
#if FUXI_M3_SMCI_LOAD
  if (Load)
    FnuLog(L"FUXIM3 SMCI %a desc %08x/%08x %08x/%08x %08x/%08x oo=%08x out=%08x/%08x nz=%u",
           Stage, SmciU32(Page+12), SmciU32(Page+16), SmciU32(Page+20), SmciU32(Page+24),
           SmciU32(Page+28), SmciU32(Page+32), SmciU32(Page+36),
           SmciU32(Page+OutOff), SmciU32(Page+OutOff+4), SmciNonZero(Page+OutOff,4096));
  else
#endif
  FnuLog(L"FUXIM3 SMCI %a buffers hdr=%08x/%08x/%08x oi=%08x/%08x oo=%08x/%08x out=%08x/%08x/%08x/%08x nz=%u",
         Stage, SmciU32(Page), SmciU32(Page+4), SmciU32(Page+8),
         SmciU32(Page+12), SmciU32(Page+16), SmciU32(Page+20), SmciU32(Page+24),
         SmciU32(Page+OutOff), SmciU32(Page+OutOff+4), SmciU32(Page+OutOff+8), SmciU32(Page+OutOff+12),
         SmciNonZero(Page+OutOff,4096));
  // Unknown SMC interruption, response type or data retains memory. A lookup
  // miss is the single interpreted case: it is reported as an object error in
  // a2 with a0/a1/a3 zero, and the raw value is logged before any fallback.
  if (Out.Arg0 || Out.Arg1 || Out.Arg3) return EFI_NOT_READY;
#if FUXI_M3_SMCI_DATE
  if (Date) {
    UINT32 RequestBytes=SmciU32(Page+48), ResponseBytes=SmciU32(Page+56), Status;
    if (Out.Arg2) return EFI_DEVICE_ERROR;
    if (!((SmciU32(Page+OutOff)==0 && SmciU32(Page+OutOff+4)==0) ||
          (SmciU32(Page+OutOff)==0x10002 &&
           (SmciU32(Page+OutOff+4)==0xfffd || SmciU32(Page+OutOff+4)==0xffff))) ||
        SmciU32(Page+OutOff+8)!=0 || !SmciZero(Page+OutOff+12,4084)) return EFI_COMPROMISED_DATA;
    if (SmciU32(Page)!=Object || SmciU32(Page+4)!=0 || SmciU32(Page+8)!=0x424 ||
        SmciU32(Page+12)!=0x60 || SmciU32(Page+16)!=12 ||
        SmciU32(Page+20)!=0x70 || SmciU32(Page+24)!=0x9ff4 ||
        SmciU32(Page+28)!=0xa068 || SmciU32(Page+32)!=0 ||
        SmciU32(Page+36)!=0xa068 || SmciU32(Page+40)!=4 ||
        SmciU32(Page+44)!=0xa070 || RequestBytes>12 ||
        SmciU32(Page+52)!=0xa080 || ResponseBytes<4 || ResponseBytes>0x9ff4 ||
        !SmciZero(Page+60,36) || SmciU32(Page+0x60)!=0x215 ||
        !SmciZero(Page+0x64,0xa068-0x64) || SmciU32(Page+0xa068)!=1 ||
        !SmciZero(Page+0xa06c,4) ||
        !SmciZero(Page+0xa070+RequestBytes,16-RequestBytes) ||
        !SmciZero(Page+0xa080+ResponseBytes,InLen-(0xa080+ResponseBytes))) return EFI_COMPROMISED_DATA;
    Status=SmciU32(Page+0xa080);
    FnuLog(L"FUXIM3 SMCI date-support status=%x bytes=%x",Status,ResponseBytes);
    if (Status) return EFI_DEVICE_ERROR;
    FnuLog(L"FUXIM3 SMCI date-support=1; no configure, no key");
    return EFI_SUCCESS;
  }
#endif
#if FUXI_M3_SMCI_SETVER
  if (SetVersion) {
    UINT32 RequestBytes=SmciU32(Page+48), ResponseBytes=SmciU32(Page+56), Status, PayloadBytes;
    if (Out.Arg2) return EFI_DEVICE_ERROR;
    if (!((SmciU32(Page+OutOff)==0 && SmciU32(Page+OutOff+4)==0) ||
          (SmciU32(Page+OutOff)==0x10002 &&
           (SmciU32(Page+OutOff+4)==0xfffd || SmciU32(Page+OutOff+4)==0xffff))) ||
        SmciU32(Page+OutOff+8)!=0 || !SmciZero(Page+OutOff+12,4084)) return EFI_COMPROMISED_DATA;
    if (SmciU32(Page)!=Object || SmciU32(Page+4)!=0 || SmciU32(Page+8)!=0x424 ||
        SmciU32(Page+12)!=0x60 || SmciU32(Page+16)!=8 ||
        SmciU32(Page+20)!=0x68 || SmciU32(Page+24)!=0x9ff8 ||
        SmciU32(Page+28)!=0xa060 || SmciU32(Page+32)!=0 ||
        SmciU32(Page+36)!=0xa060 || SmciU32(Page+40)!=4 ||
        SmciU32(Page+44)!=0xa068 || RequestBytes>8 ||
        SmciU32(Page+52)!=0xa070 || ResponseBytes<8 || ResponseBytes>0x9ff8 ||
        !SmciZero(Page+60,36) || SmciU32(Page+0x60)!=0x3121 ||
        SmciU32(Page+0x64)!=0xc8180ba1U || !SmciZero(Page+0x68,0x9ff8) ||
        SmciU32(Page+0xa060)!=1 || !SmciZero(Page+0xa064,4) ||
        !SmciZero(Page+0xa068+RequestBytes,8-RequestBytes) ||
        !SmciZero(Page+0xa070+ResponseBytes,InLen-(0xa070+ResponseBytes))) return EFI_COMPROMISED_DATA;
    Status=SmciU32(Page+0xa070); PayloadBytes=SmciU32(Page+0xa074);
    FnuLog(L"FUXIM3 SMCI set-version status=%x bytes=%x payload=%x",Status,ResponseBytes,PayloadBytes);
    if (Status) return EFI_DEVICE_ERROR;
    if (PayloadBytes>ResponseBytes-8) return EFI_COMPROMISED_DATA;
    return EFI_SUCCESS;
  }
#endif
#if FUXI_M3_SMCI_VERSION
  if (Version) {
    UINT32 RequestBytes=SmciU32(Page+48), ResponseBytes=SmciU32(Page+56);
    if (Out.Arg2) return EFI_DEVICE_ERROR;
    // No callback dispatch: only the previously observed empty piggyback form
    // is accepted. Any pending/unknown data retains the bridge and objects.
    if (!((SmciU32(Page+OutOff)==0 && SmciU32(Page+OutOff+4)==0) ||
          (SmciU32(Page+OutOff)==0x10002 &&
           (SmciU32(Page+OutOff+4)==0xfffd || SmciU32(Page+OutOff+4)==0xffff))) ||
        SmciU32(Page+OutOff+8)!=0 || !SmciZero(Page+OutOff+12,4084))
      return EFI_COMPROMISED_DATA;
    if (SmciU32(Page)!=Object || SmciU32(Page+4)!=0 || SmciU32(Page+8)!=0x424 ||
        SmciU32(Page+12)!=0x60 || SmciU32(Page+16)!=4 ||
        SmciU32(Page+20)!=0x68 || SmciU32(Page+24)!=0x9ffc ||
        SmciU32(Page+28)!=0xa068 || SmciU32(Page+32)!=0 ||
        SmciU32(Page+36)!=0xa068 || SmciU32(Page+40)!=4 ||
        SmciU32(Page+44)!=0xa070 || RequestBytes>4 ||
        SmciU32(Page+52)!=0xa078 || ResponseBytes<20 || ResponseBytes>0x9ffc ||
        !SmciZero(Page+60,36) || SmciU32(Page+0x60)!=0x200 ||
        !SmciZero(Page+0x64,0xa068-0x64) || SmciU32(Page+0xa068)!=1 ||
        !SmciZero(Page+0xa06c,4) ||
        !SmciZero(Page+0xa070+RequestBytes,8-RequestBytes) ||
        !SmciZero(Page+0xa078+ResponseBytes,InLen-(0xa078+ResponseBytes)))
      return EFI_COMPROMISED_DATA;
    if (SmciU32(Page+0xa078)!=0) return EFI_DEVICE_ERROR;
    FnuLog(L"FUXIM3 SMCI version bytes=%x fields=%08x/%08x/%08x/%08x",
           ResponseBytes,SmciU32(Page+0xa07c),SmciU32(Page+0xa080),
           SmciU32(Page+0xa084),SmciU32(Page+0xa088));
#if FUXI_M3_KEY_RECOVERY
    mRecoveryVersionOk=(SmciU32(Page+0xa07c)==4 && SmciU32(Page+0xa080)==1 &&
                        SmciU32(Page+0xa084)==4 && SmciU32(Page+0xa088)==1012);
    if(!mRecoveryVersionOk)return EFI_UNSUPPORTED;
#endif
    return EFI_SUCCESS;
  }
#endif
#if FUXI_M3_SMCI_LOAD
  if (Load) {
    // The request page carries the image, so only the fixed words are compared;
    // the payload itself is not re-read here (it was copied from the same read).
    if (SmciU32(Page)!=Object || SmciU32(Page+4)!=Op || SmciU32(Page+8)!=Counts ||
        SmciU32(Page+12)!=ElfOff || SmciU32(Page+16)!=(UINT32)mTaImageBytes ||
        SmciU32(Page+20)!=NameOff || SmciU32(Page+24)!=11 ||
        SmciU32(Page+28)!=BoOff || SmciU32(Page+32)>64 ||
        !SmciZero(Page+40,8))
      return EFI_COMPROMISED_DATA;
    if (SmciU32(Page+OutOff+8)!=0 || !SmciZero(Page+OutOff+12,4084))
      return EFI_COMPROMISED_DATA;
    if (Out.Arg2) {
      // The fixed AppLoader header returns 10..26; an object-layer value cannot
      // be separated from it from one sample, so the raw word is logged as is.
      FnuLog(L"FUXIM3 SMCI loader-status=%x; stopped, retained", (UINT32)Out.Arg2);
      return EFI_DEVICE_ERROR;
    }
    {
      UINT32 App=SmciU32(Page+36);
      if (App<=1 || (App&0x80000000U)) return EFI_COMPROMISED_DATA;
      *Returned=App;
      FnuLog(L"FUXIM3 SMCI loader-app=%x; no command, no key", App);
    }
    return EFI_SUCCESS;
  }
#endif
  // The out page is not part of the object result. The pinned reference reads
  // it only as a piggyback message (version/op at +0/+4, loop count at +8) and
  // never requires it to be zero; a tzcb_req reading would carry its count at
  // +12. Requiring +8..end to be zero therefore covers both readings: the first
  // two words may hold the device's version/op, but no object operation may be
  // pending. The object itself is the handle at +20 of the request page.
  if (SmciU32(Page)!=Object || SmciU32(Page+4)!=Op || SmciU32(Page+8)!=Counts ||
      SmciU32(Page+4104)!=0 || !SmciZero(Page+4108,4084))
    return EFI_COMPROMISED_DATA;
  if (Out.Arg2) {
#if FUXI_M3_SMCI_LOOKUP
    if (Lookup) return EFI_NOT_FOUND;
#endif
    return EFI_NOT_READY;
  }
#if FUXI_M3_SMCI_LOOKUP
  if (Register || Open || Lookup) {
#else
  if (Register || Open) {
#endif
    UINT32 Handle=SmciU32(Page+20);
    if (Handle<=1 || (Handle&0x80000000U)) return EFI_COMPROMISED_DATA;
    // Only OO low32 may change. The fixed BI descriptor and UID payload must
    // remain intact; reserved words, padding, tail and callback out stay zero.
    if (Open && (SmciU32(Page+12)!=32 || SmciU32(Page+16)!=4 ||
                 SmciU32(Page+32)!=122)) return EFI_COMPROMISED_DATA;
#if FUXI_M3_SMCI_LOOKUP
    if (Lookup && (SmciU32(Page+12)!=32 || SmciU32(Page+16)!=(UINT32)NameLen))
      return EFI_COMPROMISED_DATA;
#endif
    for (I=12; I<4096; ++I) {
      if (I>=20 && I<24) continue;
      if (Open && ((I>=12 && I<20) || (I>=32 && I<36))) continue;
#if FUXI_M3_SMCI_LOOKUP
      if (Lookup && ((I>=12 && I<20) || (I>=32 && I<32+NameLen))) continue;
#endif
      if (Page[I]) return EFI_COMPROMISED_DATA;
    }
    *Returned=Handle;
#if FUXI_M3_SMCI_LOOKUP
    if (Lookup) FnuLog(L"FUXIM3 SMCI lookup-object=%x; %a only", Handle, Name);
    else
#endif
    if (Register) FnuLog(L"FUXIM3 SMCI remote-object=%x; root register only", Handle);
#if FUXI_M3_SMCI_LOADER
    else FnuLog(L"FUXIM3 SMCI loader-object=%x; UID122 only", Handle);
#endif
  } else if (!SmciZero(Page+12,4084)) return EFI_COMPROMISED_DATA;
  return EFI_SUCCESS;
}

#include "M3ConfigureDiagnostic.inc"
STATIC VOID FnuSmciRootProbe(VOID) {
  EFI_PHYSICAL_ADDRESS Raw=SIZE_4GB-1;
  UINT8 *Page;
  UINT64 Regs[8]; ARM_SMC_ARGS Out;
  UINT64 Bridge=0;
  UINT32 Object=0, Ignored=0;
  BOOLEAN Retain=FALSE;
  UINTN Pages=FUXI_M3_BRIDGE_LARGE ? 130 : 2;
  UINTN Bytes=EFI_PAGES_TO_SIZE(Pages);
#if FUXI_M3_SMCI_LOADER
  UINT32 Loader=0, Passed=0;
  CONST CHAR8 *Step="allocate";
#endif
#if FUXI_M3_SMCI_LOAD
  UINT32 App=0;
#endif
#if FUXI_M3_SMCI_LOOKUP
  UINT32 Ta=0;
  EFI_STATUS LookupStatus=EFI_NOT_FOUND;
#endif
#if FUXI_M3_KEY_RECOVERY
  EFI_STATUS RecoveryResult=EFI_NOT_READY;
#endif
  mSmciStatus=EFI_NOT_READY;
#if FUXI_M3_SMCI_LOOKUP
  FNU_STAGE("m3-smci-lookup");
  FnuLog(L"FUXIM3 BATCH plan=root/open122/lookup64/lookup/ta-release/release-loader/release-env/delete; gated, no retry");
#elif FUXI_M3_SMCI_LOAD
  FNU_STAGE("m3-smci-load");
#if FUXI_M3_KEY_RECOVERY
#if FUXI_M3_CONFIGURE_RECOVERY && FUXI_M3_CHARACTERISTICS_PROBE
  FnuLog(L"FUXIM3 BATCH plan=root/open122/load64/version/configure/characteristics/recover/wipe/release/delete");
#elif FUXI_M3_CONFIGURE_RECOVERY
  FnuLog(L"FUXIM3 BATCH plan=root/open122/load64/version/configure/recover/wipe/release/delete; one configure");
#else
  FnuLog(L"FUXIM3 BATCH plan=root/open122/load64/version/recover/wipe/release/delete; no persistence");
#endif
#else
  FnuLog(L"FUXIM3 BATCH plan=root/open122/load64/ta-release/release-loader/release-env/delete; gated, no retry");
#endif
#elif FUXI_M3_SMCI_LOADER
  FNU_STAGE("m3-smci-loader");
  FnuLog(L"FUXIM3 BATCH plan=root/open122/release-loader/release-env/delete; gated, no retry");
#else
  FNU_STAGE("m3-smci-root");
#endif
  FnuLog(L"FUXIM3 SMCI mode=%a; one register/release, no fallback",
         FUXI_M3_SMCI_OBJECT ? "object-cmd2" : "legacy-cmd0");
  if (gBS->AllocatePages(AllocateMaxAddress,EfiBootServicesData,Pages,&Raw)!=EFI_SUCCESS) {
    mSmciStatus=EFI_OUT_OF_RESOURCES;
    FnuLog(L"FUXIM3 SMCI page allocation failed; no call");
#if FUXI_M3_SMCI_LOADER
    FnuLog(L"FUXIM3 BATCH stop=allocate passed=0; no call");
#endif
#if FUXI_M3_SMCI_LOAD
    SmciReleaseTaImage();
#endif
#if FUXI_M3_KEY_RECOVERY
    mRecoveryStatus=mSmciStatus;
    FnuDropRecoveryInput();
#endif
    return;
  }
  Page=(UINT8 *)(UINTN)Raw;ZeroMem(Page,Bytes);FnuCacheCiv(&mOps,Page,Bytes);
  FnuLog(L"FUXIM3 SMCI page phys=%lx bytes=%x; no keys",(UINT64)Raw,(UINT32)Bytes);
#if FUXI_M3_SMCI_LOADER
  Step="bridge-enable";
#endif
  mSmciStatus=FdpBuildBridgeEnable(Regs);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 SMCI bridge-enable begin");FnuSmc64(Regs,&Out);
  FnuLog(L"FUXIM3 SMCI bridge-enable return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0,(UINT64)Out.Arg1,(UINT64)Out.Arg2,(UINT64)Out.Arg3);
  if (Out.Arg0 || Out.Arg1) { mSmciStatus=EFI_NOT_READY;goto Done; }
#if FUXI_M3_SMCI_LOADER
  Step="bridge-create";
#endif
#if FUXI_M3_BRIDGE_HLOS
  FnuLog(L"FUXIM3 SMCI bridge-profile=hlos vm-count=1 vmid=3 ns-perm=6 tz-perm=6 hyp-flags=0");
  mSmciStatus=FdpBuildBridgeCreateHlos((UINT64)Raw,Bytes,Regs);
#else
  mSmciStatus=FdpBuildBridgeCreate((UINT64)Raw,Bytes,0,0,Regs);
#endif
  if (EFI_ERROR(mSmciStatus)) goto Done;
  Retain=TRUE;
  FnuLog(L"FUXIM3 SMCI bridge-create args x0=%lx x1=%lx p0=%lx p1=%lx p2=%lx p3=%lx",
         Regs[0],Regs[1],Regs[2],Regs[3],Regs[4],Regs[5]);
  FnuLog(L"FUXIM3 SMCI bridge-create begin");FnuSmc64(Regs,&Out);
  FnuLog(L"FUXIM3 SMCI bridge-create return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0,(UINT64)Out.Arg1,(UINT64)Out.Arg2,(UINT64)Out.Arg3);
  mSmciStatus=FdpDecodeBridgeCreate(Out.Arg0,Out.Arg1,Out.Arg2,&Bridge);
  if (EFI_ERROR(mSmciStatus)) goto Done;
#if FUXI_M3_SMCI_LOADER
  Step="root-register";
#endif
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,1,1,&Object);
  if (EFI_ERROR(mSmciStatus)) goto Done;
#if FUXI_M3_SMCI_LOADER
  Passed|=1;
  FnuLog(L"FUXIM3 BATCH root-register=Success; continue loader-open");
  Step="loader-open";
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,Object,2,&Loader);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  Passed|=2;
#if FUXI_M3_SMCI_LOOKUP
  FnuLog(L"FUXIM3 BATCH loader-open=Success; continue lookup");
  Step="lookup-keymaster64";
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,Loader,3,&Ta);
  if (mSmciStatus==EFI_NOT_FOUND) {
    FnuLog(L"FUXIM3 BATCH lookup=keymaster64 result=Not Found; try keymaster");
    Step="lookup-keymaster";
    mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,Loader,4,&Ta);
  }
  if (mSmciStatus==EFI_NOT_FOUND) {
    FnuLog(L"FUXIM3 BATCH lookup=keymaster result=Not Found; cleanup only");
    mSmciStatus=EFI_SUCCESS;
  } else if (EFI_ERROR(mSmciStatus)) goto Done;
  else {
    LookupStatus=EFI_SUCCESS;Passed|=0x100;
    FnuLog(L"FUXIM3 BATCH lookup=Success handle=%x",Ta);
  }
  Step="ta-release";
  if (Ta) {
    mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,Ta,0,&Ignored);
    if (EFI_ERROR(mSmciStatus)) goto Done;
    FnuLog(L"FUXIM3 BATCH ta-release=Success handle=%x",Ta);
    Ta=0;Passed|=0x200;
  }
  Step="loader-release";
#elif FUXI_M3_SMCI_LOAD
  FnuLog(L"FUXIM3 BATCH loader-open=Success; continue loader-load");
  Step="loader-load";
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,Loader,5,&App);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  Passed|=0x20;
#if FUXI_M3_SMCI_VERSION
  FnuLog(L"FUXIM3 BATCH loader-load=Success app=%x; continue get-version",App);
  Step="get-version";
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,App,6,&Ignored);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  Passed|=0x80;
#if FUXI_M3_SMCI_DATE
  Step="date-support";
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,App,8,&Ignored);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  Passed|=0x100;
#endif
#if FUXI_M3_SMCI_SETVER
  Step="set-version";
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,App,7,&Ignored);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  Passed|=0x100;
#endif
#else
  FnuLog(L"FUXIM3 BATCH loader-load=Success app=%x; continue app-release",App);
#endif
#if FUXI_M3_KEY_RECOVERY
#if FUXI_M3_CONFIGURE_RECOVERY
  Step="configure-recovery";
  mSmciStatus=SmciConfigureRecovery((UINT64)Raw,Page,Bytes,App);
  if(EFI_ERROR(mSmciStatus))goto Done;
  Passed|=0x400;
#endif
  Step="key-recovery";
  RecoveryResult=FnuRunRecovery((UINT64)Raw,Page,Bytes,Bridge,App,(BOOLEAN)(!mReady && !mPoisoned));
  if(mRecoveryRetained) { mSmciStatus=RecoveryResult;goto Done; }
  if(!EFI_ERROR(RecoveryResult))Passed|=0x200;
  // A known failure with a verified closed operation still closes the session.
  // Preserve that failure after the app/loader/env/bridge teardown succeeds.
#endif
  Step="app-release";
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,App,0,&Ignored);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 BATCH app-release=Success handle=%x",App);
  App=0;Passed|=0x40;
  Step="loader-release";
#else
  FnuLog(L"FUXIM3 BATCH loader-open=Success; continue loader-release");
  Step="loader-release";
#endif
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,Loader,0,&Ignored);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 BATCH loader-release=Success handle=%x",Loader);
  Loader=0;Passed|=4;
  Step="environment-release";
#endif
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Bytes,Object,0,&Ignored);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 SMCI object-release=Success handle=%x",Object);
  Object=0;
#if FUXI_M3_SMCI_LOADER
  Passed|=8;Step="bridge-delete";
#endif
  ZeroMem(Page,Bytes);FnuCacheCiv(&mOps,Page,Bytes);
  mSmciStatus=FdpBuildBridgeDelete(Bridge,Regs);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 SMCI bridge-delete begin handle=%lx",Bridge);FnuSmc64(Regs,&Out);
  FnuLog(L"FUXIM3 SMCI bridge-delete return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0,(UINT64)Out.Arg1,(UINT64)Out.Arg2,(UINT64)Out.Arg3);
  mSmciStatus=Out.Arg0 ? EFI_NOT_READY : EFI_SUCCESS;
  if (!EFI_ERROR(mSmciStatus)) {
    Retain=FALSE;
#if FUXI_M3_SMCI_LOADER
    Passed|=16;Step="complete";
#if FUXI_M3_KEY_RECOVERY
    if(EFI_ERROR(RecoveryResult)) { Step="recovery-failed";mSmciStatus=RecoveryResult; }
#endif
#if FUXI_M3_SMCI_LOOKUP
    if (LookupStatus!=EFI_SUCCESS) { Step="lookup-missing";mSmciStatus=LookupStatus; }
#endif
#endif
  }
Done:
#if FUXI_M3_SMCI_LOOKUP
  FnuLog(L"FUXIM3 BATCH stop=%a passed=%x env=%x loader=%x ta=%x retained=%u",Step,Passed,Object,Loader,Ta,(UINT32)Retain);
#elif FUXI_M3_SMCI_LOADER
  FnuLog(L"FUXIM3 BATCH stop=%a passed=%x env=%x loader=%x retained=%u",Step,Passed,Object,Loader,(UINT32)Retain);
#endif
  if (Retain) {
    // No further call, wipe, delete or free: callback/in-flight ownership is
    // unknown. A recovery candidate may hold secrets here. Park until reboot.
    FnuLog(L"FUXIM3 SMCI retained bridge=%lx object=%x; unknown/error state, no retry",Bridge,Object);
  } else {
    ZeroMem(Page,Bytes);FnuCacheCiv(&mOps,Page,Bytes);gBS->FreePages(Raw,Pages);
    FnuLog(L"FUXIM3 SMCI released bytes=%x",(UINT32)Bytes);
  }
#if FUXI_M3_SMCI_LOAD
#if FUXI_M3_KEY_RECOVERY
  FnuLog(L"FUXIM3 SMCI result=%r retained=%u; existing-key recovery diagnostic only",mSmciStatus,(UINT32)Retain);
  if(!mRecoveryAttempted)mRecoveryStatus=EFI_ERROR(mSmciStatus)?mSmciStatus:EFI_NOT_READY;
  FnuDropRecoveryInput();
#else
  FnuLog(L"FUXIM3 SMCI result=%r retained=%u; one load, no key, no decrypt",mSmciStatus,(UINT32)Retain);
#endif
  SmciReleaseTaImage();
#else
  FnuLog(L"FUXIM3 SMCI result=%r retained=%u; no TA, no key, no decrypt",mSmciStatus,(UINT32)Retain);
#endif
}
#endif
