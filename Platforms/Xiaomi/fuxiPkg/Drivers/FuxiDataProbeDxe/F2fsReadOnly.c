// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "F2fsReadOnly.h"
#define F2R_MAGIC 0xf2f52010U
#define F2R_SB_FEATURE 2180U
#define F2R_SB_CRC 3068U
#define F2R_CP_BITMAP 192U
// Observed metadata 0x499: encryption capability, extra attrs, project quota,
// quota inodes, verity. These do not change SB/CP address fields. Inode/data
// interpretation remains unimplemented. Optional SB CRC is already checked.
#define F2R_BOOTSTRAP_FEATURES (0x0499U | 0x0800U)
STATIC UINT32 L32(CONST UINT8 *P) {
  return P[0] | ((UINT32)P[1]<<8) | ((UINT32)P[2]<<16) | ((UINT32)P[3]<<24);
}
STATIC UINT64 L64(CONST UINT8 *P) { return L32(P) | ((UINT64)L32(P+4)<<32); }
STATIC UINT16 L16(CONST UINT8 *P) { return P[0] | ((UINT16)P[1]<<8); }
STATIC BOOLEAN Equal(CONST UINT8 *A, CONST UINT8 *B, UINTN N) {
  UINTN I; for (I=0; I<N; ++I) if (A[I]!=B[I]) return FALSE; return TRUE;
}
// F2FS uses reflected CRC32 with the magic as initial state, no final xor.
STATIC UINT32 Crc(CONST UINT8 *P, UINTN N) {
  UINT32 V=F2R_MAGIC; UINTN I,J;
  for (I=0; I<N; ++I) { V^=P[I]; for (J=0; J<8; ++J) V=(V>>1)^((V&1)?0xedb88320U:0); }
  return V;
}
STATIC EFI_STATUS Read(CONST F2R_VOLUME *V, UINT64 Block, VOID *Buffer) {
  if (Block>=V->Blocks) return EFI_VOLUME_CORRUPTED;
  return FdpReadPartition(&V->Disk,&V->Partition,Block,1,Buffer);
}
STATIC EFI_STATUS Super(CONST UINT8 *S, UINT64 PartitionBlocks, F2R_VOLUME *V) {
  UINT64 End; UINT32 CpSeg, SitSeg, SsaSeg, MainSeg, Feature=L32(S+F2R_SB_FEATURE);
  if (L32(S)!=F2R_MAGIC) return EFI_NOT_FOUND;
  if (L16(S+4)!=1 || L32(S+16)!=12 || L32(S+20)!=9 ||
      L32(S+8)<9 || L32(S+8)>12 || L32(S+12)>3 ||
      L32(S+8)+L32(S+12)!=12) return EFI_UNSUPPORTED;
  if (Feature & ~F2R_BOOTSTRAP_FEATURES) return EFI_UNSUPPORTED;
  V->Features=Feature;
  if (Feature & 0x800U) {
    if (L32(S+32)!=F2R_SB_CRC) return EFI_UNSUPPORTED;
    if (Crc(S,F2R_SB_CRC)!=L32(S+F2R_SB_CRC)) return EFI_CRC_ERROR;
  }
  if (L32(S+1664)!=0) return EFI_UNSUPPORTED; // cp_payload is a later extension.
  // No multi-device addressing in this draft.
  { UINTN I; for (I=2201; I<2745; ++I) if (S[I]) return EFI_UNSUPPORTED; }
  V->Blocks=L64(S+36); V->Checkpoint=L32(S+76); V->Nat=L32(S+84);
  V->Main=L32(S+92); V->RootInode=L32(S+96); V->NatSegments=L32(S+60);
  CpSeg=L32(S+52); SitSeg=L32(S+56); SsaSeg=L32(S+64); MainSeg=L32(S+68);
  V->SitSegments=SitSeg;
  if (V->Blocks>PartitionBlocks || V->Blocks<1024 || V->RootInode<3 ||
      L32(S+100)!=1 || L32(S+104)!=2 || CpSeg!=2 || !SitSeg || (SitSeg&1) ||
      !V->NatSegments || (V->NatSegments&1) || !SsaSeg || !MainSeg ||
      V->Checkpoint<2 || V->Checkpoint!=L32(S+72) ||
      (UINT64)V->Checkpoint+1024!=L32(S+80) ||
      (UINT64)L32(S+80)+(UINT64)SitSeg*512!=V->Nat ||
      (UINT64)V->Nat+(UINT64)V->NatSegments*512!=L32(S+88) ||
      (UINT64)L32(S+88)+(UINT64)SsaSeg*512!=V->Main ||
      (UINT64)CpSeg+SitSeg+V->NatSegments+SsaSeg+MainSeg!=L32(S+48))
    return EFI_VOLUME_CORRUPTED;
  End=(UINT64)V->Main+(UINT64)MainSeg*512;
  if (End>V->Blocks || End>MAX_UINT32) return EFI_VOLUME_CORRUPTED;
  V->MainEnd=(UINT32)End;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS Checkpoint(CONST F2R_VOLUME *V, UINT32 Start, UINT8 *First, UINT8 *Last,
                              BOOLEAN *ReadFailed) {
  UINT32 Total; EFI_STATUS Status=Read(V,Start,First);
  *ReadFailed=EFI_ERROR(Status);
  if (*ReadFailed) return Status;
  if (L32(First+164)!=4092) return EFI_UNSUPPORTED;
  if (Crc(First,4092)!=L32(First+4092)) return EFI_CRC_ERROR;
  Total=L32(First+136);
  if (Total<2 || Total>512 || L32(First+140)<1 || L32(First+140)>=Total-1)
    return EFI_VOLUME_CORRUPTED;
  Status=Read(V,(UINT64)Start+Total-1,Last);
  *ReadFailed=EFI_ERROR(Status);
  if (*ReadFailed) return Status;
  if (L32(Last+164)!=4092 || Crc(Last,4092)!=L32(Last+4092)) return EFI_CRC_ERROR;
  if (L64(First)!=L64(Last) || !Equal(First,Last,4096)) return EFI_VOLUME_CORRUPTED;
  return EFI_SUCCESS;
}
EFI_STATUS F2rPrepare(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Part,
                     F2R_VOLUME *V, VOID *Work, UINTN WorkBytes) {
  UINT8 *W=Work, *Chosen; UINTN I; UINT32 SitBytes,NatBytes,Flags;
  EFI_STATUS A,B,Status; UINT64 Difference; BOOLEAN IoError;
  if (!V) return EFI_INVALID_PARAMETER;
  // Rejected preparation never leaves an old valid capability behind.
  V->Prepared=FALSE;
  if (!Disk || !Disk->Read || Disk->BlockSize!=4096 || !Part || !Part->Present ||
      Part->First>Part->Last || Part->Last>Disk->LastBlock || !W || WorkBytes<F2R_WORK_BYTES)
    return EFI_INVALID_PARAMETER;
  V->Disk=*Disk; V->Partition=*Part; V->Blocks=Part->Last-Part->First+1;
  Status=Read(V,0,W); if (EFI_ERROR(Status)) return Status;
  Status=Read(V,1,W+4096); if (EFI_ERROR(Status)) return Status;
  // Conservative draft: both superblocks must agree; never silently repair.
  if (!Equal(W+1024,W+4096+1024,3072)) return EFI_VOLUME_CORRUPTED;
  Status=Super(W+1024,V->Blocks,V); if (EFI_ERROR(Status)) return Status;
  A=Checkpoint(V,V->Checkpoint,W,W+4096,&IoError);
  if (IoError) return A;
  B=Checkpoint(V,V->Checkpoint+512,W+8192,W+12288,&IoError);
  if (IoError) return B;
  if (A==EFI_UNSUPPORTED || B==EFI_UNSUPPORTED) return EFI_UNSUPPORTED;
  if (EFI_ERROR(A) && EFI_ERROR(B)) return EFI_VOLUME_CORRUPTED;
  Difference=L64(W+8192)-L64(W);
  if (!EFI_ERROR(A) && !EFI_ERROR(B) && Difference==((UINT64)1<<63))
    return EFI_VOLUME_CORRUPTED; // ambiguous modular ordering
  V->SelectedPack=EFI_ERROR(A) || (!EFI_ERROR(B) && Difference && Difference<((UINT64)1<<63)) ? 2:1;
  Chosen=V->SelectedPack==1?W:W+8192;
  Flags=L32(Chosen+132);
  // Clean unmount only; dirty/fsck/error/orphan/compact/payload extensions
  // need explicit recovery/journal handling, not fallback to an older pack.
  if (!(Flags&1) || (Flags&~0x181U)) return EFI_UNSUPPORTED;
  SitBytes=L32(Chosen+156); NatBytes=L32(Chosen+160);
  if (NatBytes!=(UINT64)V->NatSegments*512/2/8 || SitBytes!=(UINT64)V->SitSegments*512/2/8 ||
      NatBytes>4096 || SitBytes>4092-F2R_CP_BITMAP ||
      NatBytes>4092-F2R_CP_BITMAP-SitBytes) return EFI_VOLUME_CORRUPTED;
  V->CheckpointVersion=L64(Chosen); V->NatBitmapBytes=NatBytes;
  for (I=0; I<NatBytes; ++I) V->NatBitmap[I]=Chosen[F2R_CP_BITMAP+SitBytes+I];
  V->Prepared=TRUE;
  return EFI_SUCCESS;
}
EFI_STATUS F2rPlanNatRead(CONST F2R_VOLUME *V, UINT32 Nid,
                         UINT64 *Block, UINTN *EntryOffset) {
  UINT64 Logical,Physical;
  if (Block) *Block=0;
  if (EntryOffset) *EntryOffset=0;
  if (!V || !V->Prepared || !Block || !EntryOffset) return EFI_INVALID_PARAMETER;
  if (V->NatBitmapBytes>sizeof(V->NatBitmap)) return EFI_VOLUME_CORRUPTED;
  if (Nid<3) return EFI_VOLUME_CORRUPTED;
  Logical=Nid/455U; // nine-byte NAT records, 455 per block
  if (Logical>=((UINT64)V->NatSegments/2)*512 || Logical/8>=V->NatBitmapBytes)
    return EFI_VOLUME_CORRUPTED;
  Physical=(UINT64)V->Nat+(Logical/512)*1024+(Logical%512);
  if (V->NatBitmap[Logical/8] & (0x80U>>(Logical%8))) Physical+=512;
  if (Physical>=V->Main || Physical>=V->Blocks) return EFI_VOLUME_CORRUPTED;
  *Block=Physical; *EntryOffset=(Nid%455U)*9U;
  return EFI_SUCCESS;
}
EFI_STATUS F2rFindDentry(CONST VOID *Block, CONST CHAR8 *Name, UINTN Length,
                        UINT32 *Inode, UINT8 *Type) {
  CONST UINT8 *P=Block,*D,*Names; UINTN I,J,N,Slots; BOOLEAN Found=FALSE;
  UINT32 FoundInode=0; UINT8 FoundType=0;
  if (!P || !Name || !Inode || !Type || !Length || Length>255) return EFI_INVALID_PARAMETER;
  *Inode=0; *Type=0;
  for (I=0; I<Length; ++I) if (!Name[I] || Name[I]=='/') return EFI_INVALID_PARAMETER;
  for (I=0; I<214;) {
    if (!(P[I/8]&(1U<<(I%8)))) { ++I; continue; }
    D=P+30+I*11; N=L16(D+8); Slots=(N+7)/8;
    if (!N || N>255 || Slots>214-I || L32(D+4)<3 || D[10]>7) return EFI_VOLUME_CORRUPTED;
    for (J=0; J<Slots; ++J) if (!(P[(I+J)/8]&(1U<<((I+J)%8)))) return EFI_VOLUME_CORRUPTED;
    Names=P+2384+I*8;
    if (N==Length && Equal(Names,(CONST UINT8 *)Name,N)) {
      if (Found) return EFI_VOLUME_CORRUPTED;
      Found=TRUE; FoundInode=L32(D+4); FoundType=D[10];
    }
    I+=Slots;
  }
  if (!Found) return EFI_NOT_FOUND;
  *Inode=FoundInode; *Type=FoundType;
  return EFI_SUCCESS;
}
