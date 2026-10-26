// SPDX-License-Identifier: BSD-2-Clause-Patent
// Original bounded read-only implementation of the public F2FS disk format.
#include "F2fsReadOnly.h"

#define INODE_ADDR 360U
#define INODE_NIDS 4052U
#define NODE_FOOTER 4072U
#define NODE_ADDRS 1018U
#define MAX_DIR_BLOCKS 256U
STATIC UINT16 U16(CONST UINT8 *P) { return P[0] | ((UINT16)P[1]<<8); }
STATIC UINT32 U32(CONST UINT8 *P) { return U16(P) | ((UINT32)U16(P+2)<<16); }
STATIC UINT64 U64(CONST UINT8 *P) { return U32(P) | ((UINT64)U32(P+4)<<32); }
STATIC VOID Clear(VOID *P, UINTN N) { UINT8 *B=P; while (N--) *B++=0; }
STATIC VOID Copy(VOID *D, CONST VOID *S, UINTN N) {
  UINT8 *A=D; CONST UINT8 *B=S; while (N--) *A++=*B++;
}
STATIC BOOLEAN Same(CONST UINT8 *A, CONST UINT8 *B, UINTN N) {
  while (N--) if (*A++!=*B++) return FALSE; return TRUE;
}
STATIC BOOLEAN MainAddress(CONST F2R_VOLUME *V, UINT32 Address) {
  return Address>=V->Main && Address<V->MainEnd && Address<V->Blocks;
}
STATIC EFI_STATUS BlockRead(CONST F2R_VOLUME *V, UINT32 Block, VOID *Buffer) {
  if (Block>=V->Blocks) return EFI_VOLUME_CORRUPTED;
  return FdpReadPartition(&V->Disk,&V->Partition,Block,1,Buffer);
}
STATIC EFI_STATUS NodeRead(CONST F2R_VOLUME *V, UINT32 Nid, UINT32 Owner,
                           UINT32 NodeOffset, UINT8 *Buffer) {
  UINT64 NatBlock; UINTN Offset,I; UINT32 Ino,Address; CONST UINT8 *Entry=NULL;
  EFI_STATUS Status=F2rPlanNatRead(V,Nid,&NatBlock,&Offset);
  if (EFI_ERROR(Status)) return Status;
  // Journal entries overlay the selected NAT table copy, including tombstones.
  for (I=0; I<V->NatJournalCount; ++I) {
    if (U32(V->NatJournal+I*13)==Nid) { Entry=V->NatJournal+I*13+4; break; }
  }
  if (Entry==NULL) {
    Status=BlockRead(V,(UINT32)NatBlock,Buffer);
    if (EFI_ERROR(Status)) return Status;
    Entry=Buffer+Offset;
  }
  Ino=U32(Entry+1); Address=U32(Entry+5);
  if (!Address) return EFI_NOT_FOUND;
  if (Ino!=Owner || !MainAddress(V,Address)) return EFI_VOLUME_CORRUPTED;
  Status=BlockRead(V,Address,Buffer);
  if (EFI_ERROR(Status)) return Status;
  if (U32(Buffer+NODE_FOOTER)!=Nid || U32(Buffer+NODE_FOOTER+4)!=Owner ||
      (U32(Buffer+NODE_FOOTER+8)>>3)!=NodeOffset) return EFI_VOLUME_CORRUPTED;
  return EFI_SUCCESS;
}
EFI_STATUS F2rOpenInode(CONST F2R_VOLUME *V, UINT32 Inode, F2R_FILE *File,
                        VOID *Work, UINTN WorkBytes) {
  EFI_STATUS Status; UINT32 Flags,Extra=0,Xattrs=0; UINT8 Inline;
  if (!File) return EFI_INVALID_PARAMETER;
  File->Valid=FALSE;
  if (!V || !V->Prepared || !Work || WorkBytes<F2R_WORK_BYTES) return EFI_INVALID_PARAMETER;
  Status=NodeRead(V,Inode,Inode,0,File->Node);
  if (EFI_ERROR(Status)) return Status;
  File->Mode=U16(File->Node)&0xf000U;
  if (File->Mode!=0x8000U && File->Mode!=0x4000U) return EFI_UNSUPPORTED;
  if (!U32(File->Node+12)) return EFI_VOLUME_CORRUPTED;
  // No fscrypt/verity/compression/casefold or symlink interpretation here.
  Flags=U32(File->Node+80); Inline=File->Node[3];
  if ((File->Node[2]&0x4cU) || (Flags&0x40100804U) || (Inline&0x80U)) return EFI_UNSUPPORTED;
  if (Inline&0x20U) {
    if (!(V->Features&8)) return EFI_VOLUME_CORRUPTED;
    Extra=U16(File->Node+INODE_ADDR);
    if (Extra<4 || Extra>36 || (Extra&3)) return EFI_UNSUPPORTED;
  }
  // Flexible inline xattrs require a superblock feature not yet accepted.
  if (Inline&1) Xattrs=50;
  File->AddressOffset=INODE_ADDR+Extra;
  File->AddressCount=923-Extra/4-Xattrs;
  File->InlineOffset=File->AddressOffset+4;
  File->InlineBytes=(File->AddressCount-1)*4;
  File->Bytes=U64(File->Node+16);
  if ((Inline&6)==6 || ((Inline&2) && File->Mode!=0x8000) ||
      ((Inline&4) && File->Mode!=0x4000)) return EFI_VOLUME_CORRUPTED;
  if ((Inline&6) && File->Bytes>File->InlineBytes) return EFI_VOLUME_CORRUPTED;
  if ((Inline&2) && File->Bytes && !(Inline&8)) return EFI_UNSUPPORTED;
  File->Inline=Inline; File->Inode=Inode; File->Volume=V; File->Valid=TRUE;
  return EFI_SUCCESS;
}
// Return a data address, including zero for a sparse hole. No extent-cache
// shortcut: every node is resolved through NAT+journal and checked by footer.
STATIC EFI_STATUS Map(CONST F2R_FILE *F, UINT64 Index, UINT32 *Address, UINT8 *Work) {
  UINT32 Nid,Slot,Offset,Indirect,Direct; UINT64 R; EFI_STATUS Status;
  if (Index<F->AddressCount) {
    *Address=U32(F->Node+F->AddressOffset+(UINTN)Index*4); return EFI_SUCCESS;
  }
  R=Index-F->AddressCount;
  if (R<2U*NODE_ADDRS) {
    Slot=(UINT32)(R/NODE_ADDRS); Offset=1+Slot;
    Nid=U32(F->Node+INODE_NIDS+Slot*4); R%=NODE_ADDRS;
  } else {
    R-=2U*NODE_ADDRS;
    if (R<2ULL*NODE_ADDRS*NODE_ADDRS) {
      Slot=(UINT32)(R/((UINT64)NODE_ADDRS*NODE_ADDRS));
      Offset=3+Slot*(NODE_ADDRS+1);
      Nid=U32(F->Node+INODE_NIDS+(2+Slot)*4);
      R%=((UINT64)NODE_ADDRS*NODE_ADDRS);
    } else {
      R-=2ULL*NODE_ADDRS*NODE_ADDRS;
      if (R>=(UINT64)NODE_ADDRS*NODE_ADDRS*NODE_ADDRS) return EFI_UNSUPPORTED;
      Nid=U32(F->Node+INODE_NIDS+16);
      if (!Nid) { *Address=0; return EFI_SUCCESS; }
      Offset=5+2*NODE_ADDRS;
      Status=NodeRead(F->Volume,Nid,F->Inode,Offset,Work);
      if (EFI_ERROR(Status)) return Status;
      Indirect=(UINT32)(R/((UINT64)NODE_ADDRS*NODE_ADDRS));
      Nid=U32(Work+Indirect*4);
      Offset+=1+Indirect*(NODE_ADDRS+1);
      R%=((UINT64)NODE_ADDRS*NODE_ADDRS);
    }
    if (!Nid) { *Address=0; return EFI_SUCCESS; }
    Status=NodeRead(F->Volume,Nid,F->Inode,Offset,Work);
    if (EFI_ERROR(Status)) return Status;
    Direct=(UINT32)(R/NODE_ADDRS); Nid=U32(Work+Direct*4);
    Offset+=1+Direct; R%=NODE_ADDRS;
  }
  if (!Nid) { *Address=0; return EFI_SUCCESS; }
  Status=NodeRead(F->Volume,Nid,F->Inode,Offset,Work);
  if (EFI_ERROR(Status)) return Status;
  *Address=U32(Work+(UINTN)R*4);
  return EFI_SUCCESS;
}
EFI_STATUS F2rReadFile(CONST F2R_FILE *F, UINT64 Offset, VOID *Buffer,
                       UINTN Bytes, UINTN *ReadBytes, VOID *Work, UINTN WorkBytes) {
  UINT8 *Out=Buffer,*W=Work; UINTN Done=0,Count,Within; UINT32 Address;
  EFI_STATUS Status=EFI_SUCCESS;
  if (ReadBytes) *ReadBytes=0;
  if (!F || !F->Valid || !F->Volume || !F->Volume->Prepared ||
      F->Mode!=0x8000 || !ReadBytes || (!Buffer && Bytes) || !W ||
      WorkBytes<F2R_WORK_BYTES) return EFI_INVALID_PARAMETER;
  if (Offset>F->Bytes) return EFI_INVALID_PARAMETER;
  if (Bytes>F->Bytes-Offset) Bytes=(UINTN)(F->Bytes-Offset);
  if (F->Inline&2) {
    if (Bytes) Copy(Out,F->Node+F->InlineOffset+(UINTN)Offset,Bytes);
    *ReadBytes=Bytes; return EFI_SUCCESS;
  }
  while (Done<Bytes) {
    Within=(UINTN)((Offset+Done)%4096); Count=4096-Within;
    if (Count>Bytes-Done) Count=Bytes-Done;
    Status=Map(F,(Offset+Done)/4096,&Address,W+4096);
    if (EFI_ERROR(Status)) break;
    if (!Address) Clear(Out+Done,Count);
    else {
      if (!MainAddress(F->Volume,Address)) { Status=EFI_VOLUME_CORRUPTED; break; }
      Status=BlockRead(F->Volume,Address,W);
      if (EFI_ERROR(Status)) break;
      Copy(Out+Done,W+Within,Count);
    }
    Done+=Count;
  }
  // Failure never exposes a partial read as a complete/hashable result.
  if (EFI_ERROR(Status)) { Clear(Out,Bytes); return Status; }
  *ReadBytes=Done; return EFI_SUCCESS;
}
STATIC EFI_STATUS Entries(CONST UINT8 *P, UINTN Slots, UINTN EntryOffset,
                           F2R_DENTRY_VISITOR Visitor, VOID *Context) {
  UINTN I,J,N,Used; CONST UINT8 *D,*Name; EFI_STATUS Status;
  for (I=0; I<Slots;) {
    if (!(P[I/8]&(1U<<(I%8)))) { ++I; continue; }
    D=P+EntryOffset+I*11; N=U16(D+8); Used=(N+7)/8;
    if (!N || N>255 || Used>Slots-I || U32(D+4)<3 || D[10]>7) return EFI_VOLUME_CORRUPTED;
    for (J=0; J<Used; ++J)
      if (!(P[(I+J)/8]&(1U<<((I+J)%8)))) return EFI_VOLUME_CORRUPTED;
    Name=P+EntryOffset+Slots*11+I*8;
    for (J=0; J<N; ++J) if (!Name[J] || Name[J]=='/') return EFI_VOLUME_CORRUPTED;
    Status=Visitor(Context,(CONST CHAR8 *)Name,N,U32(D+4),D[10]);
    if (EFI_ERROR(Status)) return Status;
    I+=Used;
  }
  return EFI_SUCCESS;
}
EFI_STATUS F2rListDirectory(CONST F2R_FILE *Dir, F2R_DENTRY_VISITOR Visitor,
                            VOID *Context, VOID *Work, UINTN WorkBytes) {
  UINT8 *W=Work; UINTN Slots,EntryOffset; UINT64 I,Blocks; UINT32 Address; EFI_STATUS Status;
  if (!Dir || !Dir->Valid || !Dir->Volume || !Dir->Volume->Prepared ||
      Dir->Mode!=0x4000 || !Visitor || !W || WorkBytes<F2R_WORK_BYTES) return EFI_INVALID_PARAMETER;
  if (Dir->Inline&4) {
    Slots=(Dir->InlineBytes*8)/(19*8+1);
    EntryOffset=Dir->InlineBytes-Slots*19;
    return Entries(Dir->Node+Dir->InlineOffset,Slots,EntryOffset,Visitor,Context);
  }
  if (Dir->Bytes%4096) return EFI_VOLUME_CORRUPTED;
  Blocks=Dir->Bytes/4096;
  if (Blocks>MAX_DIR_BLOCKS) return EFI_UNSUPPORTED;
  for (I=0; I<Blocks; ++I) {
    Status=Map(Dir,I,&Address,W+4096);
    if (EFI_ERROR(Status)) return Status;
    if (!Address) continue;
    if (!MainAddress(Dir->Volume,Address)) return EFI_VOLUME_CORRUPTED;
    Status=BlockRead(Dir->Volume,Address,W);
    if (EFI_ERROR(Status)) return Status;
    Status=Entries(W,214,30,Visitor,Context);
    if (EFI_ERROR(Status)) return Status;
  }
  return EFI_SUCCESS;
}
typedef struct {
  CONST CHAR8 *Name; UINTN Length; UINT32 Inode; UINT8 Type; BOOLEAN Found;
} SEARCH;
STATIC EFI_STATUS Search(VOID *Context, CONST CHAR8 *Name, UINTN Length, UINT32 Inode, UINT8 Type) {
  SEARCH *S=Context;
  if (Length==S->Length && Same((CONST UINT8 *)Name,(CONST UINT8 *)S->Name,Length)) {
    if (S->Found) return EFI_VOLUME_CORRUPTED;
    S->Found=TRUE; S->Inode=Inode; S->Type=Type;
  }
  return EFI_SUCCESS;
}
EFI_STATUS F2rLookup(CONST F2R_VOLUME *V, CONST CHAR8 *Path, F2R_FILE *File,
                     VOID *Work, UINTN WorkBytes) {
  UINTN Length=0,Position=1,Start,Depth=0; EFI_STATUS Status; SEARCH S;
  if (!File) return EFI_INVALID_PARAMETER;
  File->Valid=FALSE;
  if (!Path || Path[0]!='/') return EFI_INVALID_PARAMETER;
  while (Length<=1024 && Path[Length]) ++Length;
  if (Length>1024 || (Length>1 && Path[Length-1]=='/')) return EFI_INVALID_PARAMETER;
  Status=F2rOpenInode(V,V?V->RootInode:0,File,Work,WorkBytes);
  if (EFI_ERROR(Status)) return Status;
  while (Position<Length) {
    if (++Depth>16) { Status=EFI_UNSUPPORTED; goto Failed; }
    Start=Position;
    while (Position<Length && Path[Position]!='/') ++Position;
    S.Length=Position-Start; S.Name=Path+Start; S.Found=FALSE;
    if (!S.Length || S.Length>255 || (S.Length==1 && S.Name[0]=='.') ||
        (S.Length==2 && S.Name[0]=='.' && S.Name[1]=='.')) { Status=EFI_INVALID_PARAMETER; goto Failed; }
    if (File->Mode!=0x4000) { Status=EFI_NOT_FOUND; goto Failed; }
    Status=F2rListDirectory(File,Search,&S,Work,WorkBytes);
    if (EFI_ERROR(Status)) goto Failed;
    if (!S.Found) { Status=EFI_NOT_FOUND; goto Failed; }
    Status=F2rOpenInode(V,S.Inode,File,Work,WorkBytes);
    if (EFI_ERROR(Status)) goto Failed;
    if (S.Type && S.Type!=(File->Mode==0x4000?2:1)) { Status=EFI_VOLUME_CORRUPTED; goto Failed; }
    ++Position;
  }
  return EFI_SUCCESS;
Failed:
  File->Valid=FALSE; return Status;
}
