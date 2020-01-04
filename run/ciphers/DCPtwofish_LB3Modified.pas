{ ****************************************************************************** }
{ * DCPcrypt v2.0 written by David Barton (crypto@cityinthesky.co.uk) ********** }
{ ****************************************************************************** }
{ * A binary compatible implementation of Twofish ****************************** }
{ ****************************************************************************** }
{ * Copyright (c) 1999-2002 David Barton                                       * }
{ * Permission is hereby granted, free of charge, to any person obtaining a    * }
{ * copy of this software and associated documentation files (the "Software"), * }
{ * to deal in the Software without restriction, including without limitation  * }
{ * the rights to use, copy, modify, merge, publish, distribute, sublicense,   * }
{ * and/or sell copies of the Software, and to permit persons to whom the      * }
{ * Software is furnished to do so, subject to the following conditions:       * }
{ *                                                                            * }
{ * The above copyright notice and this permission notice shall be included in * }
{ * all copies or substantial portions of the Software.                        * }
{ *                                                                            * }
{ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR * }
{ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,   * }
{ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    * }
{ * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER * }
{ * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING    * }
{ * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER        * }
{ * DEALINGS IN THE SOFTWARE.                                                  * }
{ ****************************************************************************** }
unit DCPtwofish_LB3Modified;
// The original unit name was DCPtwofish .
// This unit is not part of the LockBox Project, but is used by it.
// It is a modified version of Dave Barton's DCPtwofish unit of
// the DCPCrypt library. It has been cut down to just the primitives.

interface

uses
  Types,
  Classes,
  SysUtils{$IFDEF MSWINDOWS},
  Windows{$ENDIF};

const
  INPUTWHITEN = 0;
  OUTPUTWHITEN = 4;
  NUMROUNDS = 16;
  ROUNDSUBKEYS = (OUTPUTWHITEN + 4);
  TOTALSUBKEYS = (ROUNDSUBKEYS + NUMROUNDS * 2);
  RS_GF_FDBK = $14D;
  MDS_GF_FDBK = $169;
  SK_STEP = $02020202;
  SK_BUMP = $01010101;
  SK_ROTL = 9;

type

  TSubKeys = array [0 .. TOTALSUBKEYS - 1] of DWord;
  TSBox = array [0 .. 3, 0 .. 255] of DWord;
  T128 = packed array [0 .. 3] of DWord;
  T256 = packed array [0 .. 7] of DWord;
  T2048 = packed array [0 .. 255] of byte;
  Tp8x8 = packed array [0 .. 1] of T2048;

procedure DCP_towfish_Precomp;

procedure DCP_twofish_InitKey(const Key; Size: longword; var SubKeys: TSubKeys; var SBox: TSBox);

procedure DCP_twofish_EncryptECB(const SubKeys: TSubKeys; const SBox: TSBox; const InData: T128; var OutData: T128);

procedure DCP_twofish_DecryptECB(const SubKeys: TSubKeys; const SBox: TSBox; const InData: T128; var OutData: T128);

implementation

{$OVERFLOWCHECKS OFF}
{$RANGECHECKS OFF}

var
  MDS: TSBox;

function LFSR1(x: DWord): DWord;
begin
  if (x and 1) <> 0 then
    Result := (x shr 1) xor (MDS_GF_FDBK div 2)
  else
    Result := (x shr 1);
end;

function LFSR2(x: DWord): DWord;
begin
  if (x and 2) <> 0 then
    if (x and 1) <> 0 then
      Result := (x shr 2) xor (MDS_GF_FDBK div 2) xor (MDS_GF_FDBK div 4)
    else
      Result := (x shr 2) xor (MDS_GF_FDBK div 2)
  else if (x and 1) <> 0 then
    Result := (x shr 2) xor (MDS_GF_FDBK div 4)
  else
    Result := (x shr 2);
end;

function Mul_X(x: DWord): DWord;
begin
  Result := x xor LFSR2(x);
end;

function Mul_Y(x: DWord): DWord;
begin
  Result := x xor LFSR1(x) xor LFSR2(x);
end;

function RS_MDS_Encode(lK0, lK1: DWord): DWord;
var
  lR, nJ, lG2, lG3: DWord;
  bB: byte;
begin
  lR := lK1;
  for nJ := 0 to 3 do
    begin
      bB := lR shr 24;
      if (bB and $80) <> 0 then
        lG2 := ((bB shl 1) xor RS_GF_FDBK) and $FF
      else
        lG2 := (bB shl 1) and $FF;
      if (bB and 1) <> 0 then
        lG3 := ((bB shr 1) and $7F) xor (RS_GF_FDBK shr 1) xor lG2
      else
        lG3 := ((bB shr 1) and $7F) xor lG2;
      lR := (lR shl 8) xor (lG3 shl 24) xor (lG2 shl 16) xor (lG3 shl 8) xor bB;
    end;
  lR := lR xor lK0;
  for nJ := 0 to 3 do
    begin
      bB := lR shr 24;
      if (bB and $80) <> 0 then
        lG2 := ((bB shl 1) xor RS_GF_FDBK) and $FF
      else
        lG2 := (bB shl 1) and $FF;
      if (bB and 1) <> 0 then
        lG3 := ((bB shr 1) and $7F) xor (RS_GF_FDBK shr 1) xor lG2
      else
        lG3 := ((bB shr 1) and $7F) xor lG2;
      lR := (lR shl 8) xor (lG3 shl 24) xor (lG2 shl 16) xor (lG3 shl 8) xor bB;
    end;
  Result := lR;
end;

const
  p8x8: Tp8x8 = (($A9, $67, $B3, $E8, $04, $FD, $A3, $76, $9A, $92, $80, $78, $E4, $DD, $D1, $38, $0D, $C6, $35, $98, $18, $F7, $EC,
    $6C, $43, $75, $37, $26, $FA, $13, $94, $48, $F2, $D0, $8B, $30, $84, $54, $DF, $23, $19, $5B, $3D, $59, $F3, $AE, $A2, $82, $63,
    $01, $83, $2E, $D9, $51, $9B, $7C, $A6, $EB, $A5, $BE, $16, $0C, $E3, $61, $C0, $8C, $3A, $F5, $73, $2C, $25, $0B, $BB, $4E, $89,
    $6B, $53, $6A, $B4, $F1, $E1, $E6, $BD, $45, $E2, $F4, $B6, $66, $CC, $95, $03, $56, $D4, $1C, $1E, $D7, $FB, $C3, $8E, $B5, $E9,
    $CF, $BF, $BA, $EA, $77, $39, $AF, $33, $C9, $62, $71, $81, $79, $09, $AD, $24, $CD, $F9, $D8, $E5, $C5, $B9, $4D, $44, $08, $86,
    $E7, $A1, $1D, $AA, $ED, $06, $70, $B2, $D2, $41, $7B, $A0, $11, $31, $C2, $27, $90, $20, $F6, $60, $FF, $96, $5C, $B1, $AB, $9E,
    $9C, $52, $1B, $5F, $93, $0A, $EF, $91, $85, $49, $EE, $2D, $4F, $8F, $3B, $47, $87, $6D, $46, $D6, $3E, $69, $64, $2A, $CE, $CB,
    $2F, $FC, $97, $05, $7A, $AC, $7F, $D5, $1A, $4B, $0E, $A7, $5A, $28, $14, $3F, $29, $88, $3C, $4C, $02, $B8, $DA, $B0, $17, $55,
    $1F, $8A, $7D, $57, $C7, $8D, $74, $B7, $C4, $9F, $72, $7E, $15, $22, $12, $58, $07, $99, $34, $6E, $50, $DE, $68, $65, $BC, $DB,
    $F8, $C8, $A8, $2B, $40, $DC, $FE, $32, $A4, $CA, $10, $21, $F0, $D3, $5D, $0F, $00, $6F, $9D, $36, $42, $4A, $5E, $C1, $E0),
    ($75, $F3, $C6, $F4, $DB, $7B, $FB, $C8, $4A, $D3, $E6, $6B, $45, $7D, $E8, $4B, $D6, $32, $D8, $FD, $37, $71, $F1, $E1, $30, $0F,
    $F8, $1B, $87, $FA, $06, $3F, $5E, $BA, $AE, $5B, $8A, $00, $BC, $9D, $6D, $C1, $B1, $0E, $80, $5D, $D2, $D5, $A0, $84, $07, $14,
    $B5, $90, $2C, $A3, $B2, $73, $4C, $54, $92, $74, $36, $51, $38, $B0, $BD, $5A, $FC, $60, $62, $96, $6C, $42, $F7, $10, $7C, $28,
    $27, $8C, $13, $95, $9C, $C7, $24, $46, $3B, $70, $CA, $E3, $85, $CB, $11, $D0, $93, $B8, $A6, $83, $20, $FF, $9F, $77, $C3, $CC,
    $03, $6F, $08, $BF, $40, $E7, $2B, $E2, $79, $0C, $AA, $82, $41, $3A, $EA, $B9, $E4, $9A, $A4, $97, $7E, $DA, $7A, $17, $66, $94,
    $A1, $1D, $3D, $F0, $DE, $B3, $0B, $72, $A7, $1C, $EF, $D1, $53, $3E, $8F, $33, $26, $5F, $EC, $76, $2A, $49, $81, $88, $EE, $21,
    $C4, $1A, $EB, $D9, $C5, $39, $99, $CD, $AD, $31, $8B, $01, $18, $23, $DD, $1F, $4E, $2D, $F9, $48, $4F, $F2, $65, $8E, $78, $5C,
    $58, $19, $8D, $E5, $98, $57, $67, $7F, $05, $64, $AF, $63, $B6, $FE, $F5, $B7, $3C, $A5, $CE, $E9, $68, $44, $E0, $4D, $43, $69,
    $29, $2E, $AC, $15, $59, $A8, $0A, $9E, $6E, $47, $DF, $34, $35, $6A, $CF, $DC, $22, $C9, $C0, $9B, $89, $D4, $ED, $AB, $12, $A2,
    $0D, $52, $BB, $02, $2F, $A9, $D7, $61, $1E, $B4, $50, $04, $F6, $C2, $16, $25, $86, $56, $55, $09, $BE, $91));

function f32(x: DWord; const K32: T128; Len: DWord): DWord;
var
  t0, t1, t2, t3: DWord;
begin
  t0 := x and $FF;
  t1 := (x shr 8) and $FF;
  t2 := (x shr 16) and $FF;
  t3 := x shr 24;
  if Len = 256 then
    begin
      t0 := p8x8[1, t0] xor ((K32[3]) and $FF);
      t1 := p8x8[0, t1] xor ((K32[3] shr 8) and $FF);
      t2 := p8x8[0, t2] xor ((K32[3] shr 16) and $FF);
      t3 := p8x8[1, t3] xor ((K32[3] shr 24));
    end;
  if Len >= 192 then
    begin
      t0 := p8x8[1, t0] xor ((K32[2]) and $FF);
      t1 := p8x8[1, t1] xor ((K32[2] shr 8) and $FF);
      t2 := p8x8[0, t2] xor ((K32[2] shr 16) and $FF);
      t3 := p8x8[0, t3] xor ((K32[2] shr 24));
    end;
  Result := MDS[0, p8x8[0, p8x8[0, t0] xor ((K32[1]) and $FF)] xor ((K32[0]) and $FF)
    ] xor MDS[1, p8x8[0, p8x8[1, t1] xor ((K32[1] shr 8) and $FF)] xor ((K32[0] shr 8) and $FF)
    ] xor MDS[2, p8x8[1, p8x8[0, t2] xor ((K32[1] shr 16) and $FF)] xor ((K32[0] shr 16) and $FF)
    ] xor MDS[3, p8x8[1, p8x8[1, t3] xor ((K32[1] shr 24))] xor ((K32[0] shr 24))];
end;

procedure Xor256(var Dst: T2048; const Src: T2048; v: byte);
var
  i, j: DWord;
  PDst, PSrc: PDWord;
begin
  j := v * $01010101;
  PDst := @Dst;
  PSrc := @Src;
  for i := 0 to 63 do
    begin
      PDst^ := PSrc^ xor j;
      Inc(PSrc);
      Inc(PDst)
    end
end;

procedure DCP_twofish_InitKey(const Key; Size: longword; var SubKeys: TSubKeys; var SBox: TSBox);
const
  subkeyCnt = ROUNDSUBKEYS + 2 * NUMROUNDS;
var
  key32: T256;
  k32e, k32o, sboxkeys: T128;
  k64Cnt, i, j, A, B, q: DWord;
  L0, L1: T2048;
begin
  FillChar(key32, Sizeof(key32), 0);
  Move(Key, key32, Size div 8);
  if Size <= 128 then { pad the key to either 128bit, 192bit or 256bit }
    Size := 128
  else if Size <= 192 then
    Size := 192
  else
    Size := 256;
  k64Cnt := Size div 64;
  j := k64Cnt - 1;
  for i := 0 to j do
    begin
      k32e[i] := key32[2 * i];
      k32o[i] := key32[2 * i + 1];
      sboxkeys[j] := RS_MDS_Encode(k32e[i], k32o[i]);
      Dec(j);
    end;
  q := 0;
  for i := 0 to ((subkeyCnt div 2) - 1) do
    begin
      A := f32(q, k32e, Size);
      B := f32(q + SK_BUMP, k32o, Size);
      B := (B shl 8) or (B shr 24);
      SubKeys[2 * i] := A + B;
      B := A + 2 * B;
      SubKeys[2 * i + 1] := (B shl SK_ROTL) or (B shr (32 - SK_ROTL));
      Inc(q, SK_STEP);
    end;
  case Size of
    128:
      begin
        Xor256(L0, p8x8[0], (sboxkeys[1] and $FF));
        A := (sboxkeys[0] and $FF);
        i := 0;
        while i < 256 do
          begin
            SBox[0 and 2, 2 * i + (0 and 1)] := MDS[0, p8x8[0, L0[i]] xor A];
            SBox[0 and 2, 2 * i + (0 and 1) + 2] := MDS[0, p8x8[0, L0[i + 1]] xor A];
            Inc(i, 2);
          end;
        Xor256(L0, p8x8[1], (sboxkeys[1] shr 8) and $FF);
        A := (sboxkeys[0] shr 8) and $FF;
        i := 0;
        while i < 256 do
          begin
            SBox[1 and 2, 2 * i + (1 and 1)] := MDS[1, p8x8[0, L0[i]] xor A];
            SBox[1 and 2, 2 * i + (1 and 1) + 2] := MDS[1, p8x8[0, L0[i + 1]] xor A];
            Inc(i, 2);
          end;
        Xor256(L0, p8x8[0], (sboxkeys[1] shr 16) and $FF);
        A := (sboxkeys[0] shr 16) and $FF;
        i := 0;
        while i < 256 do
          begin
            SBox[2 and 2, 2 * i + (2 and 1)] := MDS[2, p8x8[1, L0[i]] xor A];
            SBox[2 and 2, 2 * i + (2 and 1) + 2] := MDS[2, p8x8[1, L0[i + 1]] xor A];
            Inc(i, 2);
          end;
        Xor256(L0, p8x8[1], (sboxkeys[1] shr 24));
        A := (sboxkeys[0] shr 24);
        i := 0;
        while i < 256 do
          begin
            SBox[3 and 2, 2 * i + (3 and 1)] := MDS[3, p8x8[1, L0[i]] xor A];
            SBox[3 and 2, 2 * i + (3 and 1) + 2] := MDS[3, p8x8[1, L0[i + 1]] xor A];
            Inc(i, 2);
          end;
      end;
    192:
      begin
        Xor256(L0, p8x8[1], sboxkeys[2] and $FF);
        A := sboxkeys[0] and $FF;
        B := sboxkeys[1] and $FF;
        i := 0;
        while i < 256 do
          begin
            SBox[0 and 2, 2 * i + (0 and 1)] := MDS[0, p8x8[0, p8x8[0, L0[i]] xor B] xor A];
            SBox[0 and 2, 2 * i + (0 and 1) + 2] := MDS[0, p8x8[0, p8x8[0, L0[i + 1]] xor B] xor A];
            Inc(i, 2);
          end;
        Xor256(L0, p8x8[1], (sboxkeys[2] shr 8) and $FF);
        A := (sboxkeys[0] shr 8) and $FF;
        B := (sboxkeys[1] shr 8) and $FF;
        i := 0;
        while i < 256 do
          begin
            SBox[1 and 2, 2 * i + (1 and 1)] := MDS[1, p8x8[0, p8x8[1, L0[i]] xor B] xor A];
            SBox[1 and 2, 2 * i + (1 and 1) + 2] := MDS[1, p8x8[0, p8x8[1, L0[i + 1]] xor B] xor A];
            Inc(i, 2);
          end;
        Xor256(L0, p8x8[0], (sboxkeys[2] shr 16) and $FF);
        A := (sboxkeys[0] shr 16) and $FF;
        B := (sboxkeys[1] shr 16) and $FF;
        i := 0;
        while i < 256 do
          begin
            SBox[2 and 2, 2 * i + (2 and 1)] := MDS[2, p8x8[1, p8x8[0, L0[i]] xor B] xor A];
            SBox[2 and 2, 2 * i + (2 and 1) + 2] := MDS[2, p8x8[1, p8x8[0, L0[i + 1]] xor B] xor A];
            Inc(i, 2);
          end;
        Xor256(L0, p8x8[0], (sboxkeys[2] shr 24));
        A := (sboxkeys[0] shr 24);
        B := (sboxkeys[1] shr 24);
        i := 0;
        while i < 256 do
          begin
            SBox[3 and 2, 2 * i + (3 and 1)] := MDS[3, p8x8[1, p8x8[1, L0[i]] xor B] xor A];
            SBox[3 and 2, 2 * i + (3 and 1) + 2] := MDS[3, p8x8[1, p8x8[1, L0[i + 1]] xor B] xor A];
            Inc(i, 2);
          end;
      end;
    256:
      begin
        Xor256(L1, p8x8[1], (sboxkeys[3]) and $FF);
        i := 0;
        while i < 256 do
          begin
            L0[i] := p8x8[1, L1[i]];
            L0[i + 1] := p8x8[1, L1[i + 1]];
            Inc(i, 2);
          end;
        Xor256(L0, L0, (sboxkeys[2]) and $FF);
        A := (sboxkeys[0]) and $FF;
        B := (sboxkeys[1]) and $FF;
        i := 0;
        while i < 256 do
          begin
            SBox[0 and 2, 2 * i + (0 and 1)] := MDS[0, p8x8[0, p8x8[0, L0[i]] xor B] xor A];
            SBox[0 and 2, 2 * i + (0 and 1) + 2] := MDS[0, p8x8[0, p8x8[0, L0[i + 1]] xor B] xor A];
            Inc(i, 2);
          end;
        Xor256(L1, p8x8[0], (sboxkeys[3] shr 8) and $FF);
        i := 0;
        while i < 256 do
          begin
            L0[i] := p8x8[1, L1[i]];
            L0[i + 1] := p8x8[1, L1[i + 1]];
            Inc(i, 2);
          end;
        Xor256(L0, L0, (sboxkeys[2] shr 8) and $FF);
        A := (sboxkeys[0] shr 8) and $FF;
        B := (sboxkeys[1] shr 8) and $FF;
        i := 0;
        while i < 256 do
          begin
            SBox[1 and 2, 2 * i + (1 and 1)] := MDS[1, p8x8[0, p8x8[1, L0[i]] xor B] xor A];
            SBox[1 and 2, 2 * i + (1 and 1) + 2] := MDS[1, p8x8[0, p8x8[1, L0[i + 1]] xor B] xor A];
            Inc(i, 2);
          end;

        Xor256(L1, p8x8[0], (sboxkeys[3] shr 16) and $FF);
        i := 0;
        while i < 256 do
          begin
            L0[i] := p8x8[0, L1[i]];
            L0[i + 1] := p8x8[0, L1[i + 1]];
            Inc(i, 2);
          end;
        Xor256(L0, L0, (sboxkeys[2] shr 16) and $FF);
        A := (sboxkeys[0] shr 16) and $FF;
        B := (sboxkeys[1] shr 16) and $FF;
        i := 0;
        while i < 256 do
          begin
            SBox[2 and 2, 2 * i + (2 and 1)] := MDS[2, p8x8[1, p8x8[0, L0[i]] xor B] xor A];
            SBox[2 and 2, 2 * i + (2 and 1) + 2] := MDS[2, p8x8[1, p8x8[0, L0[i + 1]] xor B] xor A];
            Inc(i, 2);
          end;
        Xor256(L1, p8x8[1], (sboxkeys[3] shr 24));
        i := 0;
        while i < 256 do
          begin
            L0[i] := p8x8[0, L1[i]];
            L0[i + 1] := p8x8[0, L1[i + 1]];
            Inc(i, 2);
          end;
        Xor256(L0, L0, (sboxkeys[2] shr 24));
        A := (sboxkeys[0] shr 24);
        B := (sboxkeys[1] shr 24);
        i := 0;
        while i < 256 do
          begin
            SBox[3 and 2, 2 * i + (3 and 1)] := MDS[3, p8x8[1, p8x8[1, L0[i]] xor B] xor A];
            SBox[3 and 2, 2 * i + (3 and 1) + 2] := MDS[3, p8x8[1, p8x8[1, L0[i + 1]] xor B] xor A];
            Inc(i, 2);
          end;
      end;
  end;
end;

procedure DCP_twofish_EncryptECB(const SubKeys: TSubKeys; const SBox: TSBox; const InData: T128; var OutData: T128);
var
  i: longword;
  t0, t1: DWord;
  x: T128;
  k: integer;
begin
  for k := 0 to 3 do
    x[k] := InData[k] xor SubKeys[INPUTWHITEN + k];
  i := 0;
  while i <= NUMROUNDS - 2 do
    begin
      t0 := SBox[0, (x[0] shl 1) and $1FE] xor SBox[0, ((x[0] shr 7) and $1FE) + 1] xor SBox[2, (x[0] shr 15) and $1FE] xor SBox
        [2, ((x[0] shr 23) and $1FE) + 1];
      t1 := SBox[0, ((x[1] shr 23) and $1FE)] xor SBox[0, ((x[1] shl 1) and $1FE) + 1] xor SBox[2, ((x[1] shr 7) and $1FE)
        ] xor SBox[2, ((x[1] shr 15) and $1FE) + 1];
      x[3] := (x[3] shl 1) or (x[3] shr 31);
      x[2] := x[2] xor (t0 + t1 + SubKeys[ROUNDSUBKEYS + 2 * i]);
      x[3] := x[3] xor (t0 + 2 * t1 + SubKeys[ROUNDSUBKEYS + 2 * i + 1]);
      x[2] := (x[2] shr 1) or (x[2] shl 31);

      t0 := SBox[0, (x[2] shl 1) and $1FE] xor SBox[0, ((x[2] shr 7) and $1FE) + 1] xor SBox[2, ((x[2] shr 15) and $1FE)
        ] xor SBox[2, ((x[2] shr 23) and $1FE) + 1];
      t1 := SBox[0, ((x[3] shr 23) and $1FE)] xor SBox[0, ((x[3] shl 1) and $1FE) + 1] xor SBox[2, ((x[3] shr 7) and $1FE)
        ] xor SBox[2, ((x[3] shr 15) and $1FE) + 1];
      x[1] := (x[1] shl 1) or (x[1] shr 31);
      x[0] := x[0] xor (t0 + t1 + SubKeys[ROUNDSUBKEYS + 2 * (i + 1)]);
      x[1] := x[1] xor (t0 + 2 * t1 + SubKeys[ROUNDSUBKEYS + 2 * (i + 1) + 1]);
      x[0] := (x[0] shr 1) or (x[0] shl 31);
      Inc(i, 2);
    end;
  OutData[0] := x[2] xor SubKeys[OUTPUTWHITEN];
  OutData[1] := x[3] xor SubKeys[OUTPUTWHITEN + 1];
  OutData[2] := x[0] xor SubKeys[OUTPUTWHITEN + 2];
  OutData[3] := x[1] xor SubKeys[OUTPUTWHITEN + 3];
end;

procedure DCP_twofish_DecryptECB(const SubKeys: TSubKeys; const SBox: TSBox; const InData: T128; var OutData: T128);
var
  i, k: integer;
  t0, t1: DWord;
  x: T128;
begin
  x[2] := InData[0] xor SubKeys[OUTPUTWHITEN];
  x[3] := InData[1] xor SubKeys[OUTPUTWHITEN + 1];
  x[0] := InData[2] xor SubKeys[OUTPUTWHITEN + 2];
  x[1] := InData[3] xor SubKeys[OUTPUTWHITEN + 3];
  i := NUMROUNDS - 2;
  while i >= 0 do
    begin
      t0 := SBox[0, (x[2] shl 1) and $1FE] xor SBox[0, ((x[2] shr 7) and $1FE) + 1] xor SBox[2, ((x[2] shr 15) and $1FE)
        ] xor SBox[2, ((x[2] shr 23) and $1FE) + 1];
      t1 := SBox[0, ((x[3] shr 23) and $1FE)] xor SBox[0, ((x[3] shl 1) and $1FE) + 1] xor SBox[2, ((x[3] shr 7) and $1FE)
        ] xor SBox[2, ((x[3] shr 15) and $1FE) + 1];
      x[0] := (x[0] shl 1) or (x[0] shr 31);
      x[0] := x[0] xor (t0 + t1 + SubKeys[ROUNDSUBKEYS + 2 * (i + 1)]);
      x[1] := x[1] xor (t0 + 2 * t1 + SubKeys[ROUNDSUBKEYS + 2 * (i + 1) + 1]);
      x[1] := (x[1] shr 1) or (x[1] shl 31);

      t0 := SBox[0, (x[0] shl 1) and $1FE] xor SBox[0, ((x[0] shr 7) and $1FE) + 1] xor SBox[2, (x[0] shr 15) and $1FE] xor SBox
        [2, ((x[0] shr 23) and $1FE) + 1];
      t1 := SBox[0, ((x[1] shr 23) and $1FE)] xor SBox[0, ((x[1] shl 1) and $1FE) + 1] xor SBox[2, ((x[1] shr 7) and $1FE)
        ] xor SBox[2, ((x[1] shr 15) and $1FE) + 1];
      x[2] := (x[2] shl 1) or (x[2] shr 31);
      x[2] := x[2] xor (t0 + t1 + SubKeys[ROUNDSUBKEYS + 2 * i]);
      x[3] := x[3] xor (t0 + 2 * t1 + SubKeys[ROUNDSUBKEYS + 2 * i + 1]);
      x[3] := (x[3] shr 1) or (x[3] shl 31);
      Dec(i, 2);
    end;
  for k := 0 to 3 do
    OutData[k] := x[k] xor SubKeys[INPUTWHITEN + k]
end;

procedure DCP_towfish_Precomp;
var
  m1, mx, my: array [0 .. 1] of DWord;
  nI: longword;
begin
  for nI := 0 to 255 do
    begin
      m1[0] := p8x8[0, nI];
      mx[0] := Mul_X(m1[0]);
      my[0] := Mul_Y(m1[0]);
      m1[1] := p8x8[1, nI];
      mx[1] := Mul_X(m1[1]);
      my[1] := Mul_Y(m1[1]);
      MDS[0, nI] := (m1[1] shl 0) or (mx[1] shl 8) or (my[1] shl 16) or (my[1] shl 24);
      MDS[1, nI] := (my[0] shl 0) or (my[0] shl 8) or (mx[0] shl 16) or (m1[0] shl 24);
      MDS[2, nI] := (mx[1] shl 0) or (my[1] shl 8) or (m1[1] shl 16) or (my[1] shl 24);
      MDS[3, nI] := (mx[0] shl 0) or (m1[0] shl 8) or (my[0] shl 16) or (mx[0] shl 24);
    end;
end;

end.
