{ * ***** BEGIN LICENSE BLOCK *****
  Copyright 2010 Sean B. Durkin
  This file is part of TurboPower LockBox 3. TurboPower LockBox 3 is free
  software being offered under a dual licensing scheme: LGPL3 or MPL1.1.

  The contents of this file are subject to the Mozilla Public License (MPL)
  Version 1.1 (the "License"); you may not use this file except in compliance
  with the License. You may obtain a copy of the License at
  http://www.mozilla.org/MPL/

  Alternatively, you may redistribute it and/or modify it under the terms of
  the GNU Lesser General Public License (LGPL) as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.

  You should have received a copy of the Lesser GNU General Public License
  along with TurboPower LockBox 3.  If not, see <http://www.gnu.org/licenses/>.

  TurboPower LockBox is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. In relation to LGPL,
  see the GNU Lesser General Public License for more details. In relation to MPL,
  see the MPL License for the specific language governing rights and limitations
  under the License.

  The Initial Developer of the Original Code for TurboPower LockBox version 2
  and earlier was TurboPower Software.

  * ***** END LICENSE BLOCK ***** * }

unit uTPLb_MD5;

interface

uses
  classes,
  uTPLb_HashDsc,
  uTPLb_StreamCipher;

type

  TMD5 = class(TInterfacedObject, IHashDsc, ICryptoGraphicAlgorithm)
  private
    function DisplayName: string;
    function ProgId: string;
    function Features: TAlgorithmicFeatureSet;
    function DigestSize: integer; // in units of bits. Must be a multiple of 8.
    function UpdateSize: integer; // Size that the input to the Update must be.
    function MakeHasher(const Params: IInterface): IHasher;
    function DefinitionURL: string;
    function WikipediaReference: string;
  end;

implementation

uses
  SysUtils,
  uTPLb_BinaryUtils,
  uTPLb_StreamUtils,
  uTPLb_PointerArithmetic,
  uTPLb_IntegerUtils,
  uTPLb_Constants,
  uTPLb_I18n,
  uTPLb_StrUtils;

type
  TMD5_Hasher = class(TInterfacedObject, IHasher)
  private
    ABCD: array [0 .. 3] of uint32;
    FCount: int64;

    constructor Create;
    procedure Update(Source { in } : TMemoryStream);
    procedure End_Hash(PartBlock { in } : TMemoryStream; Digest: TStream);
    procedure Burn;
    function SelfTest_Source: TBytes;
    function SelfTest_ReferenceHashValue: TBytes;
  end;

  { TMD5 }

function TMD5.DefinitionURL: string;
begin
  result := 'http://tools.ietf.org/html/rfc1321'
end;

function TMD5.DigestSize: integer;
begin
  result := 128
end;

function TMD5.DisplayName: string;
begin
  result := 'MD5'
end;

function TMD5.Features: TAlgorithmicFeatureSet;
begin
  result := [afOpenSourceSoftware, afCryptographicallyWeak]
end;

function TMD5.MakeHasher(const Params: IInterface): IHasher;
begin
  result := TMD5_Hasher.Create
end;

function TMD5.ProgId: string;
begin
  result := MD5_ProgId
end;

function TMD5.UpdateSize: integer;
begin
  result := 512
end;

function TMD5.WikipediaReference: string;
begin
  result := { 'http://en.wikipedia.org/wiki/' + } 'MD5'
end;

{ TMD5_Hasher }

constructor TMD5_Hasher.Create;
begin
  ABCD[0] := $67452301;
  ABCD[1] := $EFCDAB89;
  ABCD[2] := $98BADCFE;
  ABCD[3] := $10325476
end;

procedure TMD5_Hasher.Burn;
var
  a: integer;
begin
  for a := 0 to 3 do
    ABCD[a] := 0;
  FCount := 0
end;

procedure TMD5_Hasher.End_Hash(PartBlock: TMemoryStream; Digest: TStream);
var
  L, j: integer;
  Pad: integer;
  PadByte: byte;
  Injection, Block: TMemoryStream;
  Sentinal: byte;
  lwDigest: uint32;
begin
  L := PartBlock.Position;
  Assert(L <= 64, 'TSHA1_Hasher.End_Hash - Wrong block size.');
  Inc(FCount, L * 8);
  Pad := (64 - ((L + 9) mod 64)) mod 64;
  Injection := TMemoryStream.Create;
  Block := TMemoryStream.Create;
  try
    if L > 0 then
      Injection.Write(PartBlock.Memory^, L);
    Sentinal := $80;
    Injection.Write(Sentinal, 1);
    PadByte := $00;
    for j := 1 to Pad do
      Injection.Write(PadByte, 1);
    Injection.Write(FCount, 8);
    Block.Size := 64;
    Inc(L, Pad + 9);
    repeat
      Move(Injection.Memory^, Block.Memory^, 64);
      if L > 64 then
        Move(MemStrmOffset(Injection, 64)^, Injection.Memory^, L - 64);
      Dec(L, 64);
      Injection.Size := L;
      Update(Block)
    until L <= 0 finally BurnMemoryStream(Injection);
    Injection.Free;
    BurnMemoryStream(Block);
    Block.Free;
  end;
  Digest.Position := 0;
  for j := 0 to 3 do
    begin
      lwDigest := ABCD[j];
      Digest.WriteBuffer(lwDigest, 4)
    end;
  Digest.Position := 0;
  // Burning
  lwDigest := 0
end;

function TMD5_Hasher.SelfTest_ReferenceHashValue: TBytes;
begin
  result := AnsiBytesOf('f96b697d 7cb7938d 525a2f31 aaf161d0');
end;

function TMD5_Hasher.SelfTest_Source: TBytes;
begin
  result := AnsiBytesOf('message digest');
end;

function RotateLeft_u32(Value: uint32; Rot: integer): uint32;
begin
  result := (Value shl Rot) or (Value shr (32 - Rot))
end;

const
  T: array [0 .. 63] of uint32 = ($D76AA478, $E8C7B756, $242070DB, $C1BDCEEE, $F57C0FAF, $4787C62A, $A8304613, $FD469501, $698098D8,
    $8B44F7AF, $FFFF5BB1, $895CD7BE, $6B901122, $FD987193, $A679438E, $49B40821, $F61E2562, $C040B340, $265E5A51, $E9B6C7AA, $D62F105D,
    $02441453, $D8A1E681, $E7D3FBC8, $21E1CDE6, $C33707D6, $F4D50D87, $455A14ED, $A9E3E905, $FCEFA3F8, $676F02D9, $8D2A4C8A, $FFFA3942,
    $8771F681, $6D9D6122, $FDE5380C, $A4BEEA44, $4BDECFA9, $F6BB4B60, $BEBFBC70, $289B7EC6, $EAA127FA, $D4EF3085, $04881D05, $D9D4D039,
    $E6DB99E5, $1FA27CF8, $C4AC5665, $F4292244, $432AFF97, $AB9423A7, $FC93A039, $655B59C3, $8F0CCC92, $FFEFF47D, $85845DD1, $6FA87E4F,
    $FE2CE6E0, $A3014314, $4E0811A1, $F7537E82, $BD3AF235, $2AD7D2BB, $EB86D391);

  sValues: array [ { round } 0 .. 3, { a } 0 .. 3] of integer = (
    { round 1 } (7, 22, 17, 12),
    { round 2 } (5, 20, 14, 9),
    { round 3 } (4, 23, 16, 11),
    { round 4 } (6, 21, 15, 10));

  kFactors: array [ { round } 0 .. 3] of integer = (1, 5, 3, 7);
  kOffsets: array [ { round } 0 .. 3] of integer = (0, 1, 5, 0);

procedure TMD5_Hasher.Update(Source: TMemoryStream);
var
  X: array [0 .. 15] of uint32;
  a, k, s, i, j: integer;
  FGHI: uint32;
  Round, Cycle: integer;
  AABBCCDD: array [0 .. 3] of uint32;
  aIndicies: array [0 .. 3] of integer; // 0..3 indexing into ABCD[]

begin
  Assert(Source.Size = 64, 'TMD5_Hasher.Update - Wrong block size.');
  Inc(FCount, 512);
  Move(Source.Memory^, X, 64);
  FGHI := 0;

  for a := 0 to 3 do
    AABBCCDD[a] := ABCD[a];

  for i := 0 to 3 do
    aIndicies[i] := i;

  Round := 0;
  Cycle := 0;
  k := 0;
  for i := 0 to 63 do
    begin
      // aIndexes = (4 - (i mod 4)) mod 4;
      // Round = i div 16;
      case Round of
        0: // Round 1
          FGHI := (ABCD[aIndicies[1]] and ABCD[aIndicies[2]]) or // F(X=b,Y=c,Z=d) = XY v not(X) Z
            ((not ABCD[aIndicies[1]]) and ABCD[aIndicies[3]]);

        1: // Round 2
          FGHI := (ABCD[aIndicies[1]] and ABCD[aIndicies[3]]) or // G(X=b,Y=c,Z=d) = XZ v Y not(Z)
            ((not ABCD[aIndicies[3]]) and ABCD[aIndicies[2]]);

        2: // Round 3
          FGHI := ABCD[aIndicies[1]] xor ABCD[aIndicies[2]] xor ABCD[aIndicies[3]]; // H(X=b,Y=c,Z=d) = X xor Y xor Z

        3: // Round 4
          FGHI := ABCD[aIndicies[2]] xor // I(X=b,Y=c,Z=d) = Y xor (X v not(Z))
            (ABCD[aIndicies[1]] or (not ABCD[aIndicies[3]]))
      end;
      s := sValues[Round, aIndicies[0]];
      ABCD[aIndicies[0]] := ABCD[aIndicies[1]] + RotateLeft_u32(ABCD[aIndicies[0]] + FGHI + X[k] + T[i], s);
      for j := 0 to 3 do
        begin
          Dec(aIndicies[j]);
          if aIndicies[j] = -1 then
            aIndicies[j] := 3
        end;
      if Cycle <= 14 then
        begin
          Inc(Cycle);
          Inc(k, kFactors[Round]);
          if k >= 16 then
            Dec(k, 16)
        end
      else
        begin
          Cycle := 0;
          Inc(Round);
          k := kOffsets[Round]
        end
    end;
  for a := 0 to 3 do
    ABCD[a] := ABCD[a] + AABBCCDD[a]
end;

end.
