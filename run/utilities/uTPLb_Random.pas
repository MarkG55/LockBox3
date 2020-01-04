{* ***** BEGIN LICENSE BLOCK *****
Copyright 2009 Sean B. Durkin
Copyright 2020 Mark Griffiths
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

 * ***** END LICENSE BLOCK ***** *}

// Unit for generating pseudo random data via a Stream
//
// Uses System Entropy source along with additional entropy to get initial
// starting entropy and for periodically getting new entropy
// Uses 512 bit SHA2 Hash to combine entropy sources and then uses this as a key
// to an AES cipher to generate the actual pseudo random data
//
// If you want to, you can override the default RandomStream instance with another
// TStream descedant - in case you want to use a simpler random number generator
// for testing purposes or if you think you can come up with something better.
// You can also create your own entropy sources and add/replace the default entropy
// sources that are used in this unit.
//
// A good quality random data source is essential for secure communications.
// Previous implementations used a 64 bit integer as a seed which made a complete
// mockery of the idea of using 256 bit keys for better security.
// The previous implementation used the Windows Crypto API for the see which
// wasn't too bad (not that great with just 64 bits of course)
// On other platforms, things were far worse with it using a 64 bit counter from
// the operating system with a very (in cryptographic terms) predicatable value.
// Any long term keys created with the previous implementation should be replaced
// as a matter of urgency!

unit uTPLb_Random;

interface

uses
  Classes,
  System.SysUtils,
  uTPLb_Logging,
  uTPLb_EntropySource,
  uTPLb_SystemEntropySource,
  uTPLb_ThreadBasedEntropySource,
  uTPLb_Time,
  uTPLb_Constants,
  uTPLb_CryptographicLibrary,
  uTPLb_Codec,
  uTPLb_ECB,
  uTPLb_BlockCipher,
  uTPLb_Hash;

Const
  AES_KeySize = 256;
  AES_KeySizeInBytes = AES_KeySize div 8;
  DefaultReseedInterval = 300; // 5 minutes

Type

  TRandomStream = class(TStream)
  private
    EntropySource: TCombinedEntropySource;
    RandomDataBuffer: TBytesStream;
    Lib: TCryptographicLibrary;
    Codec: TCodec;
    Hash: THash;
    LastHashValue: TBytesStream;
    BlockCounter: Int64;
    BlockCounterStream: TBytesStream;
    LastReKey: Int64;
    FReseedInterval: Integer;
    class var FDefaultInstance: TStream;

    procedure GetNewBlock;
    procedure SetCodecKey;
    procedure SetNewKeyIfRequired;
    procedure SetReseedInterval(const Value: Integer);
    class function GetDefaultInstance: TStream; static;
    class procedure SetDefaultInstance(const Value: TStream); static;
  protected
    function GetSize: Int64; override;
    procedure SetSize(const NewSize: Int64); override;
  public
    constructor Create;
    destructor Destroy; override;
    class destructor Destroy;

    Procedure RemoveAllEntropySources;
    Procedure AddEntropySource(NewEntropySource: TEntropySource);

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;

    property ReseedInterval: Integer read FReseedInterval write SetReseedInterval;
    class property DefaultInstance: TStream read GetDefaultInstance write SetDefaultInstance;
  end;

implementation

uses
  Math,
  uTPLb_IntegerUtils;

{ TRandomStream }

procedure TRandomStream.RemoveAllEntropySources;
begin
  EntropySource.RemoveAllEntropySources;
end;

procedure TRandomStream.AddEntropySource(NewEntropySource: TEntropySource);
begin
  EntropySource.AddEntropySource(NewEntropySource);
end;

constructor TRandomStream.Create;
begin
  ReseedInterval := DefaultReseedInterval;

  EntropySource := TCombinedEntropySource.Create;
  AddEntropySource(TSystemEntropySource.Create);
  AddEntropySource(TThreadBasedEntropySource.Create);

  RandomDataBuffer := TBytesStream.Create;
  BlockCounterStream := TBytesStream.Create;

  Lib := TCryptographicLibrary.Create(nil);
  Lib.RegisterBlockChainingModel(TECB.Create as IBlockChainingModel);

  Codec := TCodec.Create(nil);
  Codec.CryptoLibrary := Lib;
  Codec.StreamCipherId := BlockCipher_ProgId;
  Codec.BlockCipherId := Format(AES_ProgId, [AES_KeySize]);
  Codec.ChainModeId := ECB_ProgId;

  Hash := THash.Create(nil);
  Hash.CryptoLibrary := Lib;
  Hash.HashId := SHA512_ProgId;
  LastHashValue := TBytesStream.Create;

  SetCodecKey;
end;

destructor TRandomStream.Destroy;
begin
  LastHashValue.Free;
  Hash.Free;
  Codec.Free;
  Lib.Free;
  BlockCounterStream.Free;
  RandomDataBuffer.Free;
  EntropySource.Free;

  inherited;
end;

class destructor TRandomStream.Destroy;
begin
  FDefaultInstance.Free;
end;

class function TRandomStream.GetDefaultInstance: TStream;
begin
  if not Assigned(FDefaultInstance) then
    FDefaultInstance := TRandomStream.Create;

  Result := FDefaultInstance;
end;

procedure TRandomStream.GetNewBlock;
begin
  BlockCounterStream.Size := SizeOf(BlockCounter);
  Move(BlockCounter, BlockCounterStream.Memory^, SizeOf(BlockCounter));
  BlockCounterStream.Position := 0;

  RandomDataBuffer.Size := 0;
  Codec.EncryptStream(BlockCounterStream, RandomDataBuffer);
  Inc(BlockCounter);
  RandomDataBuffer.Position := 0;
end;

function TRandomStream.GetSize: Int64;
begin
  Result := 0;
end;

function TRandomStream.Read(var Buffer; Count: Longint): Longint;
var
  Output: PByte;
  NewBytes: Integer;
begin
  SetNewKeyIfRequired;

  Result := 0;
  Output := @Buffer;

  while Count > 0 do
    begin
      if RandomDataBuffer.Position >= RandomDataBuffer.Size then
        GetNewBlock;

      NewBytes := Min(RandomDataBuffer.Size - RandomDataBuffer.Position, Count);

      Move(RandomDataBuffer.Memory^, Output^, NewBytes);
      Dec(Count, NewBytes);
      Inc(Result, NewBytes);
      Inc(Output, NewBytes);
      RandomDataBuffer.Position := RandomDataBuffer.Position + NewBytes;
    end;
end;

function TRandomStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  Result := 0;
end;

procedure TRandomStream.SetCodecKey;
var
  EntropyData: TBytesStream;
begin
  DebugMsg('TRandomStream.SetCodecKey');

  EntropyData := TBytesStream.Create;

  try
    LastHashValue.Position := 0;
    EntropyData.LoadFromStream(LastHashValue);
    EntropySource.ReadEntropy(EntropyData, AES_KeySize);
    EntropyData.Position := 0;
    Hash.HashStream(EntropyData);

    Hash.HashOutputValue.Position := 0;
    LastHashValue.Size := 0;
    LastHashValue.LoadFromStream(Hash.HashOutputValue);

    LastHashValue.Position := 0;
    Codec.InitFromStream(LastHashValue);

    LastReKey := TTimeUtils.GetTickCount64;
  finally
    EntropyData.Free;
  end;
end;

class procedure TRandomStream.SetDefaultInstance(const Value: TStream);
begin
  FDefaultInstance.Free;
  FDefaultInstance := Value;
end;

procedure TRandomStream.SetNewKeyIfRequired;
begin
  if ReseedInterval <= 0 then
    exit;

  if (TTimeUtils.GetTickCount64 - LastReKey) >= (ReseedInterval * 1000) then
    SetCodecKey;
end;

procedure TRandomStream.SetReseedInterval(const Value: Integer);
begin
  FReseedInterval := Value;
end;

procedure TRandomStream.SetSize(const NewSize: Int64);
begin

end;

function TRandomStream.Write(const Buffer; Count: Longint): Longint;
begin
  Result := 0;
end;

end.
