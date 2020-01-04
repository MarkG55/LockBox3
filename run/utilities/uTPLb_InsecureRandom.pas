{ * ***** BEGIN LICENSE BLOCK *****
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

  * ***** END LICENSE BLOCK ***** * }

// ATTENTION
//
// This unit is only kept mostly as is for use with the existing unit tests.
// You should not use this random number generator for generating keys that are
// used in the real world - YOU HAVE BEEN WARNED!!!!!

unit uTPLb_InsecureRandom;

interface

uses Classes;

type

  TInsecureRandomStream = class(TStream)
  private
    FValue: Int64;
    FBuffer: Int64;
    FAvail: integer;

    procedure Crunch;
    procedure SetSeed(Value: Int64);

  protected
    function GetSize: Int64; override;
    procedure SetSize(const NewSize: Int64); override;

  public
    constructor Create; Overload;
    constructor Create(Seed: Int64); Overload;

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
    procedure Randomize;

    property Seed: Int64 read FValue write SetSeed;
  end;

implementation

uses
{$IFDEF MSWINDOWS}
  Windows,
  uTPLb_WinCrypto,
{$ENDIF}
  Math,
  SysUtils,
  uTPLb_IntegerUtils;

function TimeStampClock: Int64;
{$IFDEF ASSEMBLER}
asm
  RDTSC
end;
{$ELSE}
var
  SystemTimes: TThread.TSystemTimes;
begin
  TThread.GetSystemTimes(SystemTimes);
  result:= SystemTimes.KernelTime
end;
{$ENDIF}

{ TInsecureRandomStream }

constructor TInsecureRandomStream.Create;
begin
  inherited;

  Randomize
end;

{$OVERFLOWCHECKS OFF} {$RANGECHECKS OFF}

constructor TInsecureRandomStream.Create(Seed: Int64);
begin
  inherited Create;

  Self.Seed:= Seed;
end;

procedure TInsecureRandomStream.Crunch;
// Refer http://www.merlyn.demon.co.uk/pas-rand.htm
const
  Factor: Int64 = 6364136223846793005;
begin
  FValue:= FValue * Factor + 1;
  FBuffer:= FValue;
  FAvail:= SizeOf(FValue)
end;
{$RANGECHECKS ON} {$OVERFLOWCHECKS ON}

function TInsecureRandomStream.GetSize: Int64;
begin
  result:= 0
end;

procedure TInsecureRandomStream.Randomize;
{$IFDEF MSWINDOWS}
var
  hProv: THandle;
  dwProvType, dwFlags: DWORD;
  Provider1: string;
  hasOpenHandle: boolean;
{$ENDIF}
begin
{$IFDEF MSWINDOWS}
  Provider1:= Provider;
  dwProvType:= PROV_RSA_FULL;
  dwFlags:= CRYPT_SILENT;
  hasOpenHandle:= CryptAcquireContext(hProv, nil, PChar(Provider),
    dwProvType, dwFlags);
  try
    if (not hasOpenHandle) or (not CryptGenRandom(hProv, SizeOf(FValue),
      @FValue)) then
      FValue:= TimeStampClock
  finally
    if hasOpenHandle then
      CryptReleaseContext(hProv, 0)
  end;
{$ELSE}
  FValue:= TimeStampClock;
{$ENDIF}
  Crunch
end;

function TInsecureRandomStream.Read(var Buffer; Count: Longint): Longint;
var
  P: PByte;
  Amnt, AmntBits, C: integer;
  Harv: Int64;
  Carry: uint32;
begin
  result:= Max(Count, 0);
  if result <= 0 then
    exit;
  P:= @Buffer;
  C:= result;
  repeat
    Amnt:= Min(FAvail, C);
    Move(FBuffer, P^, Amnt);
    Dec(FAvail, Amnt);
    Dec(C, Amnt);
    Inc(P, Amnt);
    if FAvail <= 0 then
      Crunch
    else
      begin
        Harv:= FBuffer;
        if Amnt >= 4 then
          begin
            Int64Rec(Harv).Lo:= Int64Rec(Harv).Hi;
            Int64Rec(Harv).Hi:= 0;
            Dec(Amnt, 4)
          end;
        if Amnt > 0 then
          begin
            AmntBits:= Amnt * 8;
            Carry:= Int64Rec(Harv).Hi shl (32 - (AmntBits));
            Int64Rec(Harv).Hi:= Int64Rec(Harv).Hi shr AmntBits;
            Int64Rec(Harv).Lo:= (Int64Rec(Harv).Lo shr AmntBits) or Carry;
          end;
        FBuffer:= Harv
      end
  until C <= 0
end;

function TInsecureRandomStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  result:= 0
end;

procedure TInsecureRandomStream.SetSeed(Value: Int64);
begin
  FValue:= Value;
  FBuffer:= FValue;
  FAvail:= SizeOf(FBuffer)
end;

procedure TInsecureRandomStream.SetSize(const NewSize: Int64);
begin
end;

function TInsecureRandomStream.Write(const Buffer; Count: Longint): Longint;
begin
  result:= Count
end;

end.
