{ * ***** BEGIN LICENSE BLOCK *****
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

// This unit is used for getting entropy based on the fact that there will
// always be some randomness to the amount of time that it will take
// for the operating system to return control after executing Sleep(1)
// This may not be the best source of entropy, however, it's only intended
// as a supplement to the system supplied entropy source just in case it has
// been compromised and is somehow predictable to a certain extent
// As a general rule, more entropy can't hurt (This isn't strictly true,
// however, as it's theoretically possible for a malicious entropy source
// to reduce overall entropy after the sources are combined, however, that should
// be very difficult to achieve in practice and hence highly unlikely to be an issue)
//
// "Any measurement taken with sufficient resolution will effectively have noise (entropy)"

unit uTPLb_ThreadBasedEntropySource;

interface

Uses
  Classes,
  SysUtils,
  Generics.Collections,
  uTPLb_EntropySource,
  SyncObjs,
  System.Diagnostics;

Type
  TReading = Word; // Only use the low order 2 Bytes

Const
  EstimatedBitsPerReading = 4; // Conservative estimate
  EstimatedBitsPerByte = EstimatedBitsPerReading / SizeOf(TReading);

Type
  TThreadBasedEntropySource = Class(TEntropySource)
  private
    LastValue: Int64;
    EntropyData: TBytesStream;
    CriticalSection: TCriticalSection;
    BeingDestroyed: Boolean;
    ThreadFinished: TEvent;

    Procedure ThreadEntropySource;
    Function HaveEnoughEntropy: Boolean;
  public
    Constructor Create(MinStandbyBits: Integer = DefaultMinStandbyBits); Override;
    Destructor Destroy; Override;

    Function ReadEntropy(EntropyData: TStream; MinimumBits: Integer): Integer; Override;
  end;

implementation

{ TThreadBasedEntropySource }

constructor TThreadBasedEntropySource.Create(MinStandbyBits: Integer);
begin
  inherited;

  CriticalSection := TCriticalSection.Create;
  ThreadFinished := TEvent.Create;
  EntropyData := TBytesStream.Create;
  TThread.CreateAnonymousThread(ThreadEntropySource).Start;
end;

destructor TThreadBasedEntropySource.Destroy;
begin
  BeingDestroyed := True;

  ThreadFinished.WaitFor;

  EntropyData.Free;
  ThreadFinished.Free;
  CriticalSection.Free;

  inherited;
end;

function TThreadBasedEntropySource.HaveEnoughEntropy: Boolean;
begin
  Result := (EntropyData.Size * EstimatedBitsPerByte) >= MinStandbyBits;
end;

function TThreadBasedEntropySource.ReadEntropy(EntropyData: TStream; MinimumBits: Integer): Integer;
var
  BytesRequired: Integer;
  NewEntropyDataSize: Integer;
begin
  Result := 0;

  if MinStandbyBits < MinimumBits then
    MinStandbyBits := MinimumBits;

  while (not HaveEnoughEntropy) do
    begin
      if BeingDestroyed then
        exit;

      Sleep(1);
    end;

  CriticalSection.Enter;

  try
    BytesRequired := Round(MinimumBits / EstimatedBitsPerByte);

    Assert(Self.EntropyData.Size >= BytesRequired);

    EntropyData.Write(Self.EntropyData.Bytes[0], BytesRequired);

    if BytesRequired >= Self.EntropyData.Size then
      Self.EntropyData.Size := 0
    else
      begin
        NewEntropyDataSize := Self.EntropyData.Size - BytesRequired;
        Move(Self.EntropyData.Bytes[BytesRequired], Self.EntropyData.Bytes[0], NewEntropyDataSize);
        EntropyData.Size := NewEntropyDataSize;
      end;

    Result := BytesRequired;
  finally
    CriticalSection.Leave;
  end;
end;

procedure TThreadBasedEntropySource.ThreadEntropySource;
var
  NextValue: Int64;
  Diff: UInt64;
  Reading: TReading;
begin
  LastValue := TStopWatch.GetTimeStamp;

  while not BeingDestroyed do
    begin
      Sleep(1);
      NextValue := TStopWatch.GetTimeStamp;
      Diff := NextValue - LastValue;
      LastValue := NextValue;

      if HaveEnoughEntropy then
        Continue;

      Reading := Diff; // Lose all but the bottom 2 bytes.

      CriticalSection.Enter;

      try
        EntropyData.Write(Reading, SizeOf(Reading));
      finally
        CriticalSection.Leave;
      end;
    end;

  ThreadFinished.SetEvent;
end;

end.
