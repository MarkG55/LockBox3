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

unit uTPLb_PosixEntropySource;

interface

Uses
  Classes,
  System.SysUtils,
  uTPLb_Logging,
  uTPLb_EntropySource;

Type
  TPosixEntropySource = Class(TEntropySource)
    Function ReadEntropy(EntropyData: TStream; MinimumBits: Integer): Integer; Override;
  end;

implementation

{ TPosixEntropySource }

Function TPosixEntropySource.ReadEntropy(EntropyData: TStream; MinimumBits: Integer): Integer;
var
  BytesRequired: Integer;
  Device: Integer;
  Bytes: TBytes;
begin
  Result:= 0;
  BytesRequired:= MinimumBits div 8;
  SetLength(Bytes, BytesRequired);

  Device:= FileOpen('/dev/urandom', fmOpenRead);

  try
    if Device <= 0 then
      Device:= FileOpen('/dev/random', fmOpenRead);

    if Device <= 0 then
      exit;

    if BytesRequired > 32 then
      BytesRequired:= 32; // up to 256 bits - see "man urandom" Usage paragraph

    Result:= FileRead(Device, Bytes[0], BytesRequired);
    EntropyData.Write(Bytes[0], Result);
  finally
    if Device > 0 then
      FileClose(Device);

    if Result <> BytesRequired then
      DebugMsg('Failed to get requested entropy from /dev/urandom - Requested: ' + IntToStr(BytesRequired) + ' Got: ' + IntToStr(Result));

    if Result < 0 then
      Result:= 0;

    Result:= Result * 8;
  end;
end;

end.
