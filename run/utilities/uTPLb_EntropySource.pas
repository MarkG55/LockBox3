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

unit uTPLb_EntropySource;

interface

Uses
  Classes,
  Generics.Collections;

Const
  DefaultMinStandbyBits = 256;

Type
  TEntropySource = Class
  protected
    MinStandbyBits: Integer;
  public
    Constructor Create(MinStandbyBits: Integer = DefaultMinStandbyBits); Virtual;
    // The entropy source may return more than MinimumBits/8 bytes - if the source data isn't completely random
    Function ReadEntropy(EntropyData: TStream; MinimumBits: Integer): Integer; Virtual; Abstract;
  end;

  TEntropySourceList = TObjectList<TEntropySource>;

  TCombinedEntropySource = Class(TEntropySource)
  private
    EntropySources: TEntropySourceList;
  public
    Function ReadEntropy(EntropyData: TStream; MinimumBits: Integer): Integer; Override;

    Constructor Create(MinStandbyBits: Integer = DefaultMinStandbyBits); Override;
    Destructor Destroy; Override;

    Procedure RemoveAllEntropySources;
    Procedure AddEntropySource(NewEntropySource: TEntropySource);
  end;

implementation

{ TEntropySource }

constructor TEntropySource.Create(MinStandbyBits: Integer = DefaultMinStandbyBits);
begin
  inherited Create;

  Self.MinStandbyBits := MinStandbyBits;
end;

{ TCombinedEntropySource }

procedure TCombinedEntropySource.AddEntropySource(NewEntropySource: TEntropySource);
begin
  EntropySources.Add(NewEntropySource);
end;

procedure TCombinedEntropySource.RemoveAllEntropySources;
begin
  EntropySources.Clear;
end;

constructor TCombinedEntropySource.Create(MinStandbyBits: Integer = DefaultMinStandbyBits);
begin
  inherited;

  EntropySources := TEntropySourceList.Create;
end;

destructor TCombinedEntropySource.Destroy;
begin
  EntropySources.Free;

  inherited;
end;

function TCombinedEntropySource.ReadEntropy(EntropyData: TStream; MinimumBits: Integer): Integer;
var
  EntropySource: TEntropySource;
begin
  Result := 0;

  for EntropySource in EntropySources do
    Result := Result + EntropySource.ReadEntropy(EntropyData, MinimumBits);
end;

end.
