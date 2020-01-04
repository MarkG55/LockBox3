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

unit uTPLb_Time;

interface

Uses
  Classes,
  System.SysUtils,
  TimeSpan;

Type
  ETimeUtilsQueryPerformanceFrequencyFailed = Class(Exception);

  TTimeUtils = Class
  private
    class var FFrequency: Int64;
    class var TickFrequency: Double;
  public
    class constructor Create;
    class function GetTimeStamp: Int64; static;
    class function GetTickCount64: Int64; static;
  end;

implementation

{$IF defined(MSWINDOWS)}
uses Winapi.Windows;
{$ELSEIF defined(MACOS)}
uses Macapi.Mach;
{$ELSEIF defined(POSIX)}
uses Posix.Time;
{$ENDIF}

{ TTimeUtils }

class constructor TTimeUtils.Create;
begin
{$IF defined(MSWINDOWS)}
  if not QueryPerformanceFrequency(FFrequency) then
    raise ETimeUtilsQueryPerformanceFrequencyFailed.Create('Error getting Windows Performance Frequency');
{$ELSEIF defined(POSIX)}
  FFrequency := 10000000; // 100 Nanosecond resolution
{$ENDIF}
  TickFrequency := 10000000.0 / FFrequency;
end;

class function TTimeUtils.GetTimeStamp: Int64;
{$IF defined(POSIX) and not defined(MACOS)}
var
  res: timespec;
{$ENDIF}
begin
{$IF defined(MSWINDOWS)}
  QueryPerformanceCounter(Result)
{$ELSEIF defined(MACOS)}
  Result := Int64(AbsoluteToNanoseconds(mach_absolute_time) div 100);
{$ELSEIF defined(POSIX)}
  clock_gettime(CLOCK_MONOTONIC, @res);
  Result := (Int64(1000000000) * res.tv_sec + res.tv_nsec) div 100;
{$ENDIF}
end;


class function TTimeUtils.GetTickCount64: Int64;
begin
  Result:= Trunc(GetTimeStamp * TickFrequency / TTimeSpan.TicksPerMillisecond);
end;


end.
