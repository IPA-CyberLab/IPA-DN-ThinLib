// SoftEther VPN Source Code
// Mayaqua Kernel
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE IT IN OTHER COUNTRIES. IMPORTING THIS
// SOFTWARE INTO OTHER COUNTRIES IS AT YOUR OWN RISK. SOME COUNTRIES
// PROHIBIT ENCRYPTED COMMUNICATIONS. USING THIS SOFTWARE IN OTHER
// COUNTRIES MIGHT BE RESTRICTED.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.


// Tracking.h
// Header of Tracking.c

#ifndef	TRACKING_H
#define	TRACKING_H

// The number of array
#define	TRACKING_NUM_ARRAY	1048576

// Hash from an pointer to an array index
#define	TRACKING_HASH(p)	(UINT)(((((UINT64)(p)) / (UINT64)(sizeof(void *))) % ((UINT64)TRACKING_NUM_ARRAY)))

// Call stack
struct CALLSTACK_DATA
{
	bool symbol_cache;
	UINT64 offset, disp;
	char *name;
	struct CALLSTACK_DATA *next;
	char filename[MAX_PATH];
	UINT line;
};

// Object
struct TRACKING_OBJECT
{
	UINT Id;
	char *Name;
	UINT64 Address;
	UINT Size;
	UINT64 CreatedDate;
	CALLSTACK_DATA *CallStack;
	char FileName[MAX_PATH];
	UINT LineNumber;
};

// Usage of the memory
struct MEMORY_STATUS
{
	UINT MemoryBlocksNum;
	UINT MemorySize;
};

// Tracking list
struct TRACKING_LIST
{
	struct TRACKING_LIST *Next;
	struct TRACKING_OBJECT *Object;
};

CALLSTACK_DATA *GetCallStack();
bool GetCallStackSymbolInfo(CALLSTACK_DATA *s);
void FreeCallStack(CALLSTACK_DATA *s);
CALLSTACK_DATA *WalkDownCallStack(CALLSTACK_DATA *s, UINT num);
void GetCallStackStr(char *str, UINT size, CALLSTACK_DATA *s);
void PrintCallStack(CALLSTACK_DATA *s);
void InitTracking();
void FreeTracking();
int CompareTrackingObject(const void *p1, const void *p2);
void LockTrackingList();
void UnlockTrackingList();
void InsertTrackingList(TRACKING_OBJECT *o);
void DeleteTrackingList(TRACKING_OBJECT *o, bool free_object_memory);
TRACKING_OBJECT *SearchTrackingList(UINT64 Address);

void TrackNewObj(UINT64 addr, char *name, UINT size);
void TrackGetObjSymbolInfo(TRACKING_OBJECT *o);
void TrackDeleteObj(UINT64 addr);
void TrackChangeObjSize(UINT64 addr, UINT size, UINT64 new_addr);

void GetMemoryStatus(MEMORY_STATUS *status);
void PrintMemoryStatus();
void MemoryDebugMenu();
int SortObjectView(void *p1, void *p2);
void DebugPrintAllObjects();
void DebugPrintCommandList();
void PrintObjectList(TRACKING_OBJECT *o);
void PrintObjectInfo(TRACKING_OBJECT *o);
void DebugPrintObjectInfo(UINT id);

void TrackingEnable();
void TrackingDisable();
bool IsTrackingEnabled();

#endif	// TRACKING_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
