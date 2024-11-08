﻿// IPA-DN-ThinLib Library Source Code
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
// Copyright (c) NTT-East Impossible Telecom Mission Group.
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on IPA-DN-ThinLib Library and SoftEther VPN Project in GitHub.
// 
// All Rights Reserved.
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (IPA, NTT-EAST, SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI
// OR OTHER SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY
// KIND OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. IPA AND NTT-EAST HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
// 
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// daiyuu.securityreport [at] dnobori.jp
// 
// Thank you for your cooperation.


// NullLan.c
// Virtual LAN card device driver for testing

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

static UCHAR null_lan_broadcast_address[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// Get the packet adapter
PACKET_ADAPTER *NullGetPacketAdapter()
{
	PACKET_ADAPTER *pa = NewPacketAdapter(NullPaInit, NullPaGetCancel, NullPaGetNextPacket,
		NullPaPutPacket, NullPaFree);

	return pa;
}

// Generate MAC address
void NullGenerateMacAddress(UCHAR *mac, UINT id, UINT seq)
{
	UCHAR hash[SHA1_SIZE];
	char name[MAX_SIZE];
	BUF *b;
	// Validate arguments
	if (mac == NULL)
	{
		return;
	}

	b = NewBuf();
	WriteBufInt(b, id);
	WriteBufInt(b, seq);
	GetMachineHostName(name, sizeof(name));
#ifdef	OS_WIN32
	WriteBufInt(b, MsGetCurrentProcessId());
#endif	// OS_WIN32
	WriteBufStr(b, name);

	HashSha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Copy(mac, hash, 6);
	mac[0] = 0x7E;
}

// Packet generation thread
void NullPacketGenerateThread(THREAD *t, void *param)
{
	NULL_LAN *n = (NULL_LAN *)param;
	UINT64 end_tick = Tick64() + (UINT64)(60 * 1000);
	UINT seq = 0;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		/*if (Tick64() >= end_tick)
		{
			break;
		}*/

		Wait(n->Event, Rand32() % 1500);
		if (n->Halt)
		{
			break;
		}

		LockQueue(n->PacketQueue);
		{
			UCHAR *data;
			BLOCK *b;
			UINT size = Rand32() % 1500 + 14;
			UCHAR dst_mac[6];

			NullGenerateMacAddress(n->MacAddr, n->Id, seq);

			//NullGenerateMacAddress(dst_mac, n->Id + 1, 0);
			//StrToMac(dst_mac, "00-1B-21-A9-47-E6");
			StrToMac(dst_mac, "00-AC-7A-EF-83-FD");

			data = Malloc(size);
			Copy(data, null_lan_broadcast_address, 6);
			//Copy(data, dst_mac, 6);
			Copy(data + 6, n->MacAddr, 6);
			b = NewBlock(data, size, 0);
			InsertQueue(n->PacketQueue, b);
		}
		UnlockQueue(n->PacketQueue);
		Cancel(n->Cancel);

		//seq++;
	}
}

// Initialize the packet adapter
bool NullPaInit(SESSION *s)
{
	NULL_LAN *n;
	static UINT id_seed = 0;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	id_seed++;

	n = ZeroMalloc(sizeof(NULL_LAN));
	n->Id = id_seed;
	s->PacketAdapter->Param = (void *)n;

	n->Cancel = NewCancel();
	n->PacketQueue = NewQueue();
	n->Event = NewEvent();

	NullGenerateMacAddress(n->MacAddr, n->Id, 0);

	n->PacketGeneratorThread = NewThread(NullPacketGenerateThread, n);

	return true;
}

// Get the cancel object
CANCEL *NullPaGetCancel(SESSION *s)
{
	// Validate arguments
	NULL_LAN *n;
	if (s == NULL || (n = s->PacketAdapter->Param) == NULL)
	{
		return NULL;
	}

	AddRef(n->Cancel->ref);

	return n->Cancel;
}

// Get the next packet
UINT NullPaGetNextPacket(SESSION *s, void **data)
{
	UINT size = 0;
	// Validate arguments
	NULL_LAN *n;
	if (s == NULL || (n = s->PacketAdapter->Param) == NULL)
	{
		return INFINITE;
	}

	LockQueue(n->PacketQueue);
	{
		BLOCK *b = GetNext(n->PacketQueue);

		if (b != NULL)
		{
			*data = b->Buf;
			size = b->Size;
			Free(b);
		}
	}
	UnlockQueue(n->PacketQueue);

	return size;
}

// Write the packet
bool NullPaPutPacket(SESSION *s, void *data, UINT size)
{
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}
	if (data == NULL)
	{
		return true;
	}

	// Packet ignored
	Free(data);

	return true;
}

// Release
void NullPaFree(SESSION *s)
{
	// Validate arguments
	NULL_LAN *n;
	BLOCK *b;
	if (s == NULL || (n = s->PacketAdapter->Param) == NULL)
	{
		return;
	}

	n->Halt = true;
	Set(n->Event);

	WaitThread(n->PacketGeneratorThread, INFINITE);
	ReleaseThread(n->PacketGeneratorThread);

	LockQueue(n->PacketQueue);
	{
		while (b = GetNext(n->PacketQueue))
		{
			FreeBlock(b);
		}
	}
	UnlockQueue(n->PacketQueue);

	ReleaseQueue(n->PacketQueue);

	ReleaseCancel(n->Cancel);

	ReleaseEvent(n->Event);

	s->PacketAdapter->Param = NULL;
	Free(n);
}


