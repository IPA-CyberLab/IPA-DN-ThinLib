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


// IPsec_Win7.c
// Initialize the helper module for Windows 7 / Windows 8 / Windows Vista / Windows Server 2008 / Windows Server 2008 R2 / Windows Server 2012 / Windows 10

#include <GlobalConst.h>

#ifdef	_WIN32

#define	_WIN32_WINNT		0x0600
#define	WINVER				0x0600
#define	INITGUID
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <fixed_Fwpmu.h>
#include <fixed_Fwpmtypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "IPsec_Win7Inner.h"
#include <Cedar/Wfp.h>

static IPSEC_WIN7_FUNCTIONS *api = NULL;
static HINSTANCE hDll = NULL;


// Initialize the IPsec helper module for Windows 7
IPSEC_WIN7 *IPsecWin7Init()
{
	IPSEC_WIN7 *w;
	FWPM_SESSION0 session;
	UINT ret;
	FWPM_FILTER0 filter;
	UINT64 weight = MAXUINT64;

	Debug("IPsecWin7Init()\n");

	if (MsIsVista() == false)
	{
		return NULL;
	}

	if (MsIsAdmin() == false)
	{
		return NULL;
	}

	if (IPsecWin7InitApi() == false)
	{
		return NULL;
	}

	// Driver Initialization
	if (IPsecWin7InitDriver() == false)
	{
		return NULL;
	}

	// Open the WFP (Dynamic Session)
	Zero(&session, sizeof(session));
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	w = ZeroMalloc(sizeof(IPSEC_WIN7));
	ret = api->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &w->hEngine);
	if (ret)
	{
		Debug("FwpmEngineOpen0 Failed.\n");
		IPsecWin7Free(w);
		return NULL;
	}

	// Create the Filter (IPv4)
	Zero(&filter, sizeof(filter));
	filter.flags = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
	filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = &weight;
	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = GUID_WFP_CALLOUT_DRIVER_V4;
	filter.displayData.name = IPSEC_WIN7_FILTER_TITLE_V4;
	ret = api->FwpmFilterAdd0(w->hEngine, &filter, NULL, &w->FilterIPv4Id);
	if (ret)
	{
		Debug("FwpmFilterAdd0 for IPv4 Failed: 0x%X\n", ret);
	}
	else
	{
		Debug("FwpmFilterAdd0 for IPv4 Ok.\n");
	}

	// Create the Filter (IPv6)
	Zero(&filter, sizeof(filter));
	filter.flags = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
	filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V6;
	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = &weight;
	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = GUID_WFP_CALLOUT_DRIVER_V6;
	filter.displayData.name = IPSEC_WIN7_FILTER_TITLE_V6;
	ret = api->FwpmFilterAdd0(w->hEngine, &filter, NULL, &w->FilterIPv6Id);
	if (ret)
	{
		Debug("FwpmFilterAdd0 for IPv6 Failed: 0x%X\n", ret);
	}
	else
	{
		Debug("FwpmFilterAdd0 for IPv6 Ok.\n");
	}

	// Open the device of the driver as a file
	w->hDriverFile = CreateFileA(WFP_DEVICE_FILE_NAME, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (w->hDriverFile == NULL || w->hDriverFile == INVALID_HANDLE_VALUE)
	{
		Debug("CreateFileA(\"%s\") Failed.\n", WFP_DEVICE_FILE_NAME);
		IPsecWin7Free(w);
		return NULL;
	}

	IPsecWin7UpdateHostIPAddressList(w);

	Debug("IPsecWin7Init() Ok.\n");

	return w;
}

// Update the IP address list of the host
void IPsecWin7UpdateHostIPAddressList(IPSEC_WIN7 *w)
{
	LIST *o;
	UINT i;
	BUF *buf;
	UINT retsize;
	// Validate arguments
	if (w == NULL)
	{
		return;
	}

	o = GetHostIPAddressList();
	if (o == NULL)
	{
		return;
	}

	buf = NewBuf();

	Debug("***** IPsecWin7UpdateHostIPAddressList Begin *****\n");

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP *ip = LIST_DATA(o, i);
		WFP_LOCAL_IP a;

		Zero(&a, sizeof(a));

		// Exclude any IPs or localhost IP
		if (IsZeroIP(ip) == false && IsLocalHostIP(ip) == false)
		{
			if (IsIP4(ip))
			{
				a.IpVersion = 4;
				Copy(a.IpAddress.IPv4Address, ip->addr, 4);
			}
			else
			{
				a.IpVersion = 6;
				Copy(a.IpAddress.IPv6Address, ip->ipv6_addr, 16);
			}

			Debug("IP %u: %r\n", i, ip);

			WriteBuf(buf, &a, sizeof(WFP_LOCAL_IP));
		}
	}

	if (WriteFile(w->hDriverFile, buf->Buf, buf->Size, &retsize, NULL) == false)
	{
		Debug("WriteFile to the driver failed. %u\n", GetLastError());
	}

	FreeHostIPAddressList(o);

	FreeBuf(buf);

	Debug("***** IPsecWin7UpdateHostIPAddressList End *****\n");
}

// Release the module
void IPsecWin7Free(IPSEC_WIN7 *w)
{
	// Validate arguments
	if (w == NULL)
	{
		return;
	}

	if (w->hEngine != NULL)
	{
		api->FwpmEngineClose0(w->hEngine);
	}

	if (w->hDriverFile != NULL && w->hDriverFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(w->hDriverFile);
	}

	Free(w);
}

// Initialize and start the driver
bool IPsecWin7InitDriver()
{
	bool ret;
	void *lock = MsInitGlobalLock("IPsecWin7InitDriver", false);
	void *p = MsDisableWow64FileSystemRedirection();

	MsGlobalLock(lock);
	{
		ret = IPsecWin7InitDriverInner();
	}
	MsGlobalUnlock(lock);

	MsFreeGlobalLock(lock);

	MsRestoreWow64FileSystemRedirection(p);

	Debug("IPsecWin7InitDriver: %u\n", ret);

	return ret;
}
bool IPsecWin7InitDriverInner()
{
	char sys_filename[MAX_PATH];
	bool install_driver = true;
	HANDLE hEngine;
	UINT ret;
	FWPM_SESSION0 session;
	UINT id;
	FWPM_CALLOUT0 callout;

	Format(sys_filename, sizeof(sys_filename), IPSEC_WIN7_DST_SYS, MsGetSystem32Dir());

	if (IsFileExists(sys_filename) && MsIsServiceInstalled(IPSEC_WIN7_DRIVER_NAME))
	{
		if (GetCurrentIPsecWin7DriverBuild() >= CEDAR_BUILD)
		{
			// Not to install since the latest version has been already installed
			install_driver = false;
		}
	}

	if (install_driver)
	{
		char src_filename[MAX_PATH];

		if (MsIsWindows10() == false)
		{
			Format(src_filename, sizeof(src_filename),
				"|DriverPackages\\Wfp\\%s\\pxwfp_%s.sys",
				(MsIsX64() ? "x64" : "x86"), (MsIsX64() ? "x64" : "x86"));
		}
		else
		{
			Format(src_filename, sizeof(src_filename),
				"|DriverPackages\\Wfp_Win10\\%s\\pxwfp_%s.sys",
				(MsIsX64() ? "x64" : "x86"), (MsIsX64() ? "x64" : "x86"));
		}

		// Copy the driver
		if (FileCopy(src_filename, sys_filename) == false)
		{
			Debug("%s copy failed. %u\n", sys_filename, GetLastError());
			if (IsFileExists(sys_filename) == false)
			{
				Debug("%s failed. Abort.\n", sys_filename);
				return false;
			}
		}
		else
		{
			Debug("%s copied.\n", sys_filename);
		}

		// Set the build number
		SetCurrentIPsecWin7DriverBuild();
	}

	// Get whether the device drivers is already installed
	if (MsIsServiceInstalled(IPSEC_WIN7_DRIVER_NAME) == false)
	{
		wchar_t sys_filename_w[MAX_PATH];

		StrToUni(sys_filename_w, sizeof(sys_filename_w), sys_filename);

		// Run a new installation
		if (MsInstallDeviceDriverW(IPSEC_WIN7_DRIVER_NAME, IPSEC_WIN7_DRIVER_TITLE,
			sys_filename_w, NULL) == false)
		{
			// Installation failed
			Debug("MsInstallDeviceDriverW failed.\n");
			return false;
		}
	}

	// Start if the device driver is stopped
	if (MsIsServiceRunning(IPSEC_WIN7_DRIVER_NAME) == false)
	{
		if (MsStartService(IPSEC_WIN7_DRIVER_NAME) == false)
		{
			// Start failure
			Debug("MsStartService failed.\n");
			return false;
		}

		Debug("%s service started.\n", IPSEC_WIN7_DRIVER_NAME);
	}
	else
	{
		Debug("%s service was already started.\n", IPSEC_WIN7_DRIVER_NAME);
	}

	// Open the WFP
	Zero(&session, sizeof(session));

	ret = api->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &hEngine);
	if (ret)
	{
		Debug("FwpmEngineOpen0 failed.\n");
		return false;
	}

	// Create the Callout Driver (IPv4)
	Zero(&callout, sizeof(callout));
	callout.calloutKey = GUID_WFP_CALLOUT_DRIVER_V4;
	callout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V4;
	callout.displayData.name = IPSEC_WIN7_DRIVER_TITLE_V4;
	ret = api->FwpmCalloutAdd0(hEngine, &callout, NULL, &id);
	if (ret)
	{
		Debug("FwpmCalloutAdd0 for IPv4 Failed: 0x%X\n", ret);
	}
	else
	{
		Debug("FwpmCalloutAdd0 for IPv4 Ok.\n");
	}

	// Create the Callout Driver (IPv6)
	Zero(&callout, sizeof(callout));
	callout.calloutKey = GUID_WFP_CALLOUT_DRIVER_V6;
	callout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V6;
	callout.displayData.name = IPSEC_WIN7_DRIVER_TITLE_V6;
	ret = api->FwpmCalloutAdd0(hEngine, &callout, NULL, &id);
	if (ret)
	{
		Debug("FwpmCalloutAdd0 for IPv6 Failed: 0x%X\n", ret);
	}
	else
	{
		Debug("FwpmCalloutAdd0 for IPv6 Ok.\n");
	}

	api->FwpmEngineClose0(hEngine);

	return true;
}

// Write the build number of the current driver
void SetCurrentIPsecWin7DriverBuild()
{
	MsRegWriteInt(REG_LOCAL_MACHINE, IPSEC_WIN7_DRIVER_REGKEY,
		(MsIsWindows10() ? IPSEC_WIN7_DRIVER_BUILDNUMBER_WIN10 : IPSEC_WIN7_DRIVER_BUILDNUMBER),
		CEDAR_BUILD);
}

// Get the build number of the current driver
UINT GetCurrentIPsecWin7DriverBuild()
{
	return MsRegReadInt(REG_LOCAL_MACHINE, IPSEC_WIN7_DRIVER_REGKEY,
		(MsIsWindows10() ? IPSEC_WIN7_DRIVER_BUILDNUMBER_WIN10 : IPSEC_WIN7_DRIVER_BUILDNUMBER));
}

// Initialization of the API
bool IPsecWin7InitApi()
{
	if (api != NULL)
	{
		return true;
	}

	if (hDll == NULL)
	{
		hDll = LoadLibraryA("FWPUCLNT.DLL");
	}

	if (hDll == NULL)
	{
		return false;
	}

	api = malloc(sizeof(IPSEC_WIN7_FUNCTIONS));
	Zero(api, sizeof(IPSEC_WIN7_FUNCTIONS));

	api->FwpmEngineOpen0 = 
		(DWORD (__stdcall *)(const wchar_t *,UINT32,SEC_WINNT_AUTH_IDENTITY_W *,const FWPM_SESSION0 *,HANDLE *))
		GetProcAddress(hDll, "FwpmEngineOpen0");

	api->FwpmEngineClose0 =
		(DWORD (__stdcall *)(HANDLE))
		GetProcAddress(hDll, "FwpmEngineClose0");

	api->FwpmFreeMemory0 =
		(void (__stdcall *)(void **))
		GetProcAddress(hDll, "FwpmFreeMemory0");

	api->FwpmFilterAdd0 =
		(DWORD (__stdcall *)(HANDLE,const FWPM_FILTER0 *,PSECURITY_DESCRIPTOR,UINT64 *))
		GetProcAddress(hDll, "FwpmFilterAdd0");

	api->IPsecSaContextCreate0 =
		(DWORD (__stdcall *)(HANDLE,const IPSEC_TRAFFIC0 *,UINT64 *,UINT64 *))
		GetProcAddress(hDll, "IPsecSaContextCreate0");

	api->IPsecSaContextGetSpi0 =
		(DWORD (__stdcall *)(HANDLE,UINT64,const IPSEC_GETSPI0 *,IPSEC_SA_SPI *))
		GetProcAddress(hDll, "IPsecSaContextGetSpi0");

	api->IPsecSaContextAddInbound0 =
		(DWORD (__stdcall *)(HANDLE,UINT64,const IPSEC_SA_BUNDLE0 *))
		GetProcAddress(hDll, "IPsecSaContextAddInbound0");

	api->IPsecSaContextAddOutbound0 =
		(DWORD (__stdcall *)(HANDLE,UINT64,const IPSEC_SA_BUNDLE0 *))
		GetProcAddress(hDll, "IPsecSaContextAddOutbound0");

	api->FwpmCalloutAdd0 =
		(DWORD (__stdcall *)(HANDLE,const FWPM_CALLOUT0 *,PSECURITY_DESCRIPTOR,UINT32 *))
		GetProcAddress(hDll, "FwpmCalloutAdd0");

	if (api->FwpmEngineOpen0 == NULL ||
		api->FwpmEngineClose0 == NULL ||
		api->FwpmFreeMemory0 == NULL ||
		api->FwpmFilterAdd0 == NULL ||
		api->IPsecSaContextCreate0 == NULL ||
		api->IPsecSaContextGetSpi0 == NULL ||
		api->IPsecSaContextAddInbound0 == NULL ||
		api->IPsecSaContextAddOutbound0 == NULL ||
		api->FwpmCalloutAdd0 == NULL)
	{
		free(api);
		api = NULL;
		return false;
	}

	return true;
}

#endif	// _WIN32


