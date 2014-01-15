// SoftEther VPN Source Code
// Cedar Communication Module
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


// IPsec_Win7.h
// Internal header of IPsec_Win7.c

#ifndef	IPSEC_WIN7_INNER_H
#define	IPSEC_WIN7_INNER_H

// API function
typedef struct IPSEC_WIN7_FUNCTIONS
{
	DWORD (WINAPI *FwpmEngineOpen0)(
		IN OPTIONAL const wchar_t* serverName,
		IN UINT32 authnService,
		IN OPTIONAL SEC_WINNT_AUTH_IDENTITY_W* authIdentity,
		IN OPTIONAL const FWPM_SESSION0* session,
		OUT HANDLE* engineHandle
		);

	DWORD (WINAPI *FwpmEngineClose0)(IN HANDLE engineHandle);

	void (WINAPI *FwpmFreeMemory0)(IN OUT void** p);

	DWORD (WINAPI *FwpmFilterAdd0)(
		IN HANDLE engineHandle,
		IN const FWPM_FILTER0* filter,
		IN OPTIONAL PSECURITY_DESCRIPTOR sd,
		OUT OPTIONAL UINT64* id
		);

	DWORD (WINAPI *IPsecSaContextCreate0)(
		IN HANDLE engineHandle,
		IN const IPSEC_TRAFFIC0* outboundTraffic,
		OUT OPTIONAL UINT64* inboundFilterId,
		OUT UINT64* id
		);

	DWORD (WINAPI *IPsecSaContextGetSpi0)(
		IN HANDLE engineHandle,
		IN UINT64 id,
		IN const IPSEC_GETSPI0* getSpi,
		OUT IPSEC_SA_SPI* inboundSpi
		);

	DWORD (WINAPI *IPsecSaContextAddInbound0)(
		IN HANDLE engineHandle,
		IN UINT64 id,
		IN const IPSEC_SA_BUNDLE0* inboundBundle
		);

	DWORD (WINAPI *IPsecSaContextAddOutbound0)(
		IN HANDLE engineHandle,
		IN UINT64 id,
		IN const IPSEC_SA_BUNDLE0* outboundBundle
		);

	DWORD (WINAPI *FwpmCalloutAdd0)(
		IN HANDLE engineHandle,
		IN const FWPM_CALLOUT0* callout,
		IN OPTIONAL PSECURITY_DESCRIPTOR sd,
		OUT OPTIONAL UINT32* id
		);

} IPSEC_WIN7_FUNCTIONS;

// Instance
struct IPSEC_WIN7
{
	HANDLE hEngine;
	HANDLE hDriverFile;
	UINT64 FilterIPv4Id, FilterIPv6Id;
};


#endif	// IPSEC_WIN7_INNER_H




// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
