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


// Wpc.c
// RPC over HTTP

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

void CertServerClientThreadProc(THREAD* thread, void* param)
{
	CERT_SERVER_CLIENT* c = NULL;
	char log_prefix[MAX_PATH] = CLEAN;
	if (thread == NULL || param == NULL)
	{
		return;
	}
	c = (CERT_SERVER_CLIENT*)param;

	Format(log_prefix, sizeof(log_prefix), "CertificateManager/%s", c->Param.ManagerLogName);
	MakeFormatSafeString(log_prefix);

	UINT num_retry = 0;

	while (c->Halt == false)
	{
		UINT next_wait = GenRandInterval2(CERT_SERVER_CLIENT_INTERVAL_NORMAL, 30);

		WtLogEx(c->Wt, log_prefix, "Downloading the SSL certificates from the URL '%s' ...", c->Param.CertListSrcUrl);

		CERTS_AND_KEY* ck = DownloadCertsAndKeyFromCertServer(&c->Param, (bool *)&c->Halt);

		if (ck != NULL)
		{
			if (SaveCertsAndKeyToDir(ck, c->Param.DestDir))
			{
				WtLogEx(c->Wt, log_prefix, "Download SSL certificates OK from the URL '%s'. Certificate files are saved to the local directory '%S'.", c->Param.CertListSrcUrl, c->Param.DestDir);
			}
			else
			{
				WtLogEx(c->Wt, log_prefix, "Error: Download SSL certificates OK from the URL '%s', but saving these certificate files are saved to the local directory '%S' failed.", c->Param.CertListSrcUrl, c->Param.DestDir);
			}

			ReleaseCertsAndKey(ck);
			num_retry = 0;
		}
		else
		{
			num_retry++;
			next_wait = GenRandIntervalWithRetry(CERT_SERVER_CLIENT_INTERVAL_RETRY_INITIAL, num_retry, CERT_SERVER_CLIENT_INTERVAL_RETRY_MAX, 30);
			WtLogEx(c->Wt, log_prefix, "Error: Failed to download the SSL certificates from the URL '%s'.", c->Param.CertListSrcUrl);
		}

		WtLogEx(c->Wt, log_prefix, "Waiting for %u seconds to next download.", next_wait / 1000);

		Wait(c->HaltEvent, next_wait);
	}
}

CERT_SERVER_CLIENT* NewCertServerClient(WT* wt, CERT_SERVER_CLIENT_PARAM* param)
{
	CERT_SERVER_CLIENT* c = NULL;
	if (param == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CERT_SERVER_CLIENT));

	Copy(&c->Param, param, sizeof(CERT_SERVER_CLIENT_PARAM));
	c->Wt = wt;

	c->HaltEvent = NewEvent();
	c->Thread = NewThread(CertServerClientThreadProc, c);

	return c;
}

void FreeCertServerClient(CERT_SERVER_CLIENT* c)
{
	if (c == NULL)
	{
		return;
	}

	c->Halt = true;

	Set(c->HaltEvent);

	WaitThread(c->Thread, INFINITE);
	ReleaseThread(c->Thread);

	ReleaseEvent(c->HaltEvent);

	Free(c);
}

CERTS_AND_KEY* DownloadCertsAndKeyFromCertServer(CERT_SERVER_CLIENT_PARAM* param, bool* cancel)
{
	BUF* certs_buf = NULL;
	BUF* key_buf = NULL;
	LIST* certs_list = NULL;
	K* key = NULL;
	CERTS_AND_KEY* ret = NULL;

	if (param == NULL)
	{
		return NULL;
	}

	if (StartWith(param->CertListSrcUrl, "http://") || StartWith(param->CertListSrcUrl, "https://"))
	{
		certs_buf = HttpDownload(param->CertListSrcUrl, param->BasicAuthUsername, param->BasicAuthPassword,
			NULL, 0, 0, NULL, false, NULL, 0, cancel, MAX_CERT_SERVER_CLIENT_DOWNLOAD_SIZE);
	}
	else
	{
		certs_buf = ReadDump(param->CertListSrcUrl);
	}

	if (certs_buf == NULL)
	{
		goto L_CLEANUP;
	}

	if (StartWith(param->CertKeySrcUrl, "http://") || StartWith(param->CertKeySrcUrl, "https://"))
	{
		key_buf = HttpDownload(param->CertKeySrcUrl, param->BasicAuthUsername, param->BasicAuthPassword,
			NULL, 0, 0, NULL, false, NULL, 0, cancel, MAX_CERT_SERVER_CLIENT_DOWNLOAD_SIZE);
	}
	else
	{
		key_buf = ReadDump(param->CertKeySrcUrl);
	}

	if (key_buf == NULL)
	{
		goto L_CLEANUP;
	}

	certs_list = BufToXList(certs_buf);
	key = BufToK(key_buf, true, true, NULL);

	ret = NewCertsAndKeyFromObjects(certs_list, key, false);

L_CLEANUP:
	FreeBuf(certs_buf);
	FreeBuf(key_buf);
	FreeXList(certs_list);
	FreeK(key);

	return ret;
}

void GenerateHttpBasicAuthHeaderValue(char* dst, UINT dst_size, char* username, char* password)
{
	char* tmp;
	UINT tmp_size;
	char tmp2[MAX_PATH] = CLEAN;
	if (dst == NULL)
	{
		return;
	}

	Format(tmp2, sizeof(tmp2), "%s:%s", username, password);

	tmp_size = (StrLen(tmp2) + 4) * 4;
	tmp = ZeroMalloc(tmp_size);

	Encode64(tmp, tmp2);

	Format(dst, dst_size, "Basic %s", tmp);

	Free(tmp);
}

BUF *HttpDownload(char *url, char *basic_auth_username, char *basic_auth_password,
	INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
	UINT *error_code, bool check_ssl_trust,
	void *sha1_cert_hash, UINT num_hashes,
	bool *cancel, UINT max_recv_size)
{
	return HttpDownloadEx(url, basic_auth_username, basic_auth_password,
		setting, timeout_connect, timeout_comm,
		error_code, check_ssl_trust,
		sha1_cert_hash, num_hashes,
		cancel, max_recv_size,
		NULL, NULL, 0, NULL, 0);
}
BUF *HttpDownloadEx(char *url, char *basic_auth_username, char *basic_auth_password,
	INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
	UINT *error_code, bool check_ssl_trust,
	void *sha1_cert_hash, UINT num_hashes,
	bool *cancel, UINT max_recv_size,
	BUF *result_buf_if_error, bool *is_server_error, UINT flags, char *redirect_url, UINT redirect_url_size)
{
	static UINT _dummy = 0;
	if (error_code == NULL)
	{
		error_code = &_dummy;
	}
	*error_code = ERR_INTERNAL_ERROR;
	if (url == NULL)
	{
		return NULL;
	}

	URL_DATA url_data = CLEAN;

	if (ParseUrl(&url_data, url, false, NULL) == false)
	{
		return NULL;
	}

	char basic_auth_value[MAX_PATH] = CLEAN;

	if (IsFilledStr(basic_auth_username) || IsFilledStr(basic_auth_password))
	{
		GenerateHttpBasicAuthHeaderValue(basic_auth_value, sizeof(basic_auth_value),
			basic_auth_username, basic_auth_password);
	}

	BUF* recv = HttpRequestEx6(&url_data, setting, timeout_connect, timeout_comm,
		error_code, check_ssl_trust, NULL, NULL, NULL,
		sha1_cert_hash, num_hashes, cancel, max_recv_size,
		"Authorization", basic_auth_value, NULL, false, false,
		result_buf_if_error, is_server_error, flags, redirect_url, redirect_url_size);

	return recv;
}

// Get whether the proxy server is specified by a private IP
bool IsProxyPrivateIp(INTERNET_SETTING *s)
{
	IP ip;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	if (s->ProxyType == PROXY_DIRECT)
	{
		return false;
	}

	if (GetIP(&ip, s->ProxyHostName) == false)
	{
		return false;
	}

	if (IsIPPrivate(&ip))
	{
		return true;
	}

	if (IsIPMyHost(&ip))
	{
		return true;
	}

	if (IsLocalHostIP(&ip))
	{
		return true;
	}

	return false;
}

// Call
PACK *WpcCall(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
			  char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash)
{
	return WpcCallEx(url, setting, timeout_connect, timeout_comm, function_name, pack, cert, key,
		sha1_cert_hash, NULL, 0, NULL, NULL);
}
PACK *WpcCallEx(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
				char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash, bool *cancel, UINT max_recv_size,
				char *additional_header_name, char *additional_header_value)
{
	return WpcCallEx2(url, setting, timeout_connect, timeout_comm, function_name, pack,
		cert, key, sha1_cert_hash, (sha1_cert_hash == NULL ? 0 : 1),
		cancel, max_recv_size, additional_header_name, additional_header_value, NULL);
}
PACK *WpcCallEx2(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
				char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash, UINT num_hashes, bool *cancel, UINT max_recv_size,
				char *additional_header_name, char *additional_header_value, char *sni_string)
{
	URL_DATA data;
	BUF *b, *recv;
	UINT error;
	WPC_PACKET packet = CLEAN;
	// Validate arguments
	if (function_name == NULL || pack == NULL)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	if (ParseUrl(&data, url, true, NULL) == false)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	PackAddStr(pack, "function", function_name);

	b = WpcGeneratePacket(pack, NULL, NULL);
	if (b == NULL)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	SeekBuf(b, b->Size, 0);
	WriteBufInt(b, 0);
	SeekBuf(b, 0, 0);

	if (IsEmptyStr(additional_header_name) == false && IsEmptyStr(additional_header_value) == false)
	{
		StrCpy(data.AdditionalHeaderName, sizeof(data.AdditionalHeaderName), additional_header_name);
		StrCpy(data.AdditionalHeaderValue, sizeof(data.AdditionalHeaderValue), additional_header_value);
	}

	if (sni_string != NULL && IsEmptyStr(sni_string) == false)
	{
		StrCpy(data.SniString, sizeof(data.SniString), sni_string);
	}

	recv = HttpRequestEx4(&data, setting, timeout_connect, timeout_comm, &error,
		false, b->Buf, NULL, NULL, sha1_cert_hash, num_hashes, cancel, max_recv_size,
		NULL, NULL, NULL);

	FreeBuf(b);

	if (recv == NULL)
	{
		return PackError(error);
	}

	if (WpcParsePacket(&packet, recv) == false)
	{
		FreeBuf(recv);
		return PackError(ERR_PROTOCOL_ERROR);
	}

	FreeBuf(recv);

	return packet.Pack;
}

// Release the packet
void WpcFreePacket(WPC_PACKET *packet)
{
	// Validate arguments
	if (packet == NULL)
	{
		return;
	}

	FreePack(packet->Pack);
}

// Parse the packet
bool WpcParsePacket(WPC_PACKET *packet, BUF *buf)
{
	LIST *o;
	BUF *b;
	bool ret = false;
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (packet == NULL || buf == NULL)
	{
		return false;
	}

	Zero(packet, sizeof(WPC_PACKET));

	o = WpcParseDataEntry(buf);

	b = WpcDataEntryToBuf(WpcFindDataEntry(o, "PACK"));
	if (b != NULL)
	{
		HashSha1(hash, b->Buf, b->Size);

		packet->Pack = BufToPack(b);
		FreeBuf(b);

		if (packet->Pack != NULL)
		{
			BUF *b;

			ret = true;

			b = WpcDataEntryToBuf(WpcFindDataEntry(o, "HASH"));

			if (b != NULL)
			{
				if (b->Size != SHA1_SIZE || Cmp(b->Buf, hash, SHA1_SIZE) != 0)
				{
					ret = false;
					FreePack(packet->Pack);
				}
				FreeBuf(b);
			}
		}
	}

	b = WpcDataEntryToBuf(WpcFindDataEntryEx(o, "HOST", 0)); // HOSTKEY

	if (b != NULL)
	{
		if (b->Size == SHA1_SIZE)
		{
			Copy(packet->HostKey, b->Buf, SHA1_SIZE);
		}

		FreeBuf(b);
	}

	b = WpcDataEntryToBuf(WpcFindDataEntryEx(o, "HOST", 1)); // HOSTSECRET

	if (b != NULL)
	{
		if (b->Size == SHA1_SIZE)
		{
			Copy(packet->HostSecret, b->Buf, SHA1_SIZE);
		}

		FreeBuf(b);
	}

	WpcFreeDataEntryList(o);

	return ret;
}

// Generate the packet
BUF *WpcGeneratePacket(PACK *pack, UCHAR *host_key, UCHAR *host_secret)
{
	UCHAR hash[SHA1_SIZE];
	BUF *pack_data;
	BUF *b;
	// Validate arguments
	if (pack == NULL)
	{
		return NULL;
	}

	pack_data = PackToBuf(pack);
	HashSha1(hash, pack_data->Buf, pack_data->Size);

	b = NewBuf();

	WpcAddDataEntryBin(b, "PACK", pack_data->Buf, pack_data->Size);
	WpcAddDataEntryBin(b, "HASH", hash, sizeof(hash));

	if (host_key != NULL && host_secret != NULL)
	{
		// 2020/5/6 バグ！ HOSTKEY, HOSTSECRET ともキー名が 4 文字を超えるため、最初の 4 文字 "HOST" のみが送信されている。
		// そして、サーバー側では おなじ "HOST" が 2 個くるので、最初の 1 個目、つまり "HOSTKEY" のみを読み込んで、"HOSTSECRET" は無視している。
		// つまり、HOSTKEY と HOSTSECRET の両方に HOSTKEY が使われている。
		// しかし、この挙動は今から変更することができないため、当面このままとする。(セキュリティ上の問題はない)
		// 今後、サーバー側で別のキーが必要となる時は、新たに 2 個目の "HOST" を読むことで対応することにする。

		WpcAddDataEntryBin(b, "HOSTKEY", host_key, SHA1_SIZE);
		WpcAddDataEntryBin(b, "HOSTSECRET", host_secret, SHA1_SIZE);
	}

	FreeBuf(pack_data);

	SeekBuf(b, 0, 0);

	return b;
}

// Decode the buffer from WPC_ENTRY
BUF *WpcDataEntryToBuf(WPC_ENTRY *e)
{
	void *data;
	UINT data_size;
	UINT size;
	BUF *b;
	// Validate arguments
	if (e == NULL)
	{
		return NULL;
	}

	data_size = e->Size + 4096;
	data = ZeroMalloc(data_size);

	if (e->Size >= 1)
	{
		size = DecodeSafe64(data, e->Data, e->Size);
	}
	else
	{
		size = 0;
	}

	b = NewBuf();
	WriteBuf(b, data, size);
	SeekBuf(b, 0, 0);

	Free(data);

	return b;
}

// Search for the data entry
WPC_ENTRY *WpcFindDataEntry(LIST *o, char *name)
{
	UINT i;
	char name_str[WPC_DATA_ENTRY_SIZE];
	// Validate arguments
	if (o == NULL || name == NULL)
	{
		return NULL;
	}

	WpcFillEntryName(name_str, name);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		WPC_ENTRY *e = LIST_DATA(o, i);

		if (Cmp(e->EntryName, name_str, WPC_DATA_ENTRY_SIZE) == 0)
		{
			return e;
		}
	}

	return NULL;
}
WPC_ENTRY* WpcFindDataEntryEx(LIST* o, char* name, UINT index)
{
	UINT i;
	UINT j = 0;
	char name_str[WPC_DATA_ENTRY_SIZE];
	// Validate arguments
	if (o == NULL || name == NULL)
	{
		return NULL;
	}

	WpcFillEntryName(name_str, name);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		WPC_ENTRY* e = LIST_DATA(o, i);

		if (Cmp(e->EntryName, name_str, WPC_DATA_ENTRY_SIZE) == 0)
		{
			if (j == index)
			{
				return e;
			}
			j++;
		}
	}

	return NULL;
}

// Release the data entry list
void WpcFreeDataEntryList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		WPC_ENTRY *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

// Parse the data entry
LIST *WpcParseDataEntry(BUF *b)
{
	char entry_name[WPC_DATA_ENTRY_SIZE];
	char size_str[11];
	LIST *o;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	SeekBuf(b, 0, 0);

	o = NewListFast(NULL);

	while (true)
	{
		UINT size;
		WPC_ENTRY *e;

		if (ReadBuf(b, entry_name, WPC_DATA_ENTRY_SIZE) != WPC_DATA_ENTRY_SIZE)
		{
			break;
		}

		Zero(size_str, sizeof(size_str));
		if (ReadBuf(b, size_str, 10) != 10)
		{
			break;
		}

		size = ToInt(size_str);
		if ((b->Size - b->Current) < size)
		{
			break;
		}

		e = ZeroMalloc(sizeof(WPC_ENTRY));
		e->Data = (UCHAR *)b->Buf + b->Current;
		Copy(e->EntryName, entry_name, WPC_DATA_ENTRY_SIZE);
		e->Size = size;

		SeekBuf(b, size, 1);

		Add(o, e);
	}

	return o;
}

// Generate a entry name
void WpcFillEntryName(char *dst, char *name)
{
	UINT i, len;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (dst == NULL || name == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), name);
	StrUpper(tmp);
	len = StrLen(tmp);

	for (i = 0;i < WPC_DATA_ENTRY_SIZE;i++)
	{
		dst[i] = ' ';
	}

	if (len <= WPC_DATA_ENTRY_SIZE)
	{
		Copy(dst, tmp, len);
	}
	else
	{
		Copy(dst, tmp, WPC_DATA_ENTRY_SIZE);
	}
}

// Add the data entry (binary)
void WpcAddDataEntryBin(BUF *b, char *name, void *data, UINT size)
{
	char *str;
	// Validate arguments
	if (b == NULL || name == NULL || (data == NULL && size != 0))
	{
		return;
	}

	str = Malloc(size * 2 + 64);

	EncodeSafe64(str, data, size);

	WpcAddDataEntry(b, name, str, StrLen(str));

	Free(str);
}


// Add the data entry
void WpcAddDataEntry(BUF *b, char *name, void *data, UINT size)
{
	char entry_name[WPC_DATA_ENTRY_SIZE];
	char size_str[11];
	// Validate arguments
	if (b == NULL || name == NULL || (data == NULL && size != 0))
	{
		return;
	}

	WpcFillEntryName(entry_name, name);
	WriteBuf(b, entry_name, WPC_DATA_ENTRY_SIZE);

	Format(size_str, sizeof(size_str), "%010u", size);
	WriteBuf(b, size_str, 10);

	WriteBuf(b, data, size);
}

// Get the empty INTERNET_SETTING
INTERNET_SETTING *GetNullInternetSetting()
{
	static INTERNET_SETTING ret;

	Zero(&ret, sizeof(ret));

	return &ret;
}

// Socket connection
SOCK *WpcSockConnect(WPC_CONNECT *param, UINT *error_code, UINT timeout)
{
	return WpcSockConnectEx(param, error_code, timeout, NULL, NULL, NULL, 0, 0);
}
SOCK *WpcSockConnectEx(WPC_CONNECT *param, UINT *error_code, UINT timeout, bool *cancel, BUF *result_buf_if_error, char *zttp_redirect_url, UINT zttp_redirect_url_size, UINT flags)
{
	CONNECTION c;
	SOCK *sock;
	UINT err = ERR_NO_ERROR;
	// Validate arguments
	ClearStr(zttp_redirect_url, zttp_redirect_url_size);
	if (param == NULL)
	{
		return NULL;
	}

	Zero(&c, sizeof(c));

	sock = NULL;
	err = ERR_INTERNAL_ERROR;

	char *direct_or_proxy_connect_hostname = param->HostName;
	UINT direct_or_proxy_connect_port = param->Port;

	bool use_zttp = false;

	if (param->EnableZttp && IsFilledStr(param->ZttpServerHostName) && param->ZttpServerPort != 0)
	{
		use_zttp = true;

		direct_or_proxy_connect_hostname = param->ZttpServerHostName;
		direct_or_proxy_connect_port = param->ZttpServerPort;
	}

	switch (param->ProxyType)
	{
	case PROXY_NO_CONNECT:
		err = ERR_PROXY_NO_CONNECTION;
		break;

	case PROXY_DIRECT:
		sock = TcpConnectEx3(direct_or_proxy_connect_hostname, direct_or_proxy_connect_port, timeout, cancel, NULL, true, NULL, false, false, NULL);
		if (sock == NULL)
		{
			err = ERR_CONNECT_FAILED;
		}
		break;

	case PROXY_HTTP:
		sock = ProxyConnectEx2(&c, param->ProxyHostName, param->ProxyPort,
			direct_or_proxy_connect_hostname, direct_or_proxy_connect_port,
			param->ProxyUsername, param->ProxyPassword, false, cancel, NULL, timeout, param->ProxyUserAgent, flags);
		if (sock == NULL)
		{
			err = c.Err;
		}
		break;

	case PROXY_SOCKS:
		sock = SocksConnectEx2(&c, param->ProxyHostName, param->ProxyPort,
			direct_or_proxy_connect_hostname, direct_or_proxy_connect_port,
			param->ProxyUsername, false, cancel, NULL, timeout, NULL);
		if (sock == NULL)
		{
			err = c.Err;
		}
		break;
	}

	if (sock != NULL)
	{
		if (use_zttp)
		{
			// ZTTP connect
			ZTTP_CONNECT_REQUEST req = CLEAN;

			StrCpy(req.TargetFqdn, sizeof(req.TargetFqdn), param->HostName);
			req.TargetPort = param->Port;

			ZTTP_CONNECT_RESPONSE res = CLEAN;

			SOCK *new_sock = ZttpStartClientOverlaySock(&req, &res, param->ZttpServerHostName, sock, zttp_redirect_url, zttp_redirect_url_size);
			if (new_sock == NULL)
			{
				char tmp[MAX_SIZE] = CLEAN;

				err = res.ErrorCode;

				Format(tmp, sizeof(tmp), "ZTTP Start Error code: %u, Error str: %S, Error details: %S",
					res.ErrorCode,
					_E(res.ErrorCode),
					res.ErrorMessage);

				WriteBufLine(result_buf_if_error, tmp);

				Disconnect(sock);
				ReleaseSock(sock);
				sock = NULL;
			}
			else
			{
				sock = new_sock;
			}
		}
	}

	if (error_code != NULL)
	{
		*error_code = err;
	}

	return sock;
}
SOCK *WpcSockConnect2(char *hostname, UINT port, INTERNET_SETTING *t, UINT *error_code, UINT timeout)
{
	// Validate arguments
	INTERNET_SETTING t2;
	WPC_CONNECT c;
	if (t == NULL)
	{
		Zero(&t2, sizeof(t2));

		t = &t2;
	}

	Zero(&c, sizeof(c));
	StrCpy(c.HostName, sizeof(c.HostName), hostname);
	c.Port = port;
	c.ProxyType = t->ProxyType;
	StrCpy(c.ProxyHostName, sizeof(c.HostName), t->ProxyHostName);
	c.ProxyPort = t->ProxyPort;
	StrCpy(c.ProxyUsername, sizeof(c.ProxyUsername), t->ProxyUsername);
	StrCpy(c.ProxyPassword, sizeof(c.ProxyPassword), t->ProxyPassword);
	StrCpy(c.ProxyUserAgent, sizeof(c.ProxyUserAgent), t->ProxyUserAgent);

	return WpcSockConnect(&c, error_code, timeout);
}

// Handle the HTTP request
BUF *HttpRequest(URL_DATA *data, INTERNET_SETTING *setting,
				 UINT timeout_connect, UINT timeout_comm,
				 UINT *error_code, bool check_ssl_trust, char *post_data,
				 WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash)
{
	return HttpRequestEx(data, setting, timeout_connect, timeout_comm,
		error_code, check_ssl_trust, post_data,
		recv_callback, recv_callback_param, sha1_cert_hash, NULL, 0);
}
BUF *HttpRequestEx(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size)
{
	return HttpRequestEx2(data, setting, timeout_connect, timeout_comm, error_code,
		check_ssl_trust, post_data, recv_callback, recv_callback_param, sha1_cert_hash,
		cancel, max_recv_size, NULL, NULL);
}
BUF *HttpRequestEx2(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size, char *header_name, char *header_value)
{
	return HttpRequestEx3(data, setting, timeout_connect, timeout_comm, error_code, check_ssl_trust,
		post_data, recv_callback, recv_callback_param, sha1_cert_hash, (sha1_cert_hash == NULL ? 0 : 1),
		cancel, max_recv_size, header_name, header_value);
}
BUF *HttpRequestEx3(URL_DATA *data, INTERNET_SETTING *setting,
					UINT timeout_connect, UINT timeout_comm,
					UINT *error_code, bool check_ssl_trust, char *post_data,
					WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
					bool *cancel, UINT max_recv_size, char *header_name, char *header_value)
{
	return HttpRequestEx4(data, setting, timeout_connect, timeout_comm, error_code, check_ssl_trust,
		post_data, recv_callback, recv_callback_param, sha1_cert_hash, (sha1_cert_hash == NULL ? 0 : 1),
		cancel, max_recv_size, header_name, header_value, NULL);
}
BUF *HttpRequestEx4(URL_DATA *data, INTERNET_SETTING *setting,
					UINT timeout_connect, UINT timeout_comm,
					UINT *error_code, bool check_ssl_trust, char *post_data,
					WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
					bool *cancel, UINT max_recv_size, char *header_name, char *header_value, WT *wt)
{
	return HttpRequestEx5(data, setting, timeout_connect, timeout_comm, error_code, check_ssl_trust,
		post_data, recv_callback, recv_callback_param, sha1_cert_hash, (sha1_cert_hash == NULL ? 0 : 1),
		cancel, max_recv_size, header_name, header_value, wt, false, false);
}
BUF *HttpRequestEx5(URL_DATA *data, INTERNET_SETTING *setting,
	UINT timeout_connect, UINT timeout_comm,
	UINT *error_code, bool check_ssl_trust, char *post_data,
	WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
	bool *cancel, UINT max_recv_size, char *header_name, char *header_value, WT *wt, bool global_ip_only, bool dest_private_ip_only)
{
	return HttpRequestEx6(data, setting, timeout_connect, timeout_comm, error_code, check_ssl_trust,
		post_data, recv_callback, recv_callback_param, sha1_cert_hash, (sha1_cert_hash == NULL ? 0 : 1),
		cancel, max_recv_size, header_name, header_value, wt, false, false, NULL, NULL, HTTP_REQUEST_FLAG_NONE,
		NULL, 0);

}
BUF *HttpRequestEx6(URL_DATA *data, INTERNET_SETTING *setting,
	UINT timeout_connect, UINT timeout_comm,
	UINT *error_code, bool check_ssl_trust, char *post_data,
	WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
	bool *cancel, UINT max_recv_size, char *header_name, char *header_value, WT *wt, bool global_ip_only, bool dest_private_ip_only,
	BUF *result_buf_if_error, bool *is_server_error, UINT flags, char *redirect_url, UINT redirect_url_size)
{
	WPC_CONNECT con;
	SOCK *s;
	HTTP_HEADER *h;
	bool use_http_proxy = false;
	char target[MAX_SIZE * 4];
	char *send_str;
	BUF *send_buf;
	BUF *recv_buf;
	UINT http_error_code;
	char len_str[100];
	UINT content_len;
	void *socket_buffer;
	UINT socket_buffer_size = WPC_RECV_BUF_SIZE;
	UINT num_continue = 0;
	INTERNET_SETTING wt_setting;
	static bool dummy_value = false;
	if (is_server_error == NULL)
	{
		is_server_error = &dummy_value;
	}
	*is_server_error = false;
	// Validate arguments
	if (result_buf_if_error != NULL)
	{
		ClearBuf(result_buf_if_error);
	}
	if (data == NULL)
	{
		return NULL;
	}
	if (setting == NULL)
	{
		Zero(&wt_setting, sizeof(wt_setting));

		// For DeskVPN
		if (wt != NULL)
		{
			WtGetInternetSetting(wt, &wt_setting);
		}

		setting = &wt_setting;
	}
	if (error_code == NULL)
	{
		static UINT ret = 0;
		error_code = &ret;
	}
	if (timeout_comm == 0)
	{
		timeout_comm = WPC_TIMEOUT;
	}
	if (sha1_cert_hash == NULL)
	{
		num_hashes = 0;
	}
	if (num_hashes == 0)
	{
		sha1_cert_hash = NULL;
	}

	// Connection
	Zero(&con, sizeof(con));
	StrCpy(con.HostName, sizeof(con.HostName), data->HostName);
	con.Port = data->Port;
	con.ProxyType = setting->ProxyType;
	StrCpy(con.ProxyHostName, sizeof(con.ProxyHostName), setting->ProxyHostName);
	con.ProxyPort = setting->ProxyPort;
	StrCpy(con.ProxyUsername, sizeof(con.ProxyUsername), setting->ProxyUsername);
	StrCpy(con.ProxyPassword, sizeof(con.ProxyPassword), setting->ProxyPassword);
	StrCpy(con.ProxyUserAgent, sizeof(con.ProxyUserAgent), setting->ProxyUserAgent);

	con.EnableZttp = setting->EnableZttp;
	StrCpy(con.ZttpServerHostName, sizeof(con.ZttpServerHostName), setting->ZttpServerHostName);
	con.ZttpServerPort = setting->ZttpServerPort;

	if (false) // ZTTP_Test
	{
		if (wt != NULL && wt->Wide->Type != WIDE_TYPE_GATE)
		{
			con.EnableZttp = true;
			StrCpy(con.ZttpServerHostName, sizeof(con.ZttpServerHostName), "pc37.sehosts.com");
			con.ZttpServerPort = 443;
		}
	}

	if (setting->ProxyType != PROXY_HTTP || data->Secure)
	{
		use_http_proxy = false;
		StrCpy(target, sizeof(target), data->Target);
	}
	else
	{
		use_http_proxy = true;
		CreateUrl(target, sizeof(target), data);
	}

	if (use_http_proxy == false)
	{
		// If the connection is not via HTTP Proxy, or is a SSL connection even via HTTP Proxy
		s = WpcSockConnectEx(&con, error_code, timeout_connect, cancel, result_buf_if_error,
			redirect_url, redirect_url_size, flags);
	}
	else
	{
		// If the connection is not SSL via HTTP Proxy (non-SSL HTTP proxy raw only)
		s = TcpConnectEx3(con.ProxyHostName, con.ProxyPort, timeout_connect, cancel, NULL, true, NULL, false, false, NULL);
		if (s == NULL)
		{
			*error_code = ERR_PROXY_CONNECT_FAILED;
		}
	}

	if (s == NULL)
	{
		WriteBufLine(result_buf_if_error, "TCP connect error.");
		return NULL;
	}

	*is_server_error = true;

	if (global_ip_only)
	{
		// Global IP only
		if (IsIPPrivate(&s->LocalIP))
		{
			*error_code = ERR_NOT_SUPPORTED;
			Disconnect(s);
			ReleaseSock(s);
			WriteBufLine(result_buf_if_error, "IsIPPrivate(LocalIP) is true.");
			return NULL;
		}
	}

	if (dest_private_ip_only)
	{
		// Dest is private IP only
		if (IsIPPrivate(&s->RemoteIP) == false)
		{
			*error_code = ERR_NOT_SUPPORTED;
			Disconnect(s);
			ReleaseSock(s);
			WriteBufLine(result_buf_if_error, "IsIPPrivate(RemoteIP) is true.");
			return NULL;
		}
	}

	if (flags & HTTP_REQUEST_FLAG_IPV4_ONLY)
	{
		// IPv4 only
		if (IsIP6(&s->RemoteIP))
		{
			char tmp[256] = CLEAN;

			Format(tmp, sizeof(tmp), "The destination hostname %s was resolved as an IPv6 address %r. IPv6 address is not supported in this function.",
				con.HostName, &s->RemoteIP);

			WriteBufLine(result_buf_if_error, tmp);

			*error_code = ERR_NOT_SUPPORTED;
			Disconnect(s);
			ReleaseSock(s);
			return NULL;
		}
	}

	if (data->Secure)
	{
		bool trusted_checked = false;
		// Start the SSL communication
		if (StartSSLEx(s, NULL, NULL, true, 0, (IsEmptyStr(data->SniString) ? NULL : data->SniString)) == false)
		{
			// SSL connection failed
			*error_code = ERR_PROTOCOL_ERROR;
			Disconnect(s);
			ReleaseSock(s);
			WriteBufLine(result_buf_if_error, "StartSSLEx error.");
			return NULL;
		}

		if (check_ssl_trust)
		{
			if (wt != NULL)
			{
				// For DeskVPN
				if (WtIsTrustedCert(wt, s->RemoteX) == false)
				{
					*error_code = ERR_SSL_X509_UNTRUSTED;
					Disconnect(s);
					ReleaseSock(s);
					WriteBufLine(result_buf_if_error, "WtIsTrustedCert() == false.");
					return NULL;
				}
				else
				{
					trusted_checked = true;
				}
			}
		}

		if (trusted_checked == false && (sha1_cert_hash != NULL && num_hashes >= 1))
		{
			UCHAR hash[SHA1_SIZE];
			UINT i;
			bool ok = false;

			Zero(hash, sizeof(hash));
			GetXDigest(s->RemoteX, hash, true);

			for (i = 0;i < num_hashes;i++)
			{
				UCHAR *a = (UCHAR *)sha1_cert_hash;
				a += (SHA1_SIZE * i);

				if (Cmp(hash, a, SHA1_SIZE) == 0)
				{
					ok = true;
					break;
				}
			}

			if (ok == false)
			{
				// Destination certificate hash mismatch
				*error_code = ERR_CERT_NOT_TRUSTED;
				Disconnect(s);
				ReleaseSock(s);
				WriteBufLine(result_buf_if_error, "Checking the destination SSL server certificate failed. Server's SSL digest SHA1 hash was different.");
				return NULL;
			}
		}
	}

	// Timeout setting
	SetTimeout(s, timeout_comm);

	// Generate a request
	h = NewHttpHeader(data->Method, target, use_http_proxy ? "HTTP/1.0" : "HTTP/1.1");
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Accept-Language", "ja"));
	AddHttpValue(h, NewHttpValue("User-Agent", WPC_USER_AGENT));
	AddHttpValue(h, NewHttpValue("Pragma", "no-cache"));
	AddHttpValue(h, NewHttpValue("Cache-Control", "no-cache"));
	AddHttpValue(h, NewHttpValue("Host", data->HeaderHostName));

	if (IsEmptyStr(header_name) == false && IsEmptyStr(header_value) == false)
	{
		AddHttpValue(h, NewHttpValue(header_name, header_value));
	}

	if (IsEmptyStr(data->Referer) == false)
	{
		AddHttpValue(h, NewHttpValue("Referer", data->Referer));
	}

	if (StrCmpi(data->Method, WPC_HTTP_POST_NAME) == 0)
	{
		ToStr(len_str, StrLen(post_data));
		AddHttpValue(h, NewHttpValue("Content-Type", "application/x-www-form-urlencoded"));
		AddHttpValue(h, NewHttpValue("Content-Length", len_str));
	}

	if (IsEmptyStr(data->AdditionalHeaderName) == false && IsEmptyStr(data->AdditionalHeaderValue) == false)
	{
		AddHttpValue(h, NewHttpValue(data->AdditionalHeaderName, data->AdditionalHeaderValue));
	}

	if (use_http_proxy)
	{
		AddHttpValue(h, NewHttpValue("Proxy-Connection", "Keep-Alive"));

		if (IsEmptyStr(setting->ProxyUsername) == false || IsEmptyStr(setting->ProxyPassword) == false)
		{
			char auth_tmp_str[MAX_SIZE], auth_b64_str[MAX_SIZE * 2];
			char basic_str[MAX_SIZE * 2];

			// Generate the authentication string
			Format(auth_tmp_str, sizeof(auth_tmp_str), "%s:%s",
				setting->ProxyUsername, setting->ProxyPassword);

			// Base64 encode
			Zero(auth_b64_str, sizeof(auth_b64_str));
			Encode64(auth_b64_str, auth_tmp_str);
			Format(basic_str, sizeof(basic_str), "Basic %s", auth_b64_str);

			AddHttpValue(h, NewHttpValue("Proxy-Authorization", basic_str));
		}
	}

	send_str = HttpHeaderToStr(h, 0);
	FreeHttpHeader(h);

	send_buf = NewBuf();
	WriteBuf(send_buf, send_str, StrLen(send_str));
	Free(send_str);

	// Append to the sending data in the case of POST
	if (StrCmpi(data->Method, WPC_HTTP_POST_NAME) == 0)
	{
		WriteBuf(send_buf, post_data, StrLen(post_data));
	}

	// Send
	if (SendAll(s, send_buf->Buf, send_buf->Size, s->SecureMode) == false)
	{
		Disconnect(s);
		ReleaseSock(s);
		FreeBuf(send_buf);

		*error_code = ERR_DISCONNECTED;

		WriteBufLine(result_buf_if_error, "Send HTTP request failed.");

		return NULL;
	}

	FreeBuf(send_buf);

CONT:
	// Receive
	h = RecvHttpHeader(s, 0, 0);
	if (h == NULL)
	{
		Disconnect(s);
		ReleaseSock(s);

		*error_code = ERR_DISCONNECTED;

		WriteBufLine(result_buf_if_error, "Receive HTTP response failed.");

		return NULL;
	}

	http_error_code = 0;
	if (StrLen(h->Method) == 8)
	{
		if (Cmp(h->Method, "HTTP/1.", 7) == 0)
		{
			http_error_code = ToInt(h->Target);
		}
	}

	*error_code = ERR_NO_ERROR;

	switch (http_error_code)
	{
	case 401:
	case 407:
		// Proxy authentication error
		*error_code = ERR_PROXY_AUTH_FAILED;
		break;

	case 404:
		// 404 File Not Found
		*error_code = ERR_OBJECT_NOT_FOUND;
		break;

	case 100:
		// Continue
		num_continue++;
		if (num_continue >= 10)
		{
			goto DEF;
		}
		FreeHttpHeader(h);
		goto CONT;

	case 200:
		// Success
		break;

	default:
		// Protocol error
DEF:
		*error_code = ERR_PROTOCOL_ERROR;
		break;
	}

	if (*error_code != ERR_NO_ERROR)
	{
		char errstr[128] = CLEAN;

		Format(errstr, sizeof(errstr), "HTTP error code: %u (%s)", http_error_code, h->Method);

		WriteBufLine(result_buf_if_error, errstr);

		// An error has occured
		if (result_buf_if_error != NULL)
		{
			content_len = GetContentLength(h);
			if (max_recv_size != 0)
			{
				content_len = MIN(content_len, max_recv_size);
			}

			socket_buffer = Malloc(socket_buffer_size);

			while (true)
			{
				UINT recvsize = MIN(socket_buffer_size, content_len - result_buf_if_error->Size);
				UINT size;

				if (recvsize == 0)
				{
					break;
				}

				size = Recv(s, socket_buffer, recvsize, s->SecureMode);
				if (size == 0)
				{
					break;
				}

				WriteBuf(result_buf_if_error, socket_buffer, size);
			}

			SeekBuf(result_buf_if_error, 0, 0);
			Free(socket_buffer);
		}

		Disconnect(s);
		ReleaseSock(s);
		FreeHttpHeader(h);
		return NULL;
	}

	// Get the length of the content
	content_len = GetContentLength(h);
	if (max_recv_size != 0)
	{
		content_len = MIN(content_len, max_recv_size);
	}

	FreeHttpHeader(h);

	socket_buffer = Malloc(socket_buffer_size);

	// Receive the content
	recv_buf = NewBuf();

	while (true)
	{
		UINT recvsize = MIN(socket_buffer_size, content_len - recv_buf->Size);
		UINT size;

		if (recv_callback != NULL)
		{
			if (recv_callback(recv_callback_param,
				content_len, recv_buf->Size, recv_buf) == false)
			{
				// Cancel the reception
				*error_code = ERR_USER_CANCEL;
				goto RECV_CANCEL;
			}
		}

		if (recvsize == 0)
		{
			break;
		}

		size = Recv(s, socket_buffer, recvsize, s->SecureMode);
		if (size == 0)
		{
			// Disconnected
			*error_code = ERR_DISCONNECTED;

RECV_CANCEL:
			FreeBuf(recv_buf);
			Free(socket_buffer);
			Disconnect(s);
			ReleaseSock(s);

			return NULL;
		}

		WriteBuf(recv_buf, socket_buffer, size);

		if (result_buf_if_error != NULL)
		{
			WriteBuf(result_buf_if_error, socket_buffer, size);
		}
	}

	SeekBuf(recv_buf, 0, 0);
	Free(socket_buffer);

	Disconnect(s);
	ReleaseSock(s);

	// Transmission
	return recv_buf;
}

// Get the proxy server settings from the registry string of IE
bool GetProxyServerNameAndPortFromIeProxyRegStr(char *name, UINT name_size, UINT *port, char *str, char *server_type)
{
#ifdef	OS_WIN32
	TOKEN_LIST *t;
	UINT i;
	bool ret = false;
	// Validate arguments
	if (name == NULL || port == NULL || str == NULL || server_type == NULL)
	{
		return false;
	}

	t = ParseToken(str, ";");

	for (i = 0;i < t->NumTokens;i++)
	{
		char *s = t->Token[i];
		UINT i;

		Trim(s);

		i = SearchStrEx(s, "=", 0, false);
		if (i != INFINITE)
		{
			char tmp[MAX_PATH];

			StrCpy(name, name_size, s);
			name[i] = 0;

			if (StrCmpi(name, server_type) == 0)
			{
				char *host;
				StrCpy(tmp, sizeof(tmp), s + i + 1);

				if (ParseHostPort(tmp, &host, port, 0))
				{
					StrCpy(name, name_size, host);
					Free(host);

					if (*port != 0)
					{
						ret = true;
					}
					break;
				}
			}
		}
	}

	FreeToken(t);

	return ret;
#else	// OS_WIN32
	return true;
#endif	// OS_WIN32
}

// Get the internet connection settings of the system
void GetSystemInternetSetting(INTERNET_SETTING *setting)
{
#ifdef	OS_WIN32
	bool use_proxy;
	// Validate arguments
	if (setting == NULL)
	{
		return;
	}

	Zero(setting, sizeof(INTERNET_SETTING));

	use_proxy = MsRegReadInt(REG_CURRENT_USER,
		"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
		"ProxyEnable");

	if (use_proxy)
	{
		char *str = MsRegReadStr(REG_CURRENT_USER,
			"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			"ProxyServer");
		if (str != NULL)
		{
			char name[MAX_HOST_NAME_LEN + 1];
			UINT port;

			if (GetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
				&port, str, "https"))
			{
				setting->ProxyType = PROXY_HTTP;
				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
				setting->ProxyPort = port;
			}
			else if (GetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
				&port, str, "http"))
			{
				setting->ProxyType = PROXY_HTTP;
				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
				setting->ProxyPort = port;
			}
			else if (GetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
				&port, str, "socks"))
			{
				setting->ProxyType = PROXY_SOCKS;
				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
				setting->ProxyPort = port;
			}
			else
			{
				if (SearchStrEx(str, "=", 0, false) == INFINITE)
				{
					char *host;
					UINT port;
					if (ParseHostPort(str, &host, &port, 0))
					{
						if (port != 0)
						{
							setting->ProxyType = PROXY_HTTP;
							StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), host);
							setting->ProxyPort = port;
						}
						Free(host);
					}
				}
			}

			Free(str);
		}
	}
#else	// OS_WIN32
	Zero(setting, sizeof(INTERNET_SETTING));
#endif	// OS_WIN32
}

// Generate the URL
void CreateUrl(char *url, UINT url_size, URL_DATA *data)
{
	char *protocol;
	// Validate arguments
	if (url == NULL || data == NULL)
	{
		return;
	}

	if (data->Secure == false)
	{
		protocol = "http://";
	}
	else
	{
		protocol = "https://";
	}

	Format(url, url_size, "%s%s%s", protocol, data->HeaderHostName, data->Target);
}


// Parse the URL
bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer)
{
	char tmp[MAX_SIZE * 3];
	char server_port[MAX_HOST_NAME_LEN + 16];
	char *s = NULL;
	char *host;
	UINT port;
	UINT i;
	// Validate arguments
	if (data == NULL || str == NULL)
	{
		return false;
	}

	Zero(data, sizeof(URL_DATA));

	if (is_post)
	{
		StrCpy(data->Method, sizeof(data->Method), WPC_HTTP_POST_NAME);
	}
	else
	{
		StrCpy(data->Method, sizeof(data->Method), WPC_HTTP_GET_NAME);
	}

	if (referrer != NULL)
	{
		StrCpy(data->Referer, sizeof(data->Referer), referrer);
	}

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	// Determine the protocol
	if (StartWith(tmp, "http://"))
	{
		data->Secure = false;
		s = &tmp[7];
	}
	else if (StartWith(tmp, "https://"))
	{
		data->Secure = true;
		s = &tmp[8];
	}
	else
	{
		if (SearchStrEx(tmp, "://", 0, false) != INFINITE)
		{
			return false;
		}
		data->Secure = false;
		s = &tmp[0];
	}

	// Get the "server name:port number"
	StrCpy(server_port, sizeof(server_port), s);
	i = SearchStrEx(server_port, "/", 0, false);
	if (i != INFINITE)
	{
		server_port[i] = 0;
		s += StrLen(server_port);
		StrCpy(data->Target, sizeof(data->Target), s);
	}
	else
	{
		StrCpy(data->Target, sizeof(data->Target), "/");
	}

	if (ParseHostPort(server_port, &host, &port, data->Secure ? 443 : 80) == false)
	{
		return false;
	}

	StrCpy(data->HostName, sizeof(data->HostName), host);
	data->Port = port;

	// SNI string
	StrCpy(data->SniString, sizeof(data->SniString), data->HostName);

	Free(host);

	if ((data->Secure && data->Port == 443) || (data->Secure == false && data->Port == 80))
	{
		StrCpy(data->HeaderHostName, sizeof(data->HeaderHostName), data->HostName);
	}
	else
	{
		Format(data->HeaderHostName, sizeof(data->HeaderHostName),
			"%s:%u", data->HostName, data->Port);
	}

	return true;
}

// String replacement
void Base64ToSafe64(char *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		switch (str[i])
		{
		case '=':
			str[i] = '(';
			break;

		case '+':
			str[i] = ')';
			break;

		case '/':
			str[i] = '_';
			break;
		}
	}
}
void Safe64ToBase64(char *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		switch (str[i])
		{
		case '(':
			str[i] = '=';
			break;

		case ')':
			str[i] = '+';
			break;

		case '_':
			str[i] = '/';
			break;
		}
	}
}

// Decode from Safe64
UINT DecodeSafe64(void *dst, char *src, UINT src_strlen)
{
	char *tmp;
	UINT ret;
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	if (src_strlen == 0)
	{
		src_strlen = StrLen(src);
	}

	tmp = Malloc(src_strlen + 1);
	Copy(tmp, src, src_strlen);
	tmp[src_strlen] = 0;
	Safe64ToBase64(tmp);

	ret = B64_Decode(dst, tmp, src_strlen);
	Free(tmp);

	return ret;
}

// Encode to Safe64
void EncodeSafe64(char *dst, void *src, UINT src_size)
{
	UINT size;
	if (dst == NULL || src == NULL)
	{
		return;
	}

	size = B64_Encode(dst, src, src_size);
	dst[size] = 0;

	Base64ToSafe64(dst);
}

