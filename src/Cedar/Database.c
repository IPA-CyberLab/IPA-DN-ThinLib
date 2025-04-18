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


// Database.c
// License database

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

// Get the License status string
wchar_t *LiGetLicenseStatusStr(UINT i)
{
	wchar_t *ret = _UU("LICENSE_STATUS_OTHERERROR");

	switch (i)
	{
	case LICENSE_STATUS_OK:
		ret = _UU("LICENSE_STATUS_OK");
		break;

	case LICENSE_STATUS_EXPIRED:
		ret = _UU("LICENSE_STATUS_EXPIRED");
		break;

	case LICENSE_STATUS_ID_DIFF:
		ret = _UU("LICENSE_STATUS_ID_DIFF");
		break;

	case LICENSE_STATUS_DUP:
		ret = _UU("LICENSE_STATUS_DUP");
		break;

	case LICENSE_STATUS_INSUFFICIENT:
		ret = _UU("LICENSE_STATUS_INSUFFICIENT");
		break;

	case LICENSE_STATUS_COMPETITION:
		ret = _UU("LICENSE_STATUS_COMPETITION");
		break;

	case LICENSE_STATUS_NONSENSE:
		ret = _UU("LICENSE_STATUS_NONSENSE");
		break;

	case LICENSE_STATUS_CPU:
		ret = _UU("LICENSE_STATUS_CPU");
		break;
	}

	return ret;
}

static char *li_keybit_chars = "ABCDEFGHJKLMNPQRSTUVWXYZ12345678";

// Convert the string to a key bit
bool LiStrToKeyBit(UCHAR *keybit, char *keystr)
{
	UINT x[36];
	UINT i, wp;
	char *str;
	// Validate arguments
	if (keybit == NULL || keystr == NULL)
	{
		return false;
	}

	str = CopyStr(keystr);
	Trim(str);

	wp = 0;
	if (StrLen(str) != 41)
	{
		Free(str);
		return false;
	}

	for (i = 0;i < 36;i++)
	{
		char c = str[wp++];
		UINT j;

		if (((i % 6) == 5) && (i != 35))
		{
			if (str[wp++] != '-')
			{
				Free(str);
				return false;
			}
		}

		x[i] = INFINITE;
		for (j = 0;j < 32;j++)
		{
			if (ToUpper(c) == li_keybit_chars[j])
			{
				x[i] = j;
			}
		}

		if (x[i] == INFINITE)
		{
			Free(str);
			return false;
		}
	}

	Zero(keybit, 23);

	keybit[0] = x[0] << 1 | x[1] >> 4;
	keybit[1] = x[1] << 4 | x[2] >> 1;
	keybit[2] = x[2] << 7 | x[3] << 2 | x[4] >> 3;
	keybit[3] = x[4] << 5 | x[5];

	keybit[4] = x[6] << 3 | x[7] >> 2;
	keybit[5] = x[7] << 6 | x[8] << 1 | x[9] >> 4;
	keybit[6] = x[9] << 4 | x[10] >> 1;
	keybit[7] = x[10] << 7 | x[11] << 2 | x[12] >> 3;
	keybit[8] = x[12] << 5 | x[13];

	keybit[9] = x[14] << 3 | x[15] >> 2;
	keybit[10] = x[15] << 6 | x[16] << 1 | x[17] >> 4;
	keybit[11] = x[17] << 4 | x[18] >> 1;
	keybit[12] = x[18] << 7 | x[19] << 2 | x[20] >> 3;
	keybit[13] = x[20] << 5 | x[21];

	keybit[14] = x[22] << 3 | x[23] >> 2;
	keybit[15] = x[23] << 6 | x[24] << 1 | x[25] >> 4;
	keybit[16] = x[25] << 4 | x[26] >> 1;
	keybit[17] = x[26] << 7 | x[27] << 2 | x[28] >> 3;
	keybit[18] = x[28] << 5 | x[29];

	keybit[19] = x[30] << 3 | x[31] >> 2;
	keybit[20] = x[31] << 6 | x[32] << 1 | x[33] >> 4;
	keybit[21] = x[33] << 4 | x[34] >> 1;
	keybit[22] = x[34] << 7 | x[35] << 2;

	Free(str);

	return true;
}

// Determine whether the string is a license key
bool LiIsLicenseKey(char *str)
{
	UCHAR keybit[23];
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	if (LiStrToKeyBit(keybit, str) == false)
	{
		return false;
	}

	return true;
}

