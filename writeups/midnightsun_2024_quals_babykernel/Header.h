#pragma once
#include <fstream>
#include <iostream>
#include <windows.h>
#include <cstdlib>
#include <cstdint>
#include <winioctl.h>
#include <tlhelp32.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
typedef long long QWORD;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    /* 0x0000 */ unsigned short UniqueProcessId;
    /* 0x0002 */ unsigned short CreatorBackTraceIndex;
    /* 0x0004 */ unsigned char ObjectTypeIndex;
    /* 0x0005 */ unsigned char HandleAttributes;
    /* 0x0006 */ unsigned short HandleValue;
    /* 0x0008 */ void* Object;
    /* 0x0010 */ unsigned long GrantedAccess;
    /* 0x0014 */ long __PADDING__[1];
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO; /* size: 0x0018 */

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    /* 0x0000 */ PVOID Object;
    /* 0x0008 */ ULONG_PTR UniqueProcessId;
    /* 0x0010 */ ULONG_PTR HandleValue;
    /* 0x0018 */ ULONG GrantedAccess;
    /* 0x001C */ USHORT CreatorBackTraceIndex;
    /* 0x001E */ USHORT ObjectTypeIndex;
    /* 0x0020 */ ULONG HandleAttributes;
    /* 0x0024 */ ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; /* size: 0x28 */


typedef struct _SYSTEM_HANDLE_INFORMATION
{
    /* 0x0000 */ unsigned long NumberOfHandles;
    /* 0x0008 */ struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION; /* size: 0x0020 */

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    /* 0x0000 */ ULONG_PTR  NumberOfHandles;
    /* 0x0008 */ ULONG_PTR Reserved;
    /* 0x0010 */ struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX; /* size: 0x0020 */


typedef struct _SEP_TOKEN_PRIVILEGES
{
    /* 0x0000 */ unsigned __int64 Present;
    /* 0x0008 */ unsigned __int64 Enabled;
    /* 0x0010 */ unsigned __int64 EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, * PSEP_TOKEN_PRIVILEGES; /* size: 0x0018 */

typedef struct _SEP_AUDIT_POLICY
{
    /* 0x0000 */ struct _TOKEN_AUDIT_POLICY AdtTokenPolicy;
    /* 0x001e */ unsigned char PolicySetStatus;
} SEP_AUDIT_POLICY, * PSEP_AUDIT_POLICY; /* size: 0x001f */

typedef struct _TOKEN
{
    /* 0x0000 */ struct _TOKEN_SOURCE TokenSource;
    /* 0x0010 */ struct _LUID TokenId;
    /* 0x0018 */ struct _LUID AuthenticationId;
    /* 0x0020 */ struct _LUID ParentTokenId;
    /* 0x0028 */ union _LARGE_INTEGER ExpirationTime;
    /* 0x0030 */ struct _ERESOURCE* TokenLock;
    /* 0x0038 */ struct _LUID ModifiedId;
    /* 0x0040 */ struct _SEP_TOKEN_PRIVILEGES Privileges;
    /* 0x0058 */ struct _SEP_AUDIT_POLICY AuditPolicy;
    /* 0x0078 */ unsigned long SessionId;
    /* 0x007c */ unsigned long UserAndGroupCount;
    /* 0x0080 */ unsigned long RestrictedSidCount;
    /* 0x0084 */ unsigned long VariableLength;
    /* 0x0088 */ unsigned long DynamicCharged;
    /* 0x008c */ unsigned long DynamicAvailable;
    /* 0x0090 */ unsigned long DefaultOwnerIndex;
    /* 0x0098 */ struct SID_AND_ATTRIBUTES* UserAndGroups;
    /* 0x00a0 */ struct SID_AND_ATTRIBUTES* RestrictedSids;
    /* 0x00a8 */ void* PrimaryGroup;
    /* 0x00b0 */ unsigned long* DynamicPart;
    /* 0x00b8 */ struct _ACL* DefaultDacl;
    /* 0x00c0 */ enum _TOKEN_TYPE TokenType;
    /* 0x00c4 */ enum _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    /* 0x00c8 */ unsigned long TokenFlags;
    /* 0x00cc */ unsigned char TokenInUse;
    /* 0x00d0 */ unsigned long IntegrityLevelIndex;
    /* 0x00d4 */ unsigned long MandatoryPolicy;
    /* 0x00d8 */ struct _SEP_LOGON_SESSION_REFERENCES* LogonSession;
    /* 0x00e0 */ struct _LUID OriginatingLogonSession;
    /* 0x00e8 */ struct _SID_AND_ATTRIBUTES_HASH SidHash;
    /* 0x01f8 */ struct _SID_AND_ATTRIBUTES_HASH RestrictedSidHash;
    /* 0x0308 */ struct _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION* pSecurityAttributes;
    /* 0x0310 */ void* Package;
    /* 0x0318 */ struct _SID_AND_ATTRIBUTES* Capabilities;
    /* 0x0320 */ unsigned long CapabilityCount;
    /* 0x0328 */ struct _SID_AND_ATTRIBUTES_HASH CapabilitiesHash;
    /* 0x0438 */ struct _SEP_LOWBOX_NUMBER_ENTRY* LowboxNumberEntry;
    /* 0x0440 */ struct _SEP_CACHED_HANDLES_ENTRY* LowboxHandlesEntry;
    /* 0x0448 */ struct _AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION* pClaimAttributes;
    /* 0x0450 */ void* TrustLevelSid;
    /* 0x0458 */ struct _TOKEN* TrustLinkedToken;
    /* 0x0460 */ void* IntegrityLevelSidValue;
    /* 0x0468 */ struct _SEP_SID_VALUES_BLOCK* TokenSidValues;
    /* 0x0470 */ struct _SEP_LUID_TO_INDEX_MAP_ENTRY* IndexEntry;
    /* 0x0478 */ struct _SEP_TOKEN_DIAG_TRACK_ENTRY* DiagnosticInfo;
    /* 0x0480 */ struct _SEP_CACHED_HANDLES_ENTRY* BnoIsolationHandlesEntry;
    /* 0x0488 */ void* SessionObject;
    /* 0x0490 */ unsigned __int64 VariablePart;
} TOKEN, * PTOKEN; /* size: 0x0498 */

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    BOOLEAN TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
    ULONG				 Reserved3;
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 LoadCount;
    WORD                 NameOffset;
    CHAR                 Name[256];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG                ModulesCount;
    SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 0xb,
    SystemHandleInformation = 0x10,
    SystemExtendedHandleInformation = 0x40
} SYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

typedef NTSTATUS(WINAPI* pNtQueryObject)(
    __in_opt  HANDLE                   Handle,
    __in      OBJECT_INFORMATION_CLASS ObjectInformationClass,
    __out_opt PVOID                    ObjectInformation,
    __in      ULONG                    ObjectInformationLength,
    __out_opt PULONG                   ReturnLength
    );

typedef NTSTATUS(__stdcall* pNtQueryIntervalProfile)(
    DWORD ProfileSource,
    PULONG Interval
    );

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* pNtMapUserPhysicalPages)(
    __in PVOID VirtualAddress,
    __in ULONG_PTR NumberOfpages,
    __in_ecount_opt(NumberOfpages) PULONG_PTR UserPfnArray
    );


constexpr char kDeviceName[] = "\\\\.\\\\babykernel";

pNtQuerySystemInformation NtQuerySystemInformation = NULL;
pNtQueryObject NtQueryObject = NULL;
pNtWriteVirtualMemory NtWriteVirtualMemory = NULL;
pNtMapUserPhysicalPages NtMapUserPhysicalPages = NULL;

#define SE_DEBUG_PRIVILEGE                    (20L)
