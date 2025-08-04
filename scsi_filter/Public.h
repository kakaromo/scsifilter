/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that app can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_scsifilter,
    0x93cf5226,0x6f8d,0x4a9b,0xbd,0xb1,0xe8,0x3a,0xe7,0x68,0xeb,0x90);
// {93cf5226-6f8d-4a9b-bdb1-e83ae768eb90}
