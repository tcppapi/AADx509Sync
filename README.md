# AADx509Sync
As I'm sure many have noticed, a huge gap in Microsoft's push for everyone to go to the cloud is RADIUS based authentication. There is no 'NPS for the cloud', so we're still currently stuck using it on-prem with on-prem identities. This works fine for hybrid identities, but AAD-only devices don't have an associated computer object on-prem, so authentication fails. This script will fix all of your NPS woes!
GitHub Link (forgive me for formatting, this is my first time uploading to github...)

Outcomes:
You'll effectively be able to manage device- and user-based RADIUS/NPS certificate authentication via Azure AD identities and groups (dynamic, static, etc) using certs issued from ADCS and Intune.

Requirements:
1.	ADCS as your CA/PKI issuing certificates via Intune PKCS or SCEP profiles
2.	Device writeback enabled via Azure AD Connect
3.	Group writeback v2 enabled via Azure AD Connect w/ DN as display name enabled
4.	Disable SAN to UPN mapping on all DCs (see notes)
5.	ActiveDirectory and PSPKI PowerShell modules (recommended to run on DCs, see notes)

What it does:
1.	Syncs msDS-Device objects to computer objects in a dedicated OU
2.	Maps certificate thumbprints issued via ADCS to the associated AADx509 computer object (and optionally map user certs to AD user objects)
3.	Syncs group writeback groups to equivalent groups w/ AD computer objects

How:
1.	This step will create the computer object with proper SPN, add it to a default group you specify and set it as the primary, then remove it from the Domain Computers group. It also checks a 'feedback loop' is not occurring with AAD Connect.
2.	This step will get all issued certificates from your ADCS servers, match certificates to computer and user objects using the certificate's SAN UPN attribute, the AADx509 computer object's name attribute, and the AD user object's UPN attribute. Once matched, it will add the certificate's SHA1 hash to the AD object's altSecurityIdentities attribute.
3.	This step will get all the writeback groups and create identical security groups ending in _AADx509Sync with the matching computer objects we created in step 1 instead of the msDS_Device objects. It will also update/remove members and groups as they are updated/removed from AAD.

Please note - Any certificates issued from your CAs with the SAN UPN attribute matching an AADx509 computer object's SPN "host/{{AAD_Device_ID}}" or a user object's UPN "example@domain.com" will have their hash mapped to the computer/user objects and resulting groups/permissions during step 2 of each run. You can turn off user mapping in the options.

Why:
1.	NPS needs device or user objects to authenticate against in AD. Since the device writeback feature in AAD Connect works perfect and provides all the attributes we need, it's easier to sync the data from the msDS-Device objects instead of direct from AAD.
2.	You used to be able to just create objects in AD that NPS (schannel) would map certificates to using SPNs/UPNs, but due to security vulnerabilities and KB5014754, you now must map certificates directly to AD objects using cryptographic attributes of the cert. The same restrictions apply to user accounts, and the EnableUserSync option allows you to enable/disable the mapping for users specifically.
3.	Group writeback v2 works perfect to sync back security and other groups types to AD using AAD Connect, but AAD-only devices will sync back to AD groups with msDS-Device objects (hybrid devices/users sync their actual AD object). You also can't add to these groups because they'll get overwritten next AAD sync, so we create the second _AADx509Sync.

Limitations:
1.	Subject to any limitations of AAD Connect writeback features
2.	Azure AD device ID acts as the anchor attribute for device certs, and UserPrincipalName acts as the anchor for user certs. These cannot be changed currently
3.	One-way sync and cleanup
4.	EnableUserSync only works for existing hybrid AAD users and does not create user objects
5.	Does not sync description attributes after initial object creation
6.	Renaming a group in the cloud will result in a new (not renamed) AADx509Sync on-prem

Setup (see pics):
1.	Configure Intune PKCS or SCEP cert profile
1.	UPN required to set as "host/{{AAD_Device_ID}}" for device certs pic
2.	UPN required to set as "{{UserPrincipalName}}" for user certs pic
3.	SN and other SANs can be set as desired
2.	Configure options at top of script, save in C:\Scripts on DCs
3.	Setup Scheduled Task on your DCs to run the script periodically (30 min for single DC, 1hr staggered for dual DCs/HA) pic1 pic2 pic3 pic4
4.	Add permissions for accounts running script on CA servers (if running as SYSTEM, it is the computer account of the servers running it) pic1
5.	Setup writeback groups in AAD portal, wait for them to be synced back by AAD Connect and the script pic1
6.	Add the resulting '_AADx509Sync' groups to policies in NPS and try authenticating pic1
7.	Logs can be found in C:\ProgramData\AADx509Sync.log

Security implications:
A user that knows an AAD Device ID or a user's UPN and has permission to enroll certificates from your CAs and specify SANs (subject alternative names) could obtain a certificate to access resources via NPS as that AAD device. Please ensure your certificate templates in ADCS are secured/locked down and you only have certificate templates available that are required. We're technically still mapping certificate's SAN to AD object's SPN/UPN, but validating the certificates came from authorized CAs in our domain, then mapping to AD objects.

Notes:
Before disabling SAN to UPN mapping, please fully read KB5014754 to understand the implications of why step 2 is required and impacts your environment may see in the coming months. According to the KB, you technically shouldn't have to disable the mapping, but I had to in order to get it working in my environment. As long as all of your ADCS servers have the May 2022 update and all required certificates have been re-enrolled with OID 1.3.6.1.4.1.311.25.2, your environment should not see an impact with disabling SAN to UPN on your DCs.
The script may take shorter or longer to run depending on the resources of the system running it, and where you run it (on DCs, CAs, laptop, etc). Since the majority of the queries the script is doing is against AD, it is best to run this directly on your DCs. Check the log file after first run to ensure everything is working properly. I'm running this on our DCs that are Server 2019 with PS version 5.1 (ADCS is also 2019) so I'm sure 2016 and 2022 will work, but unsure about 2012R2 or earlier PS versions.
You don't technically need to issue the certs via Intune, but Setup 1.1 or 1.2 must be true, and I don't know of another way to deploy cert profiles that reference the AAD device ID. If there is interest, I could re-write a v2 that fixes some of the limitations, removes reliance on AAD Connect, and syncs cloud-only users, but regardless, an ADDS instance is required to run NPS and ADCS.
Happy NPSing :-)


EDIT 11/23/22 - I realized bad logic in how the script matches existing devices could cause computer objects to be infinitely created between AD and AAD if the DeviceOU variable is set to sync in Azure AD Connect. This would escalate exponentially quickly (1000 devices turns into 2000, turns into 4000, 8000, 16000, etc each sync...) so I have pulled the script from GitHub for now until I'm able to solve this issue. I am leaving the post up for the info and will edit again once I'm able to update the script.
EDIT 11/30/22 - Added check to make sure 'feedback loop' is not happening with AAD Connect, added max lines variable for log file, and some other small tweaks. Also updated info above.

